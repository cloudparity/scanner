//go:build docker

// The brake against real servers. brake_test.go is the policy — lag and disk in, a decision out,
// no server anywhere — and this file is the two things only a server can answer: whether the
// statements really read what we think they read, and whether the drop really drops.
//
//	go test -tags docker ./agent/internal/backup/postgres/ -run Brake -v
//
// Every container is removed in a t.Cleanup, on failure and on t.Fatal alike. Nothing outside
// Docker is touched — no Azure, no testbed.
package postgres

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pglogrepl"
	"github.com/jackc/pgx/v5/pgconn"
)

// The publication the throwaway stream decodes against. Created by the superuser, because AD-039
// measured the replication role cannot create one.
const brakePublication = "vp_brake_pub"

// A disk that is nowhere near its line, so a test about something other than the arithmetic gets a
// Fine out of Assess and the trip has to be forced deliberately.
func roomyDisk(context.Context) (Space, error) {
	return Space{Total: 1024 * mib, Used: 100 * mib}, nil
}

// A disk with a single megabyte left before the read-only line, so the tens of megabytes of real
// unconsumed WAL the tests below produce come out well past tripAt. Used where the SUBJECT is the
// drop rather than the arithmetic — the arithmetic is brake_test.go's, and it needs no server.
func tightDisk(context.Context) (Space, error) {
	total := int64(1024 * mib)
	return Space{Total: total, Used: int64(float64(total)*readOnlyAt) - 1*mib}, nil
}

// writeUnconsumedWAL puts real WAL behind the slot: about 20 MB that nothing is reading, which is
// the scenario the brake exists for expressed in two statements.
func writeUnconsumedWAL(ctx context.Context, t *testing.T, id string) {
	t.Helper()
	psql(ctx, t, id, "CREATE TABLE filler AS SELECT repeat('x', 1000) AS pad FROM generate_series(1, 20000)")
	psql(ctx, t, id, "SELECT pg_switch_wal()")
}

// What the brake reads, read against real 14 and real 18. The statement is one line and it is the
// entire input to the safety of this product, so "does it parse and does it mean what we think"
// cannot be answered by a fake.
//
// restart_lsn is the column under test, not confirmed_flush_lsn: WAL retention is governed by the
// former, and the two differ exactly once a stream has confirmed anything — which is when reading
// the wrong one starts under-reporting the disk our slot occupies.
func TestBrakeReadsWhatOurSlotHoldsOnRealServers(t *testing.T) {
	for _, image := range []string{"postgres:14-alpine", "postgres:18-alpine"} {
		t.Run(image, func(t *testing.T) {
			t.Parallel()
			id := startPostgresContainer(t, image)
			conn := connectToContainer(t, portOf(t, id))

			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			b := &Brake{Slot: "vp_stream", Query: simpleQueryRows(conn), Disk: roomyDisk}

			// Before the slot exists there is nothing of ours holding anything, and the brake
			// must be silent about it rather than treat a missing slot as an emergency.
			before, err := b.read(ctx)
			if err != nil {
				t.Fatalf("read with no slot: %v", err)
			}
			if before.Present {
				t.Fatalf("a slot was reported before one was created: %+v", before)
			}

			if err := CreateSlot(ctx, conn, "vp_stream"); err != nil {
				t.Fatalf("CreateSlot: %v", err)
			}
			fresh, err := b.read(ctx)
			if err != nil {
				t.Fatalf("read a fresh slot: %v", err)
			}
			if !fresh.Present || fresh.ActivePID != 0 {
				t.Fatalf("a fresh unconsumed slot read as %+v, want present and consumed by nobody", fresh)
			}

			// Now make WAL that nothing consumes, which is the whole scenario in two statements.
			writeUnconsumedWAL(ctx, t, id)

			after, err := b.read(ctx)
			if err != nil {
				t.Fatalf("read after writing: %v", err)
			}
			if after.RetainedBytes <= fresh.RetainedBytes {
				t.Fatalf("retention did not grow while nothing consumed the slot: %d then %d bytes",
					fresh.RetainedBytes, after.RetainedBytes)
			}
			t.Logf("%s: retained %d bytes after ~20 MB of unconsumed writes (was %d)",
				image, after.RetainedBytes, fresh.RetainedBytes)

			// And the setting that would brake this server with no agent at all. Reported
			// rather than asserted to a value: the default is what it is, and what this
			// checks is that the statement answers over a replication connection.
			rows, err := b.Query(ctx, ceilingQuery)
			if err != nil {
				t.Fatalf("%s over a replication connection: %v", ceilingQuery, err)
			}
			t.Logf("%s: max_slot_wal_keep_size = %q, unlimited = %v",
				image, rows[0][0], unlimitedCeiling(rows[0][0]))
		})
	}
}

// The drop, against a real server, on an idle slot. Nothing is consuming it, which is the shape a
// leak left by a killed agent has — base.go's ErrSlotLeaked names exactly this and deliberately
// leaves establishing it to the brake.
func TestBrakeDropsOurOwnIdleSlot(t *testing.T) {
	t.Parallel()
	id := startPostgresContainer(t, "postgres:18-alpine")
	conn := connectToContainer(t, portOf(t, id))

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	if err := CreateSlot(ctx, conn, "vp_stream"); err != nil {
		t.Fatalf("CreateSlot: %v", err)
	}
	writeUnconsumedWAL(ctx, t, id)

	var alarms []Alarm
	b := &Brake{
		Slot:  "vp_stream",
		Query: simpleQueryRows(conn),
		Disk:  tightDisk,
		Alert: func(a Alarm) { alarms = append(alarms, a) },
	}

	decision, err := b.Check(ctx)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if decision.Verdict != Trip {
		t.Fatalf("verdict = %v, want trip: %s", decision.Verdict, decision.Why)
	}
	if len(alarms) != 1 || !alarms[0].Dropped {
		t.Fatalf("alarms = %v, want one saying the slot was dropped — that is the re-base signal", alarms)
	}
	if slots := countSlots(ctx, t, conn); slots != 0 {
		t.Fatalf("%d slots left on the server after the brake fired", slots)
	}
}

// THE CASE THE BRAKE EXISTS FOR. Our own stream is holding the slot open and the loop that would
// release it is the thing that is sick, so the brake has to terminate its own backend and then
// drop. A brake that refused here would refuse in exactly the situation it was built for.
//
// It also proves the privilege, which is not obvious and is not documented anywhere we control:
// pg_terminate_backend against a backend belonging to the SAME ROLE needs no superuser and no
// pg_signal_backend membership. If that were false the whole design would be unbuildable, because
// AD-034 measured the customer's administrator cannot help.
func TestBrakeTerminatesItsOwnWedgedStreamAndDrops(t *testing.T) {
	t.Parallel()
	id := startPostgresContainer(t, "postgres:18-alpine")
	port := portOf(t, id)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	psql(ctx, t, id, "CREATE PUBLICATION "+brakePublication+" FOR ALL TABLES")

	// The brake's OWN connection — see (2) in brake.go's header. Two connections here is not a
	// test convenience: the stream's is in CopyBoth below and serves no statement at all.
	watcher := connectToContainer(t, port)
	stream := connectToContainer(t, port)

	if err := CreateSlot(ctx, watcher, "vp_stream"); err != nil {
		t.Fatalf("CreateSlot: %v", err)
	}
	writeUnconsumedWAL(ctx, t, id)
	if err := pglogrepl.StartReplication(ctx, stream, "vp_stream", 0, pglogrepl.StartReplicationOptions{
		PluginArgs: []string{protoVersion, "publication_names '" + brakePublication + "'"},
	}); err != nil {
		t.Fatalf("start the stream that the brake then has to kill: %v", err)
	}

	var alarms []Alarm
	b := &Brake{
		Slot:      "vp_stream",
		Query:     simpleQueryRows(watcher),
		Disk:      tightDisk,
		StreamPID: func() uint32 { return stream.PID() },
		Alert:     func(a Alarm) { alarms = append(alarms, a) },
	}

	// The precondition the whole test rests on: the server really does report our stream as the
	// consumer, so mayDrop has something to recognise.
	held, err := b.read(ctx)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if held.ActivePID != stream.PID() {
		t.Fatalf("active_pid = %d, want our stream's backend %d", held.ActivePID, stream.PID())
	}

	decision, err := b.Check(ctx)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if decision.Verdict != Trip {
		t.Fatalf("verdict = %v, want trip: %s", decision.Verdict, decision.Why)
	}
	if len(alarms) != 1 || !alarms[0].Dropped {
		t.Fatalf("alarms = %v, want one saying the slot was dropped", alarms)
	}
	if slots := countSlots(ctx, t, watcher); slots != 0 {
		t.Fatalf("%d slots left after the brake fired against our own consumer", slots)
	}
}

// The other side of the same question, and the epic's open item: TWO PARITY INSTALLS SHARING A SLOT
// NAME CANNOT BE TOLD APART BY NAME. So a consumer that is not ours means hands off — that consumer
// may be a sibling install's perfectly healthy stream, and dropping it would end THEIR chain in
// silence, which is this file's own fault inflicted on somebody else.
func TestBrakeLeavesAConsumerThatIsNotOursAlone(t *testing.T) {
	t.Parallel()
	id := startPostgresContainer(t, "postgres:18-alpine")
	port := portOf(t, id)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	psql(ctx, t, id, "CREATE PUBLICATION "+brakePublication+" FOR ALL TABLES")

	watcher := connectToContainer(t, port)
	stranger := connectToContainer(t, port)

	if err := CreateSlot(ctx, watcher, "vp_stream"); err != nil {
		t.Fatalf("CreateSlot: %v", err)
	}
	writeUnconsumedWAL(ctx, t, id)
	if err := pglogrepl.StartReplication(ctx, stranger, "vp_stream", 0, pglogrepl.StartReplicationOptions{
		PluginArgs: []string{protoVersion, "publication_names '" + brakePublication + "'"},
	}); err != nil {
		t.Fatalf("start the stranger's stream: %v", err)
	}

	var alarms []Alarm
	b := &Brake{
		Slot:  "vp_stream",
		Query: simpleQueryRows(watcher),
		Disk:  tightDisk,
		// No stream of ours at all: the brake ticking before ours opened, or after it died.
		StreamPID: func() uint32 { return 0 },
		Alert:     func(a Alarm) { alarms = append(alarms, a) },
	}

	decision, err := b.Check(ctx)
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if decision.Verdict != Trip {
		t.Fatalf("verdict = %v, want trip — the pressure is real even though the drop is refused", decision.Verdict)
	}
	if slots := countSlots(ctx, t, watcher); slots != 1 {
		t.Fatal("the brake destroyed a slot somebody else was consuming")
	}
	// Refusing quietly would be the worst outcome available: the WAL keeps growing and nobody
	// is told. A refused trip is the loudest thing this brake ever says.
	if len(alarms) != 1 || alarms[0].Err == nil || alarms[0].Dropped {
		t.Fatalf("alarms = %v, want one carrying why the drop was refused", alarms)
	}
	t.Logf("refused, as it must: %v", alarms[0].Err)
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE ACCEPTANCE CRITERION: a real small disk, really filled, and the brake fires before it is.
// ─────────────────────────────────────────────────────────────────────────────────────────────

// smallDisk is the size of the tmpfs the server below runs its whole cluster on. Small enough to
// fill in seconds, large enough that initdb fits with room to demonstrate the arithmetic.
const smallDisk = 512 // MiB

// dataDir is where that tmpfs is mounted. PGDATA is a directory UNDER it so the image's entrypoint
// creates it with the right ownership itself, which saves this test from having to know the uid the
// postgres user has inside whichever image it is given.
const (
	diskMount = "/small"
	dataDir   = "/small/data"
)

// TestTheBrakeFiresBeforeTheSmallDiskFills is the ticket's acceptance criterion, run rather than
// argued: a server whose entire cluster lives on a 512 MiB tmpfs, a replication slot nobody
// consumes, and writes until something gives.
//
// WHAT IS REAL HERE AND WHAT IS NOT. The disk is real, the WAL retention is real, the slot is real
// and the drop is real. What Docker cannot reproduce is AZURE'S read-only flip at 95%, which is a
// platform behaviour and not a PostgreSQL one — here the same disk simply runs out and the server
// PANICs. So the criterion is measured against the 95% LINE rather than against the flip: the brake
// must trip while the disk is still below it, and the database must still take writes afterwards.
//
// THE AZURE HALF IS NOT RUN AND MUST NOT BE READ AS IF IT WERE. Standing a Flexible Server on a
// small disk, filling it, and watching the platform really turn it read-only is testbed work and it
// has not been done. What this test establishes is everything up to that boundary.
func TestTheBrakeFiresBeforeTheSmallDiskFills(t *testing.T) {
	id := startPostgresOnASmallDisk(t, "postgres:18-alpine")
	conn := connectToContainer(t, portOf(t, id))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if err := CreateSlot(ctx, conn, "vp_stream"); err != nil {
		t.Fatalf("CreateSlot: %v", err)
	}
	psql(ctx, t, id, "CREATE TABLE filler (pad text)")

	var alarms []Alarm
	b := &Brake{
		Slot:  "vp_stream",
		Query: simpleQueryRows(conn),
		Disk:  func(ctx context.Context) (Space, error) { return dfOf(ctx, id, diskMount) },
		Alert: func(a Alarm) { alarms = append(alarms, a) },
	}

	// The brake must not fire on an empty database, or "it fires" would mean nothing.
	first, err := b.Check(ctx)
	if err != nil {
		t.Fatalf("the first Check: %v", err)
	}
	if first.Verdict != Fine {
		t.Fatalf("the brake fired on an empty database: %s", first.Why)
	}

	// 8 MiB a round. Bounded, because the failure this test exists to catch is the brake NOT
	// firing, and that failure must arrive as a report rather than as a hung test.
	const maxRounds = 80
	for round := 1; ; round++ {
		if round > maxRounds {
			t.Fatalf("wrote %d MiB into a %d MiB disk and the brake never fired", 8*maxRounds, smallDisk)
		}
		if err := insert8MiB(ctx, id); err != nil {
			t.Fatalf("round %d: the disk filled before the brake fired, which is the whole "+
				"failure this test exists to catch: %v", round, err)
		}

		decision, err := b.Check(ctx)
		if err != nil {
			t.Fatalf("round %d: Check: %v", round, err)
		}
		space, err := dfOf(ctx, id, diskMount)
		if err != nil {
			t.Fatalf("round %d: df: %v", round, err)
		}
		full := float64(space.Used) / float64(space.Total)
		t.Logf("round %2d: disk %.1f%% · pressure %.3f · %v", round, full*100, decision.Pressure, decision.Verdict)

		if decision.Verdict != Trip {
			continue
		}

		// THE CRITERION. The brake fired, and it fired while the server was still well
		// below the line at which Azure would have turned it read-only.
		if full >= readOnlyAt {
			t.Fatalf("the brake fired at %.1f%% of the disk, which is at or past the %.0f%% "+
				"read-only line — too late to be a brake", full*100, readOnlyAt*100)
		}
		t.Logf("BRAKE FIRED at %.1f%% of a %d MiB disk, %.1f points below the %.0f%% read-only line",
			full*100, smallDisk, (readOnlyAt-full)*100, readOnlyAt*100)

		if len(alarms) == 0 || !alarms[len(alarms)-1].Dropped {
			t.Fatalf("alarms = %v, want the last one to say the slot was dropped", alarms)
		}
		if slots := countSlots(ctx, t, conn); slots != 0 {
			t.Fatalf("%d slots still on the server after the brake fired", slots)
		}

		// And the database is still a database. This is the premise of the whole ticket:
		// our backup must not take down the thing it is backing up.
		if err := insert8MiB(ctx, id); err != nil {
			t.Fatalf("the server would not take a write after the brake fired: %v", err)
		}
		return
	}
}

// startPostgresOnASmallDisk runs a server whose entire cluster is on a tmpfs of smallDisk MiB.
//
// A tmpfs and not a volume, because the test needs a disk it can really exhaust in seconds and a
// loopback image would need privileges this test should not have. mode=0777 on the mount point lets
// the image's own entrypoint create PGDATA underneath it as whatever user it runs as.
func startPostgresOnASmallDisk(t *testing.T, image string) string {
	t.Helper()

	id := startPostgresIn(t,
		[]string{
			"-e", "PGDATA=" + dataDir,
			"--tmpfs", fmt.Sprintf("%s:rw,size=%dm,mode=0777", diskMount, smallDisk),
		},
		image,
		"-c", "wal_level=logical",
		// The default is unlimited, which is what a real Azure server has and what the brake
		// warns about. Pinned here so this test measures OUR brake and not the server's.
		"-c", "max_slot_wal_keep_size=-1",
	)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	psql(ctx, t, id, "CREATE ROLE vp_stream WITH LOGIN REPLICATION PASSWORD '"+containerPassword+"'")
	return id
}

// dfOf reads the real free space of one mount inside the container. This is the disk half of the
// brake's single number, taken from the only place a test can take it — on Azure it comes from
// Monitor, because nothing over port 5432 can answer it (see Disk).
func dfOf(ctx context.Context, id, mount string) (Space, error) {
	out, err := exec.CommandContext(ctx, "docker", "exec", id, "df", "-k", mount).CombinedOutput() //gosec:disable G204 -- a throwaway container this test started
	if err != nil {
		return Space{}, fmt.Errorf("df -k %s in %s: %v: %s", mount, id, err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return Space{}, fmt.Errorf("df printed no row for %s: %s", mount, out)
	}
	// Filesystem, 1K-blocks, Used, Available, Use%, Mounted on.
	fields := strings.Fields(lines[len(lines)-1])
	if len(fields) < 3 {
		return Space{}, fmt.Errorf("df printed %q, which has no size and used columns", lines[len(lines)-1])
	}
	total, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return Space{}, fmt.Errorf("df size %q: %w", fields[1], err)
	}
	used, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return Space{}, fmt.Errorf("df used %q: %w", fields[2], err)
	}
	return Space{Total: total * 1024, Used: used * 1024}, nil
}

// insert8MiB writes about eight mebibytes, and returns the server's error rather than failing the
// test: running out of space is a RESULT here, not an accident.
func insert8MiB(ctx context.Context, id string) error {
	cmd := exec.CommandContext(ctx, "docker", "exec", "-i", id, //gosec:disable G204 -- a throwaway container this test started
		"psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1")
	cmd.Stdin = strings.NewReader(
		"INSERT INTO filler SELECT repeat('x', 1000) FROM generate_series(1, 8000)")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func countSlots(ctx context.Context, t *testing.T, conn *pgconn.PgConn) int {
	t.Helper()
	row := queryRow(ctx, t, conn, "SELECT count(*) FROM pg_replication_slots WHERE slot_name = 'vp_stream'")
	n, err := strconv.Atoi(row[0])
	if err != nil {
		t.Fatalf("count(*) came back as %q: %v", row[0], err)
	}
	return n
}
