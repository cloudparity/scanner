//go:build docker

// The keepalive measurement of AD-039, reproduced against a real server in seconds rather than in
// minutes:
//
//	go test -tags docker ./agent/internal/backup/postgres/ -run 'Disconnected|WalSenderTimeout|StoreWindow' -v
//
// AD-039 measured wal_sender_timeout at ONE MINUTE on both Azure fixtures, which is why the spike
// spent a minute per phase discovering it. A container can be told to use two seconds
// (-c wal_sender_timeout=2s), and the server's behaviour is the same shape at either setting: it
// asks for a reply at half the timeout and hangs up at the whole of it. So every half of the
// measurement is here, against a real wal sender, for well under a minute:
//
//	PHASE A  a stream that answers nothing is DISCONNECTED           -> the hazard is real
//	PHASE B  a stream that answers with the zero LSN STAYS UP        -> the resolution works
//	         and confirmed_flush_lsn has not moved                   -> and it confirms nothing
//
// AND THE SAME PAIR FOR THE STORE WINDOW, which is the half the read loop cannot cover: between a
// batch being handed over and its Confirm, nothing is on the connection at all, and the server does
// not distinguish a slow upload from a stream that has stopped listening.
//
//	a store window of THREE timeouts survives, confirms nothing,
//	and the cycle after it still collects                            -> forward progress, not just a socket
//	the same window with the replies switched off ends in EOF        -> and the window really is fatal
//
// Every container is removed by a t.Cleanup, which runs on failure and on t.Fatal alike. NO
// AZURE: nothing outside Docker is touched.
package postgres

import (
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/manukyanv07/parity-scanner/agent/internal/backup"
)

// walSenderTimeout is what the container is started with. The server asks for a reply at half of
// it and hangs up at the whole of it, so phase A below costs one of these and no more.
const walSenderTimeout = 2 * time.Second

// storeWindowTimeout is what the STORE-window fixtures are started with, and it is deliberately
// looser than the two seconds above. Those tests wait out three whole timeouts while a real
// container is under whatever else the suite is running, and the liveness replies that have to
// land inside that wait come off a Go ticker: four seconds gives the replies a second each and
// keeps a busy machine from reading as a server hanging up.
const storeWindowTimeout = 4 * time.Second

// THE HAZARD, MEASURED. A stream that reads and answers nothing is disconnected at
// wal_sender_timeout — which under the naive reading of C3's rule is what a batch interval longer
// than the timeout produces, every single time, forever.
//
// If this test ever stops failing to stay connected, the whole shape of since.go is unnecessary
// and should be deleted — which is a thing worth learning from a test rather than from a customer.
func TestAStreamThatAnswersNothingIsDisconnected(t *testing.T) {
	t.Parallel()
	conn, _ := streamingContainer(t, "postgres:18-alpine", walSenderTimeout)

	// Generous next to the 2s timeout, so a failure here is the server hanging up and not this
	// budget expiring.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	link := &pgLink{conn: conn, slot: "vp_stream", publication: "vp_all"}
	if _, err := link.Start(ctx); err != nil {
		t.Fatalf("start the stream: %v", err)
	}

	began := time.Now()
	beats := 0
	for {
		read, cancelRead := context.WithTimeout(ctx, 10*time.Second)
		msg, err := link.Recv(read)
		cancelRead()

		if err != nil {
			if errors.Is(err, errQuiet) {
				t.Fatalf("the server neither sent nor hung up in 10s; wal_sender_timeout of %s "+
					"is not in effect and this test proves nothing", walSenderTimeout)
			}
			t.Logf("PHASE A ended after %s, %d keepalives: %v", time.Since(began).Round(time.Millisecond), beats, err)
			if time.Since(began) < walSenderTimeout {
				t.Fatalf("the stream died after %s, sooner than wal_sender_timeout (%s), so "+
					"whatever killed it is not the timeout this test is about", time.Since(began), walSenderTimeout)
			}
			return
		}
		if msg.Keepalive {
			beats++
		}
	}
}

// THE RESOLUTION, MEASURED, and both halves of it: the batcher runs a batch several times longer
// than wal_sender_timeout and comes out the other side alive, having confirmed NOTHING — which is
// read back off the server rather than off our own bookkeeping.
//
// This is the test that would have caught the naive implementation in both directions. A batcher
// that never replies fails at the first assertion; a batcher that keeps the connection alive by
// replying with the batch's own LSN fails at the last one, having told Postgres it may discard
// WAL that is in memory and nowhere else.
func TestALongBatchSurvivesWalSenderTimeoutAndConfirmsNothing(t *testing.T) {
	t.Parallel()
	conn, admin := streamingContainer(t, "postgres:18-alpine", walSenderTimeout)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	before := confirmedFlush(ctx, t, admin, "vp_stream")

	stream := &Stream{
		Conn:        conn,
		Slot:        "vp_stream",
		Publication: "vp_all",
		// THREE TIMES THE SERVER'S TIMEOUT. Under the naive reading of C3's rule this batch
		// cannot exist: the connection would be gone before it ended.
		Interval: 3 * walSenderTimeout,
		Report:   func(l Lag) { t.Logf("lag: %d bytes behind, cycle took %s", l.Bytes, l.Took.Round(time.Millisecond)) },
	}
	counted := &countingLink{link: &pgLink{conn: conn, slot: stream.Slot, publication: stream.Publication}}
	stream.link = counted

	// Something to carry, so the batch is a real one rather than an empty cycle.
	psql(ctx, t, admin, "INSERT INTO ops.beat(note) VALUES ('c3')")

	batch, err := stream.Since(ctx, backup.Position(before))
	if err != nil {
		t.Fatalf("a batch three times longer than wal_sender_timeout: %v", err)
	}
	if counted.replies() == 0 {
		t.Fatal("the batch completed without answering a single keepalive; either the server " +
			"asked for none, in which case this test proves nothing, or it hung up and the " +
			"failure surfaced somewhere else")
	}
	t.Logf("PHASE B: batch %s..%s survived %s with %d liveness replies",
		batch.From, batch.Position, stream.Interval, counted.replies())

	// THE HALF THAT MATTERS. The liveness replies kept the connection open and moved nothing:
	// the server still says exactly what it said before the batch began.
	if after := confirmedFlush(ctx, t, admin, "vp_stream"); after != before {
		t.Fatalf("confirmed_flush_lsn moved from %s to %s during a batch that was never "+
			"confirmed durable; Postgres has been told it may discard WAL that is in memory "+
			"and nowhere else", before, after)
	}

	// And the other act does move it. Same wire message, different meaning, and the difference
	// is the whole ticket.
	if err := stream.Confirm(ctx, batch.Position); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	// The server applies a standby status update asynchronously, so this is read until it
	// changes rather than once.
	waitForFlush(ctx, t, admin, "vp_stream", before)
}

// THE STORE WINDOW, AGAINST A REAL WAL SENDER. The batch is handed over and then nothing reads
// this connection for three times the server's timeout, which is what a slow upload is: the
// pipeline chunks, hashes and stores, and the read half of the stream is idle throughout.
//
// Before this was closed, the window ended in `unexpected EOF` and the cycle re-read its batch
// forever — the failure a real `make e2e-postgres` run hit under heavy Docker load, arriving as a
// network error rather than as "my upload outran the server's patience".
//
// All three halves are asserted, and the middle one is the one that matters: the stream SURVIVES
// the window, it confirms NOTHING during it — read off the server, not off our bookkeeping — and
// it still makes FORWARD PROGRESS afterwards, which is the part a stream that merely stayed
// connected would not prove.
func TestAStoreWindowLongerThanWalSenderTimeoutSurvivesAndConfirmsNothing(t *testing.T) {
	t.Parallel()
	conn, admin := streamingContainer(t, "postgres:18-alpine", storeWindowTimeout)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	before := confirmedFlush(ctx, t, admin, "vp_stream")

	stream := &Stream{
		Conn: conn, Slot: "vp_stream", Publication: "vp_all",
		// Short: this test is about what happens AFTER the batch is handed over, so the
		// collecting half is got out of the way quickly.
		Interval: time.Second,
	}
	counted := &countingLink{link: &pgLink{conn: conn, slot: stream.Slot, publication: stream.Publication}}
	stream.link = counted
	t.Cleanup(stream.Close)

	psql(ctx, t, admin, "INSERT INTO ops.beat(note) VALUES ('before the store window')")

	batch, err := stream.Since(ctx, backup.Position(before))
	if err != nil {
		t.Fatalf("collect a batch: %v", err)
	}
	collecting := counted.replies()

	// THE WINDOW. Three times what the server will wait, spent exactly as the pipeline spends it.
	window := 3 * storeWindowTimeout
	time.Sleep(window)

	if during := counted.replies() - collecting; during == 0 {
		t.Fatalf("nothing answered the server during a %s store window; the connection has been "+
			"silent for longer than wal_sender_timeout (%s) and the assertions below are about a "+
			"stream that is already gone", window, storeWindowTimeout)
	}
	// READ OFF THE SERVER. Every one of those replies carried the zero LSN, so the slot has not
	// moved — and a fix that kept the connection alive by replying with the batch's own position
	// fails here, having told Postgres to discard WAL that is in memory and nowhere else.
	if after := confirmedFlush(ctx, t, admin, "vp_stream"); after != before {
		t.Fatalf("confirmed_flush_lsn moved from %s to %s during a store window, before any "+
			"manifest existed; Postgres has been told it may discard WAL that is durable nowhere",
			before, after)
	}
	t.Logf("store window: %s with %d liveness replies, confirmed_flush_lsn still %s",
		window, counted.replies()-collecting, before)

	// The manifest has landed. Only now does a position go on the wire.
	if err := stream.Confirm(ctx, batch.Position); err != nil {
		t.Fatalf("confirm a batch stored across a %s window: %v", window, err)
	}
	waitForFlush(ctx, t, admin, "vp_stream", before)

	// AND THE STREAM STILL WORKS, which is the half that separates "the connection survived" from
	// "the chain makes progress". A hung-up stream fails here with `unexpected EOF`.
	psql(ctx, t, admin, "INSERT INTO ops.beat(note) VALUES ('after the store window')")
	next, err := stream.Since(ctx, batch.Position)
	if err != nil {
		t.Fatalf("the cycle after a long store window: %v", err)
	}
	t.Logf("the next cycle collected %s..%s, so the chain moved on", next.From, next.Position)
	if err := stream.Confirm(ctx, next.Position); err != nil {
		t.Fatalf("confirm the cycle after the window: %v", err)
	}
}

// THE COUNTERFACTUAL, so the test above is not one that would pass however it were written. The
// same store window with the replies switched off — which is precisely the code before this was
// fixed — and the connection is gone by the end of it.
//
// If this ever stops failing, wal_sender_timeout is not in effect on the fixture and the test
// above proves nothing.
func TestAStoreWindowWithNothingAnsweringIsHungUpOn(t *testing.T) {
	t.Parallel()
	conn, admin := streamingContainer(t, "postgres:18-alpine", storeWindowTimeout)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	before := confirmedFlush(ctx, t, admin, "vp_stream")
	stream := &Stream{Conn: conn, Slot: "vp_stream", Publication: "vp_all", Interval: time.Second}
	t.Cleanup(stream.Close)

	psql(ctx, t, admin, "INSERT INTO ops.beat(note) VALUES ('nobody is answering')")
	if _, err := stream.Since(ctx, backup.Position(before)); err != nil {
		t.Fatalf("collect a batch: %v", err)
	}

	// The store window as it used to be: nothing reading and nothing answering.
	stream.Close()
	time.Sleep(3 * storeWindowTimeout)

	// DRAINED RATHER THAN READ ONCE. The keepalives the server sent during the window are sitting
	// in the receive buffer, and they arrive before the hang-up does — a single read would find one
	// of those and conclude the stream is healthy.
	for {
		read, cancelRead := context.WithTimeout(ctx, 10*time.Second)
		_, err := stream.link.Recv(read)
		cancelRead()

		if err == nil {
			continue
		}
		if errors.Is(err, errQuiet) {
			t.Fatalf("the stream was still there after %s of silence; wal_sender_timeout of %s is "+
				"not in effect on this fixture, so the store-window test beside this one is "+
				"proving nothing", 3*storeWindowTimeout, storeWindowTimeout)
		}
		t.Logf("a store window with nothing answering ends the way it was reported: %v", err)
		return
	}
}

// countingLink counts the liveness replies without being able to change what they carry — it
// forwards to the real link, whose ReplyAlive takes no LSN.
//
// UNDER A LOCK because the replies that keep a STORE window alive come from a goroutine of the
// stream's, and this counter is read from the test's.
type countingLink struct {
	link
	mu    sync.Mutex
	alive int
}

func (c *countingLink) ReplyAlive(ctx context.Context) error {
	c.mu.Lock()
	c.alive++
	c.mu.Unlock()
	return c.link.ReplyAlive(ctx) //nolint:staticcheck // the embedded field, not this method
}

func (c *countingLink) replies() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.alive
}

// streamingContainer starts a server the change stream can actually read from and returns the
// agent's replication connection beside the container id, which the test uses as the customer's
// ADMINISTRATOR — the two roles are deliberately not the same one.
//
// The publication is created by the admin because AD-039 measured that the replication role
// cannot: `CREATE PUBLICATION` comes back 42501 for it on both 14 and 18. It is a second thing the
// customer's administrator has to do, alongside CREATE ROLE … REPLICATION.
//
// senderTimeout is a parameter rather than the constant above because the two things measured
// against this container want opposite settings: the keepalive tests want a server that hangs up
// in seconds, and C4's want one that does not hang up at all while a test is busy doing something
// else, so that what killed the stream is unambiguous.
func streamingContainer(t *testing.T, image string, senderTimeout time.Duration) (*pgconn.PgConn, string) {
	t.Helper()

	// Milliseconds rather than Duration.String(), which spells a minute "1m0s" and the server
	// rejects outright — a unit it does understand, for every value a caller might pass.
	id := startPostgresWith(t, image,
		"-c", "wal_level=logical",
		"-c", "wal_sender_timeout="+strconv.FormatInt(senderTimeout.Milliseconds(), 10)+"ms",
	)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	psql(ctx, t, id, "CREATE ROLE vp_stream WITH LOGIN REPLICATION PASSWORD '"+containerPassword+"'")
	psql(ctx, t, id, "CREATE SCHEMA ops; CREATE TABLE ops.beat(id serial PRIMARY KEY, note text)")
	psql(ctx, t, id, "CREATE PUBLICATION vp_all FOR ALL TABLES")

	conn := connectToContainer(t, portOf(t, id))
	if err := CreateSlot(ctx, conn, "vp_stream"); err != nil {
		t.Fatalf("create the slot: %v", err)
	}
	return conn, id
}

// confirmedFlush is what the SERVER says has been confirmed, which is the only account of it that
// counts — our own bookkeeping is the thing under test.
func confirmedFlush(ctx context.Context, t *testing.T, id, slot string) string {
	t.Helper()
	out := psqlRead(ctx, t, id,
		"SELECT confirmed_flush_lsn FROM pg_replication_slots WHERE slot_name = '"+slot+"'")
	if out == "" {
		t.Fatalf("slot %q reports no confirmed_flush_lsn", slot)
	}
	return out
}

// waitForFlush reads until the server has applied the acknowledgement, which it does
// asynchronously — a single read straight after Confirm is a flake waiting to happen.
func waitForFlush(ctx context.Context, t *testing.T, id, slot, was string) {
	t.Helper()
	for deadline := time.Now().Add(20 * time.Second); time.Now().Before(deadline); {
		if now := confirmedFlush(ctx, t, id, slot); now != was {
			t.Logf("confirmed_flush_lsn moved %s -> %s once, and only once, the batch was durable", was, now)
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("confirmed_flush_lsn is still %s after a Confirm; the acknowledgement never reached "+
		"the server, so the slot holds WAL forever and the customer's disk fills", was)
}

// psqlRead runs one statement and returns its single value. -tAq so there is nothing to trim but
// the newline, and the statement travels over stdin for the reason psql() gives.
func psqlRead(ctx context.Context, t *testing.T, id, sql string) string {
	t.Helper()
	cmd := exec.CommandContext(ctx, "docker", "exec", "-i", id,
		"psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1", "-tAq")
	cmd.Stdin = strings.NewReader(sql)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("psql in %s: %v: %s", id, err, redact(string(out)))
	}
	return strings.TrimSpace(string(out))
}
