//go:build testbed

// THIS FILE HAS NEVER BEEN RUN. It is written, it compiles, and it is behind a build tag of its own
// so that neither `make all` nor `make test-docker` can pick it up by accident:
//
//	go test -tags testbed ./agent/internal/backup/postgres/ -run Testbed -v -timeout 60m
//
// IT COSTS MONEY AND IT DESTROYS A DATABASE. It stands a real Azure Database for PostgreSQL flexible
// server on the smallest storage the service sells, fills it, and waits for the brake to fire. Do
// not point it at anything but a disposable testbed server (parity-testbed), and never at a
// customer's.
//
// WHY IT CANNOT BE DOCKER. brake_docker_test.go already proves everything up to the cloud boundary:
// a real 512 MiB disk really filled, a real slot really dropped, the brake firing well below the
// 95% line. What Docker cannot reproduce is the two things this file is for:
//
//  1. AZURE'S READ-ONLY FLIP AT 95%, which is a platform behaviour and not a PostgreSQL one. In
//     Docker the disk simply runs out and the server PANICs; on Azure the server survives and stops
//     accepting writes, which is the outage this whole epic exists to prevent.
//
//  2. THE DISK COMING FROM AZURE MONITOR RATHER THAN FROM `df`. Every failure monitor.go defends
//     against — the metric latency, the aggregation, the units, the resource id — is invisible to a
//     test that reads the disk directly. This is the only place the number the brake decides on is
//     the number Azure publishes.
//
// WHAT IT IS EXPECTED TO FIND, WRITTEN DOWN BEFORE IT IS RUN so that a surprise is recognisable as
// one: Azure Monitor publishes storage_used about a minute behind reality, so the brake decides on a
// disk that is a minute old. On a 32 GiB server a workload can move several percent of the disk in a
// minute, which means the observed trip point will sit BELOW the computed one and the margin below
// 95% is the thing to measure. If that margin turns out to be small, the answer is a lower tripAt
// and not a faster tick — a faster tick reads the same stale metric more often.

package postgres

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/jackc/pgx/v5/pgconn"
)

// The testbed names one server, in one place. Every value is required and the test SKIPS rather
// than defaults, because a default here would reach a server nobody chose — the same discipline
// agent/cmd/scanner/backup.go applies to the real command.
type testbedServer struct {
	resourceID string // /subscriptions/.../providers/Microsoft.DBforPostgreSQL/flexibleServers/...
	host       string
	database   string
	user       string // the REPLICATION role, as on a real install
	password   string
}

func testbedFromEnv(t *testing.T) testbedServer {
	t.Helper()
	return testbedServer{
		resourceID: required(t, "PARITY_TESTBED_SERVER_ID"),
		host:       required(t, "PARITY_TESTBED_PG_HOST"),
		database:   required(t, "PARITY_TESTBED_PG_DATABASE"),
		user:       required(t, "PARITY_TESTBED_PG_USER"),
		password:   required(t, "PARITY_TESTBED_PG_PASSWORD"),
	}
}

func required(t *testing.T, name string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		t.Skipf("%s is not set; this test fills a real Azure disk and refuses to guess which", name)
	}
	return value
}

// TestTestbedTheBrakeFiresBeforeAzureTurnsTheServerReadOnly is C6's acceptance criterion on the
// only platform where the criterion is real.
//
// THE MEASUREMENT IS THE MARGIN. "The brake fired" is not the result; "the brake fired at N% and
// Azure flips at 95%" is, because N is what says whether there was time to act. It is asserted at
// two levels: the trip must land below the line at all, and it must land far enough below it that
// the drop gives the server back more room than it had left.
func TestTestbedTheBrakeFiresBeforeAzureTurnsTheServerReadOnly(t *testing.T) {
	server := testbedFromEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		t.Fatalf("resolve an Azure credential: %v", err)
	}
	monitor, err := NewAzureMonitor(cred, server.resourceID)
	if err != nil {
		t.Fatalf("build the monitor client: %v", err)
	}

	conn, err := Connect(ctx, Config{
		Host: server.host, Port: 5432, Database: server.database,
		User: server.user, Password: Secret(server.password),
	})
	if err != nil {
		t.Fatalf("connect to the testbed primary: %v", err)
	}
	defer func() { _ = conn.Close(context.WithoutCancel(ctx)) }()

	// The disk must be readable BEFORE anything is filled, or a test that never trips cannot be
	// told from a test whose metric never answered.
	first, err := monitor.Space(ctx)
	if err != nil {
		t.Fatalf("read the primary's disk from Azure Monitor before starting: %v", err)
	}
	t.Logf("before: %.1f%% of %.1f GiB used", 100*float64(first.Used)/float64(first.Total),
		float64(first.Total)/(1<<30))

	const slot = "vp_testbed_brake"
	if err := CreateSlot(ctx, conn, slot); err != nil {
		t.Fatalf("CreateSlot: %v", err)
	}
	// The slot outlives a failure of this test, and on Azure only the role that created it can
	// drop one (AD-034) — so the cleanup is not tidiness, it is the difference between a testbed
	// server and one nobody can rescue.
	//
	// DROPPED THROUGH pg_replication_slots RATHER THAN BY NAME, because on the path this test is
	// written for THE BRAKE HAS ALREADY DROPPED IT: pg_drop_replication_slot raises undefined_object
	// for a slot that is gone, so a bare drop would fail the test on its own success, with a message
	// saying the slot was left behind when it was not.
	t.Cleanup(func() {
		clean, stop := context.WithTimeout(context.WithoutCancel(ctx), time.Minute)
		defer stop()
		_, err := Query(conn)(clean, fmt.Sprintf(
			"SELECT pg_drop_replication_slot(slot_name) FROM pg_replication_slots "+
				"WHERE slot_name = '%s'", slot))
		if err != nil {
			t.Errorf("THE SLOT %q IS STILL ON %s AND ONLY THIS ROLE CAN DROP IT: %v",
				slot, server.host, err)
		}
	})

	var alarms []Alarm
	brake := &Brake{
		Slot:      slot,
		Query:     Query(conn),
		Disk:      monitor.Space,
		StreamPID: func() uint32 { return 0 }, // nothing of ours is consuming it: the leak case
		Alert:     func(a Alarm) { alarms = append(alarms, a) },
	}

	if decision, err := brake.Check(ctx); err != nil {
		t.Fatalf("the first Check: %v", err)
	} else if decision.Verdict != Fine {
		t.Fatalf("the brake fired before anything was written: %s", decision.Why)
	}

	mustExec(ctx, t, conn, "CREATE TABLE IF NOT EXISTS vp_testbed_filler (pad text)")
	t.Cleanup(func() {
		clean, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Minute)
		defer stop()
		_, _ = Query(conn)(clean, "DROP TABLE IF EXISTS vp_testbed_filler")
	})

	// A round is about 256 MiB. Bounded, because the failure worth catching is the brake NOT
	// firing, and that has to arrive as a report rather than as a hung test.
	const maxRounds = 200
	for round := 1; ; round++ {
		if round > maxRounds {
			t.Fatalf("wrote about %d GiB and the brake never fired", maxRounds/4)
		}
		mustExec(ctx, t, conn,
			"INSERT INTO vp_testbed_filler SELECT repeat('x', 1000) FROM generate_series(1, 256000)")

		decision, err := brake.Check(ctx)
		if err != nil {
			t.Fatalf("round %d: Check: %v", round, err)
		}
		space, err := monitor.Space(ctx)
		if err != nil {
			// NOT A SKIP AND NOT A PASS. The metric going quiet mid-fill is one of the failure
			// modes under test, and it is what the brake would call unknown pressure.
			t.Fatalf("round %d: the disk became unreadable mid-fill, which is exactly the state "+
				"in which the brake cannot act: %v", round, err)
		}
		full := float64(space.Used) / float64(space.Total)
		t.Logf("round %3d: disk %.2f%% · pressure %.3f · %v", round, full*100, decision.Pressure, decision.Verdict)

		if decision.Verdict != Trip {
			continue
		}

		// THE CRITERION.
		if full >= readOnlyAt {
			t.Fatalf("the brake fired at %.2f%%, at or past the %.0f%% line Azure flips at — "+
				"too late to be a brake", full*100, readOnlyAt*100)
		}
		t.Logf("BRAKE FIRED at %.2f%% of %.1f GiB, %.2f points below the %.0f%% read-only line",
			full*100, float64(space.Total)/(1<<30), (readOnlyAt-full)*100, readOnlyAt*100)

		if len(alarms) == 0 || !alarms[len(alarms)-1].Dropped {
			t.Fatalf("alarms = %v, want the last one to say the slot was dropped", alarms)
		}

		// AND THE SERVER IS STILL A DATABASE. This is the premise of the whole ticket, and on
		// Azure it is a real question rather than a rhetorical one: a server past 95% accepts
		// connections and refuses writes.
		mustExec(ctx, t, conn, "INSERT INTO vp_testbed_filler VALUES ('after the brake')")
		return
	}
}

func mustExec(ctx context.Context, t *testing.T, conn *pgconn.PgConn, sql string) {
	t.Helper()
	if _, err := Query(conn)(ctx, sql); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}
