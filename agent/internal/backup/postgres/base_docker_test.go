//go:build docker

// Behind the same tag as slot_docker_test.go, and sharing its helpers: `make test-docker`.
package postgres

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

// THE WHOLE SEQUENCE, WITH A REAL POSTGRES ON ONE SIDE AND A FAKE AZURE ON THE OTHER. The unit
// tests prove the order; this proves that the statements the order is made of are ones a server
// really accepts, on both ends of the supported range — and, in the failing half, that a slot the
// product decided to drop is genuinely gone from pg_replication_slots rather than merely dropped in
// a journal. A leaked slot is the failure nobody can clean up afterwards, so "we called drop" is
// not the claim worth making.
func TestBaseAgainstARealServer(t *testing.T) {
	for _, image := range []string{"postgres:14-alpine", "postgres:18-alpine"} {
		t.Run(image, func(t *testing.T) {
			t.Parallel()
			conn := connectToContainer(t, startPostgres(t, image))
			q := simpleQueryRows(conn)

			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			slotExists := func() bool {
				t.Helper()
				rows, err := q(ctx, "SELECT slot_name FROM pg_replication_slots WHERE slot_name = 'vp_stream'")
				if err != nil {
					t.Fatalf("read pg_replication_slots: %v", err)
				}
				return len(rows) == 1
			}

			// The failing half first, so the happy half runs against a server the failure was
			// supposed to leave clean. If the drop did not really happen, the second half fails
			// with 42710 and says so.
			failing := newStub()
			failing.backupErr = errors.New("BackupInstanceNotFound")
			if _, err := Base(ctx, failing, conn, "vp_stream"); err == nil {
				t.Fatal("a failed backup produced no error")
			}
			if slotExists() {
				t.Fatal("the slot is still on the server after the backup failed: it holds WAL on the " +
					"primary and only the role that created it can remove one")
			}

			batch, err := Base(ctx, newStub(), conn, "vp_stream")
			if err != nil {
				t.Fatalf("Base against a real %s: %v", image, err)
			}
			if !slotExists() {
				t.Fatal("Base returned a batch and left no slot; the change stream has nothing to read from")
			}

			// The seam's promise, checked against the catalog rather than against the fake: the
			// Position reported is the slot's own start, which was taken before anything was copied.
			start := queryRow(ctx, t, conn, "SELECT confirmed_flush_lsn FROM pg_replication_slots WHERE slot_name = 'vp_stream'")
			if string(batch.Position) != start[0] {
				t.Errorf("Position = %q, want the slot's start %q", batch.Position, start[0])
			}
			if batch.Schema == "" || len(batch.Parts) == 0 {
				t.Errorf("batch %+v is missing its fingerprint or its parts", batch)
			}
		})
	}
}

// The half of Base that a fake cannot answer: does a slot that has just been created actually
// REPORT a start position, on both ends of the supported range?
//
// This is the seam's promise made concrete. backup.Source.Base must return a Position at or before
// the bytes, and slotPosition treats an empty one as an error rather than shipping a Position the
// change stream cannot resume from. If confirmed_flush_lsn were unset until the first read — which
// is exactly the kind of thing that differs by major version — every base copy would fail on a real
// server while every unit test stayed green.
func TestAFreshSlotReportsItsStartPosition(t *testing.T) {
	for _, image := range []string{"postgres:14-alpine", "postgres:18-alpine"} {
		t.Run(image, func(t *testing.T) {
			t.Parallel()
			conn := connectToContainer(t, startPostgres(t, image))
			q := simpleQueryRows(conn)

			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			if _, err := slotPosition(ctx, q, "vp_stream"); err == nil {
				t.Fatal("a slot that does not exist reported a start position")
			}

			if err := CreateSlot(ctx, conn, "vp_stream"); err != nil {
				t.Fatalf("CreateSlot: %v", err)
			}
			position, err := slotPosition(ctx, q, "vp_stream")
			if err != nil {
				t.Fatalf("slotPosition straight after creating the slot: %v", err)
			}
			t.Logf("%s: the slot starts at %s", image, position)

			// The drop that step 4 depends on, against a real server. The unit tests prove the
			// sequence CALLS it; only a server proves the statement is one Postgres accepts — and a
			// drop that does not work is the leak nobody can clean up afterwards.
			if err := abandon(ctx, q, "vp_stream", errStubbedCause); err != errStubbedCause {
				t.Fatalf("dropping the slot failed, so every failed backup would leak one: %v", err)
			}
			if _, err := slotPosition(ctx, q, "vp_stream"); err == nil {
				t.Fatal("the slot still reports a position after being dropped")
			}
		})
	}
}

// THE LEAK NOBODY EVER REPORTED, against a real server and both halves of the judgement it needs.
//
// The unit test proves the classification over a fake. Only a server proves the two facts it stands
// on: that what a killed agent leaves behind really does come back as SQLSTATE 42710, and that the
// SAME code comes back for a slot that is not ours — so the name is genuinely the only thing that
// can tell a leak of ours from a customer's own slot.
//
// One image rather than both: slot_docker_test.go already measures 42710 at both ends of the
// supported range, and what is under test here sits above that and has no version branch.
func TestASlotLeftBehindComesBackAsALeakAndAStrangersDoesNot(t *testing.T) {
	t.Parallel()
	conn := connectToContainer(t, startPostgres(t, "postgres:18-alpine"))
	q := simpleQueryRows(conn)

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	onServer := func(name string) bool {
		t.Helper()
		rows, err := q(ctx, "SELECT slot_name FROM pg_replication_slots WHERE slot_name = '"+name+"'")
		if err != nil {
			t.Fatalf("read pg_replication_slots: %v", err)
		}
		return len(rows) == 1
	}

	// The kill: created, and then the process ceased to exist before anything else ran. This is the
	// entire state a killed agent leaves behind, and no error was produced for anyone to act on.
	if err := CreateSlot(ctx, conn, "vp_stream"); err != nil {
		t.Fatalf("CreateSlot: %v", err)
	}

	if _, err := Base(ctx, newStub(), conn, "vp_stream"); !errors.Is(err, ErrSlotLeaked) {
		t.Fatalf("a real 42710 on a slot of ours did not come back as ErrSlotLeaked, so the brake "+
			"never fires and the WAL keeps piling up on the primary: %v", err)
	}
	// Not dropped here: reporting it is this package's job, dropping it is the brake's (C6).
	if !onServer("vp_stream") {
		t.Fatal("the slot was dropped by the cycle that merely found it")
	}

	// A slot that is NOT ours, on the same server, answering with the same SQLSTATE. Dropping one of
	// these breaks the customer's own replication, which is the same harm in the other direction.
	//
	// It is created with a bare statement rather than through CreateSlot, because CreateSlot now
	// refuses the name — that is the fix, and this is the customer's slot, which the customer made.
	const theirs = "cust_analytics"
	if _, err := q(ctx, "SELECT pg_create_logical_replication_slot('"+theirs+"', 'pgoutput', false, false)"); err != nil {
		t.Fatalf("creating a stand-in for the customer's own slot: %v", err)
	}

	_, err := Base(ctx, newStub(), conn, theirs)
	if err == nil {
		t.Fatal("the agent was pointed at the customer's own slot name and said nothing")
	}
	if errors.Is(err, ErrSlotLeaked) {
		t.Fatalf("a slot outside our naming convention was claimed as ours: %v", err)
	}
	if !onServer(theirs) {
		t.Fatal("the customer's own slot is gone from the server")
	}

	// The classification underneath, on the server's OWN 42710 rather than a constructed one: the
	// name is refused before the server is asked now, so this is the only way left to prove that a
	// real duplicate on a stranger's slot is still handed back with no sentinel in it.
	_, dup := q(ctx, "SELECT pg_create_logical_replication_slot('"+theirs+"', 'pgoutput', false, false)")
	var pgErr *pgconn.PgError
	if !errors.As(dup, &pgErr) || pgErr.Code != duplicateObject {
		t.Fatalf("a second create on an existing slot did not answer with %s: %v", duplicateObject, dup)
	}
	if errors.Is(alreadyOnTheServer(theirs, dup), ErrSlotLeaked) {
		t.Fatalf("a real 42710 on a slot outside our convention was labelled a leak of ours: %v", dup)
	}
}

// The error abandon is asked to carry through. It has to come back unchanged: a drop that succeeded
// must not add anything to the cause, or callers cannot tell a clean abandon from a leak.
var errStubbedCause = errors.New("the backup failed, and this is the reason to preserve")
