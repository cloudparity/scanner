//go:build docker

// Behind the same tag as slot_docker_test.go, and sharing its helpers: `make test-docker`.
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/manukyanv07/parity-scanner/agent/internal/backup"
	"github.com/manukyanv07/parity-scanner/contract"
)

// C4, AGAINST A REAL WALSENDER, WITH THE SLOT TAKEN AWAY MID-STREAM.
//
// The unit tests decide what the agent does about a slot that is gone. This one is about what a
// real server actually does, because the design rests on two facts that a fake cannot vouch for:
//
//  1. A SLOT CANNOT BE DROPPED WHILE OUR SESSION HOLDS IT — 55006, `replication slot "vp_stream"
//     is active for PID n`. So losing the slot ALWAYS costs us the connection, whoever takes it:
//     an HA failover below 17 (AD-034), the provider protecting the disk, or our own brake (C6).
//     That is why the check sits at session open and nowhere else — mid-stream the catalog is
//     unreachable on the connection that would have to ask, and mid-stream is a state that cannot
//     arise.
//  2. THE STREAM DOES NOT NOTICE ON ITS OWN. Its session is killed and it comes back as an
//     ordinary read failure, indistinguishable from a network blip — which is exactly the reading
//     that makes an agent reconnect happily onto a NEW slot at a LATER position and write its next
//     file across a hole nothing downstream can see.
//
// What is then asserted is the ticket, in order: detected on the FIRST cycle after the drop, the
// chain marked with the last position it still restores to, NO further file added to it, and NO
// fresh slot on the server.
//
// Both major versions, because CreateSlot is the one thing in this agent that branches on one
// (AD-034) and the slot it produces differs across the branch. NO AZURE, and every container is
// removed by the t.Cleanup startPostgresWith registers.

// c4SenderTimeout is Azure's own setting (AD-039), used here rather than the two seconds the
// keepalive tests want: this test spends whole seconds between cycles doing things to the server,
// and a stream that the server hung up on in the meantime would make it impossible to say that
// what killed the session was the slot going.
const c4SenderTimeout = time.Minute

func TestASlotDroppedOutFromUnderTheStreamKillsTheChain(t *testing.T) {
	for _, image := range []string{"postgres:14-alpine", "postgres:18-alpine"} {
		t.Run(image, func(t *testing.T) {
			t.Parallel()
			conn, admin := streamingContainer(t, image, c4SenderTimeout)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			store := &memoryStore{objects: map[string][]byte{}}
			cycle := &backup.Cycle{
				Pipeline: &backup.Pipeline{Store: store},
				Scope:    "install-c4/pg1/postgres",
				Subject: contract.BackupSource{
					Provider: contract.ProviderAzure, ResourceID: "pg1",
					Database: "postgres", Engine: "postgres", EngineVersion: "18",
				},
				Producer: contract.Producer{Agent: "azure/0.1.0"},
				Format:   contract.FormatChangeJSONL,
				// The schema this chain's base was taken against, which every cycle is compared
				// with (rebase.go). It is the same fingerprint the stream itself takes when its
				// session opens, over this same connection — so the two ends agree and this test
				// is about the slot rather than about the schema.
				BaseSchema: fingerprintNow(ctx, t, conn),
			}

			// ── ONE HEALTHY CYCLE, so that what follows is a chain being ended and not a chain
			// that never started.
			stream := &Stream{Conn: conn, Slot: "vp_stream", Publication: "vp_all", Interval: 2 * time.Second}
			psql(ctx, t, admin, "INSERT INTO ops.beat(note) VALUES ('c4-before')")

			at := backup.Position(confirmedFlush(ctx, t, admin, "vp_stream"))
			written, err := cycle.Run(ctx, streamAsSource{stream}, at)
			if err != nil {
				t.Fatalf("the first cycle, on a slot that is right there, failed: %v", err)
			}
			if err := stream.Confirm(ctx, backup.Position(written.ReadPoint.Position)); err != nil {
				t.Fatalf("confirm the first batch: %v", err)
			}
			at = backup.Position(written.ReadPoint.Position)

			if got := store.matching("/" + manifestObject); len(got) != 1 {
				t.Fatalf("manifests after one healthy cycle: %v, want exactly one", got)
			}
			if got := store.matching("/" + reBaseObject); len(got) != 0 {
				t.Fatalf("a healthy cycle retired the chain: %v", got)
			}
			filesBefore := len(store.paths())

			// ── FACT 1: THE SLOT CANNOT BE TAKEN WHILE WE HOLD IT.
			refusal := psqlRefused(ctx, t, admin, "SELECT pg_drop_replication_slot('vp_stream')")
			if !strings.Contains(refusal, "is active for PID") {
				t.Fatalf("dropping a slot our stream is holding was refused with %q, not the "+
					"55006 this design rests on; if a slot can now vanish under a live batch, the "+
					"check has to move", refusal)
			}
			t.Logf("drop while our session holds it: %s", refusal)

			// ── AND SO THE STREAM DIES WITH IT, which is what really happens on a failover.
			psql(ctx, t, admin,
				"SELECT pg_terminate_backend(active_pid) FROM pg_replication_slots WHERE slot_name = 'vp_stream'")
			dropSlot(ctx, t, admin, "vp_stream")
			if left := psqlRead(ctx, t, admin, "SELECT count(*) FROM pg_replication_slots"); left != "0" {
				t.Fatalf("the slot is still on the server (%s slots); this test has not set up its "+
					"own premise", left)
			}

			// ── FACT 2: THE RUNNING STREAM LEARNS NOTHING USEFUL. It fails, and what it says is
			// indistinguishable from a network blip — which is the whole reason the check exists.
			_, err = stream.Since(ctx, at)
			if err == nil {
				t.Fatal("the stream handed out a batch after its slot and its session were killed")
			}
			if errors.Is(err, backup.ErrSlotGone) {
				t.Logf("unexpected but welcome: the dying session named the cause: %v", err)
			} else {
				t.Logf("the killed session reports only: %v", err)
			}

			// ── THE CYCLE THIS TICKET IS ABOUT. The agent reconnects — which is the only thing it
			// can do, and the moment it would otherwise create a new slot and carry on.
			reconnected := &Stream{
				Conn:        connectToContainer(t, portOf(t, admin)),
				Slot:        "vp_stream",
				Publication: "vp_all",
				Interval:    2 * time.Second,
			}
			psql(ctx, t, admin, "INSERT INTO ops.beat(note) VALUES ('c4-after')")

			_, err = cycle.Run(ctx, streamAsSource{reconnected}, at)
			if err == nil {
				t.Fatal("the cycle after the slot was dropped reported success; the chain now has a " +
					"hole in the middle of it that nothing downstream can see")
			}
			if !errors.Is(err, backup.ErrSlotGone) {
				t.Fatalf("%v — the error does not carry backup.ErrSlotGone, so a scheduler reads a "+
					"dead chain as a transient failure and retries it forever", err)
			}

			// THE CHAIN IS MARKED, and the marker says how far it still restores.
			markers := store.matching("/" + reBaseObject)
			if len(markers) != 1 {
				t.Fatalf("re-base markers in the store: %v, want exactly one", markers)
			}
			var mark contract.ReBase
			if err := json.Unmarshal(store.at(markers[0]), &mark); err != nil {
				t.Fatalf("the marker is not readable: %v", err)
			}
			if mark.Reason != contract.ReBaseSlotLost {
				t.Errorf("reason = %q, want %q", mark.Reason, contract.ReBaseSlotLost)
			}
			if mark.Recoverable != string(at) {
				t.Errorf("recoverable = %q, want %q — the last position this chain restores to, "+
					"and without it the marker reads as total loss", mark.Recoverable, at)
			}
			if !strings.Contains(mark.Detail, "vp_stream") {
				t.Errorf("detail %q does not name the slot that went", mark.Detail)
			}

			// NO FURTHER FILE, which is the deliverable stated as an absence: not a manifest, not a
			// change object, nothing but the marker itself.
			if now := store.matching("/" + manifestObject); len(now) != 1 {
				t.Errorf("manifests after the dead cycle: %v, want still exactly one", now)
			}
			if store.holds(strings.TrimSuffix(markers[0], reBaseObject) + manifestObject) {
				t.Errorf("a manifest sits beside the marker under %s; one prefix is one answer", markers[0])
			}
			if grew := len(store.paths()) - filesBefore; grew != 1 {
				t.Errorf("the dead cycle added %d objects, want only the marker: %v", grew, store.paths())
			}

			// AND NO FRESH SLOT. This is the bug in its purest form: an agent that answered the
			// missing slot by making another one would look completely healthy from here on.
			if left := psqlRead(ctx, t, admin, "SELECT count(*) FROM pg_replication_slots"); left != "0" {
				t.Fatalf("%s replication slot(s) on the server after the failed cycle; a new one "+
					"resumes LATER than this chain ends, and every file after it sits beyond a hole", left)
			}

			t.Logf("slot dropped mid-stream, detected on the next cycle: reason=%s recoverable=%s, "+
				"%d manifest(s) unchanged, 0 slots on the server",
				mark.Reason, mark.Recoverable, len(store.matching("/"+manifestObject)))
		})
	}
}

// streamAsSource is the batcher wearing the seam's interface. Stream deliberately does not declare
// itself a backup.Source (since.go): Base belongs to an entirely different credential (AD-035), and
// putting one on the batcher to satisfy a test would be that decision made in the wrong place.
type streamAsSource struct{ *Stream }

func (streamAsSource) Base(context.Context) (backup.Batch, error) {
	return backup.Batch{}, errors.New("the base copy is postgres.Base's, not the batcher's")
}

// fingerprintNow is the schema fingerprint over the agent's own connection, taken BEFORE any
// replication session is opened on it — the only moment it is reachable (since.go, link.Fingerprint).
func fingerprintNow(ctx context.Context, t *testing.T, conn *pgconn.PgConn) string {
	t.Helper()
	got, err := fingerprint(ctx, simpleQueryRows(conn))
	if err != nil {
		t.Fatalf("fingerprint the schema: %v", err)
	}
	return got
}

// dropSlot removes the slot once the walsender holding it has been terminated. Retried, because
// the backend is torn down asynchronously and the drop that lands too early comes back 55006 —
// which is the very refusal asserted above, and would read here as the setup having failed.
func dropSlot(ctx context.Context, t *testing.T, id, slot string) {
	t.Helper()
	for deadline := time.Now().Add(30 * time.Second); ; {
		if out := psqlOutput(ctx, t, id, "SELECT pg_drop_replication_slot('"+slot+"')"); out == "" {
			return
		} else if time.Now().After(deadline) {
			t.Fatalf("slot %q could not be dropped: %s", slot, out)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// psqlRefused runs a statement that is EXPECTED to fail and returns what the server said. The
// message is the measurement, so it is returned rather than asserted on in here.
func psqlRefused(ctx context.Context, t *testing.T, id, sql string) string {
	t.Helper()
	out := psqlOutput(ctx, t, id, sql)
	if out == "" {
		t.Fatalf("%s succeeded, and this test needs it to have been refused", sql)
	}
	return out
}

// psqlOutput runs one statement and returns the server's complaint, or "" when it succeeded. It is
// psql()'s sibling for the statements whose FAILURE is the thing under test; psql itself fails the
// test on any error, which is right everywhere else.
func psqlOutput(ctx context.Context, t *testing.T, id, sql string) string {
	t.Helper()
	cmd := exec.CommandContext(ctx, "docker", "exec", "-i", id,
		"psql", "-U", "postgres", "-v", "ON_ERROR_STOP=1", "-tAq")
	cmd.Stdin = strings.NewReader(sql)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return ""
	}
	// Redacted for the reason psql() gives: a failing statement makes the server echo the offending
	// line back, and this package's whole discipline is that a credential never reaches an output.
	return strings.TrimSpace(redact(string(out)))
}
