//go:build docker

// Behind the same tag as slot_docker_test.go, and sharing its helpers: `make test-docker`.
package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/manukyanv07/parity-scanner/agent/internal/backup"
	"github.com/manukyanv07/parity-scanner/contract"
)

// C5, AGAINST A REAL SERVER, WITH THE STREAM RUNNING.
//
// schema_docker_test.go already proves the fingerprint moves for the three DDLs, on a database
// where nothing else is happening. That is not the case that loses a customer's data. This one is:
// rows are being written continuously, the change stream is being drained cycle after cycle, and a
// migration lands in the middle of it. Everything keeps working — and THAT IS THE BUG. Logical
// decoding does not carry DDL, so the stream reports the ALTER as nothing at all and every cycle
// after it is captured against a schema the chain's base never had.
//
// So this test asserts two things a quiet database cannot show:
//
//  1. THE SILENCE IS REAL. The decoded output of the cycle the DDL lands in carries inserts and
//     says nothing whatsoever about the ALTER — measured, not assumed.
//  2. THE CYCLE STOPS ANYWAY. backup.Cycle writes rebase.json instead of a manifest and returns
//     ErrSchemaMoved, so the chain is not extended and a new base copy is owed.
//
// WHY THE STREAM IS DRAINED WITH pg_logical_slot_get_changes RATHER THAN A WALSENDER. pglogrepl
// left go.mod with C1's spike and C3 brings it back deliberately; a test that pulled it in early
// would decide that for C3. What is needed here is real logical decoding of real concurrent
// changes over the agent's own replication connection, and this function is exactly that — the
// same output plugin machinery, driven by SQL. The plugin is test_decoding rather than the
// pgoutput our slots use (slot.go) because its output is text a human can read, which is what
// makes assertion 1 above worth anything.

// c5Slot is this test's own slot. Not created through CreateSlot: that one is pgoutput, and is
// covered by slot_docker_test.go.
const c5Slot = "vp_c5_stream"

// The two objects a cycle can end with, spelled here because they are unexported in package
// backup. One prefix holds one of them and never both — which is the assertion below.
const (
	manifestObject = "manifest.json"
	reBaseObject   = "rebase.json"
)

// TestASchemaChangeMidStreamStopsTheChain runs on 14 and 18 because the catalog and the decoding
// machinery are what change across a major version, and this is the one check in the product that
// stands between a customer's migration and a chain that is quietly wrong from then on.
func TestASchemaChangeMidStreamStopsTheChain(t *testing.T) {
	for _, image := range []string{"postgres:14-alpine", "postgres:18-alpine"} {
		t.Run(image, func(t *testing.T) {
			t.Parallel()
			port := startPostgres(t, image)
			conn := connectToContainer(t, port)
			q := simpleQueryRows(conn)

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			// The customer's own deploy pipeline and the customer's own traffic: two ordinary
			// connections as the administrator, because the agent's role can write nothing.
			deploy := adminConn(t, port)
			run := func(statement string) {
				t.Helper()
				if _, err := deploy.Exec(ctx, statement).ReadAll(); err != nil {
					t.Fatalf("%s: %v", statement, err)
				}
			}
			run("CREATE TABLE orders (id serial PRIMARY KEY, total numeric(10,2))")

			// The slot first, so nothing written after this point is lost — the same order the
			// base copy takes (base.go).
			if _, err := q(ctx, "SELECT pg_create_logical_replication_slot('"+c5Slot+"', 'test_decoding')"); err != nil {
				t.Fatalf("create the decoding slot over the replication connection: %v", err)
			}
			t.Cleanup(func() {
				drop, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				if _, err := q(drop, "SELECT pg_drop_replication_slot('"+c5Slot+"')"); err != nil {
					t.Errorf("drop %s: %v", c5Slot, err)
				}
			})

			stop := keepWriting(t, adminConn(t, port))
			defer stop()

			store := &memoryStore{objects: map[string][]byte{}}
			source := &decodingSource{q: q}

			// The chain's base, standing in for what postgres.Base returns: the fingerprint taken
			// beside the copy, which is the value every cycle after it is compared against.
			base, err := fingerprint(ctx, q)
			if err != nil {
				t.Fatalf("the base's fingerprint: %v", err)
			}
			cycle := &backup.Cycle{
				Pipeline:   &backup.Pipeline{Store: store},
				Scope:      "install-c5/pg1/orders",
				Subject:    contract.BackupSource{Provider: contract.ProviderAzure, ResourceID: "pg1", Database: "postgres", Engine: "postgres", EngineVersion: "14"},
				Producer:   contract.Producer{Agent: "azure/0.1.0"},
				Format:     contract.FormatPlainSQL,
				BaseSchema: base,
			}

			// One healthy cycle first. Without it the test cannot tell a check that catches DDL
			// from one that refuses everything.
			at := backup.Position("0/0")
			written, err := cycle.Run(ctx, source, at)
			if err != nil {
				t.Fatalf("the first cycle, against the schema its base was taken on, failed: %v", err)
			}
			if !strings.Contains(source.lastBody, "INSERT") {
				t.Fatalf("the first cycle decoded no inserts, so nothing was flowing and this test "+
					"proves nothing: %q", source.lastBody)
			}
			at = backup.Position(written.ReadPoint.Position)

			for _, step := range []struct {
				name string
				ddl  string
			}{
				{"a column added", "ALTER TABLE orders ADD COLUMN note text"},
				{"a column's type changed", "ALTER TABLE orders ALTER COLUMN total TYPE numeric(12,2)"},
				{"a column dropped", "ALTER TABLE orders DROP COLUMN note"},
			} {
				// MID-STREAM: the writer above has not stopped, and the changes it made either
				// side of this statement are in the very batch the next cycle captures.
				run(step.ddl)

				manifestsBefore := len(store.matching("/" + manifestObject))
				_, err := cycle.Run(ctx, source, at)

				if err == nil {
					t.Fatalf("%s: the cycle extended the chain and reported success. The chain now "+
						"carries changes captured against a schema its base never had, and nothing "+
						"downstream will ever say so", step.name)
				}
				if !errors.Is(err, backup.ErrSchemaMoved) {
					t.Fatalf("%s: %v — the error does not carry ErrSchemaMoved, so a scheduler "+
						"cannot tell this from a transient failure and would retry it forever",
						step.name, err)
				}

				// THE SILENCE, MEASURED. The batch this cycle captured is real decoded output with
				// real inserts in it, and the DDL that just ran is nowhere in it.
				if !strings.Contains(source.lastBody, "INSERT") {
					t.Errorf("%s: the cycle decoded no inserts (%q), so the stream was not running "+
						"and the detection proved nothing", step.name, source.lastBody)
				}
				if upper := strings.ToUpper(source.lastBody); strings.Contains(upper, "ALTER") {
					t.Errorf("%s: the decoded stream mentions the DDL (%q) — if logical decoding "+
						"started carrying DDL, this whole check has a cheaper answer", step.name, upper)
				}
				// What the migration DID decode as: a transaction with nothing in it.
				if !carriesAnEmptyTransaction(source.lastRows) {
					t.Errorf("%s: no empty transaction in the batch (%q); the DDL is expected to "+
						"arrive as a bare BEGIN/COMMIT pair, and if it stopped doing so the shape "+
						"of this problem has changed", step.name, source.lastBody)
				}

				// It marked the chain, in the place the manifest would have gone, and it wrote no
				// manifest anywhere.
				markers := store.matching("/" + reBaseObject)
				if len(markers) != 1 {
					t.Fatalf("%s: re-base markers in the store: %v, want exactly one", step.name, markers)
				}
				var mark contract.ReBase
				if err := json.Unmarshal(store.at(markers[0]), &mark); err != nil {
					t.Fatalf("%s: the marker is not readable: %v", step.name, err)
				}
				if mark.Reason != contract.ReBaseSchemaChanged {
					t.Errorf("%s: reason = %q", step.name, mark.Reason)
				}
				if mark.Recoverable != string(at) {
					t.Errorf("%s: recoverable = %q, want %q — the marker has to say how far this "+
						"chain still restores, or it reads as total loss", step.name, mark.Recoverable, at)
				}
				// NO MANIFEST, ANYWHERE. Not a new one for this cycle, and not one beside the
				// marker: one prefix is one answer, and a manifest is the answer "the chain
				// continues".
				if now := len(store.matching("/" + manifestObject)); now != manifestsBefore {
					t.Errorf("%s: the cycle wrote a manifest as well (%v)", step.name,
						store.matching("/"+manifestObject))
				}
				if store.holds(strings.TrimSuffix(markers[0], reBaseObject) + manifestObject) {
					t.Errorf("%s: a manifest sits beside the re-base marker under %s; one prefix "+
						"is one answer", step.name, markers[0])
				}

				// Logged because this is the measurement the ticket is answerable to: what the
				// stream said, and what was decided anyway.
				t.Logf("%s: %d decoded rows, DDL invisible in all of them; %s → %s, chain marked at %s",
					step.name, len(source.lastRows), short(cycle.BaseSchema), short(source.lastSchema),
					mark.Recoverable)

				// THE RE-BASE IS WHAT UNSTICKS IT. A new base copy would take a fresh fingerprint,
				// and from there the chain extends again — a detector that could never recover
				// would be an agent that stops backing up on the customer's first migration.
				fresh, err := fingerprint(ctx, q)
				if err != nil {
					t.Fatalf("%s: the fingerprint after the DDL: %v", step.name, err)
				}
				cycle.BaseSchema = fresh
				resumed, err := cycle.Run(ctx, source, at)
				if err != nil {
					t.Fatalf("%s: the cycle after a re-base failed: %v", step.name, err)
				}
				at = backup.Position(resumed.ReadPoint.Position)

				// Cleared so the next step's assertion counts its own marker and not this one's.
				store.forget("/" + reBaseObject)
			}
		})
	}
}

// decodingSource is the change stream, cut down to what C5 needs to be tested: drain the slot,
// take the fingerprint beside it, hand both to the cycle. C3 owns the real one — the batching,
// the standby replies, the LSN that is only confirmed once the bytes are durable.
//
// THE FINGERPRINT IS TAKEN OVER THE SAME CONNECTION AS THE CHANGES, which is the whole point: it
// costs no second credential and no read grant on any customer table (AD-033/AD-036).
type decodingSource struct {
	q querySQL

	// lastBody and lastRows are what the last batch actually carried, kept so the test can assert
	// on the silence itself rather than only on the detection.
	lastBody   string
	lastRows   [][]string
	lastSchema string
}

func (d *decodingSource) Base(context.Context) (backup.Batch, error) {
	return backup.Batch{}, fmt.Errorf("the base copy is postgres.Base's, not this test's")
}

func (d *decodingSource) Since(ctx context.Context, from backup.Position) (backup.Batch, error) {
	// DRAINED UNTIL A ROW HAS ACTUALLY CHANGED, and the reason is the first thing this test
	// measured: the very first drain after an ALTER came back holding nothing but "BEGIN 756 /
	// COMMIT 756" — the migration's own transaction, decoded as an empty pair. That is the silence
	// this ticket exists for, and a batch of only that would let the test pass without ever
	// proving the customer's traffic was still flowing through it. So the calls are accumulated
	// until the writer's inserts appear alongside it. Bounded by a deadline; the writer goroutine
	// is what makes it terminate.
	var rows [][]string
	for deadline := time.Now().Add(30 * time.Second); ; {
		got, err := d.q(ctx, "SELECT lsn, data FROM pg_logical_slot_get_changes('"+c5Slot+"', NULL, NULL)")
		if err != nil {
			return backup.Batch{}, fmt.Errorf("drain the slot: %w", err)
		}
		rows = append(rows, got...)
		if carriesARowChange(rows) {
			break
		}
		if time.Now().After(deadline) {
			if len(rows) == 0 {
				// Said in full, because the alternative is this failing later as "the error does
				// not carry ErrSchemaMoved" and sending the next reader after the detection when
				// what actually stopped was the traffic.
				return backup.Batch{}, fmt.Errorf("the slot decoded nothing at all in 30s: the "+
					"writer has stopped, so this test is measuring an idle database and not a "+
					"stream: %w", backup.ErrNoChanges)
			}
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// AFTER the changes, so the fingerprint describes the schema at or after the state they were
	// decoded against — the same direction of error the base copy takes, and the safe one: a
	// fingerprint read too late reports a change one cycle early, never one cycle late.
	schema, err := fingerprint(ctx, d.q)
	if err != nil {
		return backup.Batch{}, err
	}

	var body strings.Builder
	for _, row := range rows {
		body.WriteString(row[0] + " " + row[1] + "\n")
	}
	d.lastBody = body.String()
	d.lastRows = rows
	d.lastSchema = schema

	return backup.Batch{
		From:     from,
		Position: backup.Position(rows[len(rows)-1][0]),
		Schema:   schema,
		Parts: []backup.Part{{
			Name:   "changes.0001",
			Format: contract.FormatPlainSQL,
			Open: func() (io.ReadCloser, error) {
				return io.NopCloser(strings.NewReader(body.String())), nil
			},
		}},
	}, nil
}

// short is a fingerprint cut down to something a log line can hold.
func short(fingerprint string) string {
	if len(fingerprint) > 18 {
		return fingerprint[:18]
	}
	return fingerprint
}

// carriesARowChange is "this batch has actual data in it", as opposed to transactions that
// decoded to nothing at all.
func carriesARowChange(rows [][]string) bool {
	for _, row := range rows {
		if strings.Contains(row[1], "INSERT") {
			return true
		}
	}
	return false
}

// carriesAnEmptyTransaction is THE MEASUREMENT, and it is what a DDL looks like on the wire: a
// BEGIN followed straight by its COMMIT, with not one line in between. Nothing in that says a
// table changed shape, and nothing downstream could ever recover it from the stream.
func carriesAnEmptyTransaction(rows [][]string) bool {
	for i := 0; i+1 < len(rows); i++ {
		if strings.HasPrefix(rows[i][1], "BEGIN ") && strings.HasPrefix(rows[i+1][1], "COMMIT ") {
			return true
		}
	}
	return false
}

// keepWriting is the customer's traffic: a row every few milliseconds until the test stops it.
// WITHOUT IT THIS IS THE QUIET-DATABASE TEST AGAIN — the DDL has to land among changes that are
// actually moving, because that is when nobody is watching and that is when it happens.
func keepWriting(t *testing.T, conn *pgconn.PgConn) func() {
	t.Helper()

	done := make(chan struct{})
	var once sync.Once
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			// The column list is the two that survive every step below, so the writer never has
			// to know a migration happened — which is exactly the customer's position.
			_, err := conn.Exec(ctx, "INSERT INTO orders (total) VALUES (1.00)").ReadAll()
			cancel()
			if err != nil {
				select {
				case <-done:
					return
				default:
				}
				// LOGGED AND CARRIED ON, NEVER RETURNED. An ALTER holds ACCESS EXCLUSIVE while it
				// runs, so a statement failing here is expected — and a writer that gave up on the
				// first one would leave the remaining DDL steps measuring an idle database while
				// still reporting a detection. t.Fatal is no use either: it does not stop a test
				// from a goroutine.
				t.Logf("the writer: %v", err)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()

	return func() {
		once.Do(func() { close(done) })
		wg.Wait()
	}
}

// memoryStore is backup.Store over a map. The blob store has its own tests; what is needed here
// is only to see which objects a cycle wrote.
type memoryStore struct {
	mu      sync.Mutex
	objects map[string][]byte
}

func (m *memoryStore) Put(_ context.Context, path string, chunk []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	stored := make([]byte, len(chunk)) // The pipeline reuses its buffer: keep a copy, not the slice.
	copy(stored, chunk)
	m.objects[path] = stored
	return nil
}

func (m *memoryStore) paths() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for path := range m.objects {
		out = append(out, path)
	}
	return out
}

func (m *memoryStore) matching(suffix string) []string {
	var out []string
	for _, path := range m.paths() {
		if strings.HasSuffix(path, suffix) {
			out = append(out, path)
		}
	}
	return out
}

func (m *memoryStore) at(path string) []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.objects[path]
}

func (m *memoryStore) holds(path string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.objects[path]
	return ok
}

func (m *memoryStore) forget(suffix string) {
	for _, path := range m.matching(suffix) {
		m.mu.Lock()
		delete(m.objects, path)
		m.mu.Unlock()
	}
}
