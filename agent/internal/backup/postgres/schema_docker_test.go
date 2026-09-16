//go:build docker

// Behind the same tag as slot_docker_test.go, and sharing its helpers: `make test-docker`.
package postgres

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	chainpkg "github.com/manukyanv07/parity-scanner/chain"
)

// THE UNIT TESTS CHECK THE HASH; ONLY A SERVER CAN CHECK THE QUERY. A fingerprint over the wrong
// catalog columns hashes just as stably and notices nothing, and the failure is invisible until a
// migration lands inside a base copy and nobody discards it.
//
// Run against 14 and 18 because the catalog is what changes across a major version, and this is the
// one query in the agent that reads it. It is also the AD-036 claim exercised for real: a role with
// REPLICATION and access to no table reads pg_attribute over the replication connection.
func TestTheFingerprintNoticesRealDDL(t *testing.T) {
	for _, image := range []string{"postgres:14-alpine", "postgres:18-alpine"} {
		t.Run(image, func(t *testing.T) {
			t.Parallel()
			port := startPostgres(t, image)
			q := simpleQueryRows(connectToContainer(t, port))

			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			// The migrations run as the administrator, over a SEPARATE connection, because the
			// replication role deliberately cannot write anything. That is also the shape of the
			// real case: somebody else's deploy lands mid-window.
			admin := adminConn(t, port)
			ddl := func(statement string) {
				t.Helper()
				if _, err := admin.Exec(ctx, statement).ReadAll(); err != nil {
					t.Fatalf("%s: %v", statement, err)
				}
			}
			take := func(what string) string {
				t.Helper()
				h, err := fingerprint(ctx, q)
				if err != nil {
					t.Fatalf("fingerprint %s: %v — the role has REPLICATION and no table access, which "+
						"AD-036 measured is enough to read the catalog", what, err)
				}
				return h
			}

			ddl("CREATE TABLE orders (id integer, total numeric(10,2))")
			start := take("the starting schema")

			if again := take("the same schema a second time"); again != start {
				t.Fatalf("the same schema hashed %s then %s; every base copy would be discarded forever", start, again)
			}

			for _, step := range []struct {
				name string
				ddl  string
			}{
				{"a column added", "ALTER TABLE orders ADD COLUMN note text"},
				{"a column's type changed", "ALTER TABLE orders ALTER COLUMN total TYPE numeric(12,2)"},
				{"a column dropped", "ALTER TABLE orders DROP COLUMN note"},
			} {
				before := take("before " + step.name)
				ddl(step.ddl)
				if after := take("after " + step.name); after == before {
					t.Errorf("%s did not move the fingerprint (%s); DDL inside the window would be "+
						"carried into the base copy instead of discarding it", step.name, after)
				}
			}

			// A dropped column leaves a tombstone in pg_attribute, so a fingerprint that did not
			// exclude attisdropped would never return to the earlier value here — and this test
			// would still pass every case above while the product silently kept re-basing.
			ddl("ALTER TABLE orders ALTER COLUMN total TYPE numeric(10,2)")
			if back := take("back at the starting schema"); back != start {
				t.Errorf("returning the schema to where it began hashed %s, want %s — most likely a "+
					"dropped column's tombstone is still being counted", back, start)
			}

			// The customer's rows are still unreadable. If this ever succeeds, the fingerprint is
			// not the only thing that changed and AD-033's whole claim needs re-measuring.
			if _, err := q(ctx, "SELECT * FROM orders"); err == nil {
				t.Error("the replication role read a customer table; the base copy is supposed to need no read grant")
			} else if !strings.Contains(err.Error(), "permission denied") {
				t.Errorf("reading a table failed for an unexpected reason: %v", err)
			}
		})
	}
}

// A CHANGE OF REPLICA IDENTITY MOVES NO COLUMN, AND IT CHANGES WHAT A DELETE CARRIES — the comment
// on schemaQuery says why that has to reach the fingerprint.
//
// The last two cases are the ones a naive fix misses, and the reason the flag is read from the
// catalog here rather than assumed: both keep relreplident at 'i' from beginning to end, so a
// fingerprint carrying only the flag would hash them identically while the key columns moved.
func TestTheFingerprintNoticesAChangeOfReplicaIdentity(t *testing.T) {
	for _, image := range []string{"postgres:14-alpine", "postgres:18-alpine"} {
		t.Run(image, func(t *testing.T) {
			t.Parallel()
			port := startPostgres(t, image)
			q := simpleQueryRows(connectToContainer(t, port))

			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			admin := adminConn(t, port)
			ddl := func(statement string) {
				t.Helper()
				if _, err := admin.Exec(ctx, statement).ReadAll(); err != nil {
					t.Fatalf("%s: %v", statement, err)
				}
			}
			take := func(what string) string {
				t.Helper()
				h, err := fingerprint(ctx, q)
				if err != nil {
					t.Fatalf("fingerprint %s: %v", what, err)
				}
				return h
			}
			// relreplident, read as the administrator, so the last case can prove the flag did NOT
			// move rather than assert it from the documentation.
			flag := func() string {
				t.Helper()
				results, err := admin.Exec(ctx,
					"SELECT relreplident FROM pg_class WHERE oid = 'customers'::regclass").ReadAll()
				if err != nil {
					t.Fatalf("read relreplident: %v", err)
				}
				if len(results) == 0 || len(results[0].Rows) == 0 {
					t.Fatal("read relreplident: the table is not in pg_class")
				}
				return string(results[0].Rows[0][0])
			}

			ddl("CREATE TABLE customers (id integer PRIMARY KEY, email text NOT NULL, code text NOT NULL)")
			ddl("CREATE UNIQUE INDEX customers_by_email ON customers (email)")
			ddl("CREATE UNIQUE INDEX customers_by_code ON customers (code)")

			for _, step := range []struct {
				name string
				ddl  []string
				// flagStays asserts relreplident is the SAME before and after. It is what makes a
				// case interesting rather than incidental, so it is stated here and checked.
				flagStays bool
			}{
				{name: "REPLICA IDENTITY FULL", ddl: []string{"ALTER TABLE customers REPLICA IDENTITY FULL"}},
				{name: "REPLICA IDENTITY NOTHING", ddl: []string{"ALTER TABLE customers REPLICA IDENTITY NOTHING"}},
				{name: "REPLICA IDENTITY USING INDEX", ddl: []string{"ALTER TABLE customers REPLICA IDENTITY USING INDEX customers_by_email"}},
				{name: "the same USING INDEX repointed at another unique index", flagStays: true,
					ddl: []string{"ALTER TABLE customers REPLICA IDENTITY USING INDEX customers_by_code"}},
				// Same flag, same index NAME, different columns under it. The name alone would
				// hash identically here, which is why indkey is in the query too.
				{name: "the replica identity index rebuilt over different columns", flagStays: true, ddl: []string{
					"ALTER TABLE customers REPLICA IDENTITY DEFAULT",
					"DROP INDEX customers_by_code",
					"CREATE UNIQUE INDEX customers_by_code ON customers (id)",
					"ALTER TABLE customers REPLICA IDENTITY USING INDEX customers_by_code",
				}},
			} {
				before, beforeFlag := take("before "+step.name), flag()
				for _, statement := range step.ddl {
					ddl(statement)
				}
				after, afterFlag := take("after "+step.name), flag()

				if after == before {
					t.Errorf("%s did not move the fingerprint (%s): relreplident went %s → %s, so the "+
						"chain is not marked and a DELETE starts carrying different columns than the "+
						"base copy was taken against", step.name, after, beforeFlag, afterFlag)
				}
				t.Logf("%s: relreplident %s → %s, fingerprint %s → %s",
					step.name, beforeFlag, afterFlag, before, after)
				if step.flagStays && beforeFlag != afterFlag {
					t.Errorf("relreplident moved %s → %s across %s; that case is only interesting "+
						"because the flag stays put", beforeFlag, afterFlag, step.name)
				}
			}
		})
	}
}

// A TEMPORARY TABLE IS NOT A SCHEMA CHANGE, AND pg_class DISAGREES — the comment on schemaQuery
// says what a fingerprint that counts them costs.
//
// The second connection is the case a naive fix misses: each backend gets its OWN pg_temp_N, so
// excluding one temp schema by name leaves every other session still moving the hash. Both majors,
// like the two tests above it, because the catalog is what changes across a major version.
func TestTheFingerprintIgnoresTemporaryTables(t *testing.T) {
	for _, image := range []string{"postgres:14-alpine", "postgres:18-alpine"} {
		t.Run(image, func(t *testing.T) {
			t.Parallel()
			port := startPostgres(t, image)
			q := simpleQueryRows(connectToContainer(t, port))

			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			// Two customer sessions, both held open for the whole test: a temp table exists only as
			// long as the backend that made it, so a closed connection would prove nothing.
			first, second := adminConn(t, port), adminConn(t, port)
			ddl := func(conn *pgconn.PgConn, statement string) {
				t.Helper()
				if _, err := conn.Exec(ctx, statement).ReadAll(); err != nil {
					t.Fatalf("%s: %v", statement, err)
				}
			}
			take := func(what string) string {
				t.Helper()
				h, err := fingerprint(ctx, q)
				if err != nil {
					t.Fatalf("fingerprint %s: %v", what, err)
				}
				return h
			}
			// The temp schemas the REPLICATION connection can see, read the same way the fingerprint
			// reads the catalog. Without this the test would pass just as happily if the temp tables
			// were never created or were invisible to this backend — which is the only way a test
			// like this goes quietly useless.
			tempSchemas := func() []string {
				t.Helper()
				rows, err := q(ctx, `SELECT n.nspname FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relpersistence = 't' AND c.relkind IN ('r', 'p') ORDER BY 1`)
				if err != nil {
					t.Fatalf("list the temp relations: %v", err)
				}
				var names []string
				for _, row := range rows {
					names = append(names, row[0])
				}
				return names
			}

			ddl(first, "CREATE TABLE orders (id integer PRIMARY KEY, total numeric(10,2))")
			start := take("the starting schema")

			ddl(first, "CREATE TEMP TABLE report (n integer, label text)")
			if seen := tempSchemas(); len(seen) != 1 {
				t.Fatalf("the replication connection sees temp relations in %v, want exactly one "+
					"session's; the rest of this test would prove nothing", seen)
			}
			if after := take("with one session's temp table"); after != start {
				t.Errorf("a temp table moved the fingerprint %s → %s; every report query would mark "+
					"the chain schema-changed and burn a re-base", start, after)
			}

			// The same NAME in a different backend, which lands in a different pg_temp_N.
			ddl(second, "CREATE TEMP TABLE report (n integer, label text)")
			seen := tempSchemas()
			if len(seen) != 2 || seen[0] == seen[1] {
				t.Fatalf("two sessions' temp tables sit in %v; this case is only interesting because "+
					"the two schema NAMES differ", seen)
			}
			t.Logf("two backends' temp tables live in %v", seen)
			if after := take("with a second session's temp table"); after != start {
				t.Errorf("a second connection's temp table moved the fingerprint %s → %s; a fix that "+
					"excludes one backend's temp schema by name leaves exactly this", start, after)
			}

			// ON COMMIT DROP is deliberately not a case: it lives and dies inside one transaction, so
			// its pg_class row never commits and no other backend can see it — a case that cannot
			// fail reads as coverage and is not.

			// THE DELIBERATE OTHER HALF: an unlogged table STAYS in the fingerprint, pinned here so
			// the decision cannot be reversed by accident. Measured against a reference taken
			// immediately before it, NOT against start: the assertions above are Errorf, so on a
			// broken exclusion start is already stale and this case would pass proving nothing.
			beforeUnlogged := take("before the unlogged table")
			ddl(first, "CREATE UNLOGGED TABLE audit (id integer, at timestamptz)")
			if after := take("with an unlogged table"); after == beforeUnlogged {
				t.Errorf("an unlogged table did not move the fingerprint (%s); unlogged DDL is real "+
					"schema and is deliberately still counted", after)
			}
		})
	}
}

// A TABLE MADE LOGGED MID-CHAIN IS THE SILENT ONE, and it is why relpersistence is selected rather
// than only filtered on. An UNLOGGED table is not replicated at all, so its changes never enter the
// stream, and the base copy restores its structure with no rows. ALTER TABLE ... SET LOGGED starts
// its changes arriving in the WAL stream, and they replay onto a table whose earlier rows were
// captured by nothing: UPDATEs and DELETEs hit rows that are not there, INSERTs land on a table
// missing all its history, and the restore looks healthy.
//
// SET UNLOGGED IS HERE TOO, and it is the same failure read backwards rather than a courtesy: the
// base copy holds that table's rows and the stream stops carrying its changes, so the restore
// produces a table frozen at an arbitrary moment with nothing anywhere saying so. Both directions
// are the table starting or stopping being carried by logical decoding, both are invisible to every
// other field in this query, and one SELECT item catches both.
//
// Both majors, because relpersistence is a catalog column and the catalog is what moves across one.
func TestTheFingerprintNoticesATableChangingPersistence(t *testing.T) {
	for _, image := range []string{"postgres:14-alpine", "postgres:18-alpine"} {
		t.Run(image, func(t *testing.T) {
			t.Parallel()
			port := startPostgres(t, image)
			q := simpleQueryRows(connectToContainer(t, port))

			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			admin := adminConn(t, port)
			ddl := func(statement string) {
				t.Helper()
				if _, err := admin.Exec(ctx, statement).ReadAll(); err != nil {
					t.Fatalf("%s: %v", statement, err)
				}
			}
			take := func(what string) string {
				t.Helper()
				h, err := fingerprint(ctx, q)
				if err != nil {
					t.Fatalf("fingerprint %s: %v", what, err)
				}
				return h
			}
			// relpersistence read as the administrator, so each case proves the catalog actually
			// moved rather than assuming ALTER TABLE did what the manual says.
			persistence := func() string {
				t.Helper()
				results, err := admin.Exec(ctx,
					"SELECT relpersistence FROM pg_class WHERE oid = 'audit'::regclass").ReadAll()
				if err != nil {
					t.Fatalf("read relpersistence: %v", err)
				}
				if len(results) == 0 || len(results[0].Rows) == 0 {
					t.Fatal("read relpersistence: the table is not in pg_class")
				}
				return string(results[0].Rows[0][0])
			}

			// An UNLOGGED table needs a primary key before SET LOGGED will replicate it, and it is
			// what the customer's table would have anyway.
			ddl("CREATE UNLOGGED TABLE audit (id integer PRIMARY KEY, at timestamptz)")

			for _, step := range []struct {
				name, ddl, want string
			}{
				{"SET LOGGED", "ALTER TABLE audit SET LOGGED", "p"},
				{"SET UNLOGGED", "ALTER TABLE audit SET UNLOGGED", "u"},
			} {
				before, beforeFlag := take("before "+step.name), persistence()
				ddl(step.ddl)
				after, afterFlag := take("after "+step.name), persistence()

				if afterFlag != step.want {
					t.Fatalf("%s left relpersistence at %q, want %q; this case proves nothing unless "+
						"the catalog moved", step.name, afterFlag, step.want)
				}
				if after == before {
					t.Errorf("%s did not move the fingerprint (%s): relpersistence went %s → %s, so "+
						"the chain is not marked and the stream starts or stops carrying a table the "+
						"base copy was not taken against", step.name, after, beforeFlag, afterFlag)
				}
				t.Logf("%s: relpersistence %s → %s, fingerprint %s → %s",
					step.name, beforeFlag, afterFlag, before, after)
			}
		})
	}
}

// THE MIGRATION, PROVED AGAINST A SERVER RATHER THAN AGAINST CANNED ROWS. The unit test pins that
// the older digest ignores the newer field; this pins that it ignores it over the real catalog, and
// that a chain based by the agent before this one is not ended by deploying this one.
//
// It reconstructs what that earlier agent stored — the untagged digest alone, taken from the same
// live schema — and asks chain.SchemaMoved the question the cycle asks every time it runs.
func TestDeployingThisAgentDoesNotReBaseAChainTheOneBeforeItStarted(t *testing.T) {
	for _, image := range []string{"postgres:14-alpine", "postgres:18-alpine"} {
		t.Run(image, func(t *testing.T) {
			t.Parallel()
			port := startPostgres(t, image)
			q := simpleQueryRows(connectToContainer(t, port))

			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			defer cancel()

			admin := adminConn(t, port)
			ddl := func(statement string) {
				t.Helper()
				if _, err := admin.Exec(ctx, statement).ReadAll(); err != nil {
					t.Fatalf("%s: %v", statement, err)
				}
			}
			ddl("CREATE TABLE orders (id integer PRIMARY KEY, total numeric(10,2))")
			ddl("CREATE UNLOGGED TABLE audit (id integer PRIMARY KEY, at timestamptz)")

			// What the agent before this one would have written into the chain's base manifest: the
			// same query, hashed the way it hashed it, with the field it did not select left out.
			stored := strings.Fields(mustFingerprint(t, ctx, q))[0]
			if strings.Contains(stored, "v2") {
				t.Fatalf("the untagged digest is %q; an already-stored fingerprint has no tag on it "+
					"and this test would be comparing something no agent ever wrote", stored)
			}

			// The cycle after the deploy, against a schema nobody touched.
			if chainpkg.SchemaMoved(stored, mustFingerprint(t, ctx, q)) {
				t.Fatal("deploying this agent read as the customer's schema moving: every chain in " +
					"the fleet would take a fresh base copy on its first cycle, simultaneously")
			}

			// And the check is still live on that chain — under the algorithm its base was taken
			// with, which is the only one both ends hold.
			ddl("ALTER TABLE orders ADD COLUMN note text")
			if !chainpkg.SchemaMoved(stored, mustFingerprint(t, ctx, q)) {
				t.Error("a column added under a chain based before the deploy went unnoticed; the " +
					"older algorithm still has to answer for the chains that were taken with it")
			}
		})
	}
}

func mustFingerprint(t *testing.T, ctx context.Context, q querySQL) string {
	t.Helper()
	h, err := fingerprint(ctx, q)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	return h
}

// adminConn is an ORDINARY connection as the superuser — the one thing this package never opens for
// itself (AD-036). It exists here only to play the customer's own deploy pipeline, which is the
// thing that moves a schema mid-window.
func adminConn(t *testing.T, port uint16) *pgconn.PgConn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := pgconn.Connect(ctx, fmt.Sprintf(
		"postgres://postgres:%s@127.0.0.1:%d/postgres?sslmode=disable", containerPassword, port))
	if err != nil {
		t.Fatalf("open the administrator's connection to the container: %v", err)
	}
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = conn.Close(closeCtx)
	})
	return conn
}
