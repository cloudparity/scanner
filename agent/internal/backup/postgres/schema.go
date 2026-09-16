package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

// The schema fingerprint: every column of every ordinary table, in a fixed order, and the replica
// identity of the table it belongs to.
//
// IT RUNS OVER THE STREAM'S REPLICATION CONNECTION, AND IT IS THE ONE THING THAT ROLE CAN READ.
// AD-036 measured a role with REPLICATION and access to no table at all: SELECT on a customer table
// is refused on 14 through 18, and this catalog query answers on both. So the fingerprint costs no
// grant — which is the entire point of AD-033, and would be undone by a fingerprint that needed one.
//
// WHAT IT MUST NOTICE, and what the tests hold it to: a column added, a column dropped, a column
// renamed, and a column whose type changed. format_type is what catches the last of those including
// its modifier, so numeric(10,2) → numeric(12,2) moves the hash; atttypid alone would not.
//
// AND A CHANGE OF REPLICA IDENTITY, WHICH MOVES NO COLUMN AT ALL. A DELETE in the logical stream
// carries the key columns and NULL for the rest, so the identity is what decides which values a
// deleted row arrives with; ALTER TABLE ... REPLICA IDENTITY FULL / NOTHING / USING INDEX changes
// that and touches no pg_attribute row, so a column-only fingerprint hashed the same and no re-base
// was scheduled while the stream described deletes the base copy was never taken against.
//
// relreplident IS NOT ENOUGH ON ITS OWN. Under USING INDEX the flag sits at 'i' while the index it
// points at is repointed underneath it, which changes the key columns and moves no flag. So the
// index is named too, by relname AND indkey — the name catches a repoint, the attribute numbers
// catch an index dropped and rebuilt over different columns under the same name. They are two
// SELECT items rather than one concatenated field so the separator below falls between them: index
// names may contain spaces, and "y 1" over (c) joined to "y" over (a, c) is otherwise one string.
//
// The two subqueries are correlated rather than a LEFT JOIN on purpose. At most one index per table
// carries indisreplident, and if that ever stopped holding, a join would silently duplicate every
// column row of the table and leave the ORDER BY no longer total — the same schema hashing two ways
// on two runs. A subquery raises instead, and fingerprint turns that into an error.
//
// relpersistence IS SELECTED, AND NOT ONLY FILTERED ON. It says whether logical decoding carries
// the table at all. An UNLOGGED table is not replicated, so its changes never enter the stream and
// pg_dump restores its structure with no rows; the moment a customer runs ALTER TABLE … SET LOGGED
// its changes begin arriving, and they replay onto a table whose earlier rows were captured by
// nothing — UPDATEs and DELETEs against rows that are not there, INSERTs onto a table missing all
// its history, and a restore that looks healthy. SET UNLOGGED is the same event backwards: the base
// copy holds the rows, the stream stops carrying the changes, and the table restores frozen at an
// arbitrary moment. Neither moves a column or a replica identity, so nothing else in this query sees
// either. It is the LAST item on purpose — see fingerprintAlgorithms.
//
// STILL NOT COVERED, and E9.7's to close with the constraints: under relreplident 'd' the effective
// identity is the primary key, no index carries indisreplident, and dropping the PK or moving it to
// another column moves nothing here. Measured on 14 and 18.
//
// Deliberately small. E9.7 owns the rest of the comparison — indexes in general, constraints, enum
// values — and will extend this query. Two properties must survive that extension: the ORDER BY,
// without which the same schema hashes differently on two runs and every base copy is discarded
// forever; and a field separator, without which a rename that moves a character from one column to
// the next hashes identically.
//
// attnum > 0 excludes the system columns, attisdropped excludes the tombstones a dropped column
// leaves behind, and relkind r/p is ordinary and partitioned tables — a view has no rows to restore.
//
// TEMPORARY TABLES ARE EXCLUDED, AND THAT IS NOT TIDINESS. pg_class carries EVERY backend's temp
// relations, so one customer session running a report or an ETL step moves this hash — twice over:
// inside the base copy's own window it fails H0 == H1 and burns one of maxBaseCopyAttempts, and
// between the base and a later cycle it is C5, so no manifest is written, the chain is marked
// schema-changed and a re-base is scheduled, which the next session's temp table then does again.
// A false positive with the exact shape of the true positive C5 exists to catch.
//
// relpersistence 't' IS THE PREDICATE, AND THE SCHEMA NAME IS NOT. Temp relations live in a
// per-backend schema — pg_temp_3, pg_temp_4 — so the NAME differs for every connected client, and
// excluding one of them by name leaves every other backend still moving the hash. relpersistence
// sits on the relation and says the same thing whichever backend created it. (A pattern on nspname
// is not WRONG where the whole pg_ prefix is meant — identity.go and verify/ both match ^pg_ and
// are correct as they stand — it is only the wrong tool for one temp schema at a time.) The toast
// schemas need no clause either: a toast relation is relkind 't', already excluded above.
//
// UNLOGGED TABLES ('u') DELIBERATELY STAY IN: per-database rather than per-session, so they do not
// churn, and their DDL is real schema a restore reproduces. That is also why relpersistence can be
// both the filter and a selected field without contradiction — 't' is excluded, 'p' and 'u' are
// compared.
const schemaQuery = `SELECT n.nspname, c.relname, a.attname, format_type(a.atttypid, a.atttypmod),
c.relreplident,
coalesce((SELECT ri.relname FROM pg_index i JOIN pg_class ri ON ri.oid = i.indexrelid
	WHERE i.indrelid = c.oid AND i.indisreplident), ''),
coalesce((SELECT i.indkey::text FROM pg_index i
	WHERE i.indrelid = c.oid AND i.indisreplident), ''),
c.relpersistence
FROM pg_attribute a
JOIN pg_class c ON c.oid = a.attrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE a.attnum > 0 AND NOT a.attisdropped AND c.relkind IN ('r', 'p')
AND c.relpersistence <> 't'
AND n.nspname NOT IN ('pg_catalog', 'information_schema')
ORDER BY n.nspname, c.relname, a.attnum`

// fingerprintAlgorithms are the ways this agent can reduce those rows to a digest, OLDEST FIRST,
// and the reason there is more than one is a deployment rather than a database.
//
// ADDING A FIELD TO THE QUERY MOVES THE DIGEST OF EVERY SCHEMA THERE IS. Under a single digest, the
// first cycle after such a release compares this agent's value against a base the agent before it
// captured, finds them different, and concludes the customer's schema moved — on every chain in the
// fleet, at once, each paying for a base copy nothing needed. relpersistence is the second time this
// query has grown and E9.7 is the third, so it is answered here rather than lived with.
//
// So the value names its algorithm, chain.SchemaMoved compares per algorithm — the reasoning is
// there and at contract.Manifest.Schema, not restated here — and a rollout costs nothing in either
// direction: the new agent's value carries the old digest too, and an old agent reports only that
// one, which a new chain's value also carries.
//
// EACH ALGORITHM IS A PREFIX OF THE ONE AFTER IT, which is what every version of this query has
// been: a growing SELECT list, appended to. So one query and one pass over its rows produce all of
// them, and fields is simply how far along each row an algorithm reads. A future field that must go
// in the MIDDLE of the list would break that and needs its own query; nothing has needed one yet.
//
// RETIRING ONE IS THE OTHER END OF THIS. Once no live chain has a base older than v2, the first
// entry goes; the few agents still comparing against a v1 base then re-base once, which is what
// they would have done anyway.
var fingerprintAlgorithms = []struct {
	// tag names the algorithm on the wire. Empty is B2's original — columns and replica identity —
	// which predates tagging and is therefore spelled as the bare digest.
	tag string
	// fields is how many of each row's leading fields the algorithm hashes.
	fields int
}{
	{tag: "", fields: 7},
	{tag: "v2", fields: 8}, // + relpersistence
}

// fingerprint reduces those rows to one comparable string: the digests above, oldest first,
// space-separated. contract.Manifest.Schema is where that wire form is written down.
//
// TWO FINGERPRINTS FROM TWO AGENTS ARE COMPARED BY chain.SchemaMoved AND BY NOTHING ELSE, because
// only that function knows they may not share an algorithm. The one place in this repo that compares
// them with != is baseCopyOnce's H0/H1 (base.go), and it is not an exception to the rule so much as
// outside it: both values are taken by THIS process, seconds apart, over the same algorithm list, so
// equality is exactly right and strictly stricter. Any comparison that could span two agent
// versions is chain.SchemaMoved's.
//
// IT NEVER RETURNS A FINGERPRINT AND AN ERROR TOGETHER, and the empty string is never a fingerprint.
// The value's only use is H0 == H1, and two empty strings are equal: a fingerprint that failed
// quietly would make the DDL check pass every time, removing the check precisely when the
// connection is unhealthy.
//
// It carries no schema NAMES into the result, only a hash of them, so the value can be put in a
// manifest and read by us without carrying a description of the customer's data model with it.
func fingerprint(ctx context.Context, q querySQL) (string, error) {
	rows, err := q(ctx, schemaQuery)
	if err != nil {
		return "", fmt.Errorf("postgres: fingerprint the schema: %w", err)
	}

	// THE NEWEST ALGORITHM READS EVERY FIELD THE QUERY SELECTS, checked rather than assumed. A field
	// added to the SELECT list without an entry beside it above would be hashed by nothing, and the
	// fingerprint would go on being perfectly stable across exactly the change it was extended to
	// notice — the failure this file exists to prevent, reintroduced by an omission no test names.
	// It also keeps the slicing below from panicking on a row narrower than the algorithm reading it.
	//
	// One row is enough: a result set has one width, set by the SELECT list, for every row in it.
	widest := fingerprintAlgorithms[len(fingerprintAlgorithms)-1].fields
	if len(rows) > 0 && len(rows[0]) != widest {
		return "", fmt.Errorf("postgres: fingerprint the schema: the catalog returned %d fields per "+
			"row, want %d", len(rows[0]), widest)
	}

	digests := make([]string, 0, len(fingerprintAlgorithms))
	for _, algorithm := range fingerprintAlgorithms {
		h := sha256.New()
		for _, row := range rows {
			for _, field := range row[:algorithm.fields] {
				h.Write([]byte(field))
				h.Write([]byte{0}) // The separator. See the comment on schemaQuery for what it prevents.
			}
			h.Write([]byte{'\n'})
		}
		digest := "sha256:" + hex.EncodeToString(h.Sum(nil))
		if algorithm.tag != "" {
			digest = algorithm.tag + ":" + digest
		}
		digests = append(digests, digest)
	}
	return strings.Join(digests, " "), nil
}

// querySQL runs one statement over the simple query protocol and returns its rows as text.
//
// A function rather than an interface, following slot.go's runSQL for the same reason: one
// operation, one real implementation, and a test that can drive every failure of it. It is the
// single injection point for everything this package does over the database, so a caller passing a
// fake gets the whole sequence — fingerprint, slot create, slot drop, slot position — with no
// server anywhere.
type querySQL func(ctx context.Context, sql string) ([][]string, error)

// exec adapts a querySQL to the runSQL that slot.go's createSlot takes, so B1's code is reused
// rather than reimplemented and there is still only one thing to fake.
func (q querySQL) exec() runSQL {
	return func(ctx context.Context, sql string) error {
		_, err := q(ctx, sql)
		return err
	}
}

// simpleQueryRows is the only real implementation: pgConn.Exec, the simple query protocol, which
// AD-036 measured is the only protocol a replication connection accepts. Every value arrives as
// text, which is all this package compares.
func simpleQueryRows(conn *pgconn.PgConn) querySQL {
	return func(ctx context.Context, sql string) ([][]string, error) {
		results, err := conn.Exec(ctx, sql).ReadAll()
		if err != nil {
			return nil, err
		}
		var out [][]string
		for _, result := range results {
			for _, row := range result.Rows {
				fields := make([]string, len(row))
				for i, field := range row {
					fields[i] = string(field)
				}
				out = append(out, fields)
			}
		}
		return out, nil
	}
}
