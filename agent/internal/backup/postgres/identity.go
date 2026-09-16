package postgres

// identity.go answers, at BACKUP time, the one question a restore cannot answer at all: which of
// this database's tables can have their changes replayed, and which cannot.
//
// WHY IT IS HERE AND NOT IN restore/. A change file for a table with nothing to identify a row by
// is unreplayable the moment it is written, and by the time anybody is restoring it there is
// nothing left to do about it. The customer needs the sentence while the database is still theirs
// to change — so this runs on the source, over the connection the agent already has, before the
// stream exists.
//
// AND MEASURED ON LIVE AZURE, IT IS WORSE THAN THAT (AD-039). Once such a table is in our
// publication, THE CUSTOMER'S OWN UPDATE AND DELETE STOP WORKING — identically on 14.23 and 18.4:
//
//	UPDATE ops.clicks …  SQLSTATE 55000: cannot update table "clicks" because it does not have a
//	                                     replica identity and publishes updates
//
// An append-only workload passes every test we run and breaks weeks later, with an error naming
// our publication. So this must be asked BEFORE the publication is created, because creating it is
// the act that breaks them.
//
// IT ASKS THE CATALOG AND NOTHING ELSE, which is what lets it run over the replication connection
// the agent holds (AD-036). That role can read no table at all and can read this.
//
// ITS CALLER IS THE PUBLICATION STEP, WHICH DOES NOT EXIST YET — C3 owns it, and creating the
// publication without calling this first is the bug AD-039 measured.

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

// Unreplayable is one table whose changes cannot be replayed, and why in a sentence a customer can
// act on.
type Unreplayable struct {
	Schema string
	Table  string
	Why    string
}

func (u Unreplayable) String() string { return u.Schema + "." + u.Table }

// What each table's replica identity is, and whether it has anything that could serve as one.
//
// relkind = 'r' only, the same rule verify/ follows: a partitioned table holds no rows of its own
// and each of its partitions is an 'r', so counting both would report every partitioned table
// twice.
//
// indisreplident is set by the server only on an index it has already checked is unique, valid,
// not partial and over NOT NULL columns — which is exactly the test "can this locate one row",
// so its presence is the whole answer and nothing here re-derives it.
const identityQuery = `SELECT n.nspname, c.relname, c.relreplident::text,
       EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid = c.oid AND i.indisprimary)::text,
       EXISTS (SELECT 1 FROM pg_index i WHERE i.indrelid = c.oid AND i.indisreplident)::text
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE c.relkind = 'r'
   AND n.nspname <> 'information_schema'
   AND n.nspname !~ '^pg_'
 ORDER BY n.nspname, c.relname`

// Screen lists every table in the database whose changes could not be replayed correctly.
//
// An empty result is the good answer and it is a POSITIVE one: every table was looked at and every
// table can be located by identity. An error is neither — see the refusal in classify.
func Screen(ctx context.Context, conn *pgconn.PgConn) ([]Unreplayable, error) {
	return screen(ctx, simpleQueryRows(conn))
}

func screen(ctx context.Context, q querySQL) ([]Unreplayable, error) {
	rows, err := q(ctx, identityQuery)
	if err != nil {
		return nil, fmt.Errorf("postgres: read the replica identity of every table: %w", err)
	}

	var found []Unreplayable
	for _, row := range rows {
		if len(row) != 5 {
			return nil, fmt.Errorf("postgres: the replica identity query returned %d columns, want 5", len(row))
		}
		primary, err := boolean(row[3])
		if err != nil {
			return nil, fmt.Errorf("postgres: %s.%s: has a primary key: %w", row[0], row[1], err)
		}
		replident, err := boolean(row[4])
		if err != nil {
			return nil, fmt.Errorf("postgres: %s.%s: has a replica identity index: %w", row[0], row[1], err)
		}
		why, err := classify(row[2], primary, replident)
		if err != nil {
			return nil, fmt.Errorf("postgres: %s.%s: %w", row[0], row[1], err)
		}
		if why != "" {
			found = append(found, Unreplayable{Schema: row[0], Table: row[1], Why: why})
		}
	}
	return found, nil
}

// classify turns one table's catalog row into the sentence a customer reads, or the empty string
// when the table is fine.
//
// AN ANSWER IT DOES NOT RECOGNISE IS AN ERROR, never a table declared fine. A screen that fails
// open reports nothing on the day it breaks, which is the day it was needed.
func classify(replident string, primary, replidentIndex bool) (string, error) {
	switch replident {
	case "d":
		// The default: the primary key, if there is one.
		if primary {
			return "", nil
		}
		return "it has no primary key and the default replica identity, so nothing in a change " +
			"file can say WHICH row changed — and once this table is published, UPDATE and DELETE " +
			"on it will fail for your own application too (SQLSTATE 55000)", nil

	case "i":
		// An index named explicitly. The server sets this flag only on an index that can locate
		// one row, so its absence means the index was dropped out from under the setting.
		if replidentIndex {
			return "", nil
		}
		return "its replica identity names an index that is no longer there, so nothing in a " +
			"change file can say which row changed", nil

	case "n":
		return "it is set to REPLICA IDENTITY NOTHING, so a change file carries no identity at " +
			"all — and once this table is published, UPDATE and DELETE on it will fail for your " +
			"own application too (SQLSTATE 55000)", nil

	case "f":
		// FULL SENDS THE WHOLE OLD ROW AS THE IDENTITY, AND THAT IS REPORTED EVEN WHEN THE TABLE
		// HAS A PRIMARY KEY — which is the opposite of what this said until the stream was
		// measured against a real server. The reasoning it used to carry ("a FULL table with a
		// primary key sends that key inside the row, so it replays as it would have without
		// FULL") is true of the TUPLE and false of what a change file can express: pgoutput's
		// relation message flags EVERY column as replica identity under FULL and names no index,
		// so nothing on the wire says which subset is unique (change.go, and measured on 18 in
		// change_docker_test.go). A record for such a table is refused at capture.
		//
		// It is reported here, before the publication exists, because that is the one moment the
		// customer can still act on it — and the ALTER that fixes it is a one-liner on a table
		// that already has a primary key.
		if primary {
			return "it is set to REPLICA IDENTITY FULL, so every change it publishes carries the " +
				"whole row as its identity and nothing says which columns are the unique ones — " +
				"even though this table HAS a primary key. Point it back at that key with " +
				"ALTER TABLE ... REPLICA IDENTITY DEFAULT and its changes replay normally", nil
		}
		// Without one, the same answer and a harder remedy: there is no key to point it back at.
		// FULL keeps the customer's own writes working, which is the one thing it does buy them
		// (AD-039), and a whole row is still not a UNIQUE identity — two identical rows cannot be
		// told apart, so one update would touch both or neither.
		return "it is set to REPLICA IDENTITY FULL and has no primary key, which keeps your own " +
			"writes working but sends the whole row as the identity; a whole row is not unique, so " +
			"two identical rows cannot be told apart and their changes cannot be replayed", nil
	}
	return "", fmt.Errorf("the catalog reports a replica identity of %q, which this does not "+
		"recognise; refusing to call the table replayable", replident)
}

// Warning is what goes on the screen. Empty when nothing is wrong, so a clean database prints
// nothing at all.
//
// It names every table rather than counting them, and it names the statement that fixes each one.
// A warning a customer cannot act on is a warning they will learn to scroll past.
func Warning(found []Unreplayable) string {
	if len(found) == 0 {
		return ""
	}
	sorted := make([]Unreplayable, len(found))
	copy(sorted, found)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].String() < sorted[j].String() })

	lines := []string{
		fmt.Sprintf("WARNING: %d table(s) in this database cannot be replayed from a change file, "+
			"so a restore would bring them back as they were at the last full copy and no later:", len(sorted)),
	}
	for _, u := range sorted {
		lines = append(lines, fmt.Sprintf("  %s — %s", u, u.Why))
	}
	lines = append(lines,
		"",
		"To fix a table, give it something that identifies a row and tell Postgres to use it:",
		"  ALTER TABLE <schema>.<table> ADD PRIMARY KEY (<columns>)",
		"  -- or, if it already has a unique index over NOT NULL columns:",
		"  ALTER TABLE <schema>.<table> REPLICA IDENTITY USING INDEX <index>",
		"",
		"Until then their changes cannot be replayed, and publishing them will make UPDATE and "+
			"DELETE fail on them for your own application.")
	return strings.Join(lines, "\n")
}

// boolean reads one of the catalog query's ::text booleans and REFUSES ANYTHING ELSE rather than
// reading it as false. A bare boolean arrives as "t" and ::text of one is "true"; a comparison
// against the wrong one of those would quietly report every table in the database as unreplayable,
// or none of them.
func boolean(s string) (bool, error) {
	switch s {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("the catalog returned %q where a boolean was expected", s)
}
