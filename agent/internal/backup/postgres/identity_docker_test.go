//go:build docker

// These tests need a working Docker daemon and pull a Postgres image, so they sit behind a build
// tag and `make all` never sees them:
//
//	go test -tags docker ./agent/internal/backup/postgres/ -v
//
// Every container is removed in a t.Cleanup that runs on failure and on t.Fatal alike. No Azure.
package postgres

import (
	"context"
	"strings"
	"testing"
	"time"
)

// The shapes the screen has to tell apart, built on a real server so the catalog answers are the
// server's rather than ours.
const identityZoo = `
CREATE SCHEMA zoo;

-- Fine: a primary key.
CREATE TABLE zoo.keyed (id bigint PRIMARY KEY, v text);

-- Fine: a COMPOSITE primary key, which is the shape that breaks "one column is the identity".
CREATE TABLE zoo.composite (day date NOT NULL, customer bigint NOT NULL, n int, PRIMARY KEY (day, customer));

-- Fine: no primary key, but a unique index named as the replica identity.
CREATE TABLE zoo.by_index (code text NOT NULL, v text);
CREATE UNIQUE INDEX by_index_code ON zoo.by_index (code);
ALTER TABLE zoo.by_index REPLICA IDENTITY USING INDEX by_index_code;

-- THE TICKET'S HARD CASE: no primary key at all, the shape of T1's ops.clicks.
CREATE TABLE zoo.clicks (session_id bigint NOT NULL, url text NOT NULL, happened timestamptz NOT NULL);

-- REPLICA IDENTITY FULL: the customer's workaround for their own writes, and still not an identity.
CREATE TABLE zoo.readings (sensor text NOT NULL, taken timestamptz NOT NULL, value numeric);
ALTER TABLE zoo.readings REPLICA IDENTITY FULL;

-- REPLICA IDENTITY NOTHING: a change file carries no identity at all.
CREATE TABLE zoo.nothing (id bigint PRIMARY KEY, v text);
ALTER TABLE zoo.nothing REPLICA IDENTITY NOTHING;
`

// The screen, against a real catalog, OVER THE REPLICATION CONNECTION — which is the one the agent
// has (AD-036) and which can read no table at all. If this needed an ordinary connection or a
// SELECT grant it could not run where it has to run.
func TestScreenAgainstARealCatalog(t *testing.T) {
	for _, image := range []string{"postgres:14-alpine", "postgres:18-alpine"} {
		t.Run(image, func(t *testing.T) {
			t.Parallel()
			port := startPostgres(t, image)

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			admin := adminConn(t, port)
			if _, err := admin.Exec(ctx, identityZoo).ReadAll(); err != nil {
				t.Fatalf("build the zoo: %v", err)
			}

			found, err := Screen(ctx, connectToContainer(t, port))
			if err != nil {
				t.Fatalf("Screen: %v", err)
			}

			reported := map[string]string{}
			for _, u := range found {
				reported[u.String()] = u.Why
				t.Logf("%-16s %s", u, u.Why)
			}

			for _, fine := range []string{"zoo.keyed", "zoo.composite", "zoo.by_index"} {
				if why, ok := reported[fine]; ok {
					t.Errorf("%s was reported unreplayable (%s); a table with an identity must not "+
						"be, or the warning becomes noise a customer scrolls past", fine, why)
				}
			}
			for table, want := range map[string]string{
				"zoo.clicks":   "no primary key",
				"zoo.readings": "REPLICA IDENTITY FULL",
				"zoo.nothing":  "REPLICA IDENTITY NOTHING",
			} {
				why, ok := reported[table]
				if !ok {
					t.Errorf("%s was NOT reported, so the customer would find out at restore", table)
					continue
				}
				if !strings.Contains(why, want) {
					t.Errorf("%s was reported as %q, want it to say %q", table, why, want)
				}
			}
		})
	}
}

// AD-039, reproduced: this is what the screen is warning about, and it is not a restore-time
// problem at all. Publishing a table with no replica identity BREAKS THE CUSTOMER'S OWN WRITES.
//
// The measurement is the point. Without it the screen reads as a caution about our own restore,
// and the ALTER TABLE it asks for looks optional.
func TestPublishingAKeylessTableBreaksTheCustomersOwnWrites(t *testing.T) {
	for _, image := range []string{"postgres:14-alpine", "postgres:18-alpine"} {
		t.Run(image, func(t *testing.T) {
			t.Parallel()
			port := startPostgres(t, image)

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			admin := adminConn(t, port)
			if _, err := admin.Exec(ctx, identityZoo).ReadAll(); err != nil {
				t.Fatalf("build the zoo: %v", err)
			}

			// The screen runs FIRST, which is the order the whole file exists to establish: this
			// answer has to be in hand before the publication is created, because creating it is
			// the act that breaks the tables below.
			found, err := Screen(ctx, connectToContainer(t, port))
			if err != nil {
				t.Fatalf("Screen: %v", err)
			}
			if warning := Warning(found); !strings.Contains(warning, "zoo.clicks") {
				t.Fatalf("the warning does not name zoo.clicks:\n%s", warning)
			}

			// The customer's writes work before anything is published.
			if _, err := admin.Exec(ctx,
				`INSERT INTO zoo.clicks VALUES (1, '/a', now()); UPDATE zoo.clicks SET url = '/b'`).ReadAll(); err != nil {
				t.Fatalf("the keyless table could not be written to before publishing: %v", err)
			}

			if _, err := admin.Exec(ctx, `CREATE PUBLICATION parity_screen FOR ALL TABLES`).ReadAll(); err != nil {
				t.Fatalf("create the publication: %v", err)
			}

			_, err = admin.Exec(ctx, `UPDATE zoo.clicks SET url = '/c'`).ReadAll()
			if err == nil {
				t.Fatal("UPDATE on a published keyless table succeeded; the whole reason this is " +
					"reported at backup time has moved")
			}
			if !strings.Contains(err.Error(), "replica identity") {
				t.Errorf("the update failed with %v, want the replica identity refusal", err)
			}
			t.Logf("as measured in AD-039: %v", err)

			// And the table the screen said was fine still is.
			if _, err := admin.Exec(ctx, `UPDATE zoo.keyed SET v = 'ok'`).ReadAll(); err != nil {
				t.Errorf("a keyed table could not be updated under the publication either, so the "+
					"screen is not telling the two cases apart: %v", err)
			}
		})
	}
}
