package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// rows turns canned catalog output into a querySQL. No server, because what these tests check is
// that the fingerprint is a function of the rows and of nothing else — whether the QUERY returns
// the right rows is a question only a server can answer, and schema_docker_test.go asks it there.
func rows(out [][]string, err error) querySQL {
	return func(context.Context, string) ([][]string, error) { return out, err }
}

func TestTheFingerprintIsStableAndSensitive(t *testing.T) {
	// Eight fields, in the order schemaQuery selects them: schema, table, column, type, the
	// table's replica identity — the flag, then the name and the columns of the index it points at
	// when the flag is 'i' — and last, the table's persistence.
	base := [][]string{
		{"public", "orders", "id", "integer", "d", "", "", "p"},
		{"public", "orders", "total", "numeric(10,2)", "d", "", "", "p"},
	}

	for _, tc := range []struct {
		name string
		rows [][]string
		same bool
	}{
		{"the same schema twice", base, true},
		{"a column added", append(append([][]string{}, base...), []string{"public", "orders", "note", "text", "d", "", "", "p"}), false},
		{"a column dropped", base[:1], false},
		{"a type changed", [][]string{
			{"public", "orders", "id", "integer", "d", "", "", "p"},
			{"public", "orders", "total", "numeric(12,2)", "d", "", "", "p"},
		}, false},
		{"a column renamed", [][]string{
			{"public", "orders", "id", "integer", "d", "", "", "p"},
			{"public", "orders", "amount", "numeric(10,2)", "d", "", "", "p"},
		}, false},
		// This one moves no column at all, which is the entire point of carrying the replica
		// identity. Whether the QUERY notices a repoint that also moves no FLAG is a question only
		// a server can answer, and schema_docker_test.go asks it there.
		{"the replica identity changed", [][]string{
			{"public", "orders", "id", "integer", "f", "", "", "p"},
			{"public", "orders", "total", "numeric(10,2)", "f", "", "", "p"},
		}, false},
		// AND THIS ONE MOVES NO COLUMN AND NO REPLICA IDENTITY. 'u' → 'p' is ALTER TABLE ... SET
		// LOGGED: a table that logical decoding was not carrying at all starts being decoded, and
		// its changes replay onto rows the base copy restored empty, because pg_dump gives an
		// unlogged table its structure and none of its data.
		{"a table made LOGGED", [][]string{
			{"public", "orders", "id", "integer", "d", "", "", "u"},
			{"public", "orders", "total", "numeric(10,2)", "d", "", "", "u"},
		}, false},
		// The separator earns its place here: without one, a run of fields could be regrouped
		// into different columns and hash the same.
		{"the same text split differently", [][]string{
			{"public", "orders", "id", "integer", "d", "", "", "p"},
			{"public", "orders", "tot", "alnumeric(10,2)", "d", "", "", "p"},
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want, err := fingerprint(context.Background(), rows(base, nil))
			if err != nil {
				t.Fatalf("fingerprinting the reference schema failed: %v", err)
			}
			got, err := fingerprint(context.Background(), rows(tc.rows, nil))
			if err != nil {
				t.Fatalf("fingerprint: %v", err)
			}
			if !strings.HasPrefix(got, "sha256:") {
				t.Errorf("fingerprint %q does not say what it is", got)
			}
			if (got == want) != tc.same {
				t.Fatalf("fingerprint %s = %s, reference %s: want equal = %v", tc.name, got, want, tc.same)
			}
		})
	}
}

// THE MIGRATION, AND IT IS THE HALF OF THIS CHANGE THAT COSTS MONEY IF IT IS WRONG. Adding
// relpersistence to the query moves the digest of every schema there is, so an agent that reported
// one digest would report a different one the moment it was deployed, every chain would compare it
// against a base taken by the agent before it, conclude the schema had moved, and take a fresh base
// copy — the whole fleet, at once, for nothing.
//
// So the value carries ONE DIGEST PER ALGORITHM THIS AGENT CAN COMPUTE, and chain.SchemaMoved
// compares per algorithm. The property that makes it work is asserted here: the OLDER digest is a
// function of the older fields alone, so relpersistence moving leaves it exactly where it was, and a
// chain whose base predates this change goes on being compared with the algorithm it was taken
// under. It is one query and one pass over the rows — the newer algorithm reads fields the older one
// stops before, which is what every version of this query has been so far.
func TestTheFingerprintCarriesEveryAlgorithmItCanCompute(t *testing.T) {
	logged := [][]string{
		{"public", "orders", "id", "integer", "d", "", "", "p"},
		{"public", "orders", "total", "numeric(10,2)", "d", "", "", "p"},
	}
	unlogged := [][]string{
		{"public", "orders", "id", "integer", "d", "", "", "u"},
		{"public", "orders", "total", "numeric(10,2)", "d", "", "", "u"},
	}

	take := func(rowsIn [][]string) string {
		t.Helper()
		got, err := fingerprint(context.Background(), rows(rowsIn, nil))
		if err != nil {
			t.Fatalf("fingerprint: %v", err)
		}
		return got
	}

	before, after := take(logged), take(unlogged)

	// Every algorithm is named, so a reader on the far side of the wire can tell which digest is
	// which without knowing which agent wrote it.
	parts := strings.Fields(before)
	if len(parts) != len(fingerprintAlgorithms) {
		t.Fatalf("fingerprint %q carries %d digests, want one per algorithm (%d)",
			before, len(parts), len(fingerprintAlgorithms))
	}
	// The oldest algorithm is spelled exactly as it always was — no tag — because every fingerprint
	// already stored in a manifest is spelled that way, and a tag on it would move all of them.
	if !strings.HasPrefix(before, "sha256:") {
		t.Errorf("fingerprint %q does not begin with the untagged digest the agents before this one "+
			"wrote; every stored fingerprint would stop comparing", before)
	}
	if !strings.Contains(before, " v2:sha256:") {
		t.Errorf("fingerprint %q does not carry the v2 digest", before)
	}

	if before == after {
		t.Fatalf("SET LOGGED did not move the fingerprint (%s)", after)
	}
	// AND THE POINT OF THE WHOLE ARRANGEMENT. The v1 digest must be byte-identical across a change
	// only v2 can see — otherwise every pre-existing chain re-bases on the first cycle after deploy.
	if parts[0] != strings.Fields(after)[0] {
		t.Errorf("the v1 digest moved %s → %s when only relpersistence changed; a chain based by an "+
			"earlier agent would re-base on the first cycle after this one is deployed, and so would "+
			"every other chain in the fleet, simultaneously", parts[0], strings.Fields(after)[0])
	}
}

// A fingerprint that cannot be taken is an error, never an empty string. An empty H0 compared
// against an empty H1 is equal, so a silently failing fingerprint would make the DDL check pass
// every time — the check disappears exactly when the connection is unhealthy.
func TestAFingerprintThatCannotBeTakenIsAnError(t *testing.T) {
	refused := errors.New("57P01: terminating connection due to administrator command")

	got, err := fingerprint(context.Background(), rows(nil, refused))
	if err == nil {
		t.Fatal("a failed catalog query produced a fingerprint")
	}
	if !errors.Is(err, refused) {
		t.Errorf("the server's error did not survive: %v", err)
	}
	if got != "" {
		t.Errorf("a failed fingerprint still returned %q", got)
	}
}
