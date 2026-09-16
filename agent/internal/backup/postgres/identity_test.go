package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// The classification, one table at a time, from the four catalog answers there are.
//
// This is the whole of the judgement the screen makes, and it is judged here rather than only
// against a server because the two rows that matter most — the table with nothing to identify a
// row by, and the one with REPLICA IDENTITY FULL — are the two a reader is most likely to think
// are the same case. They are not: one breaks the customer's own writes and one does not, and
// neither can be replayed.
func TestWhichTablesCannotBeReplayed(t *testing.T) {
	for _, tc := range []struct {
		name      string
		row       []string // nspname, relname, relreplident, has primary key, has replica index
		wantWhy   string
		replaying bool // true when the table is fine and must NOT be reported
	}{
		{
			name:      "a primary key is an identity",
			row:       []string{"sales", "customers", "d", "true", "false"},
			replaying: true,
		},
		{
			name:      "a composite primary key is an identity",
			row:       []string{"ops", "daily_totals", "d", "true", "false"},
			replaying: true,
		},
		{
			name:      "a unique index named as the replica identity is an identity",
			row:       []string{"ops", "sessions", "i", "false", "true"},
			replaying: true,
		},
		{
			// THE TICKET'S HARD CASE, and the reason it is reported at BACKUP time: measured on
			// live Azure, putting this table in the publication is what breaks the customer's own
			// UPDATE and DELETE, with SQLSTATE 55000 naming our publication (AD-039).
			name:    "no primary key and the default replica identity",
			row:     []string{"ops", "clicks", "d", "false", "false"},
			wantWhy: "no primary key",
		},
		{
			name:    "replica identity nothing",
			row:     []string{"ops", "clicks", "n", "false", "false"},
			wantWhy: "REPLICA IDENTITY NOTHING",
		},
		{
			// The distinction that costs a whole afternoon if it is not written down. FULL fixes
			// the customer's writes and decodes fine — AD-039 measured both — and it still does
			// not give a replay an identity, because a whole row is not unique. Two identical
			// rows cannot be told apart, so one update would touch both or neither.
			name:    "replica identity full with nothing unique under it",
			row:     []string{"ops", "readings", "f", "false", "false"},
			wantWhy: "REPLICA IDENTITY FULL",
		},
		{
			// AND FULL OVER A PRIMARY KEY IS REPORTED TOO, which is the opposite of what this
			// case asserted until the stream was measured against a real server. The old
			// reasoning — "FULL sends the whole old row, so a table with a primary key sends that
			// key inside it and replays as it would without FULL" — is true of the TUPLE and
			// false of what a change file can express: under FULL, pgoutput's relation message
			// flags EVERY column as replica identity and names no index, so nothing on the wire
			// says which subset is unique and the record is refused at capture (change.go).
			//
			// Reporting it is a warning a customer can act on in one line, on a table that
			// already has the key to point back at. Not reporting it was a table that passed the
			// screen and then stopped the stream.
			name:    "replica identity full over a primary key still says nothing unique on the wire",
			row:     []string{"ops", "readings", "f", "true", "false"},
			wantWhy: "REPLICA IDENTITY FULL",
		},
		{
			// relreplident stays 'i' after the index it named is dropped, and the table then
			// behaves as NOTHING. The setting alone is not the answer; the index has to be there.
			name:    "a replica identity index that is no longer there",
			row:     []string{"ops", "sessions", "i", "false", "false"},
			wantWhy: "no longer there",
		},
		{
			// A primary key that is ALSO the replica identity, which is what an explicit
			// ALTER TABLE ... USING INDEX on the primary key leaves behind.
			name:      "a primary key named explicitly as the replica identity",
			row:       []string{"sales", "customers", "i", "true", "true"},
			replaying: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			found, err := screen(context.Background(), rows([][]string{tc.row}, nil))
			if err != nil {
				t.Fatalf("screen: %v", err)
			}
			if tc.replaying {
				if len(found) != 0 {
					t.Fatalf("%s.%s was reported unreplayable: %v", tc.row[0], tc.row[1], found)
				}
				return
			}
			if len(found) != 1 {
				t.Fatalf("%s.%s was not reported, so a customer would find out at restore",
					tc.row[0], tc.row[1])
			}
			if found[0].Schema != tc.row[0] || found[0].Table != tc.row[1] {
				t.Errorf("reported %s.%s, want %s.%s", found[0].Schema, found[0].Table, tc.row[0], tc.row[1])
			}
			if !strings.Contains(found[0].Why, tc.wantWhy) {
				t.Errorf("why = %q, want it to contain %q", found[0].Why, tc.wantWhy)
			}
		})
	}
}

// A catalog answer this does not understand is an error, NOT a table quietly declared fine. A
// screen that fails open is a screen that reports nothing on the day it breaks, which is exactly
// the day the customer needed it.
func TestAnUnreadableCatalogAnswerIsRefused(t *testing.T) {
	for _, row := range [][]string{
		{"s", "t", "z", "false", "false"}, // a replica identity setting nobody defined
		{"s", "t", "d", "yes", "false"},   // a boolean that is not one
		{"s", "t", "d"},                   // a row of the wrong width
	} {
		if _, err := screen(context.Background(), rows([][]string{row}, nil)); err == nil {
			t.Errorf("the catalog answer %v was accepted", row)
		}
	}
	if _, err := screen(context.Background(), rows(nil, errors.New("the connection went away"))); err == nil {
		t.Error("a catalog query that failed reported an empty screen, which reads as a clean one")
	}
}

// The text is the deliverable, not the slice: this is what the customer sees. It must name every
// table, say what will happen, and say what to do about it — a warning that only says "some tables
// cannot be replayed" is one nobody can act on.
func TestTheWarningNamesTheTablesAndTheFix(t *testing.T) {
	if got := Warning(nil); got != "" {
		t.Errorf("Warning(nothing) = %q, want the empty string so a clean screen prints nothing", got)
	}

	got := Warning([]Unreplayable{
		{Schema: "ops", Table: "clicks", Why: "it has no primary key and the default replica identity"},
		{Schema: "ops", Table: "readings", Why: "REPLICA IDENTITY FULL is not unique"},
	})
	for _, want := range []string{
		"ops.clicks",
		"ops.readings",
		"ALTER TABLE",        // the fix, spelled
		"cannot be replayed", // what it costs
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the warning does not mention %q:\n%s", want, got)
		}
	}
}
