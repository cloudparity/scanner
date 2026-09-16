package postgres

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/manukyanv07/parity-scanner/agent/internal/backup"
)

// THE CLAIM THIS FILE TESTS: the agent can tell "our slot is gone" from "a slot that is not ours
// is there" and from "our slot is fine", and it gets the first one WRONG in only one direction —
// loudly.
//
// The failure it is aimed at is silent in every layer below it. A slot that has gone takes the
// chain with it, and nothing says so: the manifests already written still parse, the objects still
// hash, and a stream that simply reconnected onto a new slot would lay its next file on top of a
// hole nobody will find until a restore.

// THE FOUR ANSWERS, and the third is the one that costs somebody else's replication if it is
// wrong. The query behind this is filtered by our own name, so the row's name is checked as well
// as its presence: a future edit that widened the query to list every slot would otherwise report
// a customer's slot as ours being alive, which is this ticket's own failure wearing a green light.
func TestWhatTheCatalogSaysAboutOurSlot(t *testing.T) {
	for _, tc := range []struct {
		name string
		slot string
		rows [][]string
		want slotState
	}{
		{"ours, and on the server", "vp_stream", [][]string{{"vp_stream"}}, slotOurs},
		{"ours, and no longer on the server", "vp_stream", nil, slotOursGone},
		{"a name outside our convention", "customer_stream", [][]string{{"customer_stream"}}, slotNotOurs},
		{"a name outside our convention, absent too", "customer_stream", nil, slotNotOurs},
		{"no slots on the server at all", "vp_stream", [][]string{}, slotOursGone},
		// The whole point of checking the row and not merely counting it.
		{"somebody else's slot is there and ours is not", "vp_stream", [][]string{{"other_slot"}}, slotOursGone},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifySlot(tc.slot, tc.rows); got != tc.want {
				t.Errorf("classifySlot(%q, %v) = %v, want %v", tc.slot, tc.rows, got, tc.want)
			}
		})
	}
}

// checkSlot is what a session open actually calls, and the sentinel is the whole of its value: a
// caller that cannot branch on it treats a dead chain as an ordinary failure and retries it.
func TestOurSlotHavingGoneReachesTheCallerAsASentinel(t *testing.T) {
	q := func(context.Context, string) ([][]string, error) { return nil, nil }

	err := checkSlot(context.Background(), q, "vp_stream")
	if err == nil {
		t.Fatal("a slot that is no longer on the server was reported healthy; the chain would be " +
			"extended across a hole")
	}
	if !errors.Is(err, backup.ErrSlotGone) {
		t.Errorf("error %v does not carry backup.ErrSlotGone, so nothing scheduling cycles can "+
			"tell a dead chain from a blip", err)
	}
	if !strings.Contains(err.Error(), "vp_stream") {
		t.Errorf("error %v does not name the slot", err)
	}
}

// A NAME THAT IS NOT OURS IS NEVER CALLED GONE, and the two must not be confused in either
// direction: a stranger's slot reported as our dead chain sends an operator to re-base for nothing,
// and — through the brake this sentinel feeds (C6) — toward dropping a slot that was never ours.
func TestASlotNameOutsideOurConventionIsNotOurChainDying(t *testing.T) {
	q := func(context.Context, string) ([][]string, error) { return nil, nil }

	err := checkSlot(context.Background(), q, "customer_stream")
	if err == nil {
		t.Fatal("a name this agent could never recognise as its own was accepted")
	}
	if errors.Is(err, backup.ErrSlotGone) {
		t.Errorf("a slot outside our convention was reported as our chain dying: %v", err)
	}
}

// The healthy answer, asserted so that the checks above are not satisfied by a function that
// refuses everything.
func TestOurSlotBeingThereLetsTheCycleCarryOn(t *testing.T) {
	q := func(_ context.Context, sql string) ([][]string, error) {
		if !strings.Contains(sql, "pg_replication_slots") {
			t.Errorf("the check read %q; only the catalog is readable over a replication "+
				"connection, and a customer table is refused to the role that holds it", sql)
		}
		return [][]string{{"vp_stream"}}, nil
	}
	if err := checkSlot(context.Background(), q, "vp_stream"); err != nil {
		t.Fatalf("a live slot of ours was reported gone: %v", err)
	}
}

// A CATALOG WE COULD NOT READ IS NOT AN ABSENT SLOT. Treating a failed query as "gone" would end a
// perfectly healthy chain on a dropped packet; treating it as "present" would extend one across a
// slot that really had gone. It is neither, and it says so.
func TestACatalogThatCannotBeReadIsNotAnAnswer(t *testing.T) {
	refused := errors.New("57P01 terminating connection due to administrator command")
	q := func(context.Context, string) ([][]string, error) { return nil, refused }

	err := checkSlot(context.Background(), q, "vp_stream")
	if err == nil {
		t.Fatal("a catalog query that failed was read as a healthy slot")
	}
	if errors.Is(err, backup.ErrSlotGone) {
		t.Errorf("a catalog we could not read was reported as the slot having gone, which ends a "+
			"chain that may be perfectly alive: %v", err)
	}
	if !errors.Is(err, refused) {
		t.Errorf("error %v loses what the server actually said", err)
	}
}
