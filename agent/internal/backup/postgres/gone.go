package postgres

// gone.go answers ONE question, on every session this stream opens: is the slot we read through
// still there?
//
// THE BUG IT EXISTS TO PREVENT MAKES NO SOUND. Three things remove a logical replication slot and
// none of them tells anybody: an HA failover on PostgreSQL 16 or below, where the slot is simply
// not carried across because `failover` does not exist before 17 (AD-034); the provider removing
// it to keep WAL from filling the primary's disk; and our own safety brake dropping it for the
// same reason (C6). What the agent does next is the damage: it reconnects perfectly happily, gets
// a slot starting from a LATER position, and writes its next change file on the far side of a hole
// that nothing downstream can see. Every object hashes, every manifest parses, the ranges look
// contiguous, and the missing rows are found at a restore, if ever.
//
// WHY THE CHECK SITS AT SESSION OPEN AND NOT INSIDE A BATCH. Two measured facts pin it there:
//
//  1. A SLOT CANNOT BE DROPPED WHILE WE HOLD IT. `pg_drop_replication_slot` on the slot our stream
//     is reading comes back 55006 — `replication slot "vp_x" is active for PID n` — so the walsender
//     must die first, whatever kills the slot. Our session goes with it, every time. There is no
//     state in which a live batch is reading a slot that has already gone.
//  2. ONCE THE CONNECTION IS IN CopyBoth, NO ORDINARY STATEMENT RUNS ON IT. The catalog is
//     unreachable mid-stream on the very connection that would need to ask.
//
// Together those say the check belongs exactly where it is: before START_REPLICATION, on every
// open, which is every reconnect — and a reconnect is what losing the slot forces.
//
// CATALOG ONLY, SIMPLE QUERY PROTOCOL. pg_replication_slots is readable by a role with REPLICATION
// and access to no customer table whatsoever (AD-036), which is the only role this package holds,
// and pgConn.Exec is the only protocol a replication connection accepts. The slot name is
// interpolated because there are no bind parameters to bind it with; validateSlotName is what makes
// that safe, and checkSlot asks it first.

import (
	"context"
	"fmt"

	"github.com/manukyanv07/parity-scanner/agent/internal/backup"
)

// slotState is what the catalog says about THE ONE NAME THIS INSTALL WAS CONFIGURED WITH. Three
// answers, and the value of the type is that they cannot be collapsed into a bool: "not ours" and
// "gone" both mean "there is no slot of ours here", and acting on them alike is how a stranger's
// slot ends up being reported as our chain dying — and, through the brake that reads these
// sentinels, how it ends up being dropped.
type slotState int

const (
	// slotOurs is the healthy answer: a slot on our name is on the server. It is NOT a claim that
	// we created it — see isOurs, which cannot separate our slot from another Parity install's.
	slotOurs slotState = iota

	// slotOursGone is the name this install streams through having nothing behind it. The chain is
	// over.
	slotOursGone

	// slotNotOurs is a configured name this agent could never recognise as its own afterwards.
	// It is a misconfiguration and never a dead chain: refusing a name is cheap and reversible,
	// and calling somebody else's slot ours is neither.
	slotNotOurs
)

// classifySlot turns the name and what the catalog returned for it into one of those three.
//
// IT CHECKS THE ROW'S NAME AND NOT MERELY THAT A ROW CAME BACK. The query is filtered by our own
// name, so today that is the same thing — and it is the property, not the query, that has to hold:
// widen the query to list every slot, as anything reporting on the server would want to, and a
// count alone would read a customer's slot as ours being alive. That is this file's own failure
// wearing a green light, so the rule is stated where it cannot be edited away by accident.
func classifySlot(name string, rows [][]string) slotState {
	if !isOurs(name) {
		return slotNotOurs
	}
	for _, row := range rows {
		if len(row) > 0 && row[0] == name {
			return slotOurs
		}
	}
	return slotOursGone
}

// checkSlot asks the server and returns nil only when the chain may carry on.
//
// A CATALOG WE COULD NOT READ IS NOT AN ABSENT SLOT, and neither of the two tempting shortcuts is
// available: reading a failed query as "gone" retires a healthy chain on a dropped packet, and
// reading it as "present" extends one across a slot that really had gone. It is a third thing, and
// it comes back as an ordinary error that a caller retries.
func checkSlot(ctx context.Context, q querySQL, slot string) error {
	// Asked before the statement is built, because the name is interpolated into it — and asked at
	// all because a name outside our convention is a configuration fault whose answer is not a
	// re-base. validateSlotName says both reasons in full.
	if err := validateSlotName(slot); err != nil {
		return err
	}

	// Not an injection: slot is allow-listed to [a-z0-9_]{1,63} by validateSlotName above, and a
	// replication connection has no bind parameters to use instead (AD-036).
	const query = "SELECT slot_name FROM pg_replication_slots WHERE slot_name = '%s'"
	rows, err := q(ctx, fmt.Sprintf(query, slot))
	if err != nil {
		return fmt.Errorf("postgres: ask whether replication slot %q is still on the server: %w", slot, err)
	}

	switch classifySlot(slot, rows) {
	case slotOurs:
		return nil
	case slotNotOurs:
		// Unreachable while validateSlotName above is the same rule isOurs asks — and kept, because
		// the day those two drift the answer must not be "carry on". slot.go records what happened
		// the last time one name had two rules.
		return validateSlotName(slot)
	default:
		return fmt.Errorf("%w: %q is not on the server. It was removed by an HA failover below "+
			"PostgreSQL 17, by the provider protecting the primary's disk, or by our own brake; all "+
			"three are silent. The WAL it held is unreachable, so a new slot would resume LATER than "+
			"this chain ends and every file after it would sit beyond a hole. Take a new base copy",
			backup.ErrSlotGone, slot)
	}
}
