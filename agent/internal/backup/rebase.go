package backup

// rebase.go is where A CHAIN IS DECLARED OVER — the two failures in this repo that announce
// themselves nowhere else, and the one object that records either of them.
//
// TWO CAUSES, ONE OUTCOME. The schema moving under a running stream (C5) and the replication slot
// going out from under it (C4) are unrelated events with different remedies for the customer, and
// they are the same fact to a chain: nothing more may be laid on this base. So they share this
// file, the marker, the prefix and the rule that no manifest is written, and differ only in
// contract.ReBaseReason. Two ways of saying "this chain is over" is how one of them gets missed,
// and both of them are already invisible everywhere else.
//
// LOGICAL DECODING DOES NOT CARRY DDL. A customer's routine ALTER TABLE reaches the change
// stream as nothing whatsoever — measured on 14 and 18, the transaction that ran it decodes as an
// empty BEGIN/COMMIT pair (postgres/rebase_docker_test.go). Every change captured after it names
// columns that are no longer the columns it means, and there is no error, no warning and no gap:
// the objects hash, the manifests parse, the ranges are contiguous and the chain reads as
// perfectly healthy until a restore months later fails or, worse, succeeds into the wrong shape.
//
// SO THE ONLY THING THAT CAN SEE IT IS A FINGERPRINT TAKEN BESIDE THE CHANGES AND COMPARED. That
// is B2's fingerprint, unchanged — the same catalog query, over the same replication connection,
// as the base copy takes at H0/H1 (postgres/schema.go). B2 compares two of them across the base
// copy's own window; C5 compares one against the chain's base on every cycle after it. One
// fingerprint, one sentinel, two windows: a second definition of "the schema moved" is exactly
// how the base and the stream come to disagree about whether it did.
//
// WHAT DETECTION DOES, AND IT IS NOT "LOG IT". The cycle stops: no manifest is written, so the
// chain is not extended, and a contract.ReBase goes into the prefix where that manifest would
// have gone. The caller gets a sentinel and takes a new base copy. Both halves are needed — the
// sentinel is for the agent that is running, the marker is for the one that was restarted and for
// the control plane, neither of which saw the error.
//
// AND THE SLOT, WHICH IS THE SAME SILENCE FROM THE OTHER END. An HA failover below PostgreSQL 17,
// the provider protecting its disk, or our own brake (C6) removes the slot, and an agent that
// simply reconnects gets a new one starting LATER — a hole in the middle of a chain that verifies.
// The slot cannot be dropped while our session holds it (measured: 55006, "replication slot is
// active for PID"), so it always goes together with our connection, and the check therefore sits
// where the session is opened: postgres/gone.go.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/manukyanv07/parity-scanner/chain"
	"github.com/manukyanv07/parity-scanner/contract"
)

// reBaseName is the object that says this chain stops here. It sits in the cycle's own prefix,
// beside where manifest.json would have gone, and the two are alternatives: one prefix holds a
// manifest or a re-base, never both.
const reBaseName = "rebase.json"

// ErrSchemaMoved is the schema having changed under a chain — in the base copy's own window
// (postgres.Base, steps 1/5/6) or between the base and a later cycle (Cycle.Run). ONE SENTINEL
// FOR BOTH, because a caller does the same thing on either: discard what was captured and take a
// new base copy. Two sentinels would mean a scheduler that handles one and retries the other
// forever.
//
// A sentinel rather than a message because it is the one error a scheduler must not treat as
// transient. Retrying a cycle whose schema moved produces the identical failure every time, for
// as long as it takes the customer to run another migration.
var ErrSchemaMoved = errors.New("backup: the schema moved under this chain")

// ErrSlotGone is the source's stream having lost the thing it reads through — for Postgres, the
// replication slot (postgres/gone.go). A SECOND SENTINEL BESIDE ErrSchemaMoved AND NOT A SECOND
// PATH: both end in the one marker below, in the one prefix, under the one rule that no manifest
// is written, and reBase is the only place either of them is recorded. What they do not share is
// contract.ReBaseReason, because the remedy differs — a migration is the customer's doing and a
// lost slot is WAL nobody can reach any more — and a reader who cannot tell them apart cannot act
// on either.
//
// IT IS NOT AN ERROR ABOUT A CONNECTION, and the distinction is the whole ticket. A stream whose
// connection dropped reconnects and carries on; a stream whose SLOT went reconnects onto a NEW
// slot at a LATER position, and every file after that sits beyond a hole in a chain that hashes,
// parses and verifies. So a caller that retries on this sentinel is building exactly the silent
// failure it exists to announce: the only answer to it is a new base copy.
var ErrSlotGone = errors.New("backup: the replication slot this chain streams through is gone")

// mark is the every-cycle check. It returns nil when the chain may be extended, and otherwise it
// has already written the marker that says it may not.
//
// IT RUNS AFTER THE BYTES ARE STORED, which costs one wasted upload on the cycle a migration
// lands in. That is the price of the fingerprint being the SOURCE's to take: it arrives on the
// batch, so it cannot be known before the batch is asked for, and the pipeline that stores it
// knows nothing about databases and must keep knowing nothing (backup-shape.md §1). The objects
// left behind are objects no manifest references, which is the same state every other failed
// cycle leaves and which prune.go sweeps as debris. The alternative — extending the chain
// and finding out at restore — is the failure this file exists for.
func (c *Cycle) mark(ctx context.Context, schema string, from Position, at time.Time, prefix string) error {
	// NOTHING TO COMPARE IS NOT PERMISSION TO CARRY ON. One end empty and the other not means
	// either this cycle was never told what its chain's base was taken against, or a source that
	// fingerprints stopped doing so. Both extend the chain blind, for as long as nobody notices,
	// and neither produces a single error anywhere else.
	//
	// AND IT IS NOT A RE-BASE, which is the tempting answer and the wrong one. A new base copy
	// would take a fresh fingerprint and put the two ends back in step — with the field still
	// unset at whichever end was empty, so the very next cycle would compare nothing again and
	// keep on comparing nothing for the life of the install. That is this ticket's own failure
	// dressed as its remedy. It is a misconfiguration; it fails loudly and identically until
	// somebody fixes it.
	if (c.BaseSchema == "") != (schema == "") {
		return fmt.Errorf("backup: this chain's base was captured against schema %q and this cycle "+
			"against %q, so nothing can say whether the schema moved; a chain extended without that "+
			"comparison carries a DDL change nobody will see until a restore fails",
			c.BaseSchema, schema)
	}
	if !chain.SchemaMoved(c.BaseSchema, schema) {
		return nil
	}

	moved := fmt.Errorf("%w: its base was captured against %s and this cycle against %s. Logical "+
		"decoding does not carry DDL, so the changes in this batch describe columns that are no "+
		"longer the ones they name. Take a new base copy; this chain restores to %s and no further",
		ErrSchemaMoved, c.BaseSchema, schema, from)

	detail := fmt.Sprintf("the chain's base was captured against schema %s and this cycle against %s",
		c.BaseSchema, schema)
	return errors.Join(moved, c.reBase(ctx, contract.ReBaseSchemaChanged, from, at, prefix, detail))
}

// stopped is the OTHER trigger, and it is a filter over a failed cycle rather than a check of its
// own: the source is what discovers its stream is gone, and it says so with a sentinel on the way
// out (postgres/gone.go). Everything else is returned exactly as it came.
//
// THE DEFAULT IS "RETRY", AND IT HAS TO BE. A re-base marker is permanent — the next base copy
// writes under a new prefix and nothing ever clears this one — so a marker written on a dropped
// packet retires a chain that needed nothing but another cycle. Only a cause that says the chain
// itself is over ends one, which is why the switch below enumerates them rather than guessing from
// the shape of a failure.
func (c *Cycle) stopped(ctx context.Context, cause error, from Position, at time.Time, prefix string) error {
	if !errors.Is(cause, ErrSlotGone) {
		return cause
	}
	// The source's own words, which name the slot. That is what the operator woken at 3am needs and
	// the one thing this layer could not produce: this package knows nothing about databases.
	return errors.Join(cause, c.reBase(ctx, contract.ReBaseSlotLost, from, at, prefix, cause.Error()))
}

// reBase writes the marker, and it is THE ONLY PLACE ONE IS WRITTEN. Whatever killed the chain — a
// migration under it, a slot out from under it — the object, the prefix and the meaning are the
// same, so a reader that understands one understands all of them. A second writer would be a
// second way of saying the chain is over, and the way one of them gets missed.
//
// It returns nil when the marker landed and an error only when it did not. Its callers join that
// to the sentinel rather than ranking the two: the chain is dead either way and the caller must
// still act, but nothing durable records it, so the next agent to start will not know.
func (c *Cycle) reBase(ctx context.Context, reason contract.ReBaseReason, from Position, at time.Time, prefix, detail string) error {
	var missing error
	if from == "" {
		// audit is what normally refuses a cycle with no range, and on the schema path it runs
		// AFTER this — it has to, or a manifest could be written over a batch whose schema had
		// moved. So the one guarantee audit would have given is made here instead: a marker whose
		// Recoverable is empty says the chain is dead and nothing about how far it still restores,
		// which contract.ReBase records as reading like total loss.
		missing = errors.New("backup: this cycle was given no position to resume from, so the " +
			"marker cannot say how far the chain still restores")
	}

	body, err := json.MarshalIndent(contract.ReBase{
		ContractVersion: contract.BackupContractVersion,
		At:              at.Format(time.RFC3339),
		Reason:          reason,
		// THE POSITION THE PREVIOUS CYCLE REACHED, NOT THIS ONE'S, and it is the field anybody
		// acts on. This cycle produced nothing that is being kept — its changes were captured
		// against a schema that had moved, or never captured at all because the slot was gone — so
		// claiming the chain reaches them would be claiming a recovery point no stored file backs.
		Recoverable: string(from),
		Detail:      detail,
	}, "", "  ")
	if err != nil {
		return errors.Join(missing, fmt.Errorf("backup: render the re-base marker for %s: %w", prefix, err))
	}
	return errors.Join(missing, c.put(ctx, prefix+"/"+reBaseName, body))
}
