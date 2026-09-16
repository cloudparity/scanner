// Package report puts one backup cycle on the wire. It is the second schedule.Reporter, and the
// one the control plane hears from.
//
// WHY IT IS NOT IN schedule/. That package's report.go declares the seam and says in as many words
// that it is not a transport and must not grow into one: a scheduler that knew about HTTP would be
// a clock with an opinion about endpoints. So the interface is declared where it is CONSUMED and the
// implementations live where they belong — schedule.Log writes lines, this writes to the API.
//
// WHY IT IS NOT IN upload/ EITHER. That package is stdlib plus contract, deliberately, because it is
// the one place in the agent that talks to Parity and a customer's security team has to be able to
// read it. Importing the scheduler into it to satisfy an interface would put the whole backup tree in
// that dependency graph for the sake of one method signature.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// A SEND FAILURE CANNOT FAIL A BACKUP, AND IT IS STRUCTURE RATHER THAN CARE
// ─────────────────────────────────────────────────────────────────────────────────────────────
//
// upload.SendCycle argues why a lost report costs nothing; this is why it cannot cost anything even
// by accident. Three properties, none of which anybody has to remember to keep:
//
//   - Report RETURNS NOTHING. There is no error to propagate, so there is no path on which a
//     refused report becomes a failed cycle. That is the seam's shape, not this file's discipline.
//   - IT RUNS AFTER THE CYCLE HAS FINISHED. The scheduler calls it once the chain has returned, and
//     the chain acknowledges its LSN inside Cycle, after the manifest is stored. So the
//     acknowledgement is already made and already durable before anything here opens a socket.
//   - IT BOUNDS ITSELF. Report is called on the cycle loop's own goroutine, between two cycles, so
//     an API that never answers must not become an RPO that slips — see Timeout.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// AD-021: THE ONE FIELD THAT WAS ARGUED
// ─────────────────────────────────────────────────────────────────────────────────────────────
//
// Fact carries nine fields and the envelope takes four. The interesting omission is Fact.Achieved,
// because it is the one that looks like it belongs: it is MEASURED rather than configured, which is
// the case for sending it.
//
// Against, and it wins: it is one subtraction from "this install is behind its RPO", which is a
// verdict; the engine cannot CHECK it, because it is arithmetic on the agent's own clock, and
// CycleReport.At exists precisely so staleness is measured against the engine's; and the engine
// already derives the same interval from two consecutive At values it holds anyway. So Achieved
// stays on the log line, where the human who wanted it is. Interval stays off for the mirror
// reason: it is the customer's own configured RPO, and its only use here would be to be compared
// against Achieved. TestNoVerdictLeavesThisReporter is that decision, executable.
//
// Kind, Chain and Reason are left off because the envelope already says all three: a manifest names
// its own Kind, a re-base IS the chain state and carries why it ended, and a failure is a failure.
package report

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/manukyanv07/parity-scanner/agent/internal/backup"
	"github.com/manukyanv07/parity-scanner/agent/internal/backup/schedule"
	"github.com/manukyanv07/parity-scanner/contract"
)

// DefaultTimeout bounds one send. THIRTY SECONDS AND NOT upload.Client's OWN TWO MINUTES: that
// timeout is sized for a multi-megabyte estate over a customer's metered egress, and a cycle report
// is a few kilobytes. Two minutes of a five-minute interval spent waiting on an endpoint that does
// not exist yet is 40% of the RPO clock given to a dashboard row.
//
// Exported so a caller with a SHORTER interval than this can clamp it — see Timeout.
const DefaultTimeout = 30 * time.Second

// Sender is the one thing this package needs from a transport: *upload.Client satisfies it, and it
// is the only implementation that ships. It is an interface so that the property this package
// exists to guarantee — a refusal costs the cycle nothing — can be tested against a transport that
// refuses on demand, which is the same reason every other seam in this tree is one.
//
// A caller assigning a TYPED NIL to this field gets an interface that is not nil and a
// dereference mid-cycle. agent/cmd/scanner/backup.go assigns through a nil check for that reason.
type Sender interface {
	SendCycle(ctx context.Context, r *contract.CycleReport) error
}

// Send reports each cycle to the control plane and passes the fact on.
//
// The zero value sends nothing and reports nothing, which is a legitimate configuration: an install
// with no API url runs the backup and writes its lines.
type Send struct {
	// To is where reports go. Nil is the control plane switched off — the ordinary case for an
	// install that was given no API url — and it is not an error.
	To Sender

	// Chain is the stable root this source's cycles write under (backup.Cycle.Scope). It is what
	// makes consecutive reports the same chain, and a re-base carries no identity of its own.
	Chain string

	// Account is the isolation boundary, spelled as contract.Resource.Account is. It is what joins
	// these reports to the scan of the same estate.
	Account string

	// Manifest is what the cycle that just ended stored, or nil if it stored nothing.
	//
	// IT IS A FUNCTION BECAUSE A Fact CANNOT CARRY ONE. schedule.Reporter takes a value the
	// scheduler assembles, and the scheduler never sees a manifest — it drives a Chain that knows
	// nothing about databases and returns a Position. Only the chain itself holds what it wrote.
	//
	// IT MUST BE CLEARED AT THE START OF EVERY CYCLE by whoever implements it, and that is the one
	// obligation of this field: a supplier that kept the last manifest would hand it to the next
	// quiet cycle, and this reporter would post a report claiming a backup that did not happen.
	Manifest func() *contract.Manifest

	// Also is handed the same fact — in practice schedule.Log — and it is handed it FIRST, so the
	// line a human reads at 3am is written whether or not the network is. Nil is allowed.
	Also schedule.Reporter

	// Timeout bounds one send. Zero means DefaultTimeout.
	//
	// A CALLER WITH A SHORTER INTERVAL MUST CLAMP IT. The scheduler times the next cycle from the
	// previous one's START, so a send that waits longer than the interval is an RPO that slips by
	// exactly the excess — which is the one thing this field exists to prevent.
	Timeout time.Duration

	// Errs is where a lost report is named. Nil means a send failure goes nowhere, which is why the
	// wiring always sets it.
	//
	// NOT DEDUPLICATED, unlike the brake's alarm, and the difference is real: the brake repeats one
	// assessment of one unchanged reading every tick, while each line here is a DIFFERENT report
	// that was lost. Collapsing them would hide how many.
	Errs io.Writer
}

var _ schedule.Reporter = Send{}

// Report writes the line, builds the envelope, and posts it.
func (s Send) Report(ctx context.Context, f schedule.Fact) {
	if s.Also != nil {
		s.Also.Report(ctx, f)
	}
	if s.To == nil {
		return
	}
	r, ok := s.build(f)
	if !ok {
		return
	}

	// THE CYCLE'S OWN CONTEXT, narrowed and never replaced. A shutdown cancels this send along with
	// everything else, which is deliberate: the slot drop is what runs on a context that outlives a
	// cancellation, because a leaked slot holds a customer's WAL and a lost report costs a row.
	// Waiting out a timeout on the way to exiting would delay the drop that actually matters.
	sendCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()

	err := s.To.SendCycle(sendCtx, r)
	// A SHUTDOWN IS NOT A LOST REPORT WORTH A LINE. The context above is the cycle's own, so a
	// SIGTERM cancels the send in flight — by design, since delaying the slot drop for a dashboard
	// row is the wrong trade. Saying so on every rolling restart would make this the alarm people
	// learn to skip, which is the brake's own argument about a warning that always fires.
	if err != nil && s.Errs != nil && ctx.Err() == nil {
		// The write's own error is dropped: Errs is a log, and a log that cannot be written is
		// not a second thing to report to itself.
		_, _ = fmt.Fprintf(s.Errs, "backup: this cycle was not reported to the control plane, and the "+
			"backup itself is unaffected — the objects and the manifest are in the store: %v\n", err)
	}
}

// build turns one fact into one envelope, and says whether there is anything to send at all.
//
// THE ORDER OF THE CASES IS THE MEANING. Each one is the reason the one below it does not apply.
func (s Send) build(f schedule.Fact) (*contract.CycleReport, bool) {
	// AN ORDINARY STOP IS NOT A CYCLE. schedule.go marks the cycle that was in flight at shutdown
	// precisely so it is not read as a failure — it stored nothing, it confirmed nothing, and the
	// chain stands where it did. A cycle-failed on the wire for every rolling restart would teach
	// whoever reads these that the failures mean nothing.
	if f.Reason == schedule.ReasonShutdown {
		return nil, false
	}

	r := &contract.CycleReport{
		ContractVersion: contract.BackupContractVersion,
		Chain:           s.Chain,
		Account:         s.Account,
		At:              f.At.UTC().Format(time.RFC3339),
		// Slot stays nil, and nil is the honest value in this build. The brake measures all three
		// numbers every tick and they die on its goroutine: Alert is handed a Decision rather than
		// the Reading it came from, and it is only called for a verdict above Fine, so a healthy
		// install would produce no reading at all. Absent is "not measured"; three zeroes would
		// read as a full disk holding nothing, which is a fact the agent never observed.
		Slot: nil,
	}

	// A BASE COPY THAT FAILED IS A FAILURE AND NEVER A RE-BASE, even when it failed on a moved
	// schema, and the guard says it once rather than a duplicated arm saying it twice. Cycle.Base
	// writes no re-base marker on any path — only Cycle.Run does, through mark and stopped — so
	// there is no ended chain to report. The meanings differ where it counts: a re-base says a new
	// base copy is owed, and here the news is that the last one could not be taken and the run is
	// stopping.
	var ended contract.ReBaseReason
	if f.Kind != schedule.KindBase {
		ended = reBaseReason(f.Err)
	}

	switch {
	case ended != "":
		// THE CHAIN IS OVER. Keyed on the sentinel rather than on schedule.Reason because the
		// sentinel is what backup.Cycle itself branched on when it wrote the marker, so the wire
		// says "re-base" exactly when one was meant. It also survives the scheduler overwriting the
		// reason with rebase-loop on the last of a run of them, where the cause lives only in the
		// error.
		//
		// THE MARKER IS NORMALLY IN THE STORE AND THIS DOES NOT ASSUME IT. Cycle.reBase joins a
		// failed put into the same error, so the sentinel survives a marker that never landed —
		// in which case this report is the only record that the chain ended, which is an argument
		// for sending it rather than against.
		r.ReBase = &contract.ReBase{
			ContractVersion: contract.BackupContractVersion,
			At:              r.At,
			Reason:          ended,
			// The last position this chain can still be restored to. A chain that is dead and a
			// chain that is dead as of an hour ago are different incidents, and this is the field
			// anybody acts on.
			Recoverable: string(f.Recoverable),
			Detail:      f.Err.Error(),
		}

	case f.Err != nil:
		// THE ONE CycleFailure EXISTS FOR. A cycle that errors and stores nothing writes neither a
		// manifest nor a marker, so without this a backup failing every hour for a week is
		// indistinguishable from one that was never scheduled.
		r.Failure = &contract.CycleFailure{Detail: f.Err.Error()}

	default:
		// It worked. Either it stored something, or the database was quiet.
		if s.Manifest != nil {
			r.Manifest = s.Manifest()
		}
		if r.Manifest == nil {
			// A QUIET CYCLE HAS NOTHING THE ENVELOPE CAN CARRY, and this is a known gap rather
			// than a decision anybody is happy with. The database was quiet, so no manifest was
			// written; it did not fail, so a CycleFailure would be a lie; the chain did not end,
			// so a ReBase would be a worse one. All three nil is the one shape the contract says a
			// cycle cannot mean, so nothing is sent — which means a chain that is alive and quiet
			// for a week reports nothing for a week, and looks from the engine exactly like an
			// agent that stopped. That is the mirror of the failure CycleFailure was added to
			// close, and closing it needs a fourth outcome on the envelope, agreed with the ingest
			// half in parity-lambdas. It is not something this producer may invent on its own.
			return nil, false
		}
	}
	return r, true
}

// reBaseReason is the cause in the contract's vocabulary, or empty when this error did not end a
// chain. The two sentinels are the only errors that do, and a caller does something different for
// each: a migration is the customer's doing, and a lost slot is WAL nobody can reach any more.
func reBaseReason(err error) contract.ReBaseReason {
	switch {
	case errors.Is(err, backup.ErrSchemaMoved):
		return contract.ReBaseSchemaChanged
	case errors.Is(err, backup.ErrSlotGone):
		return contract.ReBaseSlotLost
	default:
		return ""
	}
}

func (s Send) timeout() time.Duration {
	if s.Timeout <= 0 {
		return DefaultTimeout
	}
	return s.Timeout
}
