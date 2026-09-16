package schedule

// report.go is THE REPORTING SEAM: an interface, and one implementation that writes lines.
//
// IT IS NOT A TRANSPORT AND MUST NOT GROW INTO ONE HERE. What the control plane accepts is somebody
// else's ticket; an HTTP client invented in this file would be a wire format guessed against an
// endpoint nobody has agreed, and the agent would then have TWO ideas of what a cycle is worth
// reporting. So the seam is declared where it is consumed — the same rule run.go's Store follows —
// and the one implementation in this repo writes to an io.Writer.
//
// AD-021: THE AGENT BRINGS FACTS, NEVER VERDICTS. Every field below is something that happened or
// something that was measured. There is no Healthy, no Severity and no Degraded, and adding one
// would be this agent deciding on the customer's behalf what its own numbers mean — which is the
// control plane's job, with the customer's RPO in front of it. "The cycle failed" is a fact. "The
// backup is unhealthy" is a verdict, and it is not ours to pass.
//
// WHAT A FACT DELIBERATELY DOES NOT CARRY: a credential, a host, a connection string, a row. The
// error a failed cycle carries is the one the packages below produced, and those are written to name
// slots, positions and containers — never a secret (postgres/conn.go redacts the one password in
// this system on the value rather than on the struct holding it).

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/manukyanv07/parity-scanner/agent/internal/backup"
)

// Kind is which of the two operations produced a fact.
type Kind string

const (
	// KindBase is a chain's segment 0 — the full copy.
	KindBase Kind = "base"
	// KindChange is one change cycle laid on top of it.
	KindChange Kind = "change"
)

// State is what the chain IS after this cycle, which is the field anything downstream schedules on.
type State string

const (
	// Live: the chain may be extended, and the next cycle will extend it.
	Live State = "live"
	// ReBasing: this chain is over — a migration under it, or the slot it read through gone — and
	// the next cycle takes a new base copy. A marker is already in the store (rebase.go).
	ReBasing State = "rebasing"
	// Stopped: no further cycle will run in this process.
	Stopped State = "stopped"
)

// Reason names WHY, in a small closed vocabulary, so that something downstream can group these
// without parsing an error message. The message stays in Err, where it belongs.
type Reason string

const (
	ReasonNone        Reason = ""
	ReasonNoChanges   Reason = "no-changes"
	ReasonSchemaMoved Reason = "schema-moved"
	ReasonSlotGone    Reason = "slot-gone"
	ReasonCycleFailed Reason = "cycle-failed"
	ReasonBaseFailed  Reason = "base-failed"

	// ReasonReBaseLoop is chains ending one after another with nothing ever laid on one. It is
	// its own reason rather than a base-failed, because the base copies all WORKED: what failed
	// is the first cycle after each of them, and an operator sent to look at the vault would
	// find nothing wrong there.
	ReasonReBaseLoop Reason = "rebase-loop"

	// ReasonShutdown is the cycle that was in flight when the process was asked to stop. Not a
	// failure: it stored nothing, it confirmed nothing, and the chain stands where it did.
	ReasonShutdown Reason = "shutdown"
)

// Fact is what one cycle leaves behind. It is a value, so a reporter can hold it, queue it or
// render it without reaching back into anything that is still running.
type Fact struct {
	// At is when the cycle ended.
	At time.Time

	// Kind is base or change.
	Kind Kind

	// OK is whether this cycle did what it set out to do. A cycle that found nothing to copy is
	// OK: the database was quiet, which is not a failure and must not be reported as one.
	OK bool

	// Recoverable is the LAST POSITION A RESTORE CAN REACH on this chain — after a failed cycle
	// too, where it is the position the chain stood at before. It is the number an operator acts
	// on during an incident, and it is a fact about the chain rather than about this cycle.
	Recoverable backup.Position

	// Achieved is the RPO this install actually managed: the previous cycle's start to this
	// cycle's end. Zero on the first cycle of a process, where there is no pair to measure.
	//
	// MEASURED, NOT CONFIGURED, and the pair with Interval below is the point: the two being far
	// apart is the only thing that says a chain is quietly falling behind.
	Achieved time.Duration

	// Interval is what the clock was set to. It is here so that Achieved is never read alone: the
	// two side by side are the only thing that says whether a chain is keeping up.
	Interval time.Duration

	// Chain is what the chain is now.
	Chain State

	// Reason names the outcome in a closed vocabulary.
	Reason Reason

	// Err is what failed, in the words of whatever failed. Nil on a cycle that worked.
	Err error
}

// Reporter is where a cycle's facts go. ONE METHOD, and every cycle calls it exactly once.
//
// The context is the running cycle's, so an implementation that one day puts a fact on a network
// inherits the shutdown the rest of the agent already has. An implementation MUST NOT block for
// long: it is called on the loop's own goroutine, between two cycles, and a reporter that waits is
// an RPO that slips.
type Reporter interface {
	Report(ctx context.Context, f Fact)
}

// Log is the one implementation in this repo: one line per cycle, on an io.Writer.
//
// A LINE RATHER THAN JSON because the reader at 3am is a human with `docker logs`, and because the
// machine-readable copy is the job of whatever transport is built on this interface — which will
// serialise the Fact itself rather than parse this back.
type Log struct {
	// To is where lines go. Nil is a reporter that writes nowhere, which check() refuses to be
	// handed a nil Reporter to avoid — so this is checked too rather than dereferenced.
	To io.Writer
}

var _ Reporter = Log{}

// Report writes one fact. The context is not used: a write to an io.Writer has nothing to cancel.
func (l Log) Report(_ context.Context, f Fact) {
	if l.To == nil {
		return
	}
	line := fmt.Sprintf("backup %s: ok=%t chain=%s recoverable=%q achieved=%s interval=%s",
		f.Kind, f.OK, f.Chain, f.Recoverable, round(f.Achieved), f.Interval)
	if f.Reason != ReasonNone {
		line += " reason=" + string(f.Reason)
	}
	if f.Err != nil {
		// Last, and on the same line, because it is the longest field: the errors this repo
		// produces are sentences, and a reader scanning for the numbers should not have to read
		// past one to reach the next line.
		line += "\n  " + f.Err.Error()
	}
	fmt.Fprintln(l.To, line)
}

// round keeps the achieved interval readable without pretending to a precision the measurement
// does not have — it spans a network round trip and an object store.
func round(d time.Duration) time.Duration { return d.Round(time.Millisecond) }
