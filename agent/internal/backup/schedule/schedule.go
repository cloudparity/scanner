// Package schedule is THE RPO CLOCK — the one item on backup-shape.md §2's list of shared work
// that was never built.
//
// Everything under agent/internal/backup runs a cycle when it is called. Nothing called one. The
// interval was honoured INSIDE a run (postgres.Stream.Interval is how long one cycle collects) and
// no scheduler ever started one, so the only thing in this repo that drove the pipeline was a test
// harness. This package is what a shipping agent runs instead.
//
// IT KNOWS NOTHING ABOUT DATABASES, and that is §1 applied one level up: it starts cycles, it reads
// three sentinels that say what a failure MEANS to a chain, and it hands a fact to a Reporter. There
// is no pgx here, no blob client, and nothing that could tell a WAL segment from a disk snapshot.
// What varies is behind Chain; the clock and the routing are written once.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// WHAT AN OVERRUNNING CYCLE DOES: THE SCHEDULE SLIPS. IT NEVER STACKS.
// ─────────────────────────────────────────────────────────────────────────────────────────────
//
// Cycles run one at a time, in this goroutine, and the next one is timed from when the previous one
// STARTED. A cycle that runs longer than the interval therefore leaves waitFor returning zero and the
// next cycle begins immediately: there is no queue to grow, no goroutine per tick, and no second
// cycle against the same slot — which a time.Ticker would produce and which the stream would refuse
// anyway, because a replication session hands out one batch at a time.
//
// SKIPPING WOULD BE MEANINGLESS HERE, and that is why it is not the choice. A change cycle does not
// process a fixed unit of work that could be dropped; it drains whatever WAL has accumulated since
// the last confirmed position. Skipping one does not save the work, it moves the work into the next
// cycle and makes it bigger. So the schedule slips, and every Fact carries Achieved — the real
// interval this install managed, measured — beside the Interval it was configured with. An install
// that cannot keep up says so in a number rather than in a silence.
//
// AND FOR A CHANGE STREAM THE WAIT IS NORMALLY ZERO, which is worth knowing before reading the
// numbers rather than after. postgres.Stream is given this same Interval as its COLLECTION WINDOW:
// one cycle spends the interval gathering and then some further time storing and confirming, so it
// almost always ends after its own deadline and the next one starts at once. That is health, not
// lateness. What this clock guarantees is therefore a FLOOR — a cycle never starts sooner than an
// interval after the last one did, which is what paces a source whose collection is instant — and
// the ceiling is reported rather than enforced, because there is nothing useful to enforce it with:
// the work is already the minimum work.
//
// THERE IS DELIBERATELY NO "overran" FLAG. It would be true on almost every line of a real install,
// for the reason just given, and a field that is always set is a field nobody reads. Achieved beside
// Interval says the same thing with a number, and a number is what an RPO is measured in.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE THREE OUTCOMES THAT ARE NOT "TRY AGAIN"
// ─────────────────────────────────────────────────────────────────────────────────────────────
//
// A generic retry is the wrong answer to all of these, and each one is silent everywhere else:
//
//   - backup.ErrSchemaMoved — a migration landed under the chain. Retrying produces the identical
//     failure for as long as it takes the customer to deploy another one. The chain is over and the
//     next cycle takes a NEW BASE (rebase.go).
//   - backup.ErrSlotGone — the replication slot went. A retry reconnects onto a slot starting LATER
//     and writes the next file on the far side of a hole that hashes, parses and verifies. Dead
//     chain, new base (gone.go).
//   - a base copy that failed — the run STOPS. It does not re-base on the next tick. A base copy is
//     the most expensive operation in the product (AD-033 measured 9 + 2 minutes of vault time), so
//     a scheduler that retried one every interval is the runaway postgres/base.go's own attempt
//     bound exists to stop, rebuilt as an outer loop. It is reported as a fact and the run ends;
//     whatever supervises the agent restarts it, and the brake ticks before the stream on every
//     restart (postgres/brake.go).
//
// postgres.ErrSlotLeaked reaches here THROUGH that last rule and deliberately not as a case of its
// own: it is only ever returned by a base copy, this package cannot import the package that defines
// it without becoming Postgres-aware, and the outcome — stop loudly, do not pay for another backup —
// is the same one. The Fact carries the error, whose own text names the slot.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// AND RE-BASING IS BOUNDED, BECAUSE IT IS THE EXPENSIVE ANSWER
// ─────────────────────────────────────────────────────────────────────────────────────────────
//
// postgres/base.go bounds the retries INSIDE one base copy and says why: "a caller that read the
// sentinel here would start the nine-minute copy again from outside, which is maxBaseCopyAttempts
// turned into an outer loop and the runaway it exists to stop." This loop is that outside, so it
// carries the same bound.
//
// The failure it prevents is not exotic. A schema fingerprint that moves on its own — a database
// where anything creates temporary tables, say — makes every first cycle after a base report
// ErrSchemaMoved, and an unbounded scheduler would then spend eleven minutes of vault time per
// interval, forever, laying down not one change file. Every Fact would read chain=rebasing, which
// is a legitimate state, and nothing anywhere would say "this install has re-based four hundred
// times and never extended a chain".
//
// SO CONSECUTIVE RE-BASES ARE COUNTED, AND THE COUNT RESETS ON A CYCLE THAT EXTENDS THE CHAIN. A
// customer deploying a migration re-bases once, streams, and is never near the bound; a chain that
// cannot be established at all stops after maxReBases and says so, which is a fact to report and
// not a race to keep losing.
package schedule

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/manukyanv07/parity-scanner/agent/internal/backup"
)

// Chain is one backup chain being written, and the scheduler drives it without ever learning what
// it is a chain of. TWO METHODS, deliberately the same two backup.Source has.
type Chain interface {
	// Base starts a NEW chain and returns the position its first segment reaches. It is called
	// once at the start and again on every re-base, and an implementation that holds a resource
	// the old chain owned — a replication slot, a connection — releases it here.
	Base(ctx context.Context) (backup.Position, error)

	// Cycle extends the chain by one and returns how far it now restores.
	//
	// IT RETURNS THE POSITION EVEN WHEN IT FAILS, and that is the field an operator acts on: the
	// last recoverable point is a fact about the chain rather than about this cycle, and a failed
	// cycle that reported an empty one would read as total loss.
	//
	// It returns backup.ErrNoChanges when nothing happened, which is not a failure.
	Cycle(ctx context.Context) (backup.Position, error)
}

// Scheduler runs cycles on the RPO clock. The zero value is not usable.
type Scheduler struct {
	// Chain is what it drives.
	Chain Chain

	// Interval is the RPO clock. There is NO DEFAULT: an interval nobody chose is a recovery
	// objective nobody chose, and Run refuses one.
	Interval time.Duration

	// Report is handed a fact after EVERY cycle, including the one that found nothing and the one
	// that failed. Nil is refused rather than treated as "nobody is listening": a backup loop
	// whose outcome reaches nothing is one that cannot be told from a stopped one.
	Report Reporter

	// Now and After are the clock, injected so every timing decision this file makes is testable
	// with no clock and no server. Nil means time.Now and time.After.
	Now   func() time.Time
	After func(time.Duration) <-chan time.Time
}

// Run takes cycles until the context ends or the chain cannot be continued.
//
// IT RETURNS NIL ON A CANCELLED CONTEXT, because that is an ordinary shutdown rather than a fault.
// The cycle in flight is cancelled with it and reported as the failure it became; nothing here
// acknowledges a position, and nothing here can — advancing what the source believes is durable is
// the Chain's own last step, after its manifest is stored (see Cycle).
func (s *Scheduler) Run(ctx context.Context) error {
	if err := s.check(); err != nil {
		return err
	}
	now, after := s.clock()

	var (
		live     bool      // a base copy exists, so the chain may be extended
		last     time.Time // when the PREVIOUS cycle started — the near end of the achieved interval
		reBases  int       // consecutive re-bases with no cycle extending a chain in between
		stopping error     // set when this is the last cycle, and why
	)

	for {
		wait := waitFor(last, now(), s.Interval)
		// Checked before the wait as well as inside it, because an overrunning cycle waits for
		// nothing and would otherwise never look at the context again.
		if ctx.Err() != nil {
			return nil
		}
		if wait > 0 {
			select {
			case <-ctx.Done():
				return nil
			case <-after(wait):
			}
		}

		began := now()
		fact := Fact{Kind: KindChange, Interval: s.Interval}
		if !live {
			fact.Kind = KindBase
		}
		previous := last
		last = began

		var (
			reach backup.Position
			err   error
		)
		if live {
			reach, err = s.Chain.Cycle(ctx)
		} else {
			reach, err = s.Chain.Base(ctx)
		}

		fact.At = now()
		fact.Recoverable = reach
		fact.OK = err == nil
		fact.Err = err
		if !previous.IsZero() {
			// FROM THE PREVIOUS CYCLE'S START TO THIS ONE'S END, which is what the exposure
			// actually is: everything committed before the previous window opened became durable
			// when this cycle's manifest landed, so the worst moment to lose the source is the
			// instant before that. One collection window plus one store-and-confirm, measured.
			fact.Achieved = fact.At.Sub(previous)
		}

		switch {
		case fact.Kind == KindBase && err != nil:
			fact.Chain, fact.Reason = Stopped, ReasonBaseFailed
			stopping = fmt.Errorf("schedule: the base copy this chain has to start from failed, "+
				"and the run stops rather than paying for another one on the next tick: %w", err)
		case fact.Kind == KindBase:
			live, fact.Chain = true, Live
		default:
			switch fact.Reason = classify(err); fact.Reason {
			case ReasonNoChanges:
				// Not a failure and not something to carry an error for: the cycle ran, the
				// database was quiet, and the chain stands exactly where it did.
				fact.OK, fact.Err, fact.Chain = true, nil, Live
			case ReasonSchemaMoved, ReasonSlotGone:
				// THE TWO THAT ARE NOT A RETRY. Unrelated events with different remedies for the
				// customer, and the same fact to a chain: nothing more may be laid on this base.
				live, fact.Chain = false, ReBasing
				if reBases++; reBases >= maxReBases {
					fact.Chain, fact.Reason = Stopped, ReasonReBaseLoop
					stopping = fmt.Errorf("schedule: %d chains in a row ended before a single "+
						"cycle extended one, and each new base costs a full copy of the source; "+
						"this is a fact to report rather than something a further attempt fixes. "+
						"The last one ended because: %w", reBases, err)
				}
			default:
				fact.Chain = Live
			}
			// EXTENDED OR MERELY QUIET, EITHER WAY THIS CHAIN IS WORKING. The bound is on chains
			// that never carry anything, not on a customer who migrates often.
			if fact.OK {
				reBases = 0
			}
		}
		// A cancelled context is an ordinary shutdown, not a cycle that failed, and reporting it
		// as one teaches whoever reads these that the reason means nothing. Every rolling restart
		// would otherwise land a cycle-failed on the wire.
		if ctx.Err() != nil && !fact.OK {
			fact.Reason = ReasonShutdown
		}

		s.Report.Report(ctx, fact)

		if stopping != nil {
			if ctx.Err() != nil {
				return nil
			}
			return stopping
		}
	}
}

// maxReBases is how many chains may end in a row before the run stops. Three, the same bound and
// the same argument postgres/base.go's maxBaseCopyAttempts uses one level down: a schema still
// moving after three whole base copies is not a race worth losing again.
const maxReBases = 3

// waitFor is the whole of the clock's arithmetic: how long to wait before starting the next cycle,
// given when the previous one started. NO I/O, no clock of its own, and every case in the tests.
func waitFor(last, now time.Time, interval time.Duration) time.Duration {
	// The first cycle runs at once. Waiting an interval before the first backup is an interval of
	// the customer's data that nothing has ever copied.
	if last.IsZero() {
		return 0
	}
	wait := interval - now.Sub(last)
	if wait <= 0 {
		// IT OVERRAN. Go now rather than queue: see the header for why nothing is skipped.
		return 0
	}
	if wait > interval {
		// The clock stepped backwards — an NTP correction, a suspended container. Capped at the
		// interval so a clock that jumped an hour into the past cannot buy an hour of no backups.
		return interval
	}
	return wait
}

// classify says what one cycle's error means, which is a different question from whether the cycle
// worked. A pure function, so the routing is table-driven with no clock and no server — and so that
// the two cases that must never become a generic retry cannot quietly become one.
//
// THE REASON IS THE WHOLE ANSWER. There was briefly a second enum beside it saying what to do; it
// was derivable from this one in every case, and two taxonomies for one decision is how they come
// to disagree.
func classify(err error) Reason {
	switch {
	case err == nil:
		return ReasonNone
	case errors.Is(err, backup.ErrNoChanges):
		return ReasonNoChanges
	case errors.Is(err, backup.ErrSchemaMoved):
		return ReasonSchemaMoved
	case errors.Is(err, backup.ErrSlotGone):
		return ReasonSlotGone
	default:
		return ReasonCycleFailed
	}
}

func (s *Scheduler) clock() (func() time.Time, func(time.Duration) <-chan time.Time) {
	now, after := s.Now, s.After
	if now == nil {
		now = time.Now
	}
	if after == nil {
		after = time.After
	}
	return now, after
}

// check refuses a scheduler that could not do its job, before it opens anything.
func (s *Scheduler) check() error {
	switch {
	case s.Chain == nil:
		return errors.New("schedule: this scheduler has no chain, so there is nothing for it to " +
			"back up on the clock")
	case s.Interval <= 0:
		return errors.New("schedule: no interval is set, and there is no default: the interval IS " +
			"the recovery point objective, so a default here would be an RPO nobody chose")
	case s.Report == nil:
		return errors.New("schedule: this scheduler has no reporter, so every cycle's outcome " +
			"would reach nothing and a stopped loop would look exactly like a healthy one")
	}
	return nil
}
