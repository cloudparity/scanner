package schedule

// Every test here runs with NO CLOCK AND NO SERVER. Time is injected, the chain is a fake, and the
// two decisions this package makes — how long to wait, and what an error means to a chain — are
// pure functions with their cases in a table.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/manukyanv07/parity-scanner/agent/internal/backup"
	"github.com/manukyanv07/parity-scanner/agent/internal/backup/postgres"
)

const interval = 5 * time.Minute

var epoch = time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

// ─────────────────────────────────────────────────────────────────────────────────────────────
// The clock.
// ─────────────────────────────────────────────────────────────────────────────────────────────

func TestWaitFor(t *testing.T) {
	for _, tc := range []struct {
		name string
		last time.Time
		now  time.Time
		want time.Duration
	}{
		{
			// Waiting an interval before the first backup is an interval of the customer's data
			// that nothing has ever copied.
			name: "the first cycle runs at once",
			last: time.Time{},
			now:  epoch,
			want: 0,
		},
		{
			name: "a cycle that took a fifth of the interval waits out the rest",
			last: epoch,
			now:  epoch.Add(time.Minute),
			want: 4 * time.Minute,
		},
		{
			// THE CASE THE HEADER IS ABOUT: no queue, no stacking, and no second cycle against
			// the same slot. The schedule slips and the Fact says so.
			name: "a cycle that overran starts the next one immediately",
			last: epoch,
			now:  epoch.Add(7 * time.Minute),
			want: 0,
		},
		{
			name: "a cycle that landed exactly on the interval starts the next one immediately",
			last: epoch,
			now:  epoch.Add(interval),
			want: 0,
		},
		{
			// An NTP correction or a suspended container. Capped, so a clock that jumped an hour
			// backwards cannot buy an hour of no backups.
			name: "a clock that stepped backwards waits at most one interval",
			last: epoch,
			now:  epoch.Add(-time.Hour),
			want: interval,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := waitFor(tc.last, tc.now, interval); got != tc.want {
				t.Fatalf("waitFor(%v, %v, %v) = %v, want %v", tc.last, tc.now, interval, got, tc.want)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// The routing. Three outcomes that must never become a generic retry.
// ─────────────────────────────────────────────────────────────────────────────────────────────

func TestClassify(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want Reason
	}{
		{name: "a cycle that worked extends the chain", err: nil, want: ReasonNone},
		{
			name: "a quiet database is not a failure",
			err:  fmt.Errorf("asking the source: %w", backup.ErrNoChanges),
			want: ReasonNoChanges,
		},
		{
			// Retrying produces the identical failure until the customer deploys another
			// migration. The only answer is a new base copy.
			name: "a migration under the chain ends it",
			err:  fmt.Errorf("cycle 4: %w", backup.ErrSchemaMoved),
			want: ReasonSchemaMoved,
		},
		{
			// A retry reconnects onto a slot starting LATER and writes the next file beyond a
			// hole that hashes, parses and verifies.
			name: "the slot going ends the chain",
			err:  fmt.Errorf("opening the session: %w", backup.ErrSlotGone),
			want: ReasonSlotGone,
		},
		{
			name: "everything else is tried again on the next tick",
			err:  errors.New("the container refused the object: 503"),
			want: ReasonCycleFailed,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classify(tc.err); got != tc.want {
				t.Fatalf("classify(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// The loop, driven over an injected clock.
// ─────────────────────────────────────────────────────────────────────────────────────────────

// fakeChain answers with a scripted result per call and records what it was asked for.
type fakeChain struct {
	// takes is what each Base call returns, in order; cycles the same for Cycle.
	takes  []step
	cycles []step

	bases int
	runs  int

	// beforeCycle runs at the top of every Cycle, which is where a test cancels a context to land
	// a shutdown inside one.
	beforeCycle func(ctx context.Context)

	reach backup.Position
}

type step struct {
	at  backup.Position
	err error
	// took is how long the fake pretends the cycle ran, on the injected clock.
	took time.Duration
}

func (f *fakeChain) Base(context.Context) (backup.Position, error) {
	s := f.next(f.takes, f.bases)
	f.bases++
	if s.err == nil {
		f.reach = s.at
	}
	return f.reach, s.err
}

func (f *fakeChain) Cycle(ctx context.Context) (backup.Position, error) {
	if f.beforeCycle != nil {
		f.beforeCycle(ctx)
	}
	s := f.next(f.cycles, f.runs)
	f.runs++
	if s.err == nil {
		f.reach = s.at
	}
	return f.reach, s.err
}

func (f *fakeChain) next(from []step, i int) step {
	if i < len(from) {
		return from[i]
	}
	if len(from) == 0 {
		return step{}
	}
	return from[len(from)-1]
}

// collector keeps every fact, which is what the assertions read.
type collector struct{ facts []Fact }

func (c *collector) Report(_ context.Context, f Fact) { c.facts = append(c.facts, f) }

// clock is an injected time source. Every wait advances it by exactly what was asked for, and each
// cycle advances it by that step's took, so a whole run is deterministic and instant.
type clock struct {
	at    time.Time
	waits []time.Duration
}

func (c *clock) now() time.Time { return c.at }

func (c *clock) after(d time.Duration) <-chan time.Time {
	c.waits = append(c.waits, d)
	c.at = c.at.Add(d)
	ch := make(chan time.Time, 1)
	ch <- c.at
	return ch
}

// harness wires a fake chain to an injected clock and stops the run after a fixed number of facts,
// which is how a loop with no real time in it terminates.
func harness(t *testing.T, chain *fakeChain, stopAfter int) (*collector, *clock, error) {
	t.Helper()

	c := &clock{at: epoch}
	got := &collector{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The fake's own duration is applied here, so the clock advances by the cycle as well as by
	// the wait — which is what makes an overrun expressible at all.
	report := reporterFunc(func(ctx context.Context, f Fact) {
		got.Report(ctx, f)
		if len(got.facts) >= stopAfter {
			cancel()
		}
	})

	s := &Scheduler{
		Chain:    &timed{fakeChain: chain, clock: c},
		Interval: interval,
		Report:   report,
		Now:      c.now,
		After:    c.after,
	}
	return got, c, s.Run(ctx)
}

// timed advances the injected clock by the step's own duration, so a cycle can be made to overrun.
type timed struct {
	*fakeChain
	clock *clock
}

func (t *timed) Base(ctx context.Context) (backup.Position, error) {
	took := t.next(t.takes, t.bases).took
	p, err := t.fakeChain.Base(ctx)
	t.clock.at = t.clock.at.Add(took)
	return p, err
}

func (t *timed) Cycle(ctx context.Context) (backup.Position, error) {
	took := t.next(t.cycles, t.runs).took
	p, err := t.fakeChain.Cycle(ctx)
	t.clock.at = t.clock.at.Add(took)
	return p, err
}

type reporterFunc func(context.Context, Fact)

func (r reporterFunc) Report(ctx context.Context, f Fact) { r(ctx, f) }

func TestFirstRunTakesABaseAndThenStreamsCycles(t *testing.T) {
	chain := &fakeChain{
		takes:  []step{{at: "0/1000000", took: 9 * time.Minute}},
		cycles: []step{{at: "0/2000000", took: time.Minute}},
	}
	facts, c, err := harness(t, chain, 3)
	if err != nil {
		t.Fatalf("the run ended with an error: %v", err)
	}

	if chain.bases != 1 {
		t.Fatalf("the chain was based %d times and a healthy run bases once", chain.bases)
	}
	if got := []Kind{facts.facts[0].Kind, facts.facts[1].Kind, facts.facts[2].Kind}; got[0] != KindBase ||
		got[1] != KindChange || got[2] != KindChange {
		t.Fatalf("the run went %v, and a first run takes a base and then streams", got)
	}
	for i, f := range facts.facts {
		if !f.OK || f.Chain != Live {
			t.Fatalf("fact %d says ok=%t chain=%s on a run where nothing failed", i, f.OK, f.Chain)
		}
	}
	if facts.facts[2].Recoverable != "0/2000000" {
		t.Fatalf("the chain reports it restores to %q, and its last cycle reached 0/2000000",
			facts.facts[2].Recoverable)
	}
	// The base copy took nine minutes against a five-minute interval, so the first change cycle
	// starts immediately and the second waits out the rest of the clock.
	if len(c.waits) != 1 || c.waits[0] != 4*time.Minute {
		t.Fatalf("the run waited %v; a nine-minute base overruns and the cycle after the "+
			"one-minute cycle waits the remaining four", c.waits)
	}
}

func TestAnOverrunningCycleSlipsRatherThanStacking(t *testing.T) {
	chain := &fakeChain{
		takes: []step{{at: "0/1000000"}},
		// Every cycle runs to seven minutes against a five-minute interval.
		cycles: []step{{at: "0/2000000", took: 7 * time.Minute}},
	}
	facts, c, err := harness(t, chain, 4)
	if err != nil {
		t.Fatalf("the run ended with an error: %v", err)
	}

	// The base copy was instant, so the first change cycle waits out the whole interval — and
	// that is the ONLY wait in the run. Every cycle after it overran, and an overrun does not
	// wait: it does not queue the interval it missed, it starts at once and says it slipped.
	if len(c.waits) != 1 || c.waits[0] != interval {
		t.Fatalf("the loop's waits were %v; one full interval after the instant base and nothing "+
			"after each seven-minute cycle", c.waits)
	}
	for i, f := range facts.facts[2:] {
		// THE NUMBER THAT MATTERS: what this install actually achieved, not what it was set to.
		//
		// Fourteen minutes and not seven, and that is the definition rather than an off-by-one.
		// The worst instant to lose the source is just BEFORE a manifest lands: at that moment
		// the durable data reaches the PREVIOUS cycle's window and the source has run on to now.
		// Two back-to-back seven-minute cycles are therefore fourteen minutes of exposure against
		// a five-minute objective, which is exactly the number an operator has to see.
		if f.Achieved != 14*time.Minute {
			t.Fatalf("cycle %d reports an achieved RPO of %v; two back-to-back seven-minute "+
				"cycles expose fourteen minutes", i+2, f.Achieved)
		}
		if f.Interval != interval {
			t.Fatalf("cycle %d reports the configured interval as %v", i+2, f.Interval)
		}
	}
}

func TestAQuietDatabaseIsNotAFailure(t *testing.T) {
	chain := &fakeChain{
		takes:  []step{{at: "0/1000000"}},
		cycles: []step{{err: backup.ErrNoChanges}},
	}
	facts, _, err := harness(t, chain, 2)
	if err != nil {
		t.Fatalf("the run ended with an error: %v", err)
	}
	f := facts.facts[1]
	if !f.OK || f.Chain != Live || f.Reason != ReasonNoChanges || f.Err != nil {
		t.Fatalf("a cycle over a quiet database reported ok=%t chain=%s reason=%q err=%v, and a "+
			"database with nothing to copy has not failed", f.OK, f.Chain, f.Reason, f.Err)
	}
}

func TestASchemaMoveMidScheduleReBasesRatherThanRetrying(t *testing.T) {
	chain := &fakeChain{
		takes: []step{{at: "0/1000000"}, {at: "0/9000000"}},
		cycles: []step{
			{at: "0/2000000"},
			{err: fmt.Errorf("cycle: %w", backup.ErrSchemaMoved)},
			{at: "0/9100000"},
		},
	}
	facts, _, err := harness(t, chain, 5)
	if err != nil {
		t.Fatalf("the run ended with an error: %v", err)
	}

	moved := facts.facts[2]
	if moved.Chain != ReBasing || moved.Reason != ReasonSchemaMoved || moved.OK {
		t.Fatalf("the cycle a migration landed under reported chain=%s reason=%q ok=%t, and a "+
			"chain whose schema moved is over", moved.Chain, moved.Reason, moved.OK)
	}
	// THE POSITION AN OPERATOR ACTS ON, on the cycle that failed: the chain still restores to
	// where it stood, and reporting nothing there would read as total loss.
	if moved.Recoverable != "0/2000000" {
		t.Fatalf("the re-basing fact says this chain restores to %q and it reached 0/2000000",
			moved.Recoverable)
	}
	if facts.facts[3].Kind != KindBase {
		t.Fatalf("the cycle after the schema moved was a %s; the one remedy for a moved schema "+
			"is a new base copy", facts.facts[3].Kind)
	}
	if chain.bases != 2 {
		t.Fatalf("the chain was based %d times over one migration", chain.bases)
	}
	if facts.facts[4].Kind != KindChange || facts.facts[4].Chain != Live {
		t.Fatal("the new chain did not go on to stream cycles after its base copy")
	}
}

func TestADeadSlotReBasesAndIsNeverRetried(t *testing.T) {
	chain := &fakeChain{
		takes: []step{{at: "0/1000000"}, {at: "0/5000000"}},
		cycles: []step{
			{err: fmt.Errorf("opening the session: %w", backup.ErrSlotGone)},
			{at: "0/5100000"},
		},
	}
	facts, _, err := harness(t, chain, 4)
	if err != nil {
		t.Fatalf("the run ended with an error: %v", err)
	}
	dead := facts.facts[1]
	if dead.Chain != ReBasing || dead.Reason != ReasonSlotGone {
		t.Fatalf("a lost slot reported chain=%s reason=%q; a stream that reconnects onto a new "+
			"slot writes its next file beyond a hole that verifies", dead.Chain, dead.Reason)
	}
	if facts.facts[2].Kind != KindBase {
		t.Fatal("the cycle after the slot went was not a base copy, so the chain would have been " +
			"extended across the WAL nobody can reach any more")
	}
}

func TestAnOrdinaryFailureIsTriedAgainAndKeepsTheChain(t *testing.T) {
	chain := &fakeChain{
		takes: []step{{at: "0/1000000"}},
		cycles: []step{
			{err: errors.New("PUT: 503 from the container")},
			{at: "0/2000000"},
		},
	}
	facts, _, err := harness(t, chain, 3)
	if err != nil {
		t.Fatalf("the run ended with an error: %v", err)
	}
	failed := facts.facts[1]
	if failed.OK || failed.Chain != Live || failed.Reason != ReasonCycleFailed {
		t.Fatalf("a refused upload reported ok=%t chain=%s reason=%q; the chain is intact and the "+
			"next cycle tries again", failed.OK, failed.Chain, failed.Reason)
	}
	if failed.Err == nil {
		t.Fatal("the failed cycle carried no error, so nobody can act on it")
	}
	if chain.bases != 1 {
		t.Fatalf("a refused upload cost %d base copies; only a moved schema or a lost slot is "+
			"worth one", chain.bases)
	}
}

func TestAFailedBaseCopyStopsTheRunRatherThanPayingForAnother(t *testing.T) {
	// A slot left by a killed process: postgres.Base cannot create one, and the answer is not to
	// ask Azure for another nine-minute backup on the next tick.
	leak := fmt.Errorf("create replication slot %q: %w", "vp_x", postgres.ErrSlotLeaked)
	chain := &fakeChain{takes: []step{{err: leak}}}

	// NOT the harness: this run has to end on its own, with nobody cancelling it, or the test
	// would be watching a shutdown rather than the stop this ticket is about.
	c := &clock{at: epoch}
	facts := &collector{}
	err := (&Scheduler{Chain: chain, Interval: interval, Report: facts, Now: c.now, After: c.after}).
		Run(context.Background())
	if err == nil {
		t.Fatal("the run ended cleanly on a base copy that never happened, so nothing supervising " +
			"this agent would know it is not backing anything up")
	}
	if !errors.Is(err, postgres.ErrSlotLeaked) {
		t.Fatalf("the run's error lost the leak sentinel, so the loudest failure in this system "+
			"arrives as an ordinary one: %v", err)
	}
	if chain.bases != 1 {
		t.Fatalf("the base copy was attempted %d times; each one costs about eleven minutes of "+
			"vault time and the second would sit on a slot already accumulating WAL", chain.bases)
	}
	f := facts.facts[0]
	if f.OK || f.Chain != Stopped || f.Reason != ReasonBaseFailed {
		t.Fatalf("the failed base reported ok=%t chain=%s reason=%q", f.OK, f.Chain, f.Reason)
	}
	if !strings.Contains(f.Err.Error(), "vp_x") {
		t.Fatalf("the fact does not name the slot, which is the one thing an operator needs: %v", f.Err)
	}
}

func TestShutdownMidCycleEndsTheRunWithoutStartingAnother(t *testing.T) {
	c := &clock{at: epoch}
	got := &collector{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	chain := &fakeChain{
		takes: []step{{at: "0/1000000"}},
		cycles: []step{
			// The cycle that is in flight when the signal lands. It fails with the context's own
			// error, which is what every layer below does on a cancelled context.
			{err: context.Canceled},
			{at: "0/9999999"},
		},
	}
	// The signal arrives INSIDE the first change cycle.
	chain.beforeCycle = func(context.Context) {
		if chain.runs == 0 {
			cancel()
		}
	}

	s := &Scheduler{Chain: chain, Interval: interval, Report: got, Now: c.now, After: c.after}
	if err := s.Run(ctx); err != nil {
		t.Fatalf("a cancelled context is an ordinary shutdown and must not be reported as a fault: %v", err)
	}

	if chain.runs != 1 {
		t.Fatalf("%d cycles ran; the one in flight finishes and no further cycle is started", chain.runs)
	}
	if chain.bases != 1 {
		t.Fatalf("shutdown cost %d base copies", chain.bases)
	}
	if len(got.facts) != 2 {
		t.Fatalf("%d facts were reported; the base and the cycle the signal landed in", len(got.facts))
	}
	// THE POSITION IS STILL THE ONE THE CHAIN REACHED, and the cycle that died reported no new
	// one — which is the whole guarantee: nothing here advances what is recoverable on a cycle
	// that did not finish, and only the Chain itself can acknowledge a position, after its
	// manifest is stored.
	last := got.facts[1]
	if last.OK || last.Recoverable != "0/1000000" {
		t.Fatalf("the abandoned cycle reported ok=%t recoverable=%q; it stored nothing, so the "+
			"chain still restores to where the base copy left it", last.OK, last.Recoverable)
	}
	// A ROLLING RESTART IS NOT A BACKUP FAILURE. Reported as cycle-failed, every deploy would put
	// one on the wire and teach whoever reads these that the reason means nothing.
	if last.Reason != ReasonShutdown {
		t.Fatalf("the cycle the signal landed in is reported as %q", last.Reason)
	}
}

// TestChainsThatNeverCarryAnythingStopRatherThanReBaseForever is the runaway postgres/base.go
// refuses one level down and could not prevent from up here: every new base is a full copy of the
// source, so a fingerprint that moves on its own would spend one per interval, forever, and lay
// down not a single change file while every fact read "rebasing" — a legitimate state.
func TestChainsThatNeverCarryAnythingStopRatherThanReBaseForever(t *testing.T) {
	chain := &fakeChain{
		takes:  []step{{at: "0/1000000"}},
		cycles: []step{{err: fmt.Errorf("cycle: %w", backup.ErrSchemaMoved)}},
	}
	c := &clock{at: epoch}
	facts := &collector{}
	err := (&Scheduler{Chain: chain, Interval: interval, Report: facts, Now: c.now, After: c.after}).
		Run(context.Background())

	if err == nil {
		t.Fatal("a chain that has never carried a single change re-based forever and the run " +
			"never ended, so nothing supervising the agent would know it is paying for a base " +
			"copy an interval and backing nothing up")
	}
	if chain.bases != maxReBases {
		t.Fatalf("%d base copies were taken against a bound of %d", chain.bases, maxReBases)
	}
	final := facts.facts[len(facts.facts)-1]
	if final.Chain != Stopped || final.Reason != ReasonReBaseLoop {
		t.Fatalf("the run ended reporting chain=%s reason=%q, and the base copies all WORKED — "+
			"an operator sent to the vault would find nothing wrong there", final.Chain, final.Reason)
	}
	if !errors.Is(err, backup.ErrSchemaMoved) {
		t.Fatalf("the run's error drops what ended the last chain: %v", err)
	}
}

// TestOneMigrationCostsOneReBaseAndTheBoundResets: a customer who deploys often must never walk
// into the bound. It counts chains that carry NOTHING, not re-bases.
func TestOneMigrationCostsOneReBaseAndTheBoundResets(t *testing.T) {
	chain := &fakeChain{
		takes: []step{{at: "0/1000000"}, {at: "0/2000000"}, {at: "0/3000000"}, {at: "0/4000000"}},
		cycles: []step{
			{err: fmt.Errorf("cycle: %w", backup.ErrSchemaMoved)},
			{at: "0/2100000"}, // the new chain carries something, so the count goes back to nothing
			{err: fmt.Errorf("cycle: %w", backup.ErrSchemaMoved)},
			{at: "0/3100000"},
			{err: fmt.Errorf("cycle: %w", backup.ErrSchemaMoved)},
			{at: "0/4100000"},
		},
	}
	_, _, err := harness(t, chain, 12)
	if err != nil {
		t.Fatalf("three migrations, each followed by a chain that streamed, ended the run: %v", err)
	}
}

func TestARefusedScheduler(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    Scheduler
		want string
	}{
		{
			name: "no chain",
			s:    Scheduler{Interval: interval, Report: &collector{}},
			want: "no chain",
		},
		{
			// No default, because the interval IS the RPO.
			name: "no interval",
			s:    Scheduler{Chain: &fakeChain{}, Report: &collector{}},
			want: "no interval",
		},
		{
			name: "no reporter",
			s:    Scheduler{Chain: &fakeChain{}, Interval: interval},
			want: "no reporter",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.s.Run(context.Background())
			if err == nil {
				t.Fatal("the scheduler ran with a hole in its configuration")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("the refusal does not say what is missing: %v", err)
			}
		})
	}
}
