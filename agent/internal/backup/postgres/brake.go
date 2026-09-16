package postgres

// brake.go is THE SAFETY BRAKE, and its premise outranks everything else in this package:
//
//	OUR BACKUP MUST NOT TAKE DOWN THE DATABASE IT IS BACKING UP.
//
// An unconsumed replication slot accumulates WAL ON THE CUSTOMER'S PRIMARY. Azure flips a Flexible
// Server to READ-ONLY at 95% disk. That is the customer's production down, caused by us, hours
// after a backup that may not even have succeeded.
//
// And there is no ordinary way out of it, which is the measurement that shapes this whole file:
// ONLY THE OWNING ROLE CAN DROP A REPLICATION SLOT (AD-034). The customer's own administrator gets
// `must be superuser or replication role to use replication slots`. So if the agent's credential is
// lost, NOBODY can drop the slot — not the customer, not support, not us — and the disk fills to
// the read-only line with no lever anywhere. The brake therefore cannot be a runbook, cannot ask an
// administrator, and cannot wait for a human: it acts with the agent's own credential or it does
// not act at all.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// ONE NUMBER, BECAUSE NEITHER HALF DECIDES ANYTHING ALONE
// ─────────────────────────────────────────────────────────────────────────────────────────────
//
//	limit    = 95% of the disk          — the line at which Azure turns the server read-only
//	headroom = limit - used             — bytes left before that line, never below zero
//	PRESSURE = retained / (retained + headroom)
//
// Read it as: OF THE ROOM OUR SLOT IS ALLOWED TO EAT, HOW MUCH HAS IT ALREADY EATEN. `retained +
// headroom` is the headroom the server would have if we dropped our slot this second, so pressure
// is our own share of the distance to the outage, and pressure = 1 is the outage with our name on
// it. It is dimensionless, it needs no per-customer tuning, and it moves the right way in both
// variables — up with retained WAL, down with free disk (TestPressureIsMonotonicInBoth).
//
// WHY LAG ALONE IS NOT A BRAKE. 8 GiB of retained WAL is a rounding error on a 4 TiB server at 10%
// and it is fatal on a 32 GiB server at 73%. No absolute lag threshold is right for both, so a lag
// alarm is either always firing or never firing, and the two cases are the first two rows of
// brake_test.go with the SAME lag and OPPOSITE answers.
//
// WHY DISK ALONE IS NOT A BRAKE. A disk at 94% says the server is in trouble; it does not say we
// caused it, and it does not say dropping our slot would help. Customers fill their own disks with
// their own data, and destroying a healthy backup chain buys them nothing. Meanwhile a disk at 40%
// with our slot holding 300 GiB is a server that will be read-only within the hour while the disk
// metric stays green the whole way down.
//
// TWO GREEN METRICS SIDE BY SIDE HIDE EXACTLY THIS. It is the combination that predicts the outage,
// so the combination is what is computed, thresholded and alerted on — the halves are inputs and
// are never thresholded on their own.
//
// THE THRESHOLDS FIRE WELL BEFORE THE LINE, and that is arithmetic rather than hope: tripping at
// pressure 0.5 means our slot holds as many bytes as are left before read-only, so dropping it
// DOUBLES the remaining headroom and there is still that whole headroom of time to act in. On the
// worked example in the tests it fires with the disk at 61%.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// HOW THE BRAKE SURVIVES THE AGENT BEING SICK — WHICH IS EXACTLY WHEN IT IS NEEDED
// ─────────────────────────────────────────────────────────────────────────────────────────────
//
// A check that only runs inside the healthy loop is not a brake: every failure that stops the loop
// also disables it, and a stopped loop IS the unconsumed slot. So three things are true here and
// each is a deliberate choice against the obvious design.
//
//  1. ITS INPUTS ARE THE SERVER'S OWN NUMBERS, NOT THE LOOP'S. Retention is read from
//     pg_replication_slots on the primary, never from Stream.Lag or any counter the cycle
//     maintains. A wedged loop reports nothing and a crashed one reports nothing, and both look
//     identical to a quiet database from the inside — but the SERVER always knows how far back its
//     slot is holding WAL.
//
//  2. IT HAS ITS OWN CLOCK AND ITS OWN CONNECTION. Watch is a goroutine with its own ticker, not a
//     step in Cycle.Run. AD-036 says the agent holds one Postgres connection and it belongs to the
//     change stream; the brake is the one thing that CANNOT use it, and not by preference — once
//     START_REPLICATION has run the connection is in CopyBoth and serves no ordinary statement
//     (since.go), and a brake sharing a wedged loop's connection is wedged with it. So the brake
//     dials its own, and that is a named exception to AD-036 rather than a drift from it.
//
//  3. IT RUNS BEFORE THE STREAM AND KEEPS RUNNING AFTER IT DIES. Start Watch first, so a
//     crash-looping agent — the classic sick agent — brakes on every restart before it tries to
//     stream, and so a stream that has ended leaves the brake still ticking.
//
// AND IT CAN DROP A SLOT ITS OWN STREAM IS STILL HOLDING, which is the case that matters most:
// C3 names an unfixed window where nothing answers keepalives while a batch is being stored, so a
// batch slower to upload than wal_sender_timeout (measured: one minute, AD-039) stalls the stream —
// no loss, no progress, and an unconsumed slot arriving by a different road. THE BRAKE SEES IT,
// because it reads the slot rather than the loop. If the server has already hung up, the slot is
// idle and the drop is plain; if our backend is still attached, mayDrop recognises the active_pid
// as OUR OWN stream's and the brake terminates that backend before dropping. Killing our own wedged
// stream is the correct thing for a brake to do.
//
// WHAT IT DOES NOT COVER, STATED PLAINLY RATHER THAN IMPLIED AWAY:
//
//   - THE AGENT GONE FOR GOOD. Uninstalled, node deleted, credential rotated or lost. No
//     client-side brake can cover this — there is no client. Only (4) below does.
//   - THE AGENT PARTITIONED FROM THE DATABASE. The brake cannot reach the server to read the slot,
//     let alone drop it. It alerts and can do nothing else.
//   - THE PROCESS STARVED RATHER THAN WEDGED. An OOM-thrashing or CPU-starved container starves the
//     brake's goroutine along with everything else in it. Separate clock, same process.
//   - THE DISK HALF BEING UNREADABLE. A 403 on the metric, ARM throttling, a metrics outage, or a
//     reading old enough to describe the disk as it was before whatever went wrong (monitor.go
//     refuses all four) leaves pressure unknown, and the brake then WARNS AND NEVER DROPS —
//     dropping on half the evidence would destroy chains every time monitoring blinked.
//
//     AND UNKNOWN DOES NOT ESCALATE WITH TIME. A metrics endpoint down for six hours while our slot
//     grows reads exactly like one down for one tick, so the brake warns for six hours and never
//     acts. That is a real hole and it is left open on purpose: the alternative is a brake that
//     destroys chains during an Azure Monitor outage, which is a fault we would cause across every
//     install at once rather than the one we would prevent. (4) is the layer that covers it.
//
//  4. SO THE ONLY BACKSTOP THAT SURVIVES ALL OF THAT IS SERVER-SIDE, AND IT IS max_slot_wal_keep_size.
//     Set it and the SERVER invalidates a slot that retains more than the ceiling, freeing the WAL
//     with no client, no credential and no agent involved. An invalidated slot is a dead chain (C4)
//     and a new base copy, which is the right trade every time: a dead chain is recoverable and a
//     read-only production database is not. It is a server parameter the customer's administrator
//     sets — the one thing in this story an administrator CAN do — so the brake reads it and says
//     so loudly when it is unlimited, which is the default.

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// readOnlyAt is the fraction of the disk at which Azure Flexible Server turns the server
// read-only. It is a measured property of the platform and not a threshold of ours — the two
// thresholds below are ours, and they are expressed as shares of the distance to THIS line.
const readOnlyAt = 0.95

// warnAt and tripAt are the two decisions on the pressure above.
//
// tripAt = 0.5 is the point at which our slot holds as many bytes as remain before the read-only
// line: dropping doubles the headroom, and what is left to act in is as large as what we give back.
// warnAt = 0.25 is a quarter of that room gone, which on a normally-consuming slot never happens —
// a healthy stream confirms every cycle and the retention falls back to nothing.
//
// NEITHER IS PER-CUSTOMER, and that is the point of a dimensionless number: a 32 GiB server and a
// 4 TiB one are the same arithmetic.
const (
	warnAt = 0.25
	tripAt = 0.50
)

// DefaultEvery is how often Watch looks. A minute, because the thing it is racing takes hours: a
// slot has to accumulate a meaningful share of a disk before pressure moves, and a tick that cost
// nothing would still be two statements against the customer's primary forever.
const DefaultEvery = time.Minute

// terminateWait is how long the SERVER waits for our own wedged backend to die before it gives up.
// See drop, where the value is put on the wire.
const terminateWait = 5 * time.Second

// Space is the primary's disk. Total <= 0 means UNKNOWN — see Disk.
type Space struct {
	Total int64
	Used  int64
}

// Reading is what the brake found on the server this tick. It is the whole input to the decision,
// and it is a plain value so the decision is testable with no server anywhere.
type Reading struct {
	// Present is whether a slot on our name is on the server at all. False is C4's dead chain,
	// not the brake's business: there is nothing holding WAL and nothing to drop.
	Present bool

	// RetainedBytes is the WAL the server is holding BECAUSE OF THIS SLOT: the distance from the
	// slot's restart_lsn to the server's current write position.
	//
	// restart_lsn AND NOT confirmed_flush_lsn, and the difference is the whole measurement.
	// confirmed_flush_lsn is where decoding resumes and it is what base.go reads to start a
	// chain from; RETENTION is governed by restart_lsn, which sits at or behind it — the server
	// keeps every segment from there on. Reading the wrong one under-reports the disk the slot
	// is really occupying, in the direction that fires the brake too late.
	RetainedBytes int64

	// ActivePID is the backend consuming the slot, or zero when nothing is. It is how the brake
	// tells its own wedged stream from a stranger — see mayDrop.
	ActivePID uint32

	// Disk is the primary's, from Brake.Disk. The zero value means it could not be read.
	Disk Space
}

// Verdict is what the brake decided.
type Verdict int

const (
	// Fine is nothing to do. It is also the answer when the disk is full of the CUSTOMER'S own
	// data and our slot holds nothing: pressure is our share of the problem, and none of that
	// one is ours. A brake that alarmed where it has no lever teaches people to ignore it.
	Fine Verdict = iota

	// Warn is loud and touches nothing.
	Warn

	// Trip is: drop our own slot, alert, and mark the chain for a new base copy.
	Trip
)

func (v Verdict) String() string {
	switch v {
	case Fine:
		return "fine"
	case Warn:
		return "warn"
	case Trip:
		return "trip"
	}
	return "unknown"
}

// Decision is the verdict and the number it came from. Why is written for whoever is woken up by
// it, so it names both halves — a pressure with no disk and no retention behind it is unactionable.
type Decision struct {
	Verdict  Verdict
	Pressure float64 // NaN when the disk could not be read.
	Why      string
}

// Alarm is what Alert is handed. EVERY verdict above Fine produces one, INCLUDING a trip whose drop
// was refused or failed: a brake that trips and then does nothing in silence is not a brake.
type Alarm struct {
	Slot     string
	Decision Decision

	// Dropped is true only if the slot is really gone. IT IS ALSO THE RE-BASE SIGNAL: our slot
	// dropped means the chain is dead and the next cycle needs a new base copy (C4). There is no
	// second field for that because there is no case where one is true and the other is not.
	Dropped bool

	// Err is why the brake could not do what the verdict called for — the disk it could not
	// read, the consumer it would not touch, the drop that failed. Nil on a clean trip.
	Err error
}

// Assess turns one reading into one decision. NO I/O, no clock, no state: this function is the
// brake's whole policy and the table in brake_test.go is its specification.
func Assess(r Reading) Decision {
	if !r.Present {
		return Decision{Verdict: Fine, Pressure: 0,
			Why: "no replication slot of ours is on the server, so none of our WAL is being held"}
	}

	p := pressure(r.RetainedBytes, r.Disk)
	if math.IsNaN(p) {
		// Never Fine and never Trip. See the header: half the evidence is enough to raise a
		// voice and not enough to destroy a chain, and (4) is the backstop for this case.
		return Decision{Verdict: Warn, Pressure: p,
			Why: fmt.Sprintf("our slot is holding %s of WAL on the primary and the disk could not be "+
				"read, so how close that is to the read-only line is unknown", megabytes(r.RetainedBytes))}
	}

	why := fmt.Sprintf("our slot is holding %s of WAL and %s remains before the %.0f%% read-only "+
		"line, so it has taken %.0f%% of the room it may take",
		megabytes(r.RetainedBytes), megabytes(headroom(r.Disk)), readOnlyAt*100, p*100)

	switch {
	case p >= tripAt:
		return Decision{Verdict: Trip, Pressure: p, Why: why}
	case p >= warnAt:
		return Decision{Verdict: Warn, Pressure: p, Why: why}
	}
	return Decision{Verdict: Fine, Pressure: p, Why: why}
}

// pressure is the one number. See the file header for what it means and why it is one number.
func pressure(retained int64, d Space) float64 {
	if d.Total <= 0 {
		return math.NaN()
	}
	if retained < 0 {
		// pg_wal_lsn_diff is a numeric subtraction and a negative answer is not something a
		// healthy primary reports. Clamped rather than trusted, because a negative would come
		// out as a negative pressure, which reads as health.
		retained = 0
	}
	room := retained + headroom(d)
	if room <= 0 {
		// The disk is at or past the line and NONE of it is ours. There is no lever here, and
		// dividing by nothing to invent one would drop a chain for no gain at all.
		return 0
	}
	return float64(retained) / float64(room)
}

// headroom is the bytes left before the read-only line, never negative.
func headroom(d Space) int64 {
	left := int64(float64(d.Total)*readOnlyAt) - d.Used
	if left < 0 {
		return 0
	}
	return left
}

func megabytes(b int64) string {
	return fmt.Sprintf("%.1f MiB", float64(b)/(1<<20))
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// The brake itself.
// ─────────────────────────────────────────────────────────────────────────────────────────────

// Disk reports the PRIMARY's disk, and it is a function for the reason querySQL and runSQL are:
// one operation, and a test needs to drive its failure.
//
// THE REAL IMPLEMENTATION IS AzureMonitor.Space in monitor.go, which says why this half cannot come
// over port 5432 and has to come from the control plane. That split is why the two halves arrive
// here as separate inputs and are combined in one place.
//
// AN ERROR FROM IT IS NOT A ZERO. Check zeroes the Space rather than keeping a half-filled one, and
// Assess reads Total <= 0 as unknown, which warns and never drops. That chain is the whole defence
// against a metrics failure reading as "the disk is fine".
type Disk func(ctx context.Context) (Space, error)

// Brake watches one slot and drops it before it takes the customer's primary down.
//
// IT IS STARTED BEFORE THE STREAM AND IT OUTLIVES IT. Its Query must be its OWN connection — see
// (2) in the header — and Watch runs on its own goroutine.
type Brake struct {
	// Slot is the slot this install created. It is refused unless it is one of ours
	// (validateSlotName), because this is the one function in the repo whose job is to destroy
	// a replication slot and a name outside our convention is the customer's.
	Slot string

	// Query is the brake's OWN connection to the primary, NOT the stream's. The stream's is in
	// CopyBoth and serves no statement, and a brake sharing a wedged loop's connection is wedged
	// with it.
	Query querySQL

	// Disk reads the primary's disk. Nil, or an error from it, leaves pressure unknown, which
	// warns and never drops.
	Disk Disk

	// StreamPID is the backend PID of the change stream's connection, or zero when there is no
	// stream. It is a function rather than a value because the stream reconnects and the brake
	// outlives any one session of it. pgconn.PgConn.PID is what a caller passes here.
	//
	// IT IS WHAT LETS THE BRAKE DROP A SLOT ITS OWN STREAM IS HOLDING, and equally what stops it
	// destroying a slot somebody else is consuming — see mayDrop.
	StreamPID func() uint32

	// Every is the tick. Zero means DefaultEvery.
	Every time.Duration

	// Alert is called for every verdict above Fine. A callback and not a log line, for the
	// reason this package has no logger at all (conn.go): it is the surest way not to log a
	// secret, and this alarm is one something upstream acts on rather than reads.
	Alert func(Alarm)
}

// Watch runs the brake until the context ends. It returns the context's error and nothing else: a
// tick that fails is alerted BY Check and the next tick is taken anyway, because the failure modes
// here — a connection that dropped, a metrics endpoint that timed out — are exactly the ones during
// which the WAL keeps growing, and giving up is the worst available response to them.
//
// The error is dropped rather than re-raised here, and that is deliberate: Check alerts on every
// path it fails on (blind holds the one exception, and it is this context ending), so raising again
// would put two alarms on the wire for one event and teach whoever reads them that the count means
// nothing. This brake DROPS A REPLICATION SLOT, so the alarm it repeats is the one that must not be
// the alarm anybody learns to skip.
//
// IT CHECKS ONCE BEFORE THE FIRST TICK, so an agent that crash-loops faster than Every still brakes
// on every restart. That is the sick agent the ticket names, and a plain time.Ticker would never
// reach the first tick.
func (b *Brake) Watch(ctx context.Context) error {
	b.reportCeiling(ctx)

	ticker := time.NewTicker(b.every())
	defer ticker.Stop()

	for {
		_, _ = b.Check(ctx)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Check is one tick: read the slot, read the disk, decide, and act on the decision.
//
// It returns the decision even when it also returns an error, because the two say different things
// and the caller needs both: the decision is what the brake concluded, the error is what stopped it
// carrying that out.
//
// EVERY PATH THAT RETURNS AN ERROR ALSO RAISES AN ALARM, including the two that fail before any
// verdict exists — see blind for the single exception, which is this process being told to stop. A
// brake that cannot read the slot is blind, and being blind is the same news as being on fire:
// nobody is watching the WAL. It is also what lets Watch drop the error rather than re-raise it, so
// one failure is one alarm.
func (b *Brake) Check(ctx context.Context) (Decision, error) {
	// Before any statement is sent. A name outside our convention is the customer's own slot,
	// and this function drops slots.
	if err := validateSlotName(b.Slot); err != nil {
		b.blind(ctx, err)
		return Decision{}, err
	}

	reading, err := b.read(ctx)
	if err != nil {
		b.blind(ctx, err)
		return Decision{}, err
	}

	var diskErr error
	if b.Disk != nil {
		reading.Disk, diskErr = b.Disk(ctx)
		if diskErr != nil {
			// Zeroed rather than left half-filled: Total <= 0 is what Assess reads as
			// unknown, and a partial Space would be read as a real, tiny disk.
			reading.Disk = Space{}
			diskErr = fmt.Errorf("postgres: read the disk of the primary holding slot %q: %w", b.Slot, diskErr)
		}
	}

	decision := Assess(reading)
	if decision.Verdict != Trip {
		if decision.Verdict != Fine {
			b.raise(Alarm{Slot: b.Slot, Decision: decision, Err: diskErr})
		}
		return decision, nil
	}

	if err := mayDrop(b.Slot, reading, b.streamPID()); err != nil {
		// A trip we will not carry out is still a trip, and it is the loudest thing the brake
		// says: the WAL is going to keep growing and this process is not going to stop it.
		b.raise(Alarm{Slot: b.Slot, Decision: decision, Err: err})
		return decision, nil
	}
	if err := b.drop(ctx, reading); err != nil {
		b.raise(Alarm{Slot: b.Slot, Decision: decision, Err: err})
		return decision, err
	}

	// Dropped is the re-base signal: our slot is gone, so the chain is dead and the next cycle
	// needs a new base copy.
	b.raise(Alarm{Slot: b.Slot, Decision: decision, Dropped: true})
	return decision, nil
}

// slotStateQuery reads both halves of the lag in one statement.
//
// The name is interpolated because a replication connection has no bind parameters (AD-036), and it
// is safe to interpolate only because validateSlotName has already restricted it to [a-z0-9_] —
// Check asks before anything reaches here.
const slotStateQuery = `SELECT coalesce(active_pid, 0),
coalesce(pg_wal_lsn_diff(pg_current_wal_lsn(), restart_lsn), 0)::bigint
FROM pg_replication_slots WHERE slot_name = '%s'`

// read asks the SERVER what our slot is holding. Never the loop's own counters — see (1) in the
// header; that substitution is the whole difference between a brake and a health check.
func (b *Brake) read(ctx context.Context) (Reading, error) {
	if b.Query == nil {
		return Reading{}, errors.New("postgres: the brake has no connection of its own to the " +
			"primary, so it cannot see what our slot is holding — and the change stream's " +
			"connection is not a substitute: it is in CopyBoth and serves no statement")
	}

	rows, err := b.Query(ctx, fmt.Sprintf(slotStateQuery, b.Slot))
	if err != nil {
		return Reading{}, fmt.Errorf("postgres: read what slot %q is holding on the primary: %w", b.Slot, err)
	}
	if len(rows) == 0 {
		// C4's territory. Present stays false and the brake says nothing.
		return Reading{}, nil
	}
	if len(rows[0]) != 2 {
		return Reading{}, fmt.Errorf("postgres: the state of slot %q came back as %v, which is not "+
			"the active_pid and retained bytes this brake reads", b.Slot, rows[0])
	}

	pid, err := strconv.ParseUint(rows[0][0], 10, 32)
	if err != nil {
		return Reading{}, fmt.Errorf("postgres: slot %q reports %q as its consumer, which is not a "+
			"backend id: %w", b.Slot, rows[0][0], err)
	}
	retained, err := strconv.ParseInt(rows[0][1], 10, 64)
	if err != nil {
		return Reading{}, fmt.Errorf("postgres: slot %q reports %q as the WAL it is holding, which "+
			"is not a byte count; refusing rather than reading it as zero, which is what a brake "+
			"with nothing to measure looks like: %w", b.Slot, rows[0][1], err)
	}
	return Reading{Present: true, ActivePID: uint32(pid), RetainedBytes: retained}, nil
}

// mayDrop establishes that the slot in front of us is one we may destroy, and it is the answer to
// the epic's open item: TWO PARITY INSTALLS SHARING A SLOT NAME CANNOT BE TOLD APART BY NAME.
//
// So the brake does not ask whose slot it is. It asks WHO IS CONSUMING IT, which is a question the
// server answers exactly:
//
//	nobody           → ours to drop. Whatever created it is not reading it, and the WAL it holds
//	                   is doing nothing but filling the customer's disk.
//	our own stream   → ours to drop, and this is the case the brake exists for: our loop is
//	                   wedged mid-batch and still holding the slot open. The consumer is killed
//	                   and then the slot goes.
//	anybody else     → LEFT ALONE. It may be a sibling install's healthy stream, and dropping it
//	                   would silently end THEIR chain — a fault of the same shape as the one this
//	                   file prevents, inflicted on someone else. Under-acting leaves WAL growing
//	                   and is loudly reported; over-acting destroys a working backup in silence.
//
// This is also what base.go's ErrSlotLeaked asked for in as many words: the sentinel says a slot
// only we can drop is on the primary and deliberately does NOT say nothing is consuming it. This
// function is where that is established.
func mayDrop(slot string, r Reading, streamPID uint32) error {
	if !r.Present {
		return fmt.Errorf("postgres: slot %q is not on the server, so there is nothing to drop", slot)
	}
	if r.ActivePID == 0 || r.ActivePID == streamPID {
		return nil
	}
	return fmt.Errorf("postgres: slot %q is being consumed by another consumer (backend %d, and our "+
		"change stream is %d), so this brake will not drop it: two Parity installs cannot be told "+
		"apart by slot name, and the WAL will keep growing toward the %.0f%% at which Azure turns "+
		"the server read-only until whoever owns that backend stops",
		slot, r.ActivePID, streamPID, readOnlyAt*100)
}

// drop terminates our own consumer if there is one and then drops the slot.
//
// THE ORDER IS NOT OPTIONAL: pg_drop_replication_slot fails outright against an active slot, so
// dropping first against our own wedged stream leaves the WAL exactly where it was and returns an
// error that reads like a permissions problem.
//
// pg_terminate_backend on our OWN backend needs no extra privilege: a role may signal backends
// belonging to the same role, and both connections here authenticate as the agent's replication
// role. It is the same credential doing both, which is the whole requirement — an administrator
// cannot do either (AD-034).
func (b *Brake) drop(ctx context.Context, r Reading) error {
	const (
		// THE SECOND ARGUMENT IS THE POINT, and it exists from PostgreSQL 14 — which is this
		// product's floor, so there is no version branch here (AD-034 settled that there is
		// exactly one, and it is not this). Without a timeout pg_terminate_backend only SIGNALS
		// the backend and returns; the slot is released whenever that backend gets round to
		// dying, so the drop on the next line races it and loses often enough to matter. With
		// it the server waits, and the boolean below says whether the backend really went.
		terminate = "SELECT pg_terminate_backend(%d, %d)"
		drop      = "SELECT pg_drop_replication_slot('%s')"
	)

	if r.ActivePID != 0 {
		rows, err := b.Query(ctx, fmt.Sprintf(terminate, r.ActivePID, terminateWait.Milliseconds()))
		if err != nil {
			return fmt.Errorf("postgres: stop our own change stream (backend %d) so slot %q can be "+
				"dropped: %w", r.ActivePID, b.Slot, err)
		}
		if len(rows) != 1 || len(rows[0]) != 1 || rows[0][0] != "t" {
			return fmt.Errorf("postgres: our own change stream (backend %d) did not stop within %s, "+
				"so slot %q is still active and cannot be dropped while it holds %s of WAL on the "+
				"PRIMARY", r.ActivePID, terminateWait, b.Slot, megabytes(r.RetainedBytes))
		}
	}
	if _, err := b.Query(ctx, fmt.Sprintf(drop, b.Slot)); err != nil {
		return fmt.Errorf("postgres: drop slot %q: %w. It is still holding %s of WAL on the PRIMARY, "+
			"and only the role that created it can drop one — an administrator cannot",
			b.Slot, err, megabytes(r.RetainedBytes))
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// The backstop that survives this process not existing.
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ceilingQuery reads the one setting that brakes with no client at all. SHOW is an ordinary
// statement and AD-036 measured that a replication connection serves those.
const ceilingQuery = "SHOW max_slot_wal_keep_size"

// unlimitedCeiling is what the setting reads as when the server will hold WAL without bound, which
// is the DEFAULT. -1 is the documented spelling; the server also renders it as "-1MB" on some
// versions, so the test is on the sign rather than on the exact text.
func unlimitedCeiling(setting string) bool {
	return strings.HasPrefix(strings.TrimSpace(setting), "-")
}

// reportCeiling says once, at start, whether anything on the server would stop this without us.
//
// IT IS THE ONLY LAYER THAT SURVIVES THE AGENT NOT EXISTING — see (4) in the header. Everything
// else in this file needs a live process holding a live credential, and the failure mode that
// matters most is precisely the one where there is neither. So the absence of a ceiling is reported
// as an alarm rather than left as a fact nobody looks up, and it is reported at START, when it can
// still be acted on, rather than at the moment the disk fills.
//
// It cannot be SET from here: max_slot_wal_keep_size is a server parameter, and on Flexible Server
// that is an ARM update on the resource, not a statement. The customer's administrator does it —
// which makes it the one thing in this whole story an administrator CAN do, since AD-034 measured
// they cannot drop the slot.
func (b *Brake) reportCeiling(ctx context.Context) {
	if b.Query == nil {
		return
	}
	rows, err := b.Query(ctx, ceilingQuery)
	if err != nil {
		b.raise(Alarm{Slot: b.Slot, Err: fmt.Errorf("postgres: read max_slot_wal_keep_size, the one "+
			"thing that brakes this server with no agent running: %w", err)})
		return
	}
	if len(rows) == 0 || len(rows[0]) == 0 || !unlimitedCeiling(rows[0][0]) {
		return
	}
	b.raise(Alarm{Slot: b.Slot, Err: fmt.Errorf("postgres: max_slot_wal_keep_size is unlimited on "+
		"this server, so nothing but this agent stands between slot %q and the %.0f%% disk at which "+
		"Azure turns the primary read-only. If this process dies for good the slot cannot be dropped "+
		"by anyone — only the role that created it can, and an administrator cannot. Setting the "+
		"parameter makes the SERVER invalidate the slot instead, which ends the backup chain and "+
		"keeps the database writable", b.Slot, readOnlyAt*100)})
}

// blind alerts that the brake could not see far enough to reach a verdict at all, which is news of
// the same weight as a trip: nobody is watching the WAL.
//
// THE ONE EXCEPTION IS A CONTEXT THAT HAS ALREADY ENDED. That is the agent shutting down rather
// than the brake going blind, and it is not something to wake anyone for — an agent crash-looping,
// which is the sick agent this file is written for, would otherwise raise it on every restart, and
// a repeating alarm is one nobody reads by the time it means something. Only the ALARM is withheld:
// Check still returns the error to whoever asked.
func (b *Brake) blind(ctx context.Context, err error) {
	if ctx.Err() == nil {
		b.raise(Alarm{Slot: b.Slot, Err: err})
	}
}

func (b *Brake) raise(a Alarm) {
	if b.Alert != nil {
		b.Alert(a)
	}
}

func (b *Brake) every() time.Duration {
	if b.Every <= 0 {
		return DefaultEvery
	}
	return b.Every
}

func (b *Brake) streamPID() uint32 {
	if b.StreamPID == nil {
		return 0
	}
	return b.StreamPID()
}
