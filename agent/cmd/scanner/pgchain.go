package main

// pgchain.go is the Postgres side of `scanner backup`: the schedule.Chain the RPO clock drives.
//
// IT ORCHESTRATES AND IT IMPLEMENTS NOTHING. Every mechanism is already built and tested where it
// lives — the connection in postgres/conn.go, the slot in slot.go, the base copy in base.go, the
// change stream in since.go, the pipeline and both manifests in agent/internal/backup. This file is
// the order they go in, and the order IS the product's correctness. If anything here starts looking
// like a mechanism, it belongs in one of those packages.
//
// THE THREE ORDERINGS IT EXISTS TO KEEP:
//
//  1. THE SLOT BEFORE THE COPY. Not this file's to arrange — postgres.Base does it — but this file
//     is what must not work around it. The slot is created first so the position reported is at or
//     before the state of the bytes, which is the seam's whole promise.
//
//  2. CONFIRM LAST, AND ONLY AFTER THE MANIFEST. Cycle.Run writes the manifest last, and Confirm is
//     called only on the value it returned. There is no path here on which the server is told an
//     LSN is safe to discard before the file covering it is in the container — which is the one way
//     this product could lose customer data with every check green.
//
//  3. THE SLOT IS DROPPED BY WHOEVER CREATED IT, ON THE WAY OUT AND ON A RE-BASE. release() is the
//     only place that happens, and it runs on a context that survives a cancellation.
//
// WHAT IT DOES NOT DO: resume a chain across a restart. Nothing in this repo can read a manifest
// back out of the container (store.Blob writes and does not list), so a new process cannot learn
// where the old one got to. It therefore takes a NEW BASE at startup, and the slot the previous
// process left is what release() exists to have already dropped. A slot that survived anyway — a
// SIGKILL, an OOM — is postgres.ErrSlotLeaked on the first base copy, which stops the run loudly
// rather than starting a second chain over WAL nobody is reading.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/manukyanv07/parity-scanner/agent/internal/backup"
	"github.com/manukyanv07/parity-scanner/agent/internal/backup/postgres"
	"github.com/manukyanv07/parity-scanner/contract"
)

// pgSource is the seam's Source for Postgres: the change stream, plus the base copy that comes from
// a different credential entirely. It is the type postgres.Stream's own comment predicts — "embeds
// this and satisfies the seam without a line changing" — and it is where the two credentials meet
// and nowhere else (AD-035).
//
// There is a near-twin of this in agent/cmd/e2e-postgres/run.go, which argues it in full and is the
// proof the epic exists for. Two package mains cannot share a type; whoever changes one should look
// at the other, and if it ever earns a home it is a postgres.Source beside Stream and ControlPlane.
type pgSource struct {
	*postgres.Stream
	cloud postgres.ControlPlane

	// created says postgres.Base returned WITHOUT AN ERROR and therefore left the replication slot
	// on the server on purpose — it is the change stream's from that moment on (AD-033).
	//
	// THIS IS THE ONLY PLACE THE FACT IS KNOWABLE, and the leak it closes is the worst one in this
	// command. postgres.Base drops the slot itself on every failure it CAN, so a nil error there
	// means exactly one thing: a slot of ours exists and this call put it there. Everything
	// backup.Cycle.Base does afterwards — checking the copy, reading every object back to hash it,
	// writing the manifest — happens with that slot already on the customer's primary, and
	// base.go's own header says so in as many words: "Every failure in this file happens after
	// that... This package cannot drop one... So it is the caller's." From the Cycle's error alone
	// the two cases are indistinguishable, and the difference is a slot nobody can remove.
	created bool
}

var _ backup.Source = (*pgSource)(nil)

func (p *pgSource) Base(ctx context.Context) (backup.Batch, error) {
	batch, err := postgres.Base(ctx, p.cloud, p.Conn, p.Slot)
	if err == nil {
		p.created = true
	}
	// AN ERROR IS NOT PERMISSION TO ASSUME THE SLOT IS GONE in the one case where it might not be:
	// a 42710 means a slot was already there and this call did not create it, so
	// postgres.ErrSlotLeaked leaves created false. base.go is explicit that dropping on that
	// sentinel alone would cut a sibling install's working stream — establishing that nothing is
	// consuming it is the brake's job, and not this one's.
	return batch, err
}

// pgChain is one Postgres backup chain: the session it streams over, the two cycles that write its
// manifests, and how far it restores.
type pgChain struct {
	cfg   backupConfig
	cloud postgres.ControlPlane
	out   io.Writer

	conn   *pgconn.PgConn
	source *pgSource

	// TWO CYCLES OVER ONE PIPELINE, differing in one field: Artifact.Format. A base copy is a
	// PGDMP archive beside three plain-SQL files and a change cycle is one decoded change file, so
	// one Cycle carrying both would have to lie about one of them (AD-037, argued at the near-twin
	// in e2e-postgres/run.go).
	base    *backup.Cycle
	changes *backup.Cycle

	// reach is how far this chain restores: the last position that has a manifest AND has been
	// confirmed. It only ever advances in Cycle, after both.
	reach backup.Position

	// wrote is the manifest THIS cycle stored, and nil once a cycle has stored nothing. It is what
	// report.Send posts, and it exists here because nothing else can hold it: a schedule.Fact is
	// assembled by a scheduler that drives a Chain returning a Position and has never seen a
	// manifest.
	//
	// CLEARED AT THE TOP OF EVERY CYCLE, which is the whole of its correctness. Left set, a quiet
	// database's cycle would hand the previous cycle's manifest to the reporter and the control
	// plane would be told a backup happened that did not. It is written and read only on the
	// scheduler's own goroutine — Base or Cycle, then Report, in that order — so unlike pid it
	// needs no atomic.
	wrote *contract.Manifest

	// created says a slot of ours is on the server because THIS process put it there, which is
	// what makes dropping it ours to do. Set only on a base copy that returned without an error.
	created bool

	// broken says the session stands at a point nothing can name, because a cycle died with
	// messages already read (since.go). The next cycle reconnects before it asks for anything.
	broken bool

	// screened says the replica-identity screen has been reported once for this run.
	screened bool

	// pid is the stream's backend, read by the BRAKE from another goroutine while this one
	// reconnects. Atomic because those two are genuinely concurrent — that is the whole point of
	// a brake with its own clock.
	pid atomic.Uint32
}

var _ interface {
	Base(context.Context) (backup.Position, error)
	Cycle(context.Context) (backup.Position, error)
} = (*pgChain)(nil)

func newPGChain(cfg backupConfig, blobs backup.Store, cloud postgres.ControlPlane, out io.Writer) *pgChain {
	pipeline := &backup.Pipeline{Store: blobs}
	return &pgChain{
		cfg:   cfg,
		cloud: cloud,
		out:   out,
		base: &backup.Cycle{
			Pipeline: pipeline,
			Scope:    cfg.scope,
			Format:   contract.FormatPGDumpCustom,
		},
		changes: &backup.Cycle{
			Pipeline: pipeline,
			Scope:    cfg.scope,
			Format:   contract.FormatChangeJSONL,
		},
	}
}

// Base starts a new chain: it releases whatever the last one held, opens a session, and takes the
// full copy that becomes segment 0.
//
// THE RELEASE COMES FIRST AND IT IS NOT TIDINESS. A re-base means the old chain is over, and the
// slot it read through is then holding WAL for a stream nothing will ever consume. Dropping it here
// is also what makes the next createSlot succeed: the name is the same one, so a slot left behind
// would come back as postgres.ErrSlotLeaked instead of a new chain.
func (c *pgChain) Base(ctx context.Context) (backup.Position, error) {
	c.wrote = nil
	if err := c.release(ctx); err != nil {
		return c.reach, err
	}
	if err := c.dial(ctx); err != nil {
		return c.reach, err
	}

	m, err := c.base.Base(ctx, c.source)
	// TAKEN BEFORE THE ERROR IS LOOKED AT, and that ordering is the whole of the fix.
	// backup.Cycle.Base runs four failure paths AFTER postgres.Base has created the slot and
	// returned — checkCopy, the read-back of every object, the audit, the manifest PUT — and the
	// read-back alone can take minutes on the largest object in the product. A SIGTERM or a 503 in
	// that window used to leave this process believing it had created nothing, so release() dropped
	// nothing, and the slot sat on the customer's primary holding WAL that only a future run of
	// ours could ever free.
	c.created = c.source.created
	if err != nil {
		return c.reach, err
	}

	// THE FINGERPRINT THE CHAIN IS FOUNDED ON. Cycle.Base deliberately does not read BaseSchema —
	// it is the call that establishes it — so it is taken from the manifest and the change cycles
	// are configured with it. Without this every cycle is refused for having nothing to compare,
	// and a migration under the chain reaches a restore months later as a shape nobody saw coming.
	c.changes.BaseSchema = m.Schema
	c.reach = backup.Position(m.ReadPoint.Position)
	c.wrote = &m
	c.broken = false
	return c.reach, nil
}

// Cycle extends the chain by one: collect, store, manifest, and only then confirm.
func (c *pgChain) Cycle(ctx context.Context) (backup.Position, error) {
	c.wrote = nil
	if c.broken || c.source == nil {
		// since.go tells a caller in three separate messages to do exactly this, and it is the
		// only recovery available: a replication session cannot rewind, so the way back to a named
		// position is a new session resuming from the last one that is durable — which is reach,
		// because reach only advances after a manifest AND a confirm.
		if err := c.dial(ctx); err != nil {
			return c.reach, err
		}
		c.broken = false
	}

	m, err := c.changes.Run(ctx, c.source, c.reach)
	if err != nil {
		// A quiet database is not a broken session: nothing was read, so nothing was lost.
		if !errors.Is(err, backup.ErrNoChanges) {
			c.broken = true
		}
		return c.reach, err
	}

	// CONFIRM COMES LAST AND IT IS A SEPARATE ACT. since.go will not produce another batch until
	// this one is confirmed, and confirming before the manifest is in the container tells Postgres
	// it may discard WAL that is durable nowhere.
	if err := c.source.Confirm(ctx, backup.Position(m.ReadPoint.Position)); err != nil {
		c.broken = true
		// The manifest IS in the container, so the chain really does reach further than reach
		// says — but nothing confirmed it, so the server still holds the WAL and the next session
		// resumes from a position we know. Under-claiming is the safe direction and the only one.
		return c.reach, fmt.Errorf("backup: the batch reaching %s is stored and the server was not "+
			"told: %w", m.ReadPoint.Position, err)
	}
	c.reach = backup.Position(m.ReadPoint.Position)
	c.wrote = &m
	return c.reach, nil
}

// manifest is what the cycle that just ended stored, for report.Send. Nil after a cycle that stored
// nothing — a quiet database, a failure, a chain declared over — and that is the answer the reporter
// needs rather than a stale manifest it would post as this cycle's.
func (c *pgChain) manifest() *contract.Manifest { return c.wrote }

// dial opens a replication session and the stream over it. It is the whole of "reconnect", and it
// does NOT touch the slot: the slot outlives any one session, which is why it is created not
// temporary (slot.go) and why a reconnect leaves no hole.
func (c *pgChain) dial(ctx context.Context) error {
	c.closeConn(ctx)

	conn, err := postgres.Connect(ctx, c.cfg.pg)
	if err != nil {
		return err
	}
	version := strings.TrimSpace(conn.ParameterStatus("server_version"))
	major, _, _ := strings.Cut(version, ".")

	subject := contract.BackupSource{
		Provider:   contract.ProviderAzure,
		ResourceID: strings.ToLower(c.cfg.serverID),
		// THE SAME STRING THE ENVELOPE CARRIES, and it must be: contract.CycleReport.Account is
		// authoritative and this one is what lets a manifest read out of the container on its own
		// still be placed. Already folded by normalise(), because it is a key.
		Account:  c.cfg.vault.SubscriptionID,
		Database: c.cfg.pg.Database,
		Engine:   "postgres",
		// Load-bearing at RESTORE rather than here: a dump from 16 fails against a 14 target at
		// the very end of a long restore, in the middle of an incident. An empty one is refused by
		// Cycle.check rather than defaulted.
		EngineVersion: major,
	}
	producer := contract.Producer{Agent: agentName, Tool: "postgres " + version}
	c.base.Subject, c.changes.Subject = subject, subject
	c.base.Producer, c.changes.Producer = producer, producer

	c.conn = conn
	c.pid.Store(conn.PID())
	c.source = &pgSource{
		Stream: &postgres.Stream{
			Conn:        conn,
			Slot:        c.cfg.slot,
			Publication: c.cfg.publication,
			Interval:    c.cfg.interval,
			// REPORTED ON EVERY CYCLE INCLUDING THE ONE THAT FOUND NOTHING, which is the cycle a
			// stream that has silently stopped receiving hides in: from the outside that looks
			// exactly like a quiet database, and Messages is the only number that tells them
			// apart. Zero over a whole interval is the signal — a healthy wal sender keepalives
			// whether or not anything is committing.
			Report: func(l postgres.Lag) {
				fmt.Fprintf(c.out, "backup lag: behind=%dB messages=%d collected=%s\n",
					l.Bytes, l.Messages, l.Took.Round(time.Millisecond))
			},
		},
		cloud: c.cloud,
	}
	c.screen(ctx, conn)
	return nil
}

// screen reports which tables cannot be replayed, once per run.
//
// AD-021, LITERALLY: it is a fact and it is not a verdict. A table with no replica identity decodes
// as an UPDATE nothing can apply, and the customer may know that perfectly well about a log table.
// So the run says what it found and carries on; deciding whether that is acceptable is the control
// plane's job with the customer's own recovery objective in front of it.
//
// IT MUST RUN BEFORE START_REPLICATION, which is why it sits at the end of dial: once the connection
// is in CopyBoth no ordinary statement runs on it at all.
func (c *pgChain) screen(ctx context.Context, conn *pgconn.PgConn) {
	if c.screened {
		return
	}
	found, err := postgres.Screen(ctx, conn)
	if err != nil {
		// NOT marked done. A screen that could not run has reported nothing, and leaving the flag
		// set would mean an operator hears about replica identity exactly once, as a failure, and
		// never again for the life of the process.
		fmt.Fprintf(c.out, "backup: could not screen the tables for replica identity: %v\n", err)
		return
	}
	c.screened = true
	if warning := postgres.Warning(found); warning != "" {
		fmt.Fprintln(c.out, warning)
	}
}

// release closes the session and drops the slot this process created. It is the ONLY place a slot
// is dropped here, and it runs both on a re-base and from the one defer that covers every exit.
//
// THE DROP RUNS ON A CONTEXT THAT SURVIVES THE CANCELLATION, and that is the whole safety of a
// SIGTERM: a slot only this role can remove (AD-034 — the customer's administrator cannot) must not
// be left holding WAL on the customer's primary because the container was asked to stop.
//
// THE SESSION IS CLOSED FIRST AND THE DROP RUNS OVER A NEW CONNECTION. Two measured facts force
// that: a slot cannot be dropped while a session holds it (55006), and after START_REPLICATION the
// stream's connection is in CopyBoth and serves no ordinary statement at all.
func (c *pgChain) release(ctx context.Context) error {
	// ONE DEADLINE OVER THE WHOLE OF IT — the close, the dial and the drop — because what this has
	// to fit inside is a container's termination grace period, 30 seconds by default on Kubernetes
	// and similar on ACI. A budget per step adds up past that, and being SIGKILLed halfway through
	// is the exact leak this function exists to prevent.
	releaseCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), releaseTimeout)
	defer cancel()

	c.closeConn(releaseCtx)
	if !c.created {
		return nil
	}

	conn, err := postgres.Connect(releaseCtx, c.cfg.pg)
	if err != nil {
		return fmt.Errorf("%w: %q could not be dropped because no connection to the primary could "+
			"be opened to drop it with. It is holding WAL on the PRIMARY, only the role that "+
			"created it can remove one, and Azure turns a Flexible Server read-only at 95%% disk: %w",
			postgres.ErrSlotLeaked, c.cfg.slot, err)
	}
	defer func() { _ = conn.Close(releaseCtx) }()

	if err := postgres.DropSlot(releaseCtx, conn, c.cfg.slot); err != nil {
		return fmt.Errorf("%w: %w", postgres.ErrSlotLeaked, err)
	}
	c.created = false
	fmt.Fprintf(c.out, "backup: replication slot %q dropped\n", c.cfg.slot)
	return nil
}

// closeConn ends the session and tells the brake there is no stream to recognise.
//
// Closing sends a Terminate message, and a shutdown that skipped it would leave the server to
// notice the socket in its own time — with the slot still active, which is exactly the state a drop
// cannot run against. The budget is the CALLER'S, so release()'s single deadline covers this too
// rather than being added to.
func (c *pgChain) closeConn(ctx context.Context) {
	if c.conn == nil {
		return
	}
	closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), releaseTimeout)
	defer cancel()

	// THE STREAM STOPS ANSWERING BEFORE THE CONNECTION GOES. A cycle that failed while STORING
	// leaves a batch handed out and never confirmed, and since.go keeps that connection alive
	// with liveness replies until Confirm — so this is reached with a goroutine still writing to
	// it, and pgconn is not safe for two. Stream.Close waits for that goroutine to be gone; it
	// closes nothing itself, because the connection is this file's to close.
	if c.source != nil {
		c.source.Close()
	}
	_ = c.conn.Close(closeCtx)
	c.conn, c.source = nil, nil
	c.pid.Store(0)
}

// streamPID is what the brake reads to tell OUR wedged stream from a stranger's healthy one. Zero
// means there is no stream, which the brake reads as "nothing of ours is consuming this slot".
func (c *pgChain) streamPID() uint32 { return c.pid.Load() }
