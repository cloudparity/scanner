package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/manukyanv07/parity-scanner/agent/internal/backup"
)

// THE ORDER OF THE TWO CALLS IN THIS FILE IS THE PRODUCT'S CORRECTNESS. Everything else here is
// plumbing around it.
//
//	slot first  → backup second  =  OVERLAP          (repaired by idempotent replay)
//	backup first → slot second   =  SILENT GAP       (never repaired, never detected)
//
// Measured both ways (AD-033): under the wrong order a row written between the backup and the slot
// is in NEITHER, and the restored database looks perfectly healthy. Nothing downstream can see it,
// because seeing it would mean ordering two Positions, which backup-shape.md §5 forbids the
// pipeline to do. There is no later layer that catches this; there is only this order.
//
// HOW THIS KEEPS THE SEAM'S PROMISE. backup.Source.Base requires the Position it reports to be AT
// OR BEFORE the state of the bytes it returns, never after. Creating the slot BEFORE asking for the
// copy is exactly how Postgres keeps that promise: the slot's start LSN is taken while the copy has
// not begun, so the copy can only be later. Azure does not expose the LSN of a vaulted backup, so
// an exact meeting point is impossible and overlap is the best available — and the overlap is on
// the survivable side, which is what the promise buys. Sequencing it belongs here rather than in
// the orchestrator (AD-035), and the pipeline never learns that any of this happened.
//
// The sequence, and the failure branch is not decoration:
//
//	1. schema fingerprint → H0
//	2. create the slot              ← from here the stream loses nothing
//	3. request the Azure backup
//	4. if the backup fails → DROP THE SLOT   (otherwise this is the runaway-WAL scenario, C6)
//	5. schema fingerprint → H1
//	6. if H0 != H1 → discard and retry from 1   (DDL in the window)
//	7. restore as files into our container

// maxBaseCopyAttempts bounds step 6. A database under continuous migration would otherwise spin
// here forever, holding a slot for a moment on every pass and reporting nothing — an agent that
// looks alive and never produces a backup. Three, because the window is however long the backup
// takes (~9 min measured), so three attempts is most of an hour: a schema still moving after that
// is a fact to report, not a race to keep losing.
const maxBaseCopyAttempts = 3

// dropTimeout bounds the drop that runs on a context that has already been cancelled.
const dropTimeout = 30 * time.Second

// duplicateObject is what the server answers when the slot is already there. Matched on the
// SQLSTATE and never on the message: AD-036 measured the wording differs across 14 and 18 for
// identical conditions, and slot_docker_test.go measures that this code does not.
const duplicateObject = "42710"

// ErrSlotLeaked marks the one failure in this file that nobody can clean up afterwards.
//
// Measured: ONLY THE OWNING ROLE CAN DROP A REPLICATION SLOT — the customer's administrator cannot.
// So a slot of ours left on the customer's PRIMARY is holding WAL and is removable by nobody but
// us. Azure flips a Flexible Server to read-only at 95% disk, which means a leaked slot takes the
// customer's production database down some hours after a backup that did not even happen.
//
// IT SAYS "A SLOT ON OUR NAME IS ON THE SERVER AND THIS CALL DID NOT PUT IT THERE", NOT "THIS CALL
// FAILED TO DROP ONE", and the difference is the whole of alreadyOnTheServer below. A drop that
// fails is only the half that produces an error at the time; the half that produces none — a kill
// between the create and the next statement — reaches a caller solely because a later cycle's 42710
// is reported through this same sentinel.
//
// WHICH IS ALSO THE LIMIT OF WHAT IT CLAIMS, AND C6 MUST NOT READ MORE INTO IT. It does not say
// nothing is consuming the slot: a healthy install that has already taken its base copy leaves the
// slot on the server for the change stream, so a second Base against a live chain arrives here too,
// as does a second agent process during a rolling restart. Dropping on the sentinel alone would cut
// a stream that is working. The brake has to confirm the slot is idle before it drops one; what
// this sentinel buys is that the condition is VISIBLE at all, which as a plain duplicate-object
// error it was not.
//
// A sentinel rather than a message, because the safety brake (C6) has to branch on it, and because
// this is the alert that must not wait for someone to read a log line.
var ErrSlotLeaked = errors.New("postgres: a replication slot was left on the server")

// DDL inside the window is backup.ErrSchemaMoved — THE SAME SENTINEL THE CHANGE CYCLES USE, not a
// private one. This file catches the schema moving across the base copy's own window (steps 1/5/6);
// C5 catches it moving between that base and any later cycle (backup/rebase.go). One fact, two
// windows, and the caller's answer to both is identical: discard what was captured and take a new
// base copy. A second sentinel would mean a scheduler that handled one of them and retried the
// other forever.
//
// Retried here rather than returned, because inside this function there is a cheaper answer than
// re-basing: the copy has not been kept yet, so starting the window again is enough.

// ControlPlane is Azure Backup, as AD-033 measured it end to end: two control-plane calls, THREE
// ARM ROLES AND ZERO DATA-PLANE ACTIONS. The agent never opens a database connection to obtain the
// base copy — which is why the only Postgres credential in this package is a REPLICATION role that
// can read no customer table at all.
//
// AN INTERFACE HERE FOR ONE REASON: every failure in the sequence above is unreachable against a
// real cloud. A backup that fails, a slot that will not drop, DDL landing inside a nine-minute
// window — none can be provoked against Azure, and all of them are where the data loss lives. This
// is backup-shape.md §7 applied one level down: if it needed a real cloud to test, we would test
// the happy path and ship the rest.
//
// THE REAL IMPLEMENTATION IS AzureBackup, beside the fake rather than instead of it. It speaks ARM
// REST over azidentity, because the agent ships as a `scratch` image and the `az` command AD-033
// measured with cannot live in one; every endpoint it calls carries the Microsoft reference it
// came from. The interface stays for the reason above, which the existence of a real client does
// not change: the failure paths are where the data loss is, and none of them is reachable against
// a live subscription.
//
// E6.5 STILL OWNS THE THREE ARM ROLES. controlplane.go records the exact operations it calls, at
// the scope it calls them on, so that ticket names roles against something measured rather than
// against a guess.
type ControlPlane interface {
	// Backup asks for an on-demand backup and returns the recovery point it produced. Measured at
	// 9 minutes, so the window this sequence has to survive is minutes, not milliseconds.
	//
	//	az dataprotection backup-instance adhoc-backup ...
	Backup(ctx context.Context) (recoveryPoint string, err error)

	// RestoreAsFiles writes that recovery point into OUR container, as files, and returns them as
	// the parts of a batch: database.sql in PGDMP format, plus roles.sql, schema.sql and
	// tablespaces.sql. Measured at 2 minutes.
	//
	//	az dataprotection restore initialize-for-data-recovery-as-files --target-blob-container-url ...
	//
	// The bytes are moved by the cloud, not by us (contract.RouteProviderCopy), so the parts here
	// read BACK what Azure wrote rather than producing it. That is a weaker guarantee than hashing
	// a stream in flight and must be described as what it is — backup-shape.md §6 records it as an
	// open shape, and E6.9 settles it.
	RestoreAsFiles(ctx context.Context, recoveryPoint string) ([]backup.Part, error)
}

// Base produces the full copy and the Position the change stream resumes from.
//
// THE TWO CREDENTIALS MEET HERE AND NOWHERE ELSE. They are of entirely different natures — ARM RBAC
// for the copy, a Postgres role with REPLICATION and no table access for the stream — and they fail
// in different vocabularies. AD-035 settled that none of that may reach the seam: the pipeline does
// the same thing whichever credential produced the bytes, so anything naming the difference
// downstream would exist only for something to branch on.
//
// A FUNCTION AND NOT A TYPE YET, matching CreateSlot beside it. AD-035 sketches the eventual shape
// as postgres.New(armCred, pgCred) with Base and Since as methods; the struct is worth writing on
// the ticket that has a Since to put in it (C1/C3), when the compile-time assertion against
// backup.Source finally compiles as an assertion. A type called Source with no Since today would
// read as the seam's Source and not be one.
func Base(ctx context.Context, cloud ControlPlane, conn *pgconn.PgConn, slot string) (backup.Batch, error) {
	// server_version comes from the startup packet, so it costs no round trip — see CreateSlot.
	return baseCopy(ctx, cloud, simpleQueryRows(conn), conn.ParameterStatus("server_version"), slot)
}

func baseCopy(ctx context.Context, cloud ControlPlane, q querySQL, serverVersion, slot string) (backup.Batch, error) {
	// Checked once, here, before anything runs — including before the control plane is touched,
	// since a nine-minute backup for a name we would refuse afterwards is pure waste. createSlot
	// checks it again; this is what makes the drop and the position query, which interpolate the
	// same name, safe by construction (AD-036: a replication connection has no bind parameters).
	if err := validateSlotName(slot); err != nil {
		return backup.Batch{}, err
	}

	var last error
	for attempt := 1; attempt <= maxBaseCopyAttempts; attempt++ {
		batch, err := baseCopyOnce(ctx, cloud, q, serverVersion, slot)
		if err == nil {
			return batch, nil
		}
		// Only DDL in the window is worth another nine minutes. Everything else — a slot that
		// cannot be created, a container we cannot write — is returned as it is, because retrying
		// it would repeat the same failure and hide the first, clearest report of it.
		//
		// A LEAK IS CHECKED FIRST, AND THE ORDER OF THESE TWO CONDITIONS IS ITSELF A BUG FIXED. The
		// two are not alternatives: a discarded attempt whose drop ALSO failed carries both, because
		// abandon joins the cause it was given. Testing backup.ErrSchemaMoved alone therefore retries a
		// leak — and the retry spends another nine-minute backup on top of a slot already
		// accumulating WAL on the primary, which is the runaway the brake exists to stop, not a
		// thing to do twice more while the disk fills.
		//
		// It no longer also LOSES the sentinel on the way: since alreadyOnTheServer, the retry's
		// 42710 carries ErrSlotLeaked too. That is the belt to this brace, and the brace stays —
		// what it prevents is the wasted backups, and that reason never depended on the other.
		if errors.Is(err, ErrSlotLeaked) || !errors.Is(err, backup.ErrSchemaMoved) {
			return backup.Batch{}, err
		}
		// The discarded attempt's recovery point stays in the vault; nothing here removes it, so a
		// schema under continuous migration orphans up to maxBaseCopyAttempts of them. Pruning them
		// belongs with whatever owns the vault (E6.9/E6.11), not here.
		last = err
	}
	// THE ONE PLACE THE SENTINEL IS DELIBERATELY NOT PASSED ON, and %v rather than %w is the whole
	// of how. backup.ErrSchemaMoved means exactly one thing to a caller — take a new base copy —
	// and this is the error that says taking one has already been tried until the bound ran out. A
	// caller that read the sentinel here would start the nine-minute copy again from outside, which
	// is maxBaseCopyAttempts turned into an outer loop and the runaway it exists to stop.
	return backup.Batch{}, fmt.Errorf("postgres: gave up on the base copy after %d attempts, each "+
		"discarded because the schema moved inside it. The schema is still moving; this is a fact "+
		"to report and not something a further attempt fixes: %v", maxBaseCopyAttempts, last)
}

func baseCopyOnce(ctx context.Context, cloud ControlPlane, q querySQL, serverVersion, slot string) (backup.Batch, error) {
	h0, err := fingerprint(ctx, q) // 1
	if err != nil {
		return backup.Batch{}, err
	}

	// 2. THE SLOT COMES FIRST. Do not move this below the Backup call: see the file header.
	//
	// A failure here returns without dropping anything, and that is deliberate rather than an
	// omission of step 4. The commonest failure is 42710 — the slot already exists — and dropping
	// on that path would destroy a slot this call did not create, which is a chain silently
	// ending. Nothing else here can undo a create it did not make. What that same 42710 does get is
	// a name: see alreadyOnTheServer.
	if err := createSlot(ctx, q.exec(), slot, serverVersion); err != nil {
		return backup.Batch{}, alreadyOnTheServer(slot, err)
	}

	// Read while the copy has not started, which is what makes the seam's promise true rather than
	// merely likely: whatever Azure captures next is at or after this LSN.
	position, err := slotPosition(ctx, q, slot)
	if err != nil {
		return backup.Batch{}, abandon(ctx, q, slot, err)
	}

	recoveryPoint, err := cloud.Backup(ctx) // 3
	if err != nil {
		// 4. NOT OPTIONAL AND NOT BEST-EFFORT. A slot kept for a backup that does not exist is
		// the C6 runaway-WAL scenario with nothing to show for it.
		return backup.Batch{}, abandon(ctx, q, slot,
			fmt.Errorf("postgres: ask the control plane for the base copy: %w", err))
	}

	h1, err := fingerprint(ctx, q) // 5
	if err != nil {
		return backup.Batch{}, abandon(ctx, q, slot, err)
	}
	if h0 != h1 { // 6
		return backup.Batch{}, abandon(ctx, q, slot,
			fmt.Errorf("%w: %s before, %s after", backup.ErrSchemaMoved, h0, h1))
	}

	parts, err := cloud.RestoreAsFiles(ctx, recoveryPoint) // 7
	if err != nil {
		return backup.Batch{}, abandon(ctx, q, slot,
			fmt.Errorf("postgres: restore the base copy as files: %w", err))
	}
	// Zero parts and no error is the same false claim a manifest over nothing makes, arrived at
	// from the other side (backup.Batch). It has to be caught HERE, while the slot can still be
	// dropped, rather than downstream where it drains clean.
	if len(parts) == 0 {
		return backup.Batch{}, abandon(ctx, q, slot,
			errors.New("postgres: the restore reported success and wrote no files"))
	}

	// h0 and h1 are equal by the check above; h0 is the one taken with the copy.
	return backup.Batch{Position: position, Schema: h0, Parts: parts}, nil
}

// alreadyOnTheServer names the one create failure that means a slot only we can drop is sitting on
// the customer's primary, and leaves every other one exactly as it came.
//
// THE FAILURE IT EXISTS FOR PRODUCES NO ERROR AT ALL WHEN IT HAPPENS. Kill the agent — OOM, node
// reboot, SIGKILL — between createSlot returning and the next statement, and Base never returns:
// abandon does not run, nothing is reported, and the slot is on the PRIMARY holding WAL. The only
// trace left anywhere is that every later cycle fails at createSlot with 42710. Read as a plain
// duplicate-object error that looks like a harmless retry, and nothing ever drops the slot while
// the customer's disk fills toward the 95% at which Azure turns the server read-only.
//
// So 42710 on a name of OURS is reported through ErrSlotLeaked even though this call created
// nothing. It is not a claim about what this call did, and it is deliberately not a claim about
// HOW the slot got there: from here a slot left by a killed run, one a healthy chain is streaming
// from, and one a second process created a moment ago are indistinguishable — 42710 and the name
// is the whole of the evidence. What the sentinel asserts is only the part that is certain and that
// a plain error hid: a slot nobody but us can drop is on the primary. Which of the three it is, and
// therefore whether to drop it, is the brake's to establish (C6) — see ErrSlotLeaked.
//
// On a name that is not ours it is returned untouched. isOurs says how ours are recognised, and why
// the two must never be confused: dropping a customer's own slot breaks THEIR replication.
//
// NOTHING IS DROPPED HERE, and that is the same rule step 2 states: this call created nothing, so
// there is nothing here it could be undoing.
func alreadyOnTheServer(slot string, err error) error {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != duplicateObject || !isOurs(slot) {
		return err
	}
	return fmt.Errorf("%w: %q was already on the server before this cycle created anything. Only "+
		"the role that created it can drop one — an administrator cannot. It holds WAL on the "+
		"PRIMARY, and Azure turns the server read-only at 95%% disk. Establish whether anything is "+
		"consuming it before dropping it: %w", ErrSlotLeaked, slot, err)
}

// slotPosition reads back where the slot the previous statement created starts.
//
// confirmed_flush_lsn rather than restart_lsn: it is the point decoding resumes from, which is what
// replay needs, and it is the value pg_create_logical_replication_slot itself reports. An empty one
// is an error rather than an empty Position — a Position nothing can resume from would send the
// first Since to the beginning of the WAL or to nowhere, and both are found at restore.
func slotPosition(ctx context.Context, q querySQL, slot string) (backup.Position, error) {
	// Not an injection: every caller has just put slot through validateSlotName, which allow-lists
	// it to [a-z0-9_]{1,63} — baseCopy directly, since.go via checkSlot — and a replication
	// connection has no bind parameters to use instead (AD-036).
	const query = "SELECT confirmed_flush_lsn FROM pg_replication_slots WHERE slot_name = '%s'"

	rows, err := q(ctx, fmt.Sprintf(query, slot))
	if err != nil {
		return "", fmt.Errorf("postgres: read the start position of slot %q: %w", slot, err)
	}
	if len(rows) != 1 || len(rows[0]) != 1 || rows[0][0] == "" {
		return "", fmt.Errorf("postgres: slot %q reported no start position (%v); the change stream "+
			"would have nothing to resume from", slot, rows)
	}
	return backup.Position(rows[0][0]), nil
}

// abandon drops the slot and returns the error the caller should see.
//
// EVERY FAILURE AFTER THE SLOT EXISTS COMES THROUGH HERE, which is the invariant worth stating
// plainly: when Base returns an error, no slot is left behind. Step 4 names the backup because that
// is the long step, but a failed restore, a fingerprint that will not run and a discarded attempt
// leave exactly the same slot holding exactly the same WAL.
//
// When the drop ITSELF fails the two causes are joined rather than ranked. An operator told only
// that the backup failed goes to Azure; an operator told only about the slot goes to the database;
// the one who needs to act needs both, and the sentinel is what makes the second one alertable.
func abandon(ctx context.Context, q querySQL, slot string, cause error) error {
	const drop = "SELECT pg_drop_replication_slot('%s')"

	// WithoutCancel so that a cancellation which arrived while we were WAITING ON AZURE — the long
	// step, and the likeliest place to be cut short — does not also cancel the drop and turn a
	// timeout into a leaked slot.
	//
	// IT DOES NOT SAVE A DROP WHOSE CONNECTION THE CANCELLATION ALREADY KILLED, and the difference
	// matters. pgx cancels an in-flight query by putting a deadline on the socket; the read fails
	// fatally and the connection is closed asynchronously. So a cancel landing inside slotPosition
	// or the second fingerprint poisons the connection this drop would run over, and the slot is
	// reported leaked even though a fresh connection could still have dropped it. Redialing here is
	// deliberately not done: this function is given a connection, not a Config, and the credential
	// belongs to the caller (AD-035). Whatever owns the reconnect owns that recovery.
	dropCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dropTimeout)
	defer cancel()

	if _, err := q(dropCtx, fmt.Sprintf(drop, slot)); err != nil {
		return fmt.Errorf("%w: %q is still on the server after the base copy failed, and only the role "+
			"that created it can drop one — an administrator cannot. It holds WAL on the PRIMARY, and "+
			"Azure turns the server read-only at 95%% disk: %w",
			ErrSlotLeaked, slot, errors.Join(cause, err))
	}
	return cause
}
