// Package backup is the seam between the pipeline and the things it copies.
//
// THE ONE RULE (docs/specs/backup-shape.md §1): the pipeline never branches on what kind of
// data it is backing up. Not once. Everything type-specific lives behind Source, and
// everything the pipeline needs arrives as data returned by Source — never as a type it
// inspects. Four unrelated technologies collapse into two operations: give me everything,
// and give me what changed since here. The rest — chunking, checksumming in flight,
// uploading, position bookkeeping, writing the manifest last — is written once and is the
// same for a pg_dump and a disk snapshot.
//
// WHAT THIS SEAM REFUSES TO MODEL: the credential a source authenticates with. Azure Postgres
// needs two of entirely different natures — a control-plane identity to obtain the base copy,
// a Postgres role with REPLICATION and no table access to read the stream — and they fail in
// different vocabularies. None of it enters this file: the pipeline does the same thing
// whichever credential produced the bytes, so anything naming the difference here would exist
// only for something downstream to branch on, which is §1 broken in the package's first file.
// It is constructor-time, not call-time. Rejected alternatives and why: AD-035.
//
// ORDERED SHIPPED WITH ITS FIRST CONSUMER, exactly as AD-035 said it would: the chain verifier
// (E9.4), where a hole between two change files has to be detectable rather than silent. It
// changes nothing about the pipeline, which still stores a Position, hands it back and compares
// it for equality, and never orders one. Ordering happens in one function, by asking the source.
//
// POSITION AND ORDERED ARE DEFINED IN chain/ AND ALIASED HERE, and the direction is deliberate.
// Replay (E9.9) runs in restore/, which cannot import agent/internal at all, and it has to verify
// the same chain against the same notion of order that the agent wrote it with. Two definitions
// of "does this position follow that one" is exactly how two answers to "is this chain intact"
// start disagreeing, so there is one, and the seam's vocabulary (backup-shape.md §4) is kept by
// an alias rather than by a copy.
package backup

import (
	"context"
	"errors"
	"io"

	"github.com/manukyanv07/parity-scanner/chain"
	"github.com/manukyanv07/parity-scanner/contract"
)

// Position is a point in a source's own timeline: a WAL LSN, a binlog file and offset, a
// snapshot id, a change-feed cursor. OPAQUE outside the source that issued it — store it,
// hand it back, compare it for equality, never parse it and never order it. The moment the
// pipeline tries to order two of these itself, MySQL binlog coordinates break it (§5).
type Position = chain.Position

// Ordered is not aliased here. Position is, because it is the seam's own vocabulary and appears
// in Source and Batch below; Ordered appears in neither, and its one caller is the chain verifier,
// which names chain.Ordered directly. A second name for an interface nothing in this package
// mentions is a name for somebody to wonder about.

// Source is one thing that can be backed up. Two methods, because two is all that actually
// varies; collectors.Collector is the same size and has carried four clouds.
type Source interface {
	// Base produces a full copy, consistent at the Position it reports.
	//
	// THE POSITION MUST BE AT OR BEFORE THE STATE OF THE BYTES IT RETURNS — never after. A
	// source that reports a Position later than its own copy leaves a gap nothing
	// downstream can detect or repair: the next Since resumes from a point the copy never
	// reached, the chain looks intact, and the missing rows are found at restore. Postgres
	// on Azure keeps the promise by creating its replication slot BEFORE requesting the
	// copy; a disk source keeps it by returning the snapshot id. Same promise, different
	// mechanics, and sequencing it belongs in here rather than in the orchestrator (AD-035).
	//
	// The price of the promise is that a base and the changes after it OVERLAP. That is
	// expected, not an error, and the pipeline cannot even see it: noticing an overlap
	// means comparing two Positions, which §5 forbids. It is resolved at replay, the only
	// layer that can be idempotent (E9.9).
	Base(ctx context.Context) (Batch, error)

	// Since produces what changed after from, and the Position that reaches. It returns
	// ErrNoChanges when nothing happened — not an empty Batch.
	//
	// A source that cannot answer Since returns a plain error and the pipeline falls back
	// to Base. That is the honest description of a full-copy-every-time source, and it
	// costs the pipeline no special case.
	Since(ctx context.Context, from Position) (Batch, error)
}

// Batch is one unit the pipeline can store and account for.
type Batch struct {
	// Position is where this batch leaves us. The next Since starts from it.
	Position Position

	// From is where this batch BEGINS, and it is the source's own account of what it actually
	// delivered — NOT an echo of the Position it was asked from. The two differ exactly when it
	// matters: a source that lost its slot and made a new one resumes later than it was asked,
	// and reporting the request instead would claim this batch begins where the last one ended,
	// leaving a chain that is contiguous on paper with the changes in between gone (C4).
	//
	// Beginning EARLIER than asked is fine and normal — replay is at-least-once (AD-039) — and
	// the overlap is resolved at replay, the only layer that can be idempotent.
	//
	// The pipeline stores it, hands it back and never orders it against anything. Whether the
	// two ends of two batches leave a hole between them is a question only the source can
	// answer, through Ordered, and only chain.go asks it.
	//
	// Empty on Base, which begins after nothing.
	From Position

	// Schema is the fingerprint at capture time, and empty where the idea is meaningless —
	// a disk snapshot has no schema. Nothing validates it, and nothing may start to: a
	// required field here would force every future source to invent a value it does not
	// have.
	Schema string

	// Parts is one or more streams. A Batch returned with a nil error carries AT LEAST ONE
	// part: a source with nothing to hand over says so with ErrNoChanges. Zero parts and no
	// error drains clean and ends in a manifest over nothing — the same false claim the
	// sentinel exists to prevent, arrived at from the other side.
	//
	// One dump is one stream today; §6 records that parallel parts wait for a source that
	// needs them.
	Parts []Part
}

// Part is one stream a source PRODUCES, before anything has been stored.
//
// Not to be confused with contract.Part (Path/Bytes/SHA256), which is one object that
// LANDED in the store and is manifest-side. This is the input to that one, and carries
// neither a size nor a checksum because neither is known until the stream has been read.
type Part struct {
	// Name becomes the object's path in the store (contract.Part.Path), so it must be a
	// single path element — no separators, no "..", nothing that writes outside the prefix —
	// and unique within its Batch. Two parts sharing a Name overwrite each other in the
	// store and leave a manifest listing both.
	Name string

	// Path is where this object ALREADY IS, and it is set by a source whose bytes THE CLOUD
	// moved into our container rather than the agent streaming them — which for an Azure base
	// copy is all four of them (AD-033). It is backup-shape.md §6's known gap arriving, and it
	// arrives in Part exactly as §8 predicted it would.
	//
	// EMPTY IS THE ORDINARY CASE and means the agent stores the stream itself, at a path the
	// pipeline decides from Name. The two are alternatives, not a fallback: run.go refuses a
	// part that says it is already stored, because storing one would copy an object onto
	// itself and describe the copy as one we made. base.go is what reads a set one, and it
	// stores nothing at all — it reads each object back, hashes it, and names it in the
	// manifest where it lies.
	//
	// WHERE IT IS SET, Open MUST READ EXACTLY THIS OBJECT. That is not a convention: the hash
	// in the manifest comes from what Open yielded and the path comes from here, so a source
	// that let the two drift would produce a manifest which is internally perfect and points a
	// restore at bytes nobody ever hashed.
	Path string

	// Format and Role become contract.Part.Format and contract.Part.Role, and the SOURCE is
	// the only layer that can fill them: an Azure base copy is one PGDMP archive beside three
	// plain-SQL files, and by the time the bytes reach the pipeline nothing distinguishes
	// them. Carried as data, not as something to branch on (§1) — the pipeline copies them
	// into the manifest and never reads them.
	//
	// EMPTY IS NOT A DEFAULT. contract.Part records what the measured cost of guessing was
	// (AD-037): a restore that reported success with the roles, grants and tablespaces
	// silently missing. A part nobody labelled is one a restorer refuses, so a source with
	// more than one part fills both, and a source whose single part makes the question
	// meaningless leaves them empty.
	Format string
	Role   contract.PartRole

	// Open is never nil, and must yield a FRESH reader on every call. The pipeline retries an
	// upload, and a second Open handing back the spent reader would upload zero bytes with
	// every check still green — a short object with a manifest over it, which is worse than
	// no backup at all (E6.10).
	//
	// A CLEAN READ IS NOT A WHOLE STREAM. A part is often a process on a pipe or a body on a
	// socket, and both deliver their verdict at Close while the read side sees an ordinary
	// EOF — pg_dump reports failure by exiting, so a Close that wraps the wait is where
	// "exit status 1" arrives. Close is therefore the last moment the pipeline can still
	// refuse to write a manifest, and its error is never discarded (E6.13).
	Open func() (io.ReadCloser, error)
}

// ErrNoChanges is what Since returns when nothing has happened since the given Position.
//
// A sentinel rather than an empty Batch, because "nothing changed" must not be able to look
// like "a batch that happens to be empty". The second flows through the pipeline like any
// other and ends in a manifest over a zero-byte artifact — a claim that a backup happened.
var ErrNoChanges = errors.New("backup: no changes since the given position")
