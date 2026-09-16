// Package chain answers one question: is this chain whole, or is a file missing out of it?
//
// WHY NO MANIFEST CAN ANSWER IT. Every check this repo had before this file was inside one
// cycle — the objects hash, the artifact is whole, the manifest went last. All of them can pass
// on every file in a chain that has a hole in the middle of it, because the loss is BETWEEN two
// files: what happened after one file's end never reached the next one's start. Nothing
// downstream re-derives that. It is caught here, or it is found by a customer at restore.
//
// IT NEVER LOOKS INSIDE A POSITION, and that is the whole design (backup-shape.md §5). Ordering,
// gap detection and "is this chain intact" are questions only the source can answer, because only
// Postgres knows that 0/1A2B3C8 follows 0/1A2B000. The moment this file parses an LSN, MySQL
// binlog coordinates break it. So it asks through Ordered and compares for equality, which is the
// one thing §5 allows — and a source that cannot order its own positions gets an honest report of
// what went unchecked rather than a guess.
//
// EVERY RANGE CHECK IS PHRASED SO THAT THE HEALTHY CASE MUST BE PROVEN. Not "fail if the source
// says there is a gap" but "fail unless the source says there is not", because a source that
// cannot place a position answers no to everything — and under the other phrasing that answer
// would read as a clean chain.
//
// IT MOVED HERE IN D2, WHICH IS WHERE THIS FILE SAID IT WOULD. Replay runs in restore/, which
// cannot import agent/internal at all, and it verifies the same chain the agent wrote against the
// same notion of order. So the verifier, Position and Ordered are one top-level package that
// depends on contract and nothing else, agent/internal/backup aliases the two types to keep the
// seam's vocabulary, and the Postgres orderer restore/ needs is chain/postgres. Nothing was
// reimplemented, because two answers to "is this chain intact" is how the two start disagreeing.
package chain

import (
	"errors"
	"fmt"
	"strings"

	"github.com/manukyanv07/parity-scanner/contract"
)

// Position is a point in a source's own timeline: a WAL LSN, a binlog file and offset, a snapshot
// id, a change-feed cursor. OPAQUE outside the source that issued it — store it, hand it back,
// compare it for equality, never parse it and never order it. The moment anything above the seam
// tries to order two of these itself, MySQL binlog coordinates break it (backup-shape.md §5).
type Position string

// Ordered is OPTIONAL, and it is how a source orders two of its own Positions.
//
// It exists because "is this chain intact" cannot be answered anywhere else. A gap between two
// change files is the difference between one file's end and the next one's start, and only the
// source can tell that difference from an overlap — only Postgres knows that 0/1A2B3C8 follows
// 0/1A2B000, and a chain verifier that compared the strings itself would be broken by the first
// MySQL binlog coordinate it met (§5). So the verifier asks; it never reaches into a Position.
//
// Follows is STRICTLY later: Follows(p, p) is false. Equality is the caller's to check, and it
// already can — comparing two Positions for equality is the one thing §5 allows.
//
// A SOURCE THAT CANNOT ORDER ITS POSITIONS SIMPLY DOES NOT IMPLEMENT THIS, and a caller gets it
// with an assertion that is allowed to fail:
//
//	order, _ := src.(Ordered)   // nil when the source cannot, which Verify reports honestly
//
// Ordering nothing is a fact to report, not a reason to guess (AD-021).
type Ordered interface {
	Follows(later, earlier Position) bool
}

// Checked is how far Verify was able to go. It is returned even on the happy path so that a
// caller can never mistake "nothing was checked" for "nothing was wrong".
type Checked string

const (
	// CheckedWhole means the shape AND every range were checked: a hole anywhere in this chain
	// would have been found.
	CheckedWhole Checked = "whole"

	// CheckedShapeOnly means the source cannot order its own positions, so THE GAPS WERE NOT
	// CHECKED. The chain is well formed and whether it is complete is unknown. A caller
	// restoring from it is restoring from something nobody could verify, and it has to say so.
	CheckedShapeOnly Checked = "shape-only"
)

// Verify checks a chain end to end: the base's position, each file in order, and the last
// position the source was told was durable.
//
// order is the source that issued these positions, and it may be nil — see CheckedShapeOnly. A
// caller gets one with an assertion that is allowed to fail: order, _ := src.(Ordered).
//
// An error means the chain is not whole and NOTHING SHOULD BE RESTORED FROM IT — not the part
// before the hole, not the base on its own. A partial restore is a database that looks like it
// worked, and the returned Checked is empty on every failing path so there is nothing on the
// error branch that reads as a verified chain.
func Verify(chain contract.Chain, order Ordered) (Checked, error) {
	if err := checkShape(chain); err != nil {
		return "", err
	}
	if order == nil {
		return CheckedShapeOnly, nil
	}
	if err := checkRanges(chain, order); err != nil {
		return "", err
	}
	return CheckedWhole, nil
}

// checkShape is everything that can be known without ordering anything: a chain nothing could
// restore, whatever its ranges turn out to say.
func checkShape(chain contract.Chain) error {
	if len(chain.Segments) == 0 {
		return errors.New("backup: this chain has no segments, so there is no base to restore " +
			"and nothing to lay over one")
	}
	if chain.Confirmed == "" {
		// Checked against its own last segment a chain always reaches exactly as far as it
		// reaches. Without an independent record of how far it SHOULD reach, a file lost off the
		// end of it is invisible — and the end is where the newest data is.
		return errors.New("backup: this chain records no confirmed position, so nothing says how " +
			"far it should reach and a file missing from the end of it cannot be seen")
	}

	base := chain.Segments[0]
	if base.Kind != contract.BackupBase {
		return fmt.Errorf("backup: this chain does not begin with a base; its first segment is a "+
			"%q, and change files restore into nothing", base.Kind)
	}

	for i, segment := range chain.Segments {
		if err := checkSegment(i, segment, base); err != nil {
			return err
		}
	}
	return nil
}

// checkSegment is one segment against the base its chain is built on.
func checkSegment(i int, segment, base contract.Manifest) error {
	switch {
	case segment.ReadPoint.Position == "":
		return fmt.Errorf("backup: segment %d records no position, so nothing can say where the "+
			"chain stands after it", i)

	case i > 0 && segment.Kind != contract.BackupChange:
		// A base halfway along is a second chain's first file. Restoring it over the first would
		// throw away every change between them, and it is the shape a re-base leaves behind when
		// the two chains get assembled into one.
		return fmt.Errorf("backup: segment %d is a %q and only the first segment of a chain may "+
			"be a base", i, segment.Kind)

	case i > 0 && segment.ReadPoint.From == "":
		// One end alone says where the file reached and nothing about what it began after, which
		// is exactly the hole this whole file exists to make visible.
		return fmt.Errorf("backup: segment %d does not say where it begins, so a hole between it "+
			"and the file before it could never be seen", i)

	case len(segment.Artifact.Parts) == 0:
		return fmt.Errorf("backup: segment %d lists no objects, so there is nothing to restore "+
			"from it and the range it claims to cover is carried by nothing", i)

	case segment.Source.ResourceID != base.Source.ResourceID || segment.Source.Database != base.Source.Database:
		// Chains are assembled by listing a container, and two databases' manifests under one
		// prefix assemble into a chain that verifies and restores one database's changes into
		// the other.
		return fmt.Errorf("backup: segment %d backs up %s/%s and this chain's base backs up "+
			"%s/%s", i, segment.Source.ResourceID, segment.Source.Database,
			base.Source.ResourceID, base.Source.Database)

	case SchemaMoved(base.Schema, segment.Schema):
		// Logical decoding does not carry DDL, so a change file captured against a different
		// schema replays into columns that are not there or silently misses ones that are.
		// Noticing it at capture time and scheduling a re-base is the agent's (rebase.go), which
		// calls SchemaMoved rather than restating it; this is the backstop, and it is what
		// makes the per-segment fingerprint worth writing down.
		return fmt.Errorf("backup: segment %d was captured against schema %s and this chain's "+
			"base against %s; the changes in it do not fit the database it would restore into",
			i, segment.Schema, base.Schema)
	}
	return nil
}

// SchemaMoved is THE rule, and it is called from both ends of the system: by the agent's cycle at
// capture time (rebase.go), and by checkSegment above at restore. It lives here because this is the
// one package both ends already import — two spellings of it is how an agent comes to extend a
// chain its own verifier would reject.
//
// It is false when either side is empty, and that is not tolerance — it is the honest answer to
// "did it move", which is that nobody knows. The two callers then differ, deliberately: the agent's
// cycle REFUSES a comparison it cannot make (see mark), because it knows what its own source
// reported a moment ago; checkSegment tolerates one, because a manifest may have been written by a
// producer or a version that never filled the field, and Manifest.Schema is validated by nothing on
// the wire.
//
// IT IS NOT A STRING COMPARISON, AND THE REASON IS A DEPLOYMENT RATHER THAN A DATABASE. A
// fingerprint carries one digest per algorithm its agent knows (contract.Manifest.Schema has the
// form and the why), because widening what a fingerprint reads moves the digest of every schema in
// existence: under a string comparison the first cycle after such a release would re-base every
// chain in the fleet, simultaneously, for nothing. So this compares the algorithms both ends
// actually hold, and "the way we fingerprint changed" stops looking like "the customer's schema
// changed".
//
// The rule is: MOVED IF ANY SHARED ALGORITHM DISAGREES. Not "if the newest one does" — an agent that
// only knows the older algorithm must still be answered — and not "if all of them do", which lets an
// older digest that cannot see a change outvote a newer one that can. A change only the newest
// algorithm sees (SET LOGGED moves no column and no replica identity) ends the chain, provided both
// ends took it.
//
// AND NO ALGORITHM IN COMMON IS A MOVE. That is the conservative answer rather than the honest one,
// deliberately: everywhere else in this file "nobody knows" is allowed to read as "carry on", but
// only where a caller checks separately (see backup.mark). Here there is no such caller, and two
// agents far enough apart to share no algorithm are two agents that cannot vouch for each other's
// chain. A re-base costs a base copy; the alternative costs the restore.
//
// What this does NOT do, and cannot: give a chain the protection of an algorithm its base never
// took. A chain based before relpersistence was fingerprinted holds no v2 digest at its base, so
// SET LOGGED under it goes unseen until it next re-bases for some other reason. Nothing can recover
// a field that was never recorded; the alternative was re-basing the fleet to record it.
func SchemaMoved(base, captured string) bool {
	if base == "" || captured == "" {
		return false
	}
	theirs := digests(captured)
	compared := false
	for algorithm, ours := range digests(base) {
		other, both := theirs[algorithm]
		if !both {
			continue
		}
		compared = true
		if ours != other {
			return true
		}
	}
	return !compared
}

// digests splits a fingerprint into its digest per algorithm. The wire form is
// contract.Manifest.Schema's, which is where it is written down and why it is spelled that way.
//
// A part is tagged when what follows its first colon still contains one, which tells a version from
// a hash name without this package having to know either — and leaves anything unrecognisable,
// including a value from a source that fingerprints some other way entirely, under the empty
// algorithm, where it is compared with whatever else arrived under that name. Which is what the
// whole field did before any of this.
func digests(fingerprint string) map[string]string {
	out := make(map[string]string, 2)
	for _, part := range strings.Fields(fingerprint) {
		algorithm, digest := "", part
		if tag, rest, _ := strings.Cut(part, ":"); strings.Contains(rest, ":") {
			algorithm, digest = tag, rest
		}
		out[algorithm] = digest
	}
	return out
}

// checkRanges walks the chain from the base to the confirmed position, asking the source about
// each consecutive pair. Two questions per pair and one at the end, and nothing else is asked.
func checkRanges(chain contract.Chain, order Ordered) error {
	previous := chain.Segments[0]
	for i := 1; i < len(chain.Segments); i++ {
		segment := chain.Segments[i]
		from := Position(segment.ReadPoint.From)
		reached := Position(segment.ReadPoint.Position)
		before := Position(previous.ReadPoint.Position)

		// CONTINUITY. The file must begin at or before where the last one ended. Equal is the
		// adjacent case; beginning EARLIER is an overlap, and an overlap is what a healthy chain
		// looks like — replay is at-least-once by construction (AD-039: after confirming nothing,
		// every transaction came back at the same LSNs), and the base overlaps the first change
		// file by design (AD-035). Overlap is resolved at replay, which is the only layer that
		// can be idempotent. A gap never is.
		if from != before && !order.Follows(before, from) {
			return fmt.Errorf("backup: nothing in this chain covers what happened between %s, "+
				"where segment %d ended, and %s, where segment %d begins: a file is missing, or "+
				"these segments are in the wrong order", before, i-1, from, i)
		}

		// ADVANCE. Every file must carry the chain forward. A file that does not is a duplicate,
		// a file out of order, or a position the source cannot place at all — and the last of
		// those is why this is phrased as a demand rather than as a test for going backwards.
		if !order.Follows(reached, before) {
			return fmt.Errorf("backup: segment %d reaches %s, which does not carry the chain past "+
				"%s where segment %d left it", i, reached, before, i-1)
		}
		previous = segment
	}

	// THE END OF THE CHAIN, WHICH IS WHERE THE NEWEST DATA IS. Reaching past the confirmed
	// position is the ordinary window between storing a batch and confirming it; falling short of
	// it means a file that was captured and confirmed is not here.
	last := Position(chain.Segments[len(chain.Segments)-1].ReadPoint.Position)
	confirmed := Position(chain.Confirmed)
	if last != confirmed && !order.Follows(last, confirmed) {
		return fmt.Errorf("backup: this chain ends at %s and the source was told %s is durable, "+
			"so everything between them was captured and is missing from here", last, confirmed)
	}
	return nil
}
