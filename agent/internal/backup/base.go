package backup

// base.go writes THE CHAIN'S SEGMENT 0 — the one manifest that says a base copy exists — and it
// writes it LAST, for the same reason manifest.go writes a change cycle's last: a manifest beside
// an artifact nobody finished checking is worse than no backup at all, because it will be believed.
//
// UNTIL THIS FILE, NOBODY WROTE ONE. chain.Verify refuses a chain whose first segment is not a
// contract.BackupBase, and manifest.go's describe says in as many words that it only ever produces
// a change — "whoever builds that writes its own manifest". Nobody did, so no chain this repo
// produced could ever be verified end to end: the base copy happened, four files landed, and
// nothing anywhere recorded them as the foundation the change files are laid on.
//
// WHAT IS DIFFERENT ABOUT A BASE, AND IT IS THE WHOLE OF THIS FILE:
//
//   - THE AGENT DID NOT MOVE THESE BYTES. Azure Backup restores the server as files straight into
//     our container (AD-033), so this manifest describes objects the agent VERIFIES rather than
//     ones it produced. It reads each one back, hashes what it read, and names the object where it
//     lies — at the path the CLOUD chose, which is why Part.Path exists. Nothing is stored except
//     the manifest, and contract.RouteProviderCopy is the honest transfer route.
//
//     That is a weaker guarantee than hashing a stream in flight, and it is stated as what it is
//     (backup-shape.md §6): a hash taken from a read-back proves the object is intact and does not
//     prove it matches what the database gave us, because nothing we ran ever saw what the database
//     gave us. It is the strongest claim available on this route, and it is still the rule that a
//     manifest never references a hash it did not verify.
//
//   - THE FOUR PARTS ARE NOT ALIKE. database.sql is a PGDMP archive and roles.sql, schema.sql and
//     tablespaces.sql are plain SQL (AD-033). contract.Part carries Format and Role per part for
//     exactly this, and an UNLABELLED PART IS REFUSED HERE rather than defaulted — the measured
//     cost of guessing was a restore that reported success with the roles, the grants and the
//     tablespaces silently missing (AD-037).
//
//   - THE POSITION IS THE SLOT'S, TAKEN BEFORE THE COPY WAS ASKED FOR. postgres/base.go creates the
//     replication slot first and reads its confirmed_flush_lsn while the copy has not started, so
//     the seam's promise holds: the Position is at or before the state of the bytes, never after.
//     This file records it unchanged and never orders it, which is what gives the chain's first
//     segment a position for the first change file to resume from.
//
//   - THE SCHEMA FINGERPRINT IS THE CHAIN'S. C5 compares every later cycle against it (rebase.go),
//     and until it is written down there is nothing to compare against — a migration under the
//     chain then reaches a restore months later as a shape mismatch nobody saw coming.
//
// WHERE THE MANIFEST GOES, AND WHY IT IS NOT WHERE THE OBJECTS ARE. It goes under a prefix this
// cycle GENERATES, exactly as manifest.go does and for the identical reason: two cycles sharing a
// prefix is one manifest over another's objects, corrupt and passing every check, so there is
// nothing for a caller to get wrong. The objects it names stay where Azure put them, which is
// outside that prefix — so the audit below does not apply manifest.go's containment rule, because
// applying it would mean either lying about the paths or copying four files to satisfy it.
//
// THAT LEFT ONE THING FOR RETENTION, AND prune.go DOES IT: pruning by the cycle's prefix would
// reach the manifest and NOT the four largest objects in the system, which sit at the container
// root. So nothing there parses a prefix — a chain's objects are the paths its manifests name, and
// backup.Segment carries the manifest's own path alongside it because a base's cannot be derived
// from one of its parts.
//
// WHAT A FAILURE HERE DOES NOT CLEAN UP, SAID PLAINLY BECAUSE THE CONTAINER IS THE CHEAP HALF.
// postgres.Base returns with the replication slot STILL ON THE SERVER — deliberately, because it
// is the change stream's from that moment on (AD-033). Every failure in this file happens after
// that, so it leaves a slot nobody but us can drop, holding WAL on the customer's primary, with no
// manifest and therefore no chain that would ever consume it. This package cannot drop one: it
// knows nothing about databases, and the credential is the caller's (AD-035). So it is the
// caller's — the same owner as the safety brake's disk half (backup-shape.md §6), and the brake
// (C6) is what stops it becoming the runaway. Named here rather than left for somebody to discover.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/manukyanv07/parity-scanner/contract"
)

// Base checks the full copy the cloud left in our container and writes the manifest that makes it
// the chain's first segment. The manifest it returns is the one that is in the store.
//
// IT MOVES NO BYTES. The one Put it makes is the manifest, and every failure before that Put leaves
// the container exactly as the restore left it, with nothing claiming a backup.
//
// Cycle.BaseSchema is NOT READ HERE, and that is the direction of the dependency rather than an
// omission: this is the call that ESTABLISHES the fingerprint a chain's later cycles are compared
// against, so a caller takes it from the returned manifest's Schema and configures the change
// cycles with it.
func (c *Cycle) Base(ctx context.Context, src Source) (contract.Manifest, error) {
	if err := c.check(); err != nil {
		return contract.Manifest{}, err
	}

	// Taken before the source is asked, so the instant recorded is at or before the state of the
	// bytes and never after — the same reason manifest.go takes it where it does.
	at := time.Now().UTC()
	prefix := c.prefixFor(at)

	batch, err := src.Base(ctx)
	if err != nil {
		return contract.Manifest{}, fmt.Errorf("backup: ask the source for the base copy: %w", err)
	}

	// BEFORE THE FIRST BYTE IS READ BACK, which is run.go's rule about names applied to the larger
	// number: a base copy is the biggest thing this agent ever touches, and discovering after
	// hundreds of gigabytes that a part was never labelled costs the whole read for a fact that was
	// on the batch all along.
	if err := checkCopy(batch, prefix); err != nil {
		return contract.Manifest{}, err
	}

	// VERIFIED BEFORE ANYTHING IS CLAIMED, and every return from here to the write below leaves no
	// manifest in the container.
	parts, err := readBack(ctx, batch.Parts)
	if err != nil {
		return contract.Manifest{}, err
	}
	if err := auditBase(parts); err != nil {
		return contract.Manifest{}, err
	}

	written := c.describeBase(batch, parts, at)
	// One Put, through the one writer — see Cycle.put for why that single call is the whole of the
	// atomicity, and why this object must never acquire a chunking path.
	if err := c.write(ctx, prefix, written); err != nil {
		return contract.Manifest{}, err
	}
	return written, nil
}

// checkCopy refuses a base copy on the facts THE SOURCE SUPPLIED, before a byte of it is read.
//
// Everything here is knowable from the batch alone, and none of it gets cheaper to discover later:
// an unlabelled part is unlabelled whether or not its hundred gigabytes have been read, and a base
// with no position is one nothing could ever resume from however whole its objects turn out to be.
func checkCopy(batch Batch, prefix string) error {
	if len(batch.Parts) == 0 {
		return fmt.Errorf("backup: the base copy under %s has no objects, and a manifest over "+
			"none would claim a chain founded on nothing", prefix)
	}
	if batch.Position == "" {
		// The first change file resumes from this. A base with no position is one the stream
		// cannot be started from, and a chain whose segment 0 records none can never be ordered
		// against segment 1 — the hole is then permanently invisible.
		return fmt.Errorf("backup: the base copy under %s recorded no position, so the change "+
			"stream would have nothing to resume from", prefix)
	}
	if batch.From != "" {
		// contract.ReadPoint: empty on a base, which begins after nothing. A base that claims a
		// range start is claiming to continue a chain that does not exist, and a verifier reading
		// it would place segment 0 somewhere it never was.
		return fmt.Errorf("backup: the base copy under %s says it begins at %q; a base begins "+
			"after nothing, and a range start on one describes a chain before the chain", prefix, batch.From)
	}

	seen := make(map[string]bool, len(batch.Parts))
	for _, part := range batch.Parts {
		switch {
		case part.Path == "":
			// The agent did not choose these paths and cannot reconstruct them. A part that does
			// not say where it is, is an object nothing will ever find again — and it is how a
			// batch meant for the pipeline arrives here by mistake.
			return fmt.Errorf("backup: the object %q of this base copy does not say where it is, "+
				"and the agent did not put it there, so nothing could ever read it back", part.Name)
		case part.Format == "" || part.Role == "":
			// AN UNLABELLED PART IS REFUSED, NOT DEFAULTED. contract.Part treats empty as "nobody
			// said" precisely so a restorer does not have to guess, and the measured cost of
			// guessing was a restore reporting success with the roles, the grants and the
			// tablespaces silently missing (AD-037). Refused here, where the copy can still be
			// taken again, rather than at a restore in the middle of an incident.
			return fmt.Errorf("backup: nobody labelled %s — it is format %q, role %q — and a "+
				"restorer refuses a part it would have to guess the meaning of", part.Path, part.Format, part.Role)
		case part.Open == nil:
			// Documented as never nil. A source that breaks that would panic the agent in the
			// middle of a cycle, and library code does not panic (CONTRIBUTING.md).
			return fmt.Errorf("backup: part %q has no Open, so there is no object to check and "+
				"nothing a manifest could vouch for", part.Path)
		case part.Path == prefix+"/"+manifestName:
			// The manifest is written last, so an object here would be destroyed by the very
			// manifest that lists it.
			return fmt.Errorf("backup: %s sits where the %s goes and would be overwritten by it",
				part.Path, manifestName)
		case seen[part.Path]:
			return fmt.Errorf("backup: %s appears twice, so one of the two objects the manifest "+
				"would list overwrote the other", part.Path)
		}
		seen[part.Path] = true
	}
	return nil
}

// readBack reads every object of the copy and describes what it actually holds.
//
// IT IS THE ONLY THING BETWEEN A RESTORE-AS-FILES AND A MANIFEST, so it reads each object WHOLE: a
// hash taken from anything less would describe a half-written container perfectly. The bytes are
// read and dropped a buffer at a time, because a base copy is the largest thing this agent ever
// touches.
//
// WHAT THIS CAN AND CANNOT CLAIM, said once rather than implied. A hash from a read-back proves the
// object is intact and does NOT prove it matches what the database gave us, because nothing we ran
// ever saw what the database gave us (backup-shape.md §6). It is the strongest claim available on
// this route, and the rule it keeps is still the rule: a manifest never references a hash it did
// not verify.
//
// NOTHING IS RETRIED. A change cycle retries a part because re-opening it costs one more read of a
// stream that is still there; here a failure means the container does not hold what the restore
// said it wrote, and reading it a second time asks the same question of the same bytes. The copy is
// taken again, from the top, by whoever schedules — the expensive answer and the only correct one.
func readBack(ctx context.Context, parts []Part) ([]contract.Part, error) {
	checked := make([]contract.Part, 0, len(parts))
	for _, part := range parts {
		// BETWEEN OBJECTS, WHICH IS AS FAR AS THIS CONTEXT REACHES. Part.Open carries no context of
		// its own — the Azure reader closes over the one RestoreAsFiles was asked on — so a single
		// enormous database.sql is not interruptible from here. What this buys is that a cancelled
		// cycle does not go on to read the objects after it, and that it stops with no manifest.
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("backup: checking the base copy: %w", err)
		}
		one, err := readBackOne(part)
		if err != nil {
			return nil, err
		}
		checked = append(checked, one)
	}
	return checked, nil
}

// readBackOne reads one object to the end and hashes what it read.
//
// CLOSE IS THE LAST MOMENT ANYTHING CAN STILL REFUSE, exactly as it is in the pipeline: the object
// arrives as a body on a socket, and a truncated response can deliver its verdict at Close while
// the read side saw an ordinary EOF. Its error is never discarded.
func readBackOne(part Part) (contract.Part, error) {
	stream, err := part.Open()
	if err != nil {
		return contract.Part{}, fmt.Errorf("backup: open %s to check it: %w", part.Path, err)
	}

	sum := sha256.New()
	read, readErr := io.Copy(sum, stream)
	if readErr != nil {
		readErr = fmt.Errorf("backup: read %s back: %w", part.Path, readErr)
	}
	closeErr := stream.Close()
	if closeErr != nil {
		closeErr = fmt.Errorf("backup: close %s: %w", part.Path, closeErr)
	}
	if readErr != nil || closeErr != nil {
		// Joined rather than ranked when both fire: the one a human can act on is not reliably the
		// first.
		return contract.Part{}, errors.Join(readErr, closeErr)
	}

	return contract.Part{
		// WHERE IT IS, NOT WHERE WE PUT IT. Part.Open is required to read exactly this object, and
		// the whole of "never a hash it did not verify" rests on that for this route: a Path naming
		// one object and an Open reading another would produce a manifest that is internally
		// perfect and points a restore at bytes nobody hashed.
		Path:   part.Path,
		Bytes:  read,
		SHA256: hex.EncodeToString(sum.Sum(nil)),
		// The source's own labels, carried and never read here. Only the source can say which of
		// the four files is the archive (AD-037).
		Format: part.Format,
		Role:   part.Role,
	}, nil
}

// auditBase is what is only knowable AFTER every object has been read, and it is the same pair of
// rules manifest.go's audit applies to an artifact the pipeline produced.
//
// Neither can fire today: readBackOne computes the hash and counts the bytes itself. That is the
// point — the guarantee is "never", not "never so far", so the day something else builds these
// parts the manifest fails loudly instead of quietly claiming a backup.
func auditBase(parts []contract.Part) error {
	for _, part := range parts {
		switch {
		case !isSHA256(part.SHA256):
			// The rule, literally: a manifest never references a hash it did not verify.
			return fmt.Errorf("backup: the checksum %q on %s is not a sha256 this cycle computed, "+
				"and a manifest never references a hash it did not verify", part.SHA256, part.Path)
		case part.Bytes <= 0:
			// A restore-as-files that wrote an empty object wrote a copy no restore can use, and an
			// 11-minute copy refused loudly beats one claimed and found hollow at a restore.
			return fmt.Errorf("backup: %s carries no bytes, so this base copy is not one anything "+
				"could be restored from", part.Path)
		}
	}
	return nil
}

// describeBase turns a checked copy into the chain's segment 0. It reads the read-back parts and
// the Cycle's own fields and takes nothing from anywhere else, which is what makes "never a hash it
// did not verify" a property of the shape rather than of a code path.
//
// IT DIFFERS FROM manifest.go's describe IN EXACTLY TWO FIELDS — Kind and Transfer — and the
// commentary below covers only those. The empty From, the empty whole-artifact SHA256 and the nil
// Skipped mean there what they mean here, and describe is where they are argued.
func (c *Cycle) describeBase(batch Batch, parts []contract.Part, at time.Time) contract.Manifest {
	var total int64
	for _, part := range parts {
		total += part.Bytes
	}

	return contract.Manifest{
		ContractVersion: contract.BackupContractVersion,

		// THE ONE KIND THIS ENTRY POINT CAN PRODUCE, and the reason it exists: chain.Verify requires
		// Segments[0].Kind to be this, and no other writer in the repo produces one.
		Kind: contract.BackupBase,

		Source: c.Subject,
		ReadPoint: contract.ReadPoint{
			At: at.Format(time.RFC3339),
			// The slot's confirmed_flush_lsn, read BEFORE the copy was requested (AD-033), carried
			// unchanged and never parsed. It is at or before the state of these bytes, so the base
			// and the first change file OVERLAP — which is health, resolved at replay, and the
			// survivable side of the one trade this route forces.
			Position: string(batch.Position),
			// Empty, and checkCopy refuses anything else: a base begins after nothing.
			From: "",
		},
		// THE FINGERPRINT THE CHAIN IS FOUNDED ON. Every later cycle is compared against this one
		// (rebase.go), and a base that did not write it down leaves C5 with nothing to hold a
		// migration against.
		Schema: batch.Schema,

		Artifact: contract.Artifact{
			// What the artifact PRINCIPALLY is, which is a judgment only a producer can make and is
			// deliberately not read off the parts — that is the sniffing AD-037 closes, and a
			// heterogeneous copy has no first-part answer anyway.
			Format: c.Format,
			Bytes:  total,
			// There was no single stream here to hash: the cloud wrote four objects and the agent
			// read four objects back. Part.SHA256 is what vouches for anything.
			SHA256: "",
			// In the order the source reported them.
			Parts: parts,
		},
		Producer: c.Producer,

		// THE CLOUD MOVED THESE BYTES AND OUR CODE WAS NEVER IN THE BYTE PATH (AD-033). Recorded on
		// every cycle and compared on ingest, because the day a base falls back to being streamed
		// by the agent is the day cost and latency both jump with nothing else able to see it.
		Transfer: contract.RouteProviderCopy,

		// Nil, the claim that nothing was skipped. A restore-as-files copies the server or it
		// fails: postgres/base.go refuses a restore that reported success and wrote no files, and
		// one that wrote no archive.
		Skipped: nil,
	}
}
