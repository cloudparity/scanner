package backup

// manifest.go writes the one object that says a backup happened, and it writes it LAST.
//
// THE WHOLE FILE IS THAT ORDER: store every object, audit what landed, and only then claim it.
// A manifest beside an incomplete artifact is worse than no backup at all, because it will be
// believed — nothing downstream re-derives it. A restore reads this object, trusts the paths and
// the hashes in it, and reports success. So every failure before the Put at the end of Run must
// end with no manifest in the container, and that is what the tests here are for.
//
// WHERE B3 STOPS AND THIS STARTS. Pipeline.Since returns a Result and makes no claim that a
// backup happened; this turns a Result into the claim. Nothing here branches on what was backed
// up either (backup-shape.md §1) — a Result is paths, sizes and hashes, and this file cannot
// tell a WAL segment from a disk snapshot any more than run.go can.
//
// IT DOES NOT CLASSIFY THE STORE'S FAILURES. store.Blob.Put reports its HTTP status inside a
// message, so a 403 and a 429 are retried alike; that gap is owned by pacing and written down in
// backup-shape.md §6. It does not change what this file guarantees — an upload that fails for
// any reason, well-paced or not, ends with no manifest.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/manukyanv07/parity-scanner/contract"
)

// manifestName is the object that makes a cycle a backup. One spelling, because the audit that
// keeps an artifact object off this path and the tests that assert no manifest appeared both
// have to mean the same object.
const manifestName = "manifest.json"

// Cycle is one backup cycle end to end: the pipeline's bytes, then the manifest over them.
//
// Its fields are the facts a manifest needs that no Result carries — who we are, what we were
// backing up, what the artifact principally is. They are constructor-time and per-installation,
// never per-cycle, which is why they sit on the struct instead of in Run's signature.
type Cycle struct {
	// Pipeline stores the bytes. Its Store is also where the manifest goes: one container, and
	// a manifest in a different one from its artifact is a chain nothing can follow.
	Pipeline *Pipeline

	// Scope is the stable root every cycle for this source writes under, e.g.
	// "install-7/pg1/orders". IT IS NOT THE PREFIX — see prefixFor.
	Scope string

	// Subject is what is being backed up, in the contract's vocabulary. Named to keep it apart
	// from the Source interface Run is handed: this is the description, that is the bytes.
	Subject contract.BackupSource

	// BaseSchema is the fingerprint THE CHAIN'S BASE COPY WAS CAPTURED AGAINST, and every cycle
	// is compared against it — see rebase.go for why nothing else can see a DDL change. It is
	// per-chain rather than per-cycle: it changes only when a new base is taken, which is exactly
	// what a mismatch here schedules.
	//
	// Empty is legitimate only for a source that has no schema at all, such as a disk snapshot. A
	// cycle whose source reports a fingerprint and whose BaseSchema is empty is REFUSED rather
	// than run, because the alternative is a chain extended across every migration the customer
	// ever deploys with nothing anywhere saying so.
	BaseSchema string

	// Producer is what made this, so a bad backup traces to the build that wrote it.
	Producer contract.Producer

	// Format is contract.Artifact.Format — what the artifact PRINCIPALLY is, which is a judgment
	// only a producer can make. NOT derived from the parts: reading it off the first one is the
	// sniffing AD-037 closes, and a heterogeneous artifact has no first-part answer. Per-object
	// format is Part.Format and comes from the source.
	Format string
}

// Run stores one batch of changes and writes the manifest over it. The manifest it returns is
// the one that is in the store; there is no path through this function that returns a manifest
// nobody can find.
func (c *Cycle) Run(ctx context.Context, src Source, from Position) (contract.Manifest, error) {
	if err := c.check(); err != nil {
		return contract.Manifest{}, err
	}

	// TAKEN BEFORE THE SOURCE IS ASKED, so the instant recorded is at or before the state of the
	// bytes and never after. The same promise Source.Base makes about its Position, for the same
	// reason: a read point later than the data it describes leaves a gap that looks like
	// agreement when this backup is compared against a snapshot taken alongside it.
	at := time.Now().UTC()
	prefix := c.prefixFor(at)

	// Already wrapped with what failed and where. Every return from here to the put below leaves
	// the container holding artifact objects and no manifest, which is the state everything
	// downstream reads as "no backup here" — objects nothing references cost storage and cost
	// nothing else.
	result, err := c.Pipeline.Since(ctx, src, from, prefix)
	if err != nil {
		// MOST FAILURES ARE JUST FAILURES and come straight back out. The one that is not is a
		// source saying the thing it streams through has gone — that chain is over, and it is
		// recorded here rather than left as an error the next agent to start never saw (rebase.go).
		return contract.Manifest{}, c.stopped(ctx, err, from, at, prefix)
	}
	// BEFORE THE MANIFEST, ALWAYS. A batch captured against a schema that has moved must not be
	// laid over this base, and the manifest is what would lay it there — so the schema is compared
	// on the way to writing one, on every cycle, and a mismatch ends the chain here instead of at
	// a restore months from now (rebase.go).
	if err := c.mark(ctx, result.Schema, from, at, prefix); err != nil {
		return contract.Manifest{}, err
	}
	if err := audit(result, prefix); err != nil {
		return contract.Manifest{}, err
	}

	written := c.describe(result, at)
	if err := c.write(ctx, prefix, written); err != nil {
		return contract.Manifest{}, err
	}
	return written, nil
}

// write renders a manifest whole and stores it, and it is the ONE place either kind is written —
// base.go's segment 0 comes through here too. A second renderer is how two manifests in one
// container come to be shaped differently, and a reader that has to cope with both is a reader
// that will one day accept a manifest neither writer meant.
//
// Indented because the one object a human opens at 3am should be readable; the wire does not care.
func (c *Cycle) write(ctx context.Context, prefix string, m contract.Manifest) error {
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return fmt.Errorf("backup: render the manifest for %s: %w", prefix, err)
	}
	return c.put(ctx, prefix+"/"+manifestName, body)
}

// put writes the manifest, and it is the last thing that happens.
//
// THE ATOMICITY, IN THE STORE'S ACTUAL PRIMITIVES. Store.Put is one Azure `PUT Blob` carrying
// the complete body and a Content-Length covering it (store/blob.go), and Azure commits a
// single-shot Put Blob as one operation: a reader of this path sees no blob, or the whole blob,
// and never a prefix of one. A body that arrives short of its announced length is rejected
// rather than committed, so a connection that dies mid-request leaves nothing behind.
//
// THAT HOLDS ONLY WHILE THE MANIFEST IS ONE PUT. The artifact is chunked across many objects
// precisely because it can be enormous; the manifest is a list of descriptors and is not, and it
// must never acquire a chunking path — two objects that together make a manifest is exactly the
// half-written state this ordering exists to prevent, and an object store gives us no
// transaction to fix that with.
//
// RETRIED LIKE EVERY OTHER OBJECT, and this is the write where that matters most: it is the
// last, the smallest, and the only one whose failure throws away an artifact that is already
// whole and already paid for. Safe because the bytes are identical on every attempt and each
// attempt is one atomic Put, so a second cannot interleave with the first.
func (c *Cycle) put(ctx context.Context, path string, body []byte) error {
	var last error
	made := 0
	for made < defaultAttempts {
		made++
		last = c.Pipeline.Store.Put(ctx, path, body)
		if last == nil {
			return nil
		}
		// A cancelled context fails identically on every remaining attempt, and they would be
		// spent hiding the first, clearest report of why.
		if ctx.Err() != nil {
			break
		}
	}
	return fmt.Errorf("backup: write %s after %d attempts: %w", path, made, last)
}

// prefixFor is where this cycle's objects live, and B4 GENERATES IT RATHER THAN ACCEPTING ONE.
//
// Pipeline.Since requires a unique prefix and cannot enforce one. Two cycles sharing a prefix is
// one cycle's manifest over the other cycle's objects — corrupt, and passing every check in this
// package, because every object it names exists and hashes correctly. So it is not prevented by
// a caller getting it right; it is prevented by there being nothing to get wrong. The reasoning
// in full is in backup-shape.md §3.
//
// The instant is there to be read by a human; the random tail is what carries the uniqueness,
// because two agents can start a cycle in the same second and a clock can step backwards.
func (c *Cycle) prefixFor(at time.Time) string {
	// rand.Text never hands back weak bytes and never returns an error — it crashes the program
	// rather than do either — so there is no failure branch to write here.
	return c.Scope + "/" + at.Format("2006-01-02T15-04-05Z") + "-" + strings.ToLower(rand.Text()[:16])
}

// audit is the check between the artifact and the claim over it.
//
// WHAT IT IS NOT: a read-back. Re-downloading every object would prove the objects are intact
// and would prove nothing about whether they match what the source produced — the contract says
// so at Artifact.SHA256 — and B3 already closed the gap it would be aimed at, because the store
// is handed the bytes rather than a reader over them (run.go, putChunk). A second pass over an
// artifact that may be hundreds of gigabytes would buy a weaker claim than the one already held.
//
// WHAT IT IS: the rule that a manifest never describes something nobody checked. Most of these
// are shapes the pipeline cannot produce today, and that is the point — the guarantee is
// "never", not "never so far", so the day the pipeline changes the manifest fails loudly instead
// of quietly claiming a backup. Position is the one that is reachable now: run.go copies it
// verbatim from the source and validates nothing.
func audit(result Result, prefix string) error {
	if len(result.Parts) == 0 {
		return fmt.Errorf("backup: the cycle under %s stored no objects, and a manifest over "+
			"none would claim a backup that copied nothing", prefix)
	}
	if result.Position == "" {
		// The next cycle resumes from this. A manifest with no position is one nothing can
		// continue from, and a caller that stored it anyway would re-ask for a batch it already
		// has or skip one it never took — found at restore, as a hole.
		return fmt.Errorf("backup: the cycle under %s recorded no position, so nothing could "+
			"resume from its manifest", prefix)
	}
	if result.From == "" {
		// THE OTHER END OF THE RANGE, and without it the file is permanently unverifiable: a
		// hole between this file and the one before it is the difference between two ends, and
		// one end alone cannot show one. Refused here rather than at restore, because a file
		// nobody will ever be able to check is better not written than written and believed.
		return fmt.Errorf("backup: the cycle under %s does not say where it begins, so a hole "+
			"between it and the backup before it could never be seen", prefix)
	}

	seen := make(map[string]bool, len(result.Parts))
	for _, part := range result.Parts {
		switch {
		case !isSHA256(part.SHA256):
			// Absent, or in a second spelling of the same digest — upper-case hex compares
			// unequal to what a restorer computes, so it reads as a corrupt object rather than
			// a variant. THE RULE, LITERALLY: a manifest never references a hash it did not
			// verify, and this is what "did not verify" looks like on the wire.
			return fmt.Errorf("backup: the checksum %q on %s is not a sha256 this cycle computed, "+
				"and a manifest never references a hash it did not verify", part.SHA256, part.Path)
		case part.Bytes <= 0:
			return fmt.Errorf("backup: %s carries no bytes; no source produces an empty object "+
				"and no restore can use one", part.Path)
		case !strings.HasPrefix(part.Path, prefix+"/"):
			return fmt.Errorf("backup: %s is outside this cycle's prefix %s, so the manifest "+
				"would describe another cycle's object", part.Path, prefix)
		case part.Path == prefix+"/"+manifestName:
			// The manifest is written last, so an artifact object here would be destroyed by
			// the very manifest that lists it.
			return fmt.Errorf("backup: %s sits where the %s goes and would be overwritten by it",
				part.Path, manifestName)
		case seen[part.Path]:
			return fmt.Errorf("backup: %s was written twice, so one of the two objects the "+
				"manifest lists overwrote the other", part.Path)
		}
		seen[part.Path] = true
	}
	return nil
}

// isSHA256 is 64 lower-case hex digits and nothing else.
func isSHA256(sum string) bool {
	if len(sum) != hex.EncodedLen(32) {
		return false
	}
	for _, r := range sum {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// describe turns an audited Result into the manifest. It reads Result.Parts and the Cycle's own
// fields and takes nothing from anywhere else, which is what makes "never a hash it did not
// verify" a property of the shape rather than of a code path.
func (c *Cycle) describe(result Result, at time.Time) contract.Manifest {
	return contract.Manifest{
		ContractVersion: contract.BackupContractVersion,

		// ALWAYS A CHANGE, and that is not a branch on the data — it is the one kind this entry
		// point can produce. AD-033 took the base copy out of the byte path entirely: Azure
		// restores the server as files into our container, so a base is verified rather than
		// produced and there is no Base here to reach. Whoever builds that writes its own
		// manifest, for a copy it did not make.
		Kind: contract.BackupChange,

		Source: c.Subject,
		ReadPoint: contract.ReadPoint{
			At: at.Format(time.RFC3339),
			// The source's own, carried unchanged and never parsed. Only Postgres knows that
			// 0/1A2B3C8 follows 0/1A2B000.
			//
			// BOTH ENDS, because one end alone cannot show a hole between two backups — and the
			// near end is what the SOURCE said it delivered, never the position this cycle asked
			// from. Run has that argument in hand and deliberately does not use it: a source that
			// resumed later than it was asked would otherwise be written up as contiguous.
			Position: string(result.Position),
			From:     string(result.From),
		},
		Schema: result.Schema,

		Artifact: contract.Artifact{
			Format: c.Format,
			Bytes:  result.Bytes,
			// EMPTY, AND THAT IS THE HONEST VALUE. A whole-artifact hash is the single-stream
			// case only; this artifact is chunked and no such stream was ever hashed. Inventing
			// one — a hash of the concatenation, say — would be a digest nothing computed at
			// upload time, which is the one thing a manifest must not carry. Part.SHA256 is what
			// vouches for anything here, and a restorer checks the part it is loading.
			SHA256: "",
			// In the order the pipeline wrote them, which is authoritative — a four-digit
			// ordinal sorts wrong past ten thousand objects, so a listing is not.
			Parts: result.Parts,
		},
		Producer: c.Producer,

		// The agent read these bytes and wrote them. A change stream has no provider-side copy
		// to fall back from, so this is a fact about this entry point rather than a choice made
		// per cycle; the base copy is the one that moves between routes, and it is not written
		// here.
		Transfer: contract.RouteAgentStream,

		// Nil, and nil is the claim that nothing was skipped rather than an unfilled field. It
		// is true for a change stream by construction: Since returns every change after the
		// given position or it returns an error, so there is no third outcome where something
		// was asked for and quietly left out. A source that grows one reports it as a Gap here.
		Skipped: nil,
	}
}

// check refuses a cycle that could not describe what it backed up, BEFORE it stores a byte — and
// before it opens the customer's database, which is why the nil Store is caught here as well as
// in the pipeline. Discovering afterwards that the manifest cannot be written means an artifact
// in the container that nothing will ever reference, paid for in full.
func (c *Cycle) check() error {
	switch {
	case c.Pipeline == nil:
		return errors.New("backup: this cycle has no pipeline, so there is nothing to store the " +
			"bytes it would write a manifest over")
	case c.Pipeline.Store == nil:
		// The pipeline reports this too, but only after it has asked the source — which for
		// Postgres means connecting and creating a replication slot on the customer's server
		// (AD-036) to serve a cycle that was never going to be able to store anything.
		return errors.New("backup: this cycle's pipeline has no store, so there is nowhere for " +
			"the bytes or the manifest to land")
	case c.Scope == "":
		return errors.New("backup: this cycle has no scope, so every cycle for every source " +
			"would write under one root and their manifests would overwrite each other")
	case c.Format == "":
		return errors.New("backup: this cycle names no artifact format, and a restorer refuses " +
			"an artifact it would have to guess how to read")
	case c.Producer.Agent == "":
		return errors.New("backup: this cycle names no producer, so a backup that turns out bad " +
			"traces to no build")
	case c.Subject.Provider == "" || c.Subject.ResourceID == "" || c.Subject.Engine == "":
		return fmt.Errorf("backup: this cycle does not say what it is backing up: %+v", c.Subject)
	case c.Subject.EngineVersion == "":
		// Load-bearing at restore rather than at backup: a dump from 16 fails against a 14
		// target at the very end of a long restore, in the middle of an incident. Recorded here
		// is what lets the target be checked before anything starts.
		return errors.New("backup: this cycle records no engine version, so nothing can check a " +
			"restore target against it before the restore starts")
	}
	// The same rule the pipeline applies to a prefix, applied to the root it is built from, so a
	// scope that leaves itself is caught here rather than one segment later.
	return checkPrefix(c.Scope)
}
