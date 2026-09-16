package backup

// run.go is THE PIPELINE, and backup-shape.md §3 describes it in five words: it knows nothing
// about databases. Read the imports as the enforcement of that — there is no pgx here, no
// pglogrepl, no azcore, and nothing that could tell a WAL segment from a disk snapshot. What
// varies is behind Source; what is written once is here.
//
// THE REVIEW QUESTION, EVERY TIME (§1, §9): does this file branch on what kind of data it is
// backing up? It does not, and the two fields that most look like it would — Part.Format and
// Part.Role — are copied into the result and never read. They are labels a restorer selects on
// (AD-037), carried as data.
//
// WHAT THIS FILE DOES NOT DO, DELIBERATELY:
//
//   - It does not write the manifest. That is B4, and the ORDER is the product's correctness:
//     store every object, check it, and only then claim a backup happened. Result is the seam
//     for it — everything a manifest needs and no claim that one exists.
//   - It has no Base entry point. AD-033 took the base copy out of the byte path: Azure Backup
//     restores the server as files straight into our container, so there is nothing here to
//     upload and nothing in flight to hash. What is left of the base is VERIFYING what the
//     cloud left, which is a different operation with a different guarantee, and §6 records the
//     shape as unsettled with E6.9 owning it. A Base method here would quietly re-upload four
//     files onto themselves and describe the copy as one we made.
//   - It does not fall back from Since to Base. §4 says a source that cannot answer Since gets
//     that fallback, and there is no sentinel to tell "this source never could" from "the
//     network dropped this once" — the second would spend a nine-minute base copy on a blip.
//     Whoever adds the sentinel adds the fallback.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/manukyanv07/parity-scanner/contract"
)

// defaultChunkSize bounds how much of a stream is in memory at once. THE AGENT IS A SMALL
// CONTAINER AND THE CHANGE VOLUME MAY NOT BE SMALL, so the whole stream is never held: one
// chunk is read, hashed, stored and dropped before the next is read. 8 MiB because that is
// what a chunk costs in resident memory and it is the block size Azure's own SDK defaults to.
const defaultChunkSize = 8 << 20

// defaultAttempts is how many times one part is tried before the cycle fails. A retry re-Opens
// and starts from byte zero — see Part.Open — so three is three whole streams, not three
// resumptions of a broken one.
const defaultAttempts = 3

// Store is where bytes land.
//
// ONE METHOD, AND ONE IMPLEMENTATION BEHIND IT (§6: a second store waits for the first AWS
// source). It is an interface at all for the reason §7 gives: a pipeline that needed a real
// container to test would have its failure paths — a refused object, a container we were not
// granted — tested nowhere. It is declared here, where it is consumed, rather than in store/,
// so the package that ships the one implementation ships no abstraction.
//
// A CHUNK AND NOT A STREAM, and that is not the whole stream in memory: it is one chunk of it,
// bounded by Pipeline.ChunkSize, read and dropped before the next is read. Azure Blob requires
// a Content-Length and refuses a chunked transfer encoding, so a body of unknown length cannot
// be sent at all — and handing over the exact bytes rather than a reader over them is what makes
// a short object impossible here rather than merely detected.
//
// AN IMPLEMENTATION MUST NOT RETAIN chunk BEYOND THE CALL. The pipeline reuses one buffer for
// every chunk of a part, so a store that kept the slice — to write it later, or to hand to a
// goroutine — would end up with every object holding the last chunk's bytes.
type Store interface {
	Put(ctx context.Context, path string, chunk []byte) error
}

// Pipeline stores what a Source produces. The zero value needs only a Store.
type Pipeline struct {
	Store Store

	// ChunkSize is the largest object this pipeline writes. Zero means defaultChunkSize.
	ChunkSize int64
}

// Result is everything one batch left in the store, and it is the input to the manifest B4
// writes. IT IS NOT A CLAIM THAT A BACKUP HAPPENED — that claim is the manifest, and it is
// made last, after this returns without an error.
type Result struct {
	// From, Position and Schema are the source's own, carried unchanged. The pipeline stores a
	// Position and hands it back; it never parses one and never orders two (§5).
	//
	// FROM AND POSITION ARE THE RANGE THIS BATCH COVERS, and the near end is the source's answer
	// rather than the position the pipeline asked from — substituting the request here would
	// make a source that resumed late indistinguishable from one that did not, which is the one
	// thing the range exists to expose.
	From     Position
	Position Position
	Schema   string

	// Bytes is the total across every object.
	Bytes int64

	// Parts is EVERY object written, IN THE ORDER IT WAS WRITTEN. A chunk stored and not
	// listed here is one nobody will ever notice is missing, because the objects that are
	// listed checksum and manifest exactly like a whole copy.
	//
	// THIS ORDER IS THE AUTHORITATIVE ONE and a listing of the container is not: the ordinal
	// in an object's name is four digits, so a part chunked past ten thousand objects sorts
	// wrong lexically. Anything that reconstructs a stream reads this list.
	Parts []contract.Part
}

// Since stores what changed after from, under prefix.
//
// prefix is where this cycle's objects live in the store, and TWO CYCLES SHARING ONE OVERWRITE
// EACH OTHER — whoever schedules cycles owns making it unique. ErrNoChanges arrives wrapped and
// survives the wrap, because the caller's alternative to recognising it is taking a base copy.
func (p *Pipeline) Since(ctx context.Context, src Source, from Position, prefix string) (Result, error) {
	batch, err := src.Since(ctx, from)
	if err != nil {
		return Result{}, fmt.Errorf("backup: ask the source for the changes since %q: %w", from, err)
	}
	return p.store(ctx, batch, prefix)
}

// store writes every part of one batch and accounts for every object it wrote.
func (p *Pipeline) store(ctx context.Context, batch Batch, prefix string) (Result, error) {
	if p.Store == nil {
		// Reported rather than dereferenced: library code does not panic (CONTRIBUTING.md), and a
		// nil store would take the agent down mid-cycle with a stack trace instead of the one
		// sentence that says what is misconfigured.
		return Result{}, errors.New("backup: this pipeline has no store, so there is nowhere " +
			"for the bytes to land")
	}
	if err := checkPrefix(prefix); err != nil {
		return Result{}, err
	}
	// A Batch returned with a nil error carries at least one part (§4): a source with nothing
	// to hand over says so with ErrNoChanges. Zero parts drains clean and ends in a manifest
	// over nothing, which is the same false claim the sentinel exists to prevent.
	if len(batch.Parts) == 0 {
		return Result{}, errors.New("backup: the source returned a batch with no parts and no " +
			"error; a manifest over it would claim a backup that copied nothing")
	}
	// Every name is checked BEFORE the first byte is stored. Finding the eighth part's name
	// unusable after seven have been written leaves seven objects nothing will ever reference.
	if err := checkNames(batch.Parts); err != nil {
		return Result{}, err
	}

	out := Result{From: batch.From, Position: batch.Position, Schema: batch.Schema}
	for _, part := range batch.Parts {
		stored, err := p.storePart(ctx, part, prefix)
		if err != nil {
			return Result{}, err
		}
		for _, object := range stored {
			out.Bytes += object.Bytes
		}
		out.Parts = append(out.Parts, stored...)
	}
	return out, nil
}

// storePart tries one part until it stores whole or the attempts run out.
//
// A FAILED ATTEMPT MAY HAVE LEFT OBJECTS BEHIND, and nothing here removes them. That is safe
// for the reason the manifest exists: an object no Result lists is an object no manifest
// references, and the next attempt overwrites the ones it reaches. Sweeping them is prune.go's,
// not the middle of a cycle that is still failing — it is the debris case there, and it is safe
// precisely because the manifest goes last.
func (p *Pipeline) storePart(ctx context.Context, part Part, prefix string) ([]contract.Part, error) {
	var last error
	made := 0
	for made < defaultAttempts {
		made++
		stored, err := p.storeOnce(ctx, part, prefix)
		if err == nil {
			return stored, nil
		}
		last = err
		// A cancelled context will fail identically on every remaining attempt, and the
		// attempts would be spent hiding the first, clearest report of why.
		if ctx.Err() != nil {
			break
		}
	}
	// made rather than attempts: a run cut short by a cancellation that claimed three tries
	// sends whoever reads it looking for two failures that never happened.
	return nil, fmt.Errorf("backup: gave up on part %q after %d attempts: %w", part.Name, made, last)
}

// storeOnce opens the part, stores every chunk of it, and closes it.
//
// CLOSE IS THE LAST MOMENT ANYTHING CAN STILL REFUSE. A part is often a process on a pipe or a
// body on a socket, and both deliver their verdict there while the read side sees an ordinary
// EOF: pg_dump reports failure by exiting, so a Close that wraps the wait is where "exit status
// 1" arrives. Its error is never discarded, and a part that read clean and closed badly stored
// nothing this function will vouch for.
func (p *Pipeline) storeOnce(ctx context.Context, part Part, prefix string) ([]contract.Part, error) {
	stream, err := part.Open()
	if err != nil {
		return nil, fmt.Errorf("backup: open %s: %w", part.Name, err)
	}

	stored, storeErr := p.upload(ctx, part, prefix, stream)
	closeErr := stream.Close()
	if closeErr != nil {
		closeErr = fmt.Errorf("backup: close %s: %w", part.Name, closeErr)
	}
	if storeErr != nil || closeErr != nil {
		// Joined rather than ranked when both fire: the stream says "connection reset" and
		// Close says "pg_dump: error: query failed", and the one a human can act on is not
		// reliably the first.
		return nil, errors.Join(storeErr, closeErr)
	}
	return stored, nil
}

// upload reads the stream a chunk at a time and stores each chunk as its own object.
//
// ONE CHUNK IS IN MEMORY AT A TIME AND THE WHOLE STREAM NEVER IS. The buffer is reused, so a
// hundred-gigabyte change stream costs the same resident memory as a one-megabyte one.
//
// THE CHECKSUM IS OF THE BYTES HANDED TO THE STORE, and never of the object read back. Hashing
// the object afterwards would prove the object is intact and prove nothing about whether it
// matches what the source gave us, and only the second claim is worth anything at restore.
func (p *Pipeline) upload(ctx context.Context, part Part, prefix string, stream io.Reader) ([]contract.Part, error) {
	size := p.ChunkSize
	if size <= 0 {
		size = defaultChunkSize
	}
	chunk := make([]byte, size)

	var stored []contract.Part
	for index := 0; ; index++ {
		n, readErr := io.ReadFull(stream, chunk)
		switch {
		case readErr == nil, errors.Is(readErr, io.ErrUnexpectedEOF):
			// A full chunk, or the last short one.
		case errors.Is(readErr, io.EOF):
			// The stream ended exactly on a chunk boundary — or it never began.
			if len(stored) == 0 {
				return nil, fmt.Errorf("backup: %q opened and yielded no bytes; a backup of "+
					"nothing is reported with ErrNoChanges, not stored", part.Name)
			}
			return stored, nil
		default:
			return nil, fmt.Errorf("backup: read %s: %w", part.Name, readErr)
		}

		object, err := p.putChunk(ctx, part, objectPath(prefix, part.Name, index), chunk[:n])
		if err != nil {
			return nil, err
		}
		stored = append(stored, object)

		if errors.Is(readErr, io.ErrUnexpectedEOF) {
			return stored, nil
		}
	}
}

// putChunk stores one object and describes exactly what went into it.
//
// THE STORE IS HANDED THE BYTES AND NOT A READER OVER THEM, which is what makes "the store took
// fewer bytes than it was given, said 201, and the checksum describes the whole chunk" — an
// object that is short with every check green — impossible here rather than something to detect.
func (p *Pipeline) putChunk(ctx context.Context, part Part, path string, chunk []byte) (contract.Part, error) {
	if err := p.Store.Put(ctx, path, chunk); err != nil {
		return contract.Part{}, fmt.Errorf("backup: store %s: %w", path, err)
	}
	sum := sha256.Sum256(chunk)

	return contract.Part{
		Path:   path,
		Bytes:  int64(len(chunk)),
		SHA256: hex.EncodeToString(sum[:]),
		// Copied, never read. The source is the only layer that can say what a part is
		// (AD-037), and every chunk of one part is a chunk of the same thing.
		Format: part.Format,
		Role:   part.Role,
	}, nil
}

// objectPath is where one chunk lands. Result.Parts is the authoritative order — see there.
//
// EVERY OBJECT CARRIES ITS ORDINAL, INCLUDING WHEN THERE IS ONLY ONE, and the alternative is
// worse than it looks: a plain name when the stream fits and a suffix when it does not cannot
// be decided until the stream has been read past the first chunk, which means either buffering
// a chunk to find out — the thing chunking exists to avoid — or renaming an object after it
// has been written. A uniform ordinal also removes a branch, and it is what the contract's own
// examples already spell (contract/backup_test.go: "base.0000").
func objectPath(prefix, name string, index int) string {
	return fmt.Sprintf("%s/%s.%04d", prefix, name, index)
}

// checkNames refuses the names that cost data rather than merely an odd path, and it also
// refuses a part nothing can read. All of it runs before the first byte is stored.
func checkNames(parts []Part) error {
	seen := make(map[string]bool, len(parts))
	for _, part := range parts {
		// A separator is the whole hazard: without one the name is a single element, and
		// objectPath's ordinal suffix means it can never come out as "." or ".." however it
		// was spelled. WITH one, a name can contribute a ".." segment that JoinPath resolves,
		// and the object lands outside the prefix — over another cycle, or another customer.
		if part.Name == "" || strings.Contains(part.Name, "/") {
			return fmt.Errorf("backup: part name %q is not one safe path element, so the object "+
				"it named would be written somewhere other than under the cycle's prefix", part.Name)
		}
		// A part that says where it already is has been put there by the cloud (Part.Path), and
		// storing it here would read it back out of the container and write it in again under a
		// path of ours — an object copied onto itself, paid for twice, and described as one the
		// agent produced. base.go is the entry point for those, and it moves no bytes.
		if part.Path != "" {
			return fmt.Errorf("backup: part %q says it is already stored at %q; this pipeline "+
				"would copy it back into the container under a name of its own and describe the "+
				"copy as one the agent made", part.Name, part.Path)
		}
		// Open is documented as never nil. A source that breaks that would panic the agent in
		// the middle of a cycle, and library code does not panic (CONTRIBUTING.md).
		if part.Open == nil {
			return fmt.Errorf("backup: part %q has no Open, so there is no stream to store", part.Name)
		}
		if seen[part.Name] {
			// Two parts under one name overwrite each other in the store and leave a manifest
			// listing both: a short backup that reads as complete.
			return fmt.Errorf("backup: the batch names %q twice, and the second would overwrite "+
				"the first while the manifest listed both", part.Name)
		}
		seen[part.Name] = true
	}
	return nil
}

// checkPrefix refuses a prefix that does not contain what is written under it.
func checkPrefix(prefix string) error {
	if prefix == "" {
		return errors.New("backup: this cycle was given no prefix, so its objects would be " +
			"written over the previous cycle's")
	}
	for _, segment := range strings.Split(prefix, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return fmt.Errorf("backup: the prefix %q has a segment that leaves it, so this "+
				"cycle's objects would land outside it", prefix)
		}
	}
	return nil
}
