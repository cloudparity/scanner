package backup

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/manukyanv07/parity-scanner/contract"
)

// THE CLAIM backup-shape.md §7 MAKES ABOUT THIS SEAM IS TESTED HERE AND NOWHERE ELSE: a fake
// Source and a fake store drive the whole pipeline — chunking, checksumming in flight,
// uploading, position bookkeeping — with no Azure and no Postgres. Every failure below is one
// that cannot be provoked against a real server, which is exactly why it would otherwise ship
// untested.
//
// The part fakes are fake_test.go's. Nothing here writes a second set.

// memStore is the store, faked. It keeps what it was handed so a test can compare the bytes
// that landed against the bytes the source produced — which is the only way to catch a
// checksum computed over something other than what was stored.
type memStore struct {
	mu      sync.Mutex
	objects map[string][]byte
	puts    []string // every path, in order, including a path written twice by a retry

	// deletes is every path Apply asked to remove, IN ORDER, so the pruning tests can check that
	// a retired chain's manifests went before the objects they name (prune.go).
	deletes []string

	// refuse fails the named path, so a store that will not take an object is a shape the
	// pipeline has to survive as well as a source that will not produce one.
	refuse map[string]error

	// written is when each object was last written, which is the other half of what a listing
	// carries (store.Blob.List) and the only thing that tells a killed cycle's debris from a cycle
	// that is uploading right now. now is the clock a test sets before it writes.
	written map[string]time.Time
	now     time.Time

	// unreadable fails a HEAD for the named path, so "the container would not say" can be told
	// apart from "it is not there" — a distinction the pruning floor turns on.
	unreadable map[string]error
}

func newMemStore() *memStore {
	return &memStore{
		objects:    map[string][]byte{},
		refuse:     map[string]error{},
		written:    map[string]time.Time{},
		unreadable: map[string]error{},
	}
}

func (m *memStore) Put(ctx context.Context, path string, chunk []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Recorded before the checks, so a test can count the attempts a failing cycle spent.
	m.puts = append(m.puts, path)
	// A real store is an HTTP call and honours the context. Without this the pipeline's
	// cancellation path has nothing to fail it.
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := m.refuse[path]; err != nil {
		return err
	}
	// Copied, because the pipeline reuses one buffer across chunks: a store that kept the
	// slice would find every object holding the last chunk's bytes.
	m.objects[path] = append([]byte(nil), chunk...)
	m.written[path] = m.now
	return nil
}

// List is the assembler's half (assemble.go), and it ANCHORS THE PREFIX exactly as the real one
// does: a scope whose name is another scope's prefix must not sweep it.
func (m *memStore) List(ctx context.Context, prefix string) (map[string]time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if prefix == "" {
		return nil, errors.New("memStore: a listing with no prefix is the whole container")
	}
	root := strings.TrimSuffix(prefix, "/") + "/"
	listed := map[string]time.Time{}
	for path := range m.objects {
		if strings.HasPrefix(path, root) {
			listed[path] = m.written[path]
		}
	}
	return listed, nil
}

// Get reads a claim back. An object that is not there is an ERROR, which is what the real one does
// and why: a manifest a listing named and the container does not hold must not read as no segment.
func (m *memStore) Get(ctx context.Context, path string) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	body, held := m.objects[path]
	if !held {
		return nil, fmt.Errorf("memStore: %s is not in the container", path)
	}
	return append([]byte(nil), body...), nil
}

// Exists is the question asked about ONE NAMED OBJECT, which is how a base copy's objects are
// vouched for without widening the listing that bounds the debris sweep (AD-033).
func (m *memStore) Exists(ctx context.Context, path string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := m.unreadable[path]; err != nil {
		return false, err
	}
	_, held := m.objects[path]
	return held, nil
}

// Delete is the pruning half (prune.go). Removing an object that is not there is SUCCESS, which
// is what the real container does and what makes an interrupted prune resumable by re-running it.
func (m *memStore) Delete(ctx context.Context, path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Recorded before the checks, so a test can see what a refusing container was asked for.
	m.deletes = append(m.deletes, path)
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := m.refuse[path]; err != nil {
		return err
	}
	delete(m.objects, path)
	return nil
}

func (m *memStore) get(path string) string { return string(m.objects[path]) }

func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// changing returns a Source whose Since hands back the given parts. Base is never reached: the
// pipeline has no Base entry point, because AD-033 moved the base copy out of the byte path.
//
// It reports a range that BEGINS WHERE IT WAS ASKED TO, which is what a source that resumed
// where it was told to does. That is the ordinary case and not the only one — a source that lost
// its slot and made a new one resumes later, and reports the later position — so the tests that
// turn on the difference build their own fake rather than using this one.
func changing(position Position, schema string, parts ...Part) *fakeSource {
	return &fakeSource{since: func(from Position) (Batch, error) {
		return Batch{From: from, Position: position, Schema: schema, Parts: parts}, nil
	}}
}

func TestEveryPartLandsWithTheChecksumOfWhatWasRead(t *testing.T) {
	store := newMemStore()
	p := &Pipeline{Store: store}
	src := changing("0/1A2B999", "sha256:abc",
		Part{
			Name: "changes.0001", Format: contract.FormatPGDumpCustom, Role: contract.PartDatabase,
			Open: wholePart("changes.0001", "CDC-one").Open,
		},
		wholePart("changes.0002", "CDC-two"),
	)

	got, err := p.Since(context.Background(), src, "0/1A2B000", "install-7/cycle-3")
	if err != nil {
		t.Fatalf("a clean batch failed: %v", err)
	}

	// Position bookkeeping: the pipeline stores what the source reported and invents nothing.
	if got.Position != "0/1A2B999" || got.Schema != "sha256:abc" {
		t.Errorf("result %+v lost the position or the schema", got)
	}
	// BOTH ENDS OF THE RANGE, because one end alone cannot show a hole between two batches.
	// The fake echoes the position it was asked from, which is what a source that resumed where
	// it was told to does; a source that resumed LATER reports the later one, and that the
	// pipeline carries that through rather than substituting the request is pinned end to end
	// in manifest_test.go.
	if got.From != "0/1A2B000" {
		t.Errorf("result %+v lost where the source says the batch began", got)
	}
	if len(got.Parts) != 2 {
		t.Fatalf("stored %d objects, want 2: %+v", len(got.Parts), got.Parts)
	}
	if got.Bytes != int64(len("CDC-one")+len("CDC-two")) {
		t.Errorf("total bytes %d", got.Bytes)
	}

	first := got.Parts[0]
	if first.Path != "install-7/cycle-3/changes.0001.0000" {
		t.Errorf("path %q", first.Path)
	}
	if store.get(first.Path) != "CDC-one" {
		t.Errorf("the store holds %q", store.get(first.Path))
	}
	// The checksum has to be of the bytes the source gave us, not of the object read back.
	if first.SHA256 != digest("CDC-one") {
		t.Errorf("sha256 %q, want %q", first.SHA256, digest("CDC-one"))
	}
	if first.Bytes != int64(len("CDC-one")) {
		t.Errorf("bytes %d", first.Bytes)
	}
	// Format and Role are carried, never read (§1). Losing them is the AD-037 failure: a
	// restore that reports success with the roles and grants silently missing.
	if first.Format != contract.FormatPGDumpCustom || first.Role != contract.PartDatabase {
		t.Errorf("the label did not survive: %+v", first)
	}
	if got.Parts[1].Path != "install-7/cycle-3/changes.0002.0000" {
		t.Errorf("second path %q", got.Parts[1].Path)
	}
}

// The rule this test exists for: EVERY CHUNK GOES IN THE RESULT. One that is stored and not
// listed is an object nobody will ever notice is missing, and the manifest B4 writes over the
// rest reads as complete.
func TestAStreamLargerThanOneChunkLandsAsSeveralObjectsAndAllOfThemAreListed(t *testing.T) {
	const body = "0123456789abcdefghij" // 20 bytes over a 7-byte chunk: 2 full and a 6-byte tail
	store := newMemStore()
	p := &Pipeline{Store: store, ChunkSize: 7}

	got, err := p.Since(context.Background(), changing("0/2", "", wholePart("changes.0001", body)),
		"0/1", "install-7/cycle-4")
	if err != nil {
		t.Fatalf("a chunked part failed: %v", err)
	}
	if len(got.Parts) != 3 {
		t.Fatalf("%d objects for a 20-byte stream in 7-byte chunks: %+v", len(got.Parts), got.Parts)
	}

	var rejoined strings.Builder
	for i, part := range got.Parts {
		want := fmt.Sprintf("install-7/cycle-4/changes.0001.%04d", i)
		if part.Path != want {
			t.Errorf("object %d is at %q, want %q", i, part.Path, want)
		}
		stored := store.get(part.Path)
		if part.SHA256 != digest(stored) || part.Bytes != int64(len(stored)) {
			t.Errorf("object %d does not describe itself: %+v over %q", i, part, stored)
		}
		rejoined.WriteString(stored)
	}
	// Rejoined in the order the result lists them: a chunking that loses or reorders a chunk
	// is not visible in any single object's checksum.
	if rejoined.String() != body {
		t.Errorf("the chunks rejoin to %q, want %q", rejoined.String(), body)
	}
	if got.Bytes != int64(len(body)) {
		t.Errorf("total bytes %d, want %d", got.Bytes, len(body))
	}
}

// THE CANONICAL CHUNKING OFF-BY-ONE: a stream whose length is an exact multiple of the chunk
// size. The read after the last full chunk returns nothing at a clean EOF, and the two ways to
// get that wrong are both silent — drop the final chunk, or store a zero-byte object and list
// it in the manifest as if it held something.
func TestAStreamThatEndsExactlyOnAChunkBoundaryStoresNoEmptyObject(t *testing.T) {
	const body = "0123456789abcd" // 14 bytes over a 7-byte chunk: exactly 2, with no tail
	store := newMemStore()
	p := &Pipeline{Store: store, ChunkSize: 7}

	got, err := p.Since(context.Background(), changing("0/2", "", wholePart("changes.0001", body)),
		"0/1", "cycle")
	if err != nil {
		t.Fatalf("a stream ending on a chunk boundary failed: %v", err)
	}
	if len(got.Parts) != 2 {
		t.Fatalf("%d objects for 14 bytes in 7-byte chunks, want exactly 2: %+v", len(got.Parts), got.Parts)
	}

	var rejoined strings.Builder
	for _, part := range got.Parts {
		if part.Bytes == 0 {
			t.Errorf("%s is a zero-byte object and the manifest would list it", part.Path)
		}
		rejoined.WriteString(store.get(part.Path))
	}
	if rejoined.String() != body {
		t.Errorf("the chunks rejoin to %q, want %q — the final chunk was dropped", rejoined.String(), body)
	}
	// Nothing was written that the result does not account for.
	if len(store.puts) != len(got.Parts) {
		t.Errorf("%d objects were written and %d are listed", len(store.puts), len(got.Parts))
	}
}

// The three shapes a part fails in, and the one thing they have in common: nothing is
// returned for B4 to write a manifest over.
func TestAPartThatFailsAtOpenMidStreamOrAtCloseYieldsNoResult(t *testing.T) {
	tests := []struct {
		name    string
		part    Part
		wantErr error
		says    string
	}{
		{
			name:    "at open, before a single byte",
			part:    unopenablePart("changes.0001", errRefused),
			wantErr: errRefused,
			says:    "open changes.0001",
		},
		{
			name:    "mid-stream, after bytes have already landed",
			part:    truncatedPart("changes.0001", "CDC-hal", errStreamDied),
			wantErr: errStreamDied,
			says:    "read changes.0001",
		},
		{
			// A CLEAN READ IS NOT A WHOLE STREAM. The bytes all arrived and the reader saw an
			// ordinary EOF; Close is where "exit status 1" turns up. A pipeline that discards
			// what Close says stores a stream that ends mid-COPY, checksums it, and hands B4
			// something to write a manifest over. Every check green, the loss found at restore.
			name:    "at close, after the whole stream read clean",
			part:    flushFailsPart("changes.0001", "CDC-one", errFlushFailed),
			wantErr: errFlushFailed,
			says:    "close changes.0001",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := newMemStore()
			p := &Pipeline{Store: store}

			got, err := p.Since(context.Background(), changing("0/2", "", tc.part), "0/1", "cycle")
			if err == nil {
				t.Fatal("a failing part stored cleanly")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("error %v does not carry %v", err, tc.wantErr)
			}
			// Which of the three it was has to be legible: open, read and close are different
			// incidents and they are fixed in different places.
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("error %q does not say %q", err, tc.says)
			}
			if len(got.Parts) != 0 || got.Bytes != 0 {
				t.Errorf("a failed part still produced %+v", got)
			}
		})
	}
}

// The retry the whole Part.Open contract exists for, and the chunk size is small on purpose so
// that the first attempt gets objects into the store before it dies. The second attempt must
// start over from BYTE ZERO: one that resumed where the first stopped would leave the early
// chunks holding one half of the stream and the later ones the other half of a second read,
// and every object would checksum happily.
func TestATransientIsRetriedAndTheChunksStartOverFromByteZero(t *testing.T) {
	const whole = "CDC-one-two-three" // 17 bytes in 4-byte chunks: 4 full and a 1-byte tail
	store := newMemStore()
	p := &Pipeline{Store: store, ChunkSize: 4}

	got, err := p.Since(context.Background(),
		changing("0/2", "", flakyPart("changes.0001", whole, errStreamDied)), "0/1", "cycle")
	if err != nil {
		t.Fatalf("the retry did not recover: %v", err)
	}
	if len(got.Parts) != 5 {
		t.Fatalf("%d objects: %+v", len(got.Parts), got.Parts)
	}

	var rejoined strings.Builder
	for _, part := range got.Parts {
		stored := store.get(part.Path)
		if part.SHA256 != digest(stored) {
			t.Errorf("%s does not describe what the store holds", part.Path)
		}
		rejoined.WriteString(stored)
	}
	if rejoined.String() != whole {
		t.Errorf("the objects rejoin to %q, want the whole %q", rejoined.String(), whole)
	}
	// The first attempt died mid-stream with objects already written, and the retry wrote over
	// them. Without that, nothing here has driven the recovery path at all.
	if len(store.puts) <= len(got.Parts) {
		t.Errorf("%d writes for %d objects; the first attempt was meant to fail after storing some",
			len(store.puts), len(got.Parts))
	}
}

// A store that will not take the object fails the cycle, and says which object.
func TestAStoreThatRefusesAnObjectFailsTheCycle(t *testing.T) {
	errFull := errors.New("HTTP 403 from the container: AuthorizationPermissionMismatch")
	store := newMemStore()
	store.refuse["cycle/changes.0001.0000"] = errFull
	p := &Pipeline{Store: store}

	_, err := p.Since(context.Background(),
		changing("0/2", "", wholePart("changes.0001", "CDC-one")), "0/1", "cycle")
	if !errors.Is(err, errFull) {
		t.Fatalf("a refused object gave %v", err)
	}
	if !strings.Contains(err.Error(), "cycle/changes.0001.0000") {
		t.Errorf("error %q does not name the object", err)
	}
}

// Zero parts, a part that yields no bytes, a name that is not one safe path element, and two
// parts sharing a name: four ways to end up with a manifest over nothing or over an object
// that overwrote another. All four are refused before anything is stored.
func TestABatchThatCannotBeAccountedForIsRefused(t *testing.T) {
	tests := []struct {
		name  string
		batch Batch
		says  string
	}{
		{
			name:  "no parts at all",
			batch: Batch{Position: "0/2"},
			says:  "no parts",
		},
		{
			name:  "a part that opens and yields nothing",
			batch: Batch{Position: "0/2", Parts: []Part{wholePart("changes.0001", "")}},
			says:  "no bytes",
		},
		{
			name:  "a name with a separator in it, which writes outside the prefix",
			batch: Batch{Position: "0/2", Parts: []Part{wholePart("a/b", "CDC")}},
			says:  "a/b",
		},
		{
			// The separator is what makes this dangerous rather than merely odd: it is what
			// lets a ".." become a path segment a store will resolve. A name of ".." on its
			// own cannot, because every object's name gets an ordinal suffix.
			name:  "a name that climbs out of the prefix entirely",
			batch: Batch{Position: "0/2", Parts: []Part{wholePart("../../elsewhere", "CDC")}},
			says:  "../../elsewhere",
		},
		{
			name: "two parts under one name, which overwrite each other in the store",
			batch: Batch{Position: "0/2", Parts: []Part{
				wholePart("changes.0001", "CDC-one"), wholePart("changes.0001", "CDC-two"),
			}},
			says: "twice",
		},
		{
			// Open is documented as never nil, and a source that broke that would otherwise
			// take the agent down with a nil dereference in the middle of a cycle.
			name:  "a part with no Open at all",
			batch: Batch{Position: "0/2", Parts: []Part{{Name: "changes.0001"}}},
			says:  "no Open",
		},
		{
			// A part the CLOUD already put in the container (Part.Path). Storing it here would
			// read it back out and write it in again under a name of ours — an object copied
			// onto itself, paid for twice, and described in the manifest as one the agent
			// produced. base.go is the entry point for those, and it moves no bytes.
			name: "a part that says it is already stored, which this pipeline would copy onto itself",
			batch: Batch{Position: "0/2", Parts: []Part{func() Part {
				p := wholePart("database.sql", "PGDMP")
				p.Path = "parity-rp-1/database.sql"
				return p
			}()}},
			says: "already stored",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := newMemStore()
			p := &Pipeline{Store: store}
			batch := tc.batch

			_, err := p.Since(context.Background(),
				&fakeSource{since: func(Position) (Batch, error) { return batch, nil }}, "0/1", "cycle")
			if err == nil {
				t.Fatal("the batch was accepted")
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("error %q does not say %q", err, tc.says)
			}
		})
	}
}

// A prefix that is not a prefix would write this cycle's objects on top of somebody else's.
func TestAPrefixThatWritesOutsideItselfIsRefused(t *testing.T) {
	for _, prefix := range []string{"", "/absolute", "up/../../elsewhere", "double//slash"} {
		t.Run(prefix, func(t *testing.T) {
			p := &Pipeline{Store: newMemStore()}
			_, err := p.Since(context.Background(),
				changing("0/2", "", wholePart("changes.0001", "CDC")), "0/1", prefix)
			if err == nil {
				t.Fatalf("prefix %q was accepted", prefix)
			}
		})
	}
}

// A cancelled cycle stops at once. Spending the other attempts would re-read the whole stream
// twice more on behalf of work that has already been abandoned, and each would fail identically
// while hiding the first, clearest report of why.
func TestACancelledCycleStopsInsteadOfSpendingItsAttempts(t *testing.T) {
	store := newMemStore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := (&Pipeline{Store: store}).Since(ctx,
		changing("0/2", "", wholePart("changes.0001", "CDC-one")), "0/1", "cycle")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("a cancelled cycle gave %v", err)
	}
	if len(store.puts) != 1 {
		t.Errorf("the cycle made %d attempts against a context that was already cancelled", len(store.puts))
	}
}

// A pipeline with nowhere to put the bytes says so. Library code does not panic, and a nil
// dereference here would take the agent down mid-cycle with a stack trace in place of the one
// sentence that says what is misconfigured.
func TestAPipelineWithNoStoreSaysSoRatherThanPanicking(t *testing.T) {
	_, err := (&Pipeline{}).Since(context.Background(),
		changing("0/2", "", wholePart("changes.0001", "CDC-one")), "0/1", "cycle")
	if err == nil {
		t.Fatal("a pipeline with no store reported success")
	}
	if !strings.Contains(err.Error(), "no store") {
		t.Errorf("error %q does not say what is missing", err)
	}
}

// Nothing changed is a sentinel, and the pipeline wraps it with its own context. It has to
// survive that wrap, because the caller's alternative to recognising it is taking a base copy.
func TestNoChangesSurvivesThePipelinesWrap(t *testing.T) {
	p := &Pipeline{Store: newMemStore()}

	_, err := p.Since(context.Background(), &fakeSource{}, "0/1A2B000", "cycle")
	if !errors.Is(err, ErrNoChanges) {
		t.Fatalf("a source with nothing new gave %v", err)
	}
}

// The Position goes out opaque and comes back opaque. Nothing in the pipeline looks inside it,
// which is what lets a WAL LSN and a snapshot id share one seam (§5).
func TestThePositionIsHandedStraightThrough(t *testing.T) {
	var saw Position
	src := &fakeSource{since: func(from Position) (Batch, error) {
		saw = from
		return Batch{Position: from + "-later", Parts: []Part{wholePart("changes.0001", "CDC")}}, nil
	}}

	got, err := (&Pipeline{Store: newMemStore()}).
		Since(context.Background(), src, "file.000123:4096", "cycle")
	if err != nil {
		t.Fatalf("Since failed: %v", err)
	}
	if saw != "file.000123:4096" {
		t.Errorf("the source was handed %q", saw)
	}
	if got.Position != "file.000123:4096-later" {
		t.Errorf("result position %q", got.Position)
	}
}
