package backup

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/manukyanv07/parity-scanner/contract"
)

// THE ONE CLAIM THIS FILE EXISTS TO TEST: a manifest never appears beside an artifact that was
// not finished and checked. Everything else here is a corollary.
//
// The part fakes are fake_test.go's and the store fake is run_test.go's memStore. What is added
// here wraps that store rather than replacing it, because the two shapes B4 owns — an agent
// killed mid-upload, and a store that takes the artifact and then refuses the manifest — are
// about WHEN a Put happens, not about what a store holds.

// killAfter cancels the cycle's context once `at` objects have landed. That is what being
// killed mid-upload looks like from inside the pipeline: some objects are in the container, the
// next call fails, and nothing gets a chance to tidy up. No Azure, no signals, no process.
type killAfter struct {
	inner  Store
	at     int
	seen   int
	cancel context.CancelFunc
}

func (k *killAfter) Put(ctx context.Context, path string, chunk []byte) error {
	err := k.inner.Put(ctx, path, chunk)
	if err == nil {
		k.seen++
		if k.seen == k.at {
			k.cancel()
		}
	}
	return err
}

// flakyManifest takes every artifact object and refuses the manifest the first `refusals` times
// — the store failure that matters most, because it is the one where every byte of the backup is
// present and the only missing object is the one that says so.
type flakyManifest struct {
	inner    Store
	err      error
	refusals int
	tries    int
}

func (r *flakyManifest) Put(ctx context.Context, path string, chunk []byte) error {
	if !strings.HasSuffix(path, "/"+manifestName) {
		return r.inner.Put(ctx, path, chunk)
	}
	r.tries++
	if r.tries <= r.refusals {
		return r.err
	}
	return r.inner.Put(ctx, path, chunk)
}

// landed is every object the store actually holds. Not memStore.puts: a Put that was recorded
// and then failed left nothing behind, and the question here is always what a reader of the
// container would find.
func landed(m *memStore) []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	paths := make([]string, 0, len(m.objects))
	for path := range m.objects {
		paths = append(paths, path)
	}
	return paths
}

// manifestsIn is every object that reads as a manifest. A test asserts on this and never on one
// path it computed itself: the prefix is generated per cycle, so a test that guessed the path
// would pass by looking in the wrong place.
func manifestsIn(m *memStore) []string {
	return manifestsAmong(landed(m))
}

// manifestsAttemptedIn is every manifest the store was ASKED to write, whether or not the write
// succeeded. memStore records a path before it decides to fail it, which is the difference that
// matters: a cycle that tried to write a manifest and was saved by a store that happened to
// refuse it has still got the order wrong, and would write one against a store that did not.
func manifestsAttemptedIn(m *memStore) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return manifestsAmong(m.puts)
}

// object is what the store holds at a path, and whether it holds anything there at all.
func object(m *memStore, path string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	body, ok := m.objects[path]
	return string(body), ok
}

// lastPut is the last path the store was asked to write, which is the only way to assert that
// the manifest went last rather than merely that it went.
func lastPut(m *memStore) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.puts) == 0 {
		return ""
	}
	return m.puts[len(m.puts)-1]
}

func manifestsAmong(paths []string) []string {
	var found []string
	for _, path := range paths {
		if strings.HasSuffix(path, "/"+manifestName) {
			found = append(found, path)
		}
	}
	return found
}

// testCycle is a cycle with everything filled that is not the point of the test at hand.
func testCycle(p *Pipeline) *Cycle {
	return &Cycle{
		Pipeline: p,
		Scope:    "install-7/pg1/orders",
		Subject: contract.BackupSource{
			Provider:      contract.ProviderAzure,
			ResourceID:    "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.dbforpostgresql/flexibleservers/pg1",
			Database:      "orders",
			Engine:        "postgres",
			EngineVersion: "16",
		},
		Producer: contract.Producer{Agent: "azure/0.1.0", Tool: "pglogrepl 0.0.0"},
		Format:   contract.FormatPGDumpCustom,
		// The fingerprint the chain's base was taken against, and what every cycle here is
		// compared to. It matches what `changing` reports, so these tests exercise a chain whose
		// schema is standing still; the cycle that finds it has moved is rebase_test.go's.
		BaseSchema: "sha256:abc",
	}
}

// THE FIRST TEST, AND THE DELIVERABLE. Kill the agent while the objects are still going up and
// the container must hold no manifest. A manifest here would be believed: nothing downstream
// re-derives it, so a half-written artifact with a manifest over it restores as a short
// database with every check green.
func TestKillingTheAgentMidUploadLeavesNoManifest(t *testing.T) {
	const body = "CDC-one-two-three-four" // 22 bytes in 4-byte chunks: six objects, killed at two

	store := newMemStore()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := testCycle(&Pipeline{Store: &killAfter{inner: store, at: 2, cancel: cancel}, ChunkSize: 4})
	_, err := c.Run(ctx, changing("0/2", "sha256:abc", wholePart("changes.0001", body)), "0/1")

	if err == nil {
		t.Fatal("a cycle killed mid-upload reported success")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error %v does not carry the cancellation", err)
	}

	// The kill has to have landed somewhere that proves something. If nothing was stored, the
	// test is passing because the cycle never started, not because the ordering holds.
	if len(landed(store)) == 0 {
		t.Fatal("nothing reached the store before the kill, so this test proved nothing")
	}
	if found := manifestsIn(store); len(found) != 0 {
		t.Fatalf("a manifest at %v sits beside an artifact that was never finished", found)
	}
	// AND IT WAS NEVER EVEN OFFERED. Stopping at "no manifest is in the container" would pass
	// against a cycle that tried to write one and was saved by the store refusing a cancelled
	// call — which is luck, not order, and it runs out against a store that accepts it.
	if tried := manifestsAttemptedIn(store); len(tried) != 0 {
		t.Fatalf("the cycle offered the store a manifest at %v after being killed mid-upload", tried)
	}
}

// The other three ways a cycle ends without a whole artifact. Each leaves the container in a
// different state and all three leave it with no manifest.
func TestAnArtifactThatCouldNotBeFinishedGetsNoManifest(t *testing.T) {
	tests := []struct {
		name       string
		part       Part
		wantErr    error
		wantLanded bool
	}{
		{
			// Bytes arrived and then the stream died. The objects on the floor are real and
			// nothing references them, which is the state that is safe precisely because no
			// manifest was written.
			name:       "the stream died after bytes had already landed",
			part:       truncatedPart("changes.0001", "CDC-one-two", errStreamDied),
			wantErr:    errStreamDied,
			wantLanded: true,
		},
		{
			name:       "nothing would open, so nothing landed either",
			part:       unopenablePart("changes.0001", errRefused),
			wantErr:    errRefused,
			wantLanded: false,
		},
		{
			// THE COMPLETE UPLOAD THAT DOES NOT CHECK OUT. Every byte was read, every object
			// was stored, and the verdict arrived at Close — pg_dump reports failure by
			// exiting. This is the case where a manifest is easiest to write and worst to
			// have: the artifact looks whole from the store's side.
			name:       "every byte landed and the check at close refused it",
			part:       flushFailsPart("changes.0001", "CDC-one-two", errFlushFailed),
			wantErr:    errFlushFailed,
			wantLanded: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := newMemStore()
			c := testCycle(&Pipeline{Store: store, ChunkSize: 4})

			_, err := c.Run(context.Background(), changing("0/2", "sha256:abc", tc.part), "0/1")
			if err == nil {
				t.Fatal("a cycle that could not finish its artifact reported success")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("error %v does not carry %v", err, tc.wantErr)
			}
			if got := len(landed(store)) > 0; got != tc.wantLanded {
				t.Errorf("objects in the store: %v, want %v (%v)", got, tc.wantLanded, landed(store))
			}
			if found := manifestsAttemptedIn(store); len(found) != 0 {
				t.Fatalf("a manifest at %v claims a backup that failed with %v", found, err)
			}
		})
	}
}

// A store that takes every byte of the artifact and then refuses the manifest. The cycle FAILS
// — it does not return a manifest that was never stored. A caller that recorded the position
// from a manifest nothing can find would resume past changes no one can restore.
func TestAStoreThatTakesTheArtifactAndRefusesTheManifestFailsTheCycle(t *testing.T) {
	errRefusedManifest := errors.New("HTTP 403 from the container: AuthorizationPermissionMismatch")
	store := newMemStore()
	refusing := &flakyManifest{inner: store, err: errRefusedManifest, refusals: 99}
	c := testCycle(&Pipeline{Store: refusing})

	_, err := c.Run(context.Background(),
		changing("0/2", "sha256:abc", wholePart("changes.0001", "CDC-one")), "0/1")
	if !errors.Is(err, errRefusedManifest) {
		t.Fatalf("a refused manifest gave %v", err)
	}
	if !strings.Contains(err.Error(), manifestName) {
		t.Errorf("error %q does not say it was the manifest that was refused", err)
	}
	// Tried as hard as any other object, and then given up on rather than reported as written.
	if refusing.tries != defaultAttempts {
		t.Errorf("the manifest was offered %d times, want %d", refusing.tries, defaultAttempts)
	}
	// The artifact is there and unreferenced, which is the correct outcome: an object nothing
	// points at costs storage, and a manifest over it would cost the restore.
	if len(landed(store)) != 1 {
		t.Errorf("the artifact objects are %v, want the one that was stored", landed(store))
	}
	if found := manifestsIn(store); len(found) != 0 {
		t.Fatalf("the manifest at %v was refused and is somehow present", found)
	}
}

// A transient on the manifest write must not throw the artifact away. It is the last, smallest
// and most idempotent object of the cycle, and it is the only one whose failure discards bytes
// that are already whole and already paid for — so it is retried like every other object.
func TestATransientOnTheManifestDoesNotThrowTheArtifactAway(t *testing.T) {
	store := newMemStore()
	flaky := &flakyManifest{inner: store, err: errStreamDied, refusals: 1}
	c := testCycle(&Pipeline{Store: flaky})

	got, err := c.Run(context.Background(),
		changing("0/2", "sha256:abc", wholePart("changes.0001", "CDC-one")), "0/1")
	if err != nil {
		t.Fatalf("one transient on the manifest cost the whole cycle: %v", err)
	}
	if flaky.tries != 2 {
		t.Errorf("the manifest was offered %d times, want a refusal and then a success", flaky.tries)
	}
	found := manifestsIn(store)
	if len(found) != 1 {
		t.Fatalf("manifests in the store: %v", found)
	}
	if got.ReadPoint.Position != "0/2" {
		t.Errorf("the manifest that was returned is %+v", got)
	}
}

// The happy path, and the two things it has to prove: the manifest is the LAST object written,
// and every hash in it is one the pipeline computed over the bytes it handed the store.
func TestTheManifestIsWrittenLastAndDescribesExactlyWhatLanded(t *testing.T) {
	const body = "CDC-one-two-three" // 17 bytes in 4-byte chunks: five objects
	store := newMemStore()
	c := testCycle(&Pipeline{Store: store, ChunkSize: 4})

	got, err := c.Run(context.Background(), changing("0/1A2B999", "sha256:abc",
		Part{
			Name: "changes.0001", Format: contract.FormatPGDumpCustom, Role: contract.PartDatabase,
			Open: wholePart("changes.0001", body).Open,
		}), "0/1A2B000")
	if err != nil {
		t.Fatalf("a clean cycle failed: %v", err)
	}

	// LAST, with nothing after it. An object written after the manifest is an object the
	// manifest does not describe.
	found := manifestsIn(store)
	if len(found) != 1 {
		t.Fatalf("manifests in the store: %v, want exactly one", found)
	}
	if last := lastPut(store); last != found[0] {
		t.Errorf("the last write was %q, not the manifest %q", last, found[0])
	}

	stored, _ := object(store, found[0])
	var wire contract.Manifest
	if err := json.Unmarshal([]byte(stored), &wire); err != nil {
		t.Fatalf("the manifest that was stored is not a manifest: %v", err)
	}
	if wire.ContractVersion != contract.BackupContractVersion || wire.Kind != contract.BackupChange {
		t.Errorf("manifest header %+v", wire)
	}
	if wire.ReadPoint.Position != "0/1A2B999" || wire.Schema != "sha256:abc" {
		t.Errorf("the source's own position and schema did not survive: %+v", wire)
	}
	if _, err := time.Parse(time.RFC3339, wire.ReadPoint.At); err != nil {
		t.Errorf("readPoint.at %q is not RFC3339: %v", wire.ReadPoint.At, err)
	}
	if wire.Transfer != contract.RouteAgentStream {
		t.Errorf("transfer %q: the agent read these bytes and wrote them", wire.Transfer)
	}
	if wire.Source.Database != "orders" || wire.Producer.Agent != "azure/0.1.0" {
		t.Errorf("the cycle's own facts did not reach the manifest: %+v", wire)
	}

	// EVERY HASH IS ONE THAT WAS VERIFIED. Rebuilding the stream from the objects the manifest
	// names, in the order it names them, has to give back the bytes the source produced — and
	// each object has to hold what its own hash says it holds.
	if len(wire.Artifact.Parts) != 5 {
		t.Fatalf("%d parts for a 17-byte stream in 4-byte chunks: %+v", len(wire.Artifact.Parts), wire.Artifact.Parts)
	}
	var rejoined strings.Builder
	var total int64
	for _, part := range wire.Artifact.Parts {
		body, ok := object(store, part.Path)
		if !ok {
			t.Fatalf("the manifest names %q and the store has no such object", part.Path)
		}
		if part.SHA256 != digest(body) {
			t.Errorf("%s: the manifest says %q and the object hashes to %q",
				part.Path, part.SHA256, digest(body))
		}
		if part.Bytes != int64(len(body)) {
			t.Errorf("%s: the manifest says %d bytes and the object is %d", part.Path, part.Bytes, len(body))
		}
		if part.Format != contract.FormatPGDumpCustom || part.Role != contract.PartDatabase {
			t.Errorf("%s lost its label: %+v", part.Path, part)
		}
		rejoined.WriteString(body)
		total += part.Bytes
	}
	if rejoined.String() != body {
		t.Errorf("the parts the manifest names rejoin to %q, want %q", rejoined.String(), body)
	}
	if wire.Artifact.Bytes != total {
		t.Errorf("artifact.bytes is %d and its parts total %d", wire.Artifact.Bytes, total)
	}
	// A whole-artifact hash would be a hash of a stream nobody hashed. Empty is the contract's
	// answer for a chunked artifact, and Part.SHA256 is what vouches for anything.
	if wire.Artifact.SHA256 != "" {
		t.Errorf("artifact.sha256 is %q, and no such single stream was hashed", wire.Artifact.SHA256)
	}
	if wire.Artifact.Format != contract.FormatPGDumpCustom {
		t.Errorf("artifact.format %q", wire.Artifact.Format)
	}

	// What Run returns is what was stored, so a caller reads the next position from the same
	// object a restorer will.
	if got.ReadPoint.Position != wire.ReadPoint.Position || len(got.Artifact.Parts) != len(wire.Artifact.Parts) {
		t.Errorf("Run returned %+v and the store holds %+v", got, wire)
	}
}

// THE RANGE IS THE SOURCE'S ACCOUNT OF WHAT IT DELIVERED, NEVER THE POSITION WE ASKED FROM, and
// this is the difference that makes a hole in a chain detectable at all.
//
// The failure it exists to catch is C4's: the agent loses its replication slot, makes a new one,
// and resumes at a LATER position than it asked for. Everything after that is internally perfect
// — the objects hash, the manifest goes last, the chain is contiguous on paper — and the changes
// in between are gone. A manifest that recorded the asked-for position would claim this file
// begins exactly where the last one ended, and no verifier could ever see the hole.
func TestTheManifestRecordsWhereTheSourceSaysTheBatchBegan(t *testing.T) {
	store := newMemStore()
	c := testCycle(&Pipeline{Store: store})

	// Asked from 0/100; the source answers that what it actually has starts at 0/300.
	resumedLater := &fakeSource{since: func(Position) (Batch, error) {
		return Batch{
			From:     "0/300",
			Position: "0/400",
			Schema:   "sha256:abc",
			Parts:    []Part{wholePart("changes.0001", "CDC-one")},
		}, nil
	}}

	got, err := c.Run(context.Background(), resumedLater, "0/100")
	if err != nil {
		t.Fatalf("a clean cycle failed: %v", err)
	}
	if got.ReadPoint.From != "0/300" {
		t.Errorf("readPoint.from is %q, want the source's own 0/300: a range copied from the "+
			"request would hide every change between 0/100 and 0/300", got.ReadPoint.From)
	}
	if got.ReadPoint.Position != "0/400" {
		t.Errorf("readPoint.position is %q, want 0/400", got.ReadPoint.Position)
	}

	// And it is the stored object that says so, not just the value Run handed back.
	stored, _ := object(store, manifestsIn(store)[0])
	var wire contract.Manifest
	if err := json.Unmarshal([]byte(stored), &wire); err != nil {
		t.Fatalf("the manifest that was stored is not a manifest: %v", err)
	}
	if wire.ReadPoint.From != "0/300" {
		t.Errorf("the stored manifest says it begins at %q: %s", wire.ReadPoint.From, stored)
	}
}

// TWO CYCLES MUST NOT SHARE A PREFIX, and B4 owns that rather than trusting a caller with it:
// the manifest is what makes a cycle identifiable, so a colliding prefix is one cycle's
// manifest describing the other cycle's objects — a corrupted chain that every check passes.
func TestTwoCyclesUnderOneScopeNeverCollide(t *testing.T) {
	store := newMemStore()
	c := testCycle(&Pipeline{Store: store})
	src := changing("0/2", "sha256:abc", wholePart("changes.0001", "CDC-one"))

	first, err := c.Run(context.Background(), src, "0/1")
	if err != nil {
		t.Fatalf("the first cycle failed: %v", err)
	}
	second, err := c.Run(context.Background(), changing("0/3", "sha256:abc", wholePart("changes.0001", "CDC-two")), "0/2")
	if err != nil {
		t.Fatalf("the second cycle failed: %v", err)
	}

	if len(manifestsIn(store)) != 2 {
		t.Fatalf("two cycles left %v; one overwrote the other", manifestsIn(store))
	}
	firstPath := first.Artifact.Parts[0].Path
	if firstPath == second.Artifact.Parts[0].Path {
		t.Fatalf("both cycles wrote their artifact to %q", firstPath)
	}
	// The first cycle's bytes are still the first cycle's bytes.
	if body, _ := object(store, firstPath); body != "CDC-one" {
		t.Errorf("the first cycle's object now holds %q", body)
	}
	// Both prefixes are under the scope, so a cycle cannot wander out of its own installation.
	for _, path := range manifestsIn(store) {
		if !strings.HasPrefix(path, "install-7/pg1/orders/") {
			t.Errorf("a manifest landed at %q, outside the scope it was given", path)
		}
	}
}

// The audit between the artifact and the manifest, driven directly. Each row is a Result the
// manifest MUST NOT be written over, and none of them can be produced by the pipeline today —
// which is the point: the audit is what keeps that true when the pipeline changes.
func TestTheAuditRefusesAnArtifactItCannotVouchFor(t *testing.T) {
	const prefix = "install-7/cycle-1"
	whole := func() Result {
		return Result{
			From:     "0/1",
			Position: "0/2",
			Bytes:    7,
			Parts: []contract.Part{{
				Path: prefix + "/changes.0001.0000", Bytes: 7, SHA256: digest("CDC-one"),
			}},
		}
	}

	tests := []struct {
		name string
		bend func(*Result)
		says string
	}{
		{
			name: "no parts at all, which is a manifest over nothing",
			bend: func(r *Result) { r.Parts = nil },
			says: "no objects",
		},
		{
			// THE RULE, LITERALLY: a manifest never references a hash it did not verify, and
			// an absent hash is the clearest case of one.
			name: "an object with no hash",
			bend: func(r *Result) { r.Parts[0].SHA256 = "" },
			says: "never references a hash it did not verify",
		},
		{
			name: "a hash that is not a sha256",
			bend: func(r *Result) { r.Parts[0].SHA256 = "deadbeef" },
			says: "not a sha256",
		},
		{
			name: "a hash in a second spelling, which compares unequal to the one that was computed",
			bend: func(r *Result) { r.Parts[0].SHA256 = strings.ToUpper(digest("CDC-one")) },
			says: "not a sha256",
		},
		{
			name: "a zero-byte object, which no source produces and no restore can use",
			bend: func(r *Result) { r.Parts[0].Bytes = 0; r.Bytes = 0 },
			says: "no bytes",
		},
		{
			// THE ONE ROW THE PIPELINE CAN PRODUCE TODAY: run.go copies the source's Position
			// verbatim and validates nothing. A manifest without one is a manifest nothing can
			// resume from, and the next cycle re-asks for a batch it has or skips one it never
			// took — found at restore, as a hole.
			name: "no position, so nothing could resume from the manifest",
			bend: func(r *Result) { r.Position = "" },
			says: "resume",
		},
		{
			// THE OTHER ROW THE PIPELINE CAN PRODUCE TODAY, and it is refused HERE rather than
			// left for a verifier to trip over later: a change file that does not say where it
			// begins makes a hole between it and the file before it permanently invisible, so it
			// is better never written than written and refused at restore.
			name: "no range start, so a hole before this file could never be seen",
			bend: func(r *Result) { r.From = "" },
			says: "where it begins",
		},
		{
			name: "two objects at one path, where the second overwrote the first",
			bend: func(r *Result) { r.Parts = append(r.Parts, r.Parts[0]); r.Bytes = 14 },
			says: "twice",
		},
		{
			name: "an object outside this cycle's prefix, which belongs to another cycle",
			bend: func(r *Result) { r.Parts[0].Path = "install-7/cycle-2/changes.0001.0000" },
			says: "outside",
		},
		{
			// An artifact object at the manifest's own path would be overwritten by the
			// manifest, and the manifest would then describe an object it had destroyed.
			name: "an object sitting where the manifest goes",
			bend: func(r *Result) { r.Parts[0].Path = prefix + "/" + manifestName },
			says: manifestName,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := whole()
			tc.bend(&result)

			err := audit(result, prefix)
			if err == nil {
				t.Fatal("the audit vouched for it")
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("error %q does not say %q", err, tc.says)
			}
		})
	}

	if err := audit(whole(), prefix); err != nil {
		t.Errorf("the audit refused an artifact that is fine: %v", err)
	}
}

// The audit is only worth anything if Run actually consults it, and every other row above is a
// shape the pipeline cannot produce — so this is what pins the call site. An empty Position IS
// reachable: run.go carries the source's own through without looking at it.
func TestARunWhoseArtifactFailsTheAuditWritesNoManifest(t *testing.T) {
	store := newMemStore()
	c := testCycle(&Pipeline{Store: store})

	_, err := c.Run(context.Background(), changing("", "sha256:abc", wholePart("changes.0001", "CDC-one")), "0/1")
	if err == nil {
		t.Fatal("a batch with no position was written up as a backup")
	}
	if !strings.Contains(err.Error(), "resume") {
		t.Errorf("error %q does not say why the artifact could not be claimed", err)
	}
	// The bytes are in the container and unreferenced, which is the safe half of the failure.
	if len(landed(store)) != 1 {
		t.Errorf("the artifact objects are %v", landed(store))
	}
	if tried := manifestsAttemptedIn(store); len(tried) != 0 {
		t.Fatalf("a manifest at %v was offered for an artifact the audit refused", tried)
	}
}

// Nothing changed is not a failed cycle and not a backup either, and the caller's alternative
// to recognising it is taking a base copy. It has to survive this wrap as it survived B3's.
func TestNoChangesSurvivesTheCyclesWrapAndWritesNothing(t *testing.T) {
	store := newMemStore()
	c := testCycle(&Pipeline{Store: store})

	_, err := c.Run(context.Background(), &fakeSource{}, "0/1")
	if !errors.Is(err, ErrNoChanges) {
		t.Fatalf("a source with nothing new gave %v", err)
	}
	if len(landed(store)) != 0 {
		t.Errorf("a cycle with no changes wrote %v", landed(store))
	}
}

// A cycle that is not configured to describe what it backed up must fail before it stores a
// byte, not after: a manifest missing the engine version is one a restore cannot check a target
// against, and that is discovered at the end of a long restore, in the middle of an incident.
func TestACycleThatCouldNotDescribeItselfRefusesBeforeStoringAnything(t *testing.T) {
	tests := []struct {
		name string
		bend func(*Cycle)
		says string
	}{
		{"no scope, so every cycle would share one prefix", func(c *Cycle) { c.Scope = "" }, "scope"},
		{"a scope that climbs out of itself", func(c *Cycle) { c.Scope = "install-7/../elsewhere" }, "prefix"},
		{"no pipeline", func(c *Cycle) { c.Pipeline = nil }, "pipeline"},
		{
			// Caught here as well as in the pipeline, because the pipeline only finds out after
			// it has asked the source — which for Postgres means connecting to the customer's
			// server and creating a replication slot on it, for a cycle that could never store.
			name: "a pipeline with nowhere to put the bytes",
			bend: func(c *Cycle) { c.Pipeline.Store = nil },
			says: "nowhere",
		},
		{"nothing saying what is being backed up", func(c *Cycle) { c.Subject.ResourceID = "" }, "backing up"},
		{"no artifact format, which a restorer refuses", func(c *Cycle) { c.Format = "" }, "format"},
		{"no producer, so a bad backup traces to nothing", func(c *Cycle) { c.Producer = contract.Producer{} }, "producer"},
		{"no engine version to check a restore target against", func(c *Cycle) { c.Subject.EngineVersion = "" }, "engine"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := newMemStore()
			c := testCycle(&Pipeline{Store: store})
			tc.bend(c)

			_, err := c.Run(context.Background(),
				changing("0/2", "sha256:abc", wholePart("changes.0001", "CDC-one")), "0/1")
			if err == nil {
				t.Fatal("a cycle that cannot describe itself ran anyway")
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("error %q does not say %q", err, tc.says)
			}
			if len(landed(store)) != 0 {
				t.Errorf("it stored %v before finding out", landed(store))
			}
		})
	}
}
