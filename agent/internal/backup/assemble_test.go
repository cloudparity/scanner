package backup

// assemble_test.go proves the thing prune.go said would prove its design or find it wrong: that a
// REAL CONTAINER — objects laid out exactly as base.go, manifest.go and rebase.go lay them — comes
// back as the chains a prune may safely delete on.
//
// NO AZURE. The container is memStore, the same fake the pipeline and the pruning tests use, and it
// answers List, Get and Exists the way store.Blob does: the listing anchored at a separator, a Get
// of an object that is not there an error, an Exists that can refuse to say.
//
// THE VERIFIER IS THE REAL ONE, asked through the real Postgres orderer over real LSNs, and the last
// test here re-reads the container AFTER a real Apply and asks it again. A stand-in for chain.Verify
// would be a second answer to "is this chain intact", and the whole point is that the first one still
// says yes.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/manukyanv07/parity-scanner/chain"
	"github.com/manukyanv07/parity-scanner/contract"
)

// Compile-time proof memStore is what an assembly reads through. Objects has no Delete on it: the
// read half of pruning cannot reach the write half, which is a property of the shape.
var _ Objects = (*memStore)(nil)

// errWillNotSay is a container that will not say whether an object is there — a 403, a 503, a proxy.
// It is neither "it is gone" nor "it is there", which is the whole point of it.
var errWillNotSay = errors.New("HTTP 403")

// baseCopy is where Azure put the restore-as-files, which is OUTSIDE the scope every cycle writes
// under (AD-033). Two of them, because a base copy is four objects and one of them going missing on
// its own is the case that matters.
var baseCopy = []string{"restore-2026-08-21/database.sql", "restore-2026-08-21/roles.sql"}

// put writes one object with the instant it was written, which is what a listing carries and what
// the debris grace period is measured against.
func put(t *testing.T, store *memStore, when time.Time, path string, body []byte) {
	t.Helper()
	store.now = when
	if err := store.Put(context.Background(), path, body); err != nil {
		t.Fatalf("lay %s into the container: %v", path, err)
	}
}

// putJSON writes a claim — a manifest or a marker — as the agent writes one.
func putJSON(t *testing.T, store *memStore, when time.Time, path string, claim any) {
	t.Helper()
	body, err := json.Marshal(claim)
	if err != nil {
		t.Fatalf("encode the claim for %s: %v", path, err)
	}
	put(t, store, when, path, body)
}

// layBase writes segment 0 THE WAY base.go DOES: the manifest under a prefix this cycle chose, and
// the objects it names where the cloud left them, outside that prefix and outside the scope.
func layBase(t *testing.T, store *memStore, prefix string, at time.Time, position string, objects []string) {
	t.Helper()
	layBaseAs(t, store, prefix, at, position, objects, pruneSubject)
}

// layBaseAs is the same, for a fixture that needs two databases in one scope.
func layBaseAs(t *testing.T, store *memStore, prefix string, at time.Time, position string, objects []string, subject contract.BackupSource) {
	t.Helper()
	var parts []contract.Part
	var total int64
	for _, path := range objects {
		body := []byte("base bytes of " + path)
		put(t, store, at, path, body)
		total += int64(len(body))
		parts = append(parts, contract.Part{
			Path:   path,
			Bytes:  int64(len(body)),
			SHA256: digest(path),
			Format: contract.FormatPlainSQL,
			Role:   contract.PartDatabase,
		})
	}
	putJSON(t, store, at, prefix+"/"+manifestName, contract.Manifest{
		ContractVersion: contract.BackupContractVersion,
		Kind:            contract.BackupBase,
		Source:          subject,
		ReadPoint:       contract.ReadPoint{At: at.Format(time.RFC3339), Position: position},
		Schema:          "sha256:abc",
		Artifact: contract.Artifact{
			Format: contract.FormatPGDumpCustom,
			Bytes:  total,
			Parts:  parts,
		},
		Producer: contract.Producer{Agent: "azure/0.1.0", Tool: "az 2.0.0"},
		// The cloud moved these bytes and our code was never in the byte path.
		Transfer: contract.RouteProviderCopy,
	})
}

// layChange writes one change cycle the way manifest.go does: the object and the manifest over it,
// both under the cycle's own prefix.
func layChange(t *testing.T, store *memStore, prefix string, at time.Time, from, position string) {
	t.Helper()
	layChangeAs(t, store, prefix, at, from, position, pruneSubject)
}

// layChangeAs is the same, for a fixture that needs two databases in one scope.
func layChangeAs(t *testing.T, store *memStore, prefix string, at time.Time, from, position string, subject contract.BackupSource) {
	t.Helper()
	path := prefix + "/changes.0000"
	body := []byte("changes reaching " + position)
	put(t, store, at, path, body)

	putJSON(t, store, at, prefix+"/"+manifestName, contract.Manifest{
		ContractVersion: contract.BackupContractVersion,
		Kind:            contract.BackupChange,
		Source:          subject,
		ReadPoint: contract.ReadPoint{
			At:       at.Format(time.RFC3339),
			From:     from,
			Position: position,
		},
		Schema: "sha256:abc",
		Artifact: contract.Artifact{
			Format: contract.FormatChangeJSONL,
			Bytes:  int64(len(body)),
			SHA256: digest(path),
			Parts: []contract.Part{{
				Path:   path,
				Bytes:  int64(len(body)),
				SHA256: digest(path),
				Format: contract.FormatChangeJSONL,
				Role:   contract.PartChanges,
			}},
		},
		Producer: contract.Producer{Agent: "azure/0.1.0", Tool: "pglogrepl 0.0.0"},
		Transfer: contract.RouteAgentStream,
	})
}

// layMarker ends a chain the way rebase.go does: a marker in the prefix where a manifest would have
// gone, and no manifest beside it.
func layMarker(t *testing.T, store *memStore, prefix string, at time.Time, recoverable string) {
	t.Helper()
	putJSON(t, store, at, prefix+"/"+reBaseName, contract.ReBase{
		ContractVersion: contract.BackupContractVersion,
		At:              at.Format(time.RFC3339),
		Reason:          contract.ReBaseSlotLost,
		Recoverable:     recoverable,
		Detail:          "the replication slot this chain streams through is gone",
	})
}

// paths is a chain's segment manifests, in the order the assembler put them.
func paths(s Stored) []string {
	var out []string
	for _, segment := range s.Segments {
		out = append(out, segment.Path)
	}
	return out
}

// THE ORDER IS FOLLOWED AND NEVER SORTED, AND THIS FIXTURE IS A CLOCK THAT STEPPED BACKWARDS —
// which manifest.go's prefixFor names as a thing that happens, and which is why the uniqueness of a
// prefix is carried by a random tail rather than by the instant in it.
//
// The base was written at 09:00 and the two change cycles at 07:00 and 08:00. So sorting by path
// puts the BASE LAST, and sorting by ReadPoint.At does the same, and either produces a chain
// chain.Verify refuses outright. The only thing that puts these three in replay order is the one
// comparison backup-shape.md §5 allows: a change file's From equals the position the segment before
// it reached.
func TestAContainerBecomesTheChainThatIsInIt(t *testing.T) {
	store := newMemStore()
	start := time.Date(2026, 8, 21, 6, 0, 0, 0, time.UTC)

	layBase(t, store, pruneScope+"/2026-08-21T09-00-00Z-mmmmmmmm",
		start.Add(3*time.Hour), "0/1000000", baseCopy)
	layChange(t, store, pruneScope+"/2026-08-21T07-00-00Z-zzzzzzzz",
		start.Add(time.Hour), "0/1000000", "0/2000000")
	layChange(t, store, pruneScope+"/2026-08-21T08-00-00Z-aaaaaaaa",
		start.Add(2*time.Hour), "0/2000000", "0/3000000")

	assembled, err := Assemble(context.Background(), store, pruneScope)
	if err != nil {
		t.Fatalf("assembling the container failed: %v", err)
	}
	if len(assembled.Chains) != 1 {
		t.Fatalf("%d chains assembled from one chain's objects: %v", len(assembled.Chains), assembled.Chains)
	}
	stored := assembled.Chains[0]

	want := []string{
		pruneScope + "/2026-08-21T09-00-00Z-mmmmmmmm/" + manifestName,
		pruneScope + "/2026-08-21T07-00-00Z-zzzzzzzz/" + manifestName,
		pruneScope + "/2026-08-21T08-00-00Z-aaaaaaaa/" + manifestName,
	}
	got := paths(stored)
	if len(got) != len(want) {
		t.Fatalf("%d segments, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("segment %d is %s, want %s — the chain was sorted rather than followed",
				i, got[i], want[i])
		}
	}
	if stored.Confirmed != "0/3000000" {
		t.Errorf("the chain reaches %q, want the last segment's position", stored.Confirmed)
	}
	// EVERY OBJECT IN THE SCOPE, and nothing outside it: the listing is what bounds the debris
	// sweep, so a base copy's objects must NOT be in it.
	if len(assembled.Listed) != 5 {
		t.Errorf("%d objects listed, want the three manifests and the two change objects: %v",
			len(assembled.Listed), assembled.Listed)
	}
	for _, path := range baseCopy {
		if _, held := assembled.Listed[path]; held {
			t.Errorf("%s is outside the scope and is in the listing the debris sweep reads", path)
		}
	}

	// THE REAL VERIFIER, over the real LSNs. An assembler that produced a chain nothing accepts has
	// produced nothing.
	how, err := chain.Verify(stored.chain(), order)
	if err != nil {
		t.Fatalf("the assembled chain is not one the verifier accepts: %v", err)
	}
	if how != chain.CheckedWhole {
		t.Errorf("the assembled chain was checked %q, want %q", how, chain.CheckedWhole)
	}
}

// A BASE COPY'S OBJECTS ARE VOUCHED FOR BY ASKING, and the answer is what lets the chain hold the
// floor up. Present, and the chain counts; gone, and it does not — whatever the manifest says.
func TestABaseCopysObjectsAreAskedAboutOneByOne(t *testing.T) {
	for _, tc := range []struct {
		name string
		drop string
		want bool
	}{
		{name: "the copy is where the manifest says it is", want: true},
		{name: "one of the four is gone", drop: baseCopy[1], want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newMemStore()
			start := time.Date(2026, 8, 21, 6, 0, 0, 0, time.UTC)
			layBase(t, store, pruneScope+"/base", start, "0/1000000", baseCopy)
			layChange(t, store, pruneScope+"/change-a", start.Add(time.Hour), "0/1000000", "0/2000000")
			if tc.drop != "" {
				delete(store.objects, tc.drop)
			}

			assembled, err := Assemble(context.Background(), store, pruneScope)
			if err != nil {
				t.Fatalf("assembling failed: %v", err)
			}
			if got := assembled.Chains[0].Elsewhere; got != tc.want {
				t.Fatalf("the chain's objects outside the scope were vouched for = %v, want %v", got, tc.want)
			}
			// A LISTING THAT REACHED THEM WOULD MAKE EVERY STRANGER'S OBJECT THIS SCOPE'S DEBRIS,
			// so the question is asked about one named object at a time and never widened.
			for path := range assembled.Listed {
				if !strings.HasPrefix(path, pruneScope+"/") {
					t.Errorf("the listing reached outside the scope: %s", path)
				}
			}
		})
	}
}

// THE FLOOR, AND THE FAILURE THIS TICKET EXISTS TO CLOSE. A base copy that is not there must not
// license retiring every other chain: the chain reads whole — the manifests are all present and the
// verifier accepts it — and there is nothing to restore from.
func TestABaseCopyThatIsGoneDoesNotLicenceRetiringTheOtherChains(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

	build := func(t *testing.T, keepCopy bool) (Assembled, error) {
		t.Helper()
		store := newMemStore()
		// The old chain, whose newest point is well outside any window a policy would keep.
		layBase(t, store, pruneScope+"/old-base", now.Add(-90*24*time.Hour), "0/1000000",
			[]string{"restore-old/database.sql"})
		layChange(t, store, pruneScope+"/old-change-a", now.Add(-89*24*time.Hour),
			"0/1000000", "0/2000000")
		// And the new one, which is the only thing that would be left.
		layBase(t, store, pruneScope+"/new-base", now.Add(-3*time.Hour), "1/1000000", baseCopy)
		layChange(t, store, pruneScope+"/new-change-a", now.Add(-2*time.Hour),
			"1/1000000", "1/2000000")

		if !keepCopy {
			// A lifecycle rule on the container, an operator tidying up, a half-finished prune:
			// the manifest still names it and the bytes are not there.
			delete(store.objects, baseCopy[0])
		}
		return Assemble(context.Background(), store, pruneScope)
	}

	policy := Policy{Before: now.Add(-30 * 24 * time.Hour)}

	assembled, err := build(t, false)
	if err != nil {
		t.Fatalf("assembling failed: %v", err)
	}
	_, err = Prune(assembled.Scope, now, assembled.Chains, assembled.Listed, policy, order)
	if err == nil {
		t.Fatal("the old chain was retired in favour of a new one whose base copy is not in the " +
			"container: every recovery point in this scope would have gone")
	}
	if !strings.Contains(err.Error(), "checked whole") {
		t.Errorf("the refusal does not say the floor is what stopped it: %v", err)
	}

	// AND IT IS NOT A PERMANENT REFUSAL. With the copy where the manifest says it is, the same
	// policy retires the same chain — which is what makes erring towards absent a cost rather than
	// a wall.
	assembled, err = build(t, true)
	if err != nil {
		t.Fatalf("assembling failed: %v", err)
	}
	plan, err := Prune(assembled.Scope, now, assembled.Chains, assembled.Listed, policy, order)
	if err != nil {
		t.Fatalf("a whole chain whose base copy is present did not hold the floor up: %v", err)
	}
	if len(plan.Delete) == 0 {
		t.Errorf("nothing was retired although the old chain is ninety days past the window:\n%s", plan)
	}
}

// A CHAIN WHOSE BYTES ARE MISSING FROM THE LISTING IS NOT WHOLE, however perfectly its manifests
// read. chain.Verify never touches an object, so this is the only place the difference is visible.
func TestAChainMissingItsObjectsIsNotCountedWhole(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	store := newMemStore()

	layBase(t, store, pruneScope+"/old-base", now.Add(-90*24*time.Hour), "0/1000000",
		[]string{"restore-old/database.sql"})
	layChange(t, store, pruneScope+"/old-change-a", now.Add(-89*24*time.Hour), "0/1000000", "0/2000000")
	layBase(t, store, pruneScope+"/new-base", now.Add(-3*time.Hour), "1/1000000", baseCopy)
	layChange(t, store, pruneScope+"/new-change-a", now.Add(-2*time.Hour), "1/1000000", "1/2000000")

	// The change file itself, gone, with its manifest left standing over it: the silent hole.
	delete(store.objects, pruneScope+"/new-change-a/changes.0000")

	assembled, err := Assemble(context.Background(), store, pruneScope)
	if err != nil {
		t.Fatalf("assembling failed: %v", err)
	}
	// The verifier is perfectly happy with it, which is the whole reason the presence check exists.
	if _, err := chain.Verify(assembled.Chains[0].chain(), order); err != nil {
		t.Fatalf("the fixture is wrong: the verifier should accept a chain with its bytes gone: %v", err)
	}

	_, err = Prune(assembled.Scope, now, assembled.Chains, assembled.Listed,
		Policy{Before: now.Add(-30 * 24 * time.Hour)}, order)
	if err == nil {
		t.Fatal("the old chain was retired in favour of one whose change file is not in the container")
	}
}

// DEBRIS INSIDE THE GRACE PERIOD IS LEFT, and it is the same shape as a cycle uploading right now:
// objects, no manifest. B4 writes the manifest last, so there is nothing else to tell them apart.
func TestDebrisIsSweptOnlyOnceItCannotBeACycleStillWriting(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	store := newMemStore()

	layBase(t, store, pruneScope+"/base", now.Add(-4*time.Hour), "0/1000000", baseCopy)
	layChange(t, store, pruneScope+"/change-a", now.Add(-3*time.Hour), "0/1000000", "0/2000000")

	killed := pruneScope + "/2026-08-19T09-00-00Z-4f2c9a1b/changes.0000"
	put(t, store, now.Add(-48*time.Hour), killed, []byte("what a killed cycle left"))
	running := pruneScope + "/2026-08-21T11-59-00Z-77aa11bb/changes.0000"
	put(t, store, now.Add(-time.Minute), running, []byte("a cycle uploading right now"))

	assembled, err := Assemble(context.Background(), store, pruneScope)
	if err != nil {
		t.Fatalf("assembling failed: %v", err)
	}
	plan, err := Prune(assembled.Scope, now, assembled.Chains, assembled.Listed, Policy{}, order)
	if err != nil {
		t.Fatalf("pruning failed: %v", err)
	}

	going := deleted(plan)
	if !going[killed] {
		t.Errorf("the killed cycle's object survived:\n%s", plan)
	}
	if going[running] {
		t.Errorf("an object written a minute ago was swept; the manifest about to name it would "+
			"then cover bytes that are gone:\n%s", plan)
	}
	if len(going) != 1 {
		t.Errorf("%d objects proposed for deletion, want only the debris:\n%s", len(going), plan)
	}
}

// A MARKER IS THE ONLY RECORD OF WHY A CHAIN ENDED, and it is matched to its chain by the one
// comparison allowed on a position: the marker says how far the chain still restores, and that is
// the position the chain's last segment reached.
func TestASupersededChainComesBackWithTheMarkerThatEndedIt(t *testing.T) {
	store := newMemStore()
	start := time.Date(2026, 8, 21, 6, 0, 0, 0, time.UTC)

	layBase(t, store, pruneScope+"/dead-base", start, "0/1000000", []string{"restore-old/database.sql"})
	layChange(t, store, pruneScope+"/dead-change-a", start.Add(time.Hour), "0/1000000", "0/2000000")
	layMarker(t, store, pruneScope+"/dead-ended", start.Add(2*time.Hour), "0/2000000")

	// The chain that replaced it, so the marker has more than one candidate to be matched against.
	layBase(t, store, pruneScope+"/live-base", start.Add(3*time.Hour), "1/1000000", baseCopy)

	assembled, err := Assemble(context.Background(), store, pruneScope)
	if err != nil {
		t.Fatalf("assembling failed: %v", err)
	}
	if len(assembled.Chains) != 2 {
		t.Fatalf("%d chains assembled, want the dead one and the live one", len(assembled.Chains))
	}
	for _, stored := range assembled.Chains {
		ended := stored.Ended != nil
		if want := stored.Confirmed == "0/2000000"; ended != want {
			t.Errorf("the chain reaching %s has a marker = %v, want %v", stored.Confirmed, ended, want)
		}
		if ended && stored.Ended.Marker.Reason != contract.ReBaseSlotLost {
			t.Errorf("the marker says %q", stored.Ended.Marker.Reason)
		}
	}
}

// NOTHING IS EVER DROPPED, and this is the rule that makes the assembler safe rather than merely
// correct. Prune reads "no manifest names this object" off the chains it is HANDED, so a manifest
// this file quietly discarded would make itself and every object it names into debris.
func TestEveryClaimComesBackEvenWhenItBelongsToNoChain(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	store := newMemStore()

	layBase(t, store, pruneScope+"/base", now.Add(-4*time.Hour), "0/1000000", baseCopy)
	layChange(t, store, pruneScope+"/change-a", now.Add(-3*time.Hour), "0/1000000", "0/2000000")

	// A change file whose base an earlier prune already took, three days old so the grace period
	// is nowhere near it. Its manifest names it, and no chain here can reach it.
	orphan := pruneScope + "/orphan"
	layChange(t, store, orphan, now.Add(-72*time.Hour), "9/1000000", "9/2000000")
	// And a marker that matches no chain at all.
	stray := pruneScope + "/stray-ended"
	layMarker(t, store, stray, now.Add(-72*time.Hour), "9/9000000")

	assembled, err := Assemble(context.Background(), store, pruneScope)
	if err != nil {
		t.Fatalf("assembling failed: %v", err)
	}
	plan, err := Prune(assembled.Scope, now, assembled.Chains, assembled.Listed,
		Policy{Superseded: true}, order)
	if err != nil {
		t.Fatalf("pruning failed: %v", err)
	}
	if len(plan.Delete) != 0 {
		t.Fatalf("objects nothing could place were deleted:\n%s", plan)
	}
	if len(plan.Unverifiable) != 2 {
		t.Fatalf("%d chains the verifier refuses, want the orphaned change file and the stray "+
			"marker:\n%s", len(plan.Unverifiable), plan)
	}
	// AND THE PLAN SAYS SO. A chain kept because nobody could verify it is not the same as a
	// healthy one, and an operator reading the plan has to learn it is there.
	if !strings.Contains(plan.String(), "the verifier refuses it") {
		t.Errorf("the plan does not report what it could not verify:\n%s", plan)
	}
}

// A CLAIM THAT WILL NOT PARSE STOPS EVERYTHING. It cannot become a chain, so nothing would claim
// the objects it names — and an assembly that carried on would hand a prune a picture in which a
// live chain's parts are a killed cycle's debris.
func TestAManifestNothingCanReadStopsTheAssembly(t *testing.T) {
	store := newMemStore()
	start := time.Date(2026, 8, 21, 6, 0, 0, 0, time.UTC)

	layBase(t, store, pruneScope+"/base", start, "0/1000000", baseCopy)
	put(t, store, start, pruneScope+"/half-written/"+manifestName, []byte("{\"kind\":"))

	_, err := Assemble(context.Background(), store, pruneScope)
	if err == nil {
		t.Fatal("a manifest nothing can read was skipped, and the objects it names would be swept")
	}
	if !strings.Contains(err.Error(), "half-written") {
		t.Errorf("the error does not name the object: %v", err)
	}
}

// A CONTAINER THAT WILL NOT SAY WHETHER A BASE COPY IS THERE IS NOT ONE TO DELETE FROM. It is
// neither "it is gone" nor "it is there", and rounding it to either is one of the two failures
// this whole design is between.
func TestAContainerThatWillNotAnswerAboutABaseCopyStopsThePrune(t *testing.T) {
	store := newMemStore()
	start := time.Date(2026, 8, 21, 6, 0, 0, 0, time.UTC)
	layBase(t, store, pruneScope+"/base", start, "0/1000000", baseCopy)
	store.unreadable[baseCopy[0]] = errWillNotSay

	_, err := Assemble(context.Background(), store, pruneScope)
	if err == nil {
		t.Fatal("a container that refused to say whether the base copy is there was read as an answer")
	}
	if !strings.Contains(err.Error(), baseCopy[0]) {
		t.Errorf("the error does not name the object nobody could see: %v", err)
	}
}

// THE DELIVERABLE. Assemble a real container, prune it, DELETE, and then read the container back
// from scratch and ask the real verifier about what is actually left in it.
//
// It is re-assembled rather than checked against plan.Keep on purpose: Keep is what the prune
// BELIEVED it was leaving, and the question is what the container HOLDS.
func TestWhatIsLeftInTheContainerAfterAnApplyIsStillAChainTheVerifierAccepts(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	store := newMemStore()

	// A chain a re-base ended, four days ago.
	layBase(t, store, pruneScope+"/dead-base", now.Add(-96*time.Hour), "0/1000000",
		[]string{"restore-old/database.sql", "restore-old/roles.sql"})
	layChange(t, store, pruneScope+"/dead-change-a", now.Add(-95*time.Hour), "0/1000000", "0/2000000")
	layChange(t, store, pruneScope+"/dead-change-b", now.Add(-94*time.Hour), "0/2000000", "0/3000000")
	layMarker(t, store, pruneScope+"/dead-ended", now.Add(-93*time.Hour), "0/3000000")

	// The chain that is being written now.
	layBase(t, store, pruneScope+"/live-base", now.Add(-4*time.Hour), "1/1000000", baseCopy)
	layChange(t, store, pruneScope+"/live-change-a", now.Add(-3*time.Hour), "1/1000000", "1/2000000")
	layChange(t, store, pruneScope+"/live-change-b", now.Add(-2*time.Hour), "1/2000000", "1/3000000")

	// And a killed cycle's debris, old enough to be nothing else.
	debris := pruneScope + "/2026-08-18T09-00-00Z-4f2c9a1b/changes.0000"
	put(t, store, now.Add(-72*time.Hour), debris, []byte("what a killed cycle left"))

	assembled, err := Assemble(context.Background(), store, pruneScope)
	if err != nil {
		t.Fatalf("assembling failed: %v", err)
	}
	plan, err := Prune(assembled.Scope, now, assembled.Chains, assembled.Listed,
		Policy{Superseded: true}, order)
	if err != nil {
		t.Fatalf("pruning failed: %v", err)
	}
	// DRY RUN IS THE SHAPE. Producing the plan reached no container at all.
	if len(store.deletes) != 0 {
		t.Fatalf("%d objects were deleted before anything applied the plan", len(store.deletes))
	}

	if err := Apply(context.Background(), store, plan, order); err != nil {
		t.Fatalf("applying the plan failed: %v", err)
	}

	left, err := Assemble(context.Background(), store, pruneScope)
	if err != nil {
		t.Fatalf("re-reading the container after the prune failed: %v", err)
	}
	if len(left.Chains) != 1 {
		t.Fatalf("%d chains are left in the container, want the live one", len(left.Chains))
	}
	how, err := chain.Verify(left.Chains[0].chain(), order)
	if err != nil {
		t.Fatalf("what is actually left in the container is not a chain the verifier accepts: %v", err)
	}
	if how != chain.CheckedWhole {
		t.Errorf("what is left was checked %q, want %q", how, chain.CheckedWhole)
	}
	// AND ITS BYTES ARE THERE, which the verifier never looks at.
	if !left.Chains[0].Elsewhere {
		t.Error("the base copy of the chain that survived is no longer in the container")
	}
	for _, path := range left.Chains[0].objects() {
		if _, held := store.objects[path]; !held {
			t.Errorf("the chain that remains names %s and the prune deleted it", path)
		}
	}

	// The retired chain is gone, its own base copy included — those are the objects the bill is.
	for _, path := range []string{"restore-old/database.sql", "restore-old/roles.sql", debris} {
		if _, held := store.objects[path]; held {
			t.Errorf("%s belongs to the retired chain or to a killed cycle and is still being paid for", path)
		}
	}
}

// A RE-BASE IS A WALL AND THE WALK STOPS AT IT. The new base copy's position is the slot's
// confirmed_flush_lsn, and on an idle source that is the very position the dead chain reached — so
// a walk that did not know about the marker would find the NEW chain's change files hanging off the
// OLD chain's last position and take them, leaving the new base as a one-segment chain for the
// marker to land on.
//
// Then a Policy.Superseded prune deletes the newest base copy, and what survives is post-re-base
// change files laid over a pre-re-base base — for ReBaseSchemaChanged, exactly the corruption the
// marker exists to prevent, verifying clean because the positions are contiguous.
func TestTheWalkDoesNotCrossTheReBaseThatEndedAChain(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	store := newMemStore()

	layBase(t, store, pruneScope+"/a-dead-base", now.Add(-8*time.Hour), "0/1000000",
		[]string{"restore-old/database.sql"})
	layChange(t, store, pruneScope+"/b-dead-change", now.Add(-7*time.Hour), "0/1000000", "0/2000000")
	layMarker(t, store, pruneScope+"/c-ended", now.Add(-6*time.Hour), "0/2000000")

	// THE IDLE SOURCE: nothing committed between the last change cycle and the re-base, so the new
	// base copy reports the position the old chain already reached.
	layBase(t, store, pruneScope+"/d-live-base", now.Add(-5*time.Hour), "0/2000000", baseCopy)
	layChange(t, store, pruneScope+"/e-live-change", now.Add(-4*time.Hour), "0/2000000", "0/3000000")

	assembled, err := Assemble(context.Background(), store, pruneScope)
	if err != nil {
		t.Fatalf("assembling failed: %v", err)
	}
	for _, stored := range assembled.Chains {
		if len(stored.Segments) > 0 && stored.Segments[0].Path == pruneScope+"/a-dead-base/"+manifestName {
			if len(stored.Segments) > 2 {
				t.Errorf("the dead chain took %d segments and it ended after two: %v",
					len(stored.Segments), paths(stored))
			}
		}
	}

	plan, err := Prune(assembled.Scope, now, assembled.Chains, assembled.Listed,
		Policy{Superseded: true}, order)
	if err != nil {
		// A refusal here is the conservative outcome and is acceptable; deleting the new base is not.
		t.Logf("the prune refused, which is the safe answer: %v", err)
		return
	}
	going := deleted(plan)
	for _, path := range append([]string{pruneScope + "/d-live-base/" + manifestName,
		pruneScope + "/e-live-change/changes.0000"}, baseCopy...) {
		if going[path] {
			t.Errorf("%s belongs to the chain the re-base STARTED and the plan deletes it:\n%s", path, plan)
		}
	}
}

// TWO SEGMENTS CLAIMING THE SAME PREDECESSOR IS A QUESTION ONLY THE SOURCE COULD ANSWER, so it is
// not answered: the walk stops, and BOTH come out as chains of their own that the verifier refuses
// and the prune keeps. What must not happen is one of them being picked and the other dropped,
// because a dropped manifest is an object nothing claims.
func TestAForkStopsTheWalkAndKeepsBothSides(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	store := newMemStore()

	layBase(t, store, pruneScope+"/base", now.Add(-96*time.Hour), "0/1000000", baseCopy)
	layChange(t, store, pruneScope+"/fork-a", now.Add(-95*time.Hour), "0/1000000", "0/2000000")
	layChange(t, store, pruneScope+"/fork-b", now.Add(-95*time.Hour), "0/1000000", "0/2500000")

	assembled, err := Assemble(context.Background(), store, pruneScope)
	if err != nil {
		t.Fatalf("assembling failed: %v", err)
	}
	plan, err := Prune(assembled.Scope, now, assembled.Chains, assembled.Listed, Policy{}, order)
	if err != nil {
		t.Fatalf("pruning failed: %v", err)
	}
	if len(plan.Delete) != 0 {
		t.Fatalf("a fork nothing could resolve was deleted from:\n%s", plan)
	}
	for _, path := range []string{
		pruneScope + "/fork-a/changes.0000", pruneScope + "/fork-b/changes.0000",
	} {
		if _, held := store.objects[path]; !held {
			t.Errorf("%s is missing from the fixture", path)
		}
	}
}

// SEGMENTS THAT POINT AT EACH OTHER ARE A SHAPE NOTHING WRITES AND A CONTAINER IS NOT OBLIGED TO BE
// FREE OF. The walk has to end; an assembler that spun here would hang the only command that can
// delete a backup, and it would hang it holding a container connection.
func TestAWalkOverSegmentsThatPointAtEachOtherEnds(t *testing.T) {
	store := newMemStore()
	start := time.Date(2026, 8, 21, 6, 0, 0, 0, time.UTC)

	layBase(t, store, pruneScope+"/base", start, "0/1000000", baseCopy)
	// A → B → A, and one that resumes from where it reached.
	layChange(t, store, pruneScope+"/loop-a", start.Add(time.Hour), "0/1000000", "0/2000000")
	layChange(t, store, pruneScope+"/loop-b", start.Add(2*time.Hour), "0/2000000", "0/1000000")
	layChange(t, store, pruneScope+"/self", start.Add(3*time.Hour), "0/9000000", "0/9000000")

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := Assemble(context.Background(), store, pruneScope); err != nil {
			t.Errorf("assembling failed: %v", err)
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the walk never ended over segments that point at each other")
	}
}

// TWO DATABASES UNDER ONE SCOPE MUST NOT BE CHAINED TOGETHER. Their positions are issued by
// different servers and can be equal by coincidence, and a chain assembled across them restores one
// database's changes into the other. chain.Verify would refuse the result — but only after the
// segments of two real chains had been mixed into one and the leftovers of both dropped.
func TestTwoDatabasesInOneScopeAreNeverChainedTogether(t *testing.T) {
	store := newMemStore()
	start := time.Date(2026, 8, 21, 6, 0, 0, 0, time.UTC)

	other := pruneSubject
	other.Database = "invoices"

	layBase(t, store, pruneScope+"/orders-base", start, "0/1000000", baseCopy)
	layChange(t, store, pruneScope+"/orders-change", start.Add(time.Hour), "0/1000000", "0/2000000")

	layBaseAs(t, store, pruneScope+"/invoices-base", start, "0/1000000",
		[]string{"restore-invoices/database.sql"}, other)
	// The SAME positions, issued by a different server.
	layChangeAs(t, store, pruneScope+"/invoices-change", start.Add(time.Hour),
		"0/1000000", "0/2000000", other)

	assembled, err := Assemble(context.Background(), store, pruneScope)
	if err != nil {
		t.Fatalf("assembling failed: %v", err)
	}
	if len(assembled.Chains) != 2 {
		t.Fatalf("%d chains assembled from two databases' cycles, want one each", len(assembled.Chains))
	}
	for _, stored := range assembled.Chains {
		if len(stored.Segments) != 2 {
			t.Fatalf("a chain came out with %d segments: %v", len(stored.Segments), paths(stored))
		}
		base := stored.Segments[0].Manifest.Source.Database
		if got := stored.Segments[1].Manifest.Source.Database; got != base {
			t.Errorf("a chain founded on %s was extended with %s's changes", base, got)
		}
		if _, err := chain.Verify(stored.chain(), order); err != nil {
			t.Errorf("the chain for %s is not one the verifier accepts: %v", base, err)
		}
	}
}

// A MANIFEST THAT PARSES AND NAMES NOTHING IS THE SUBTLER HALF OF "a claim that will not parse
// stops everything": it reads perfectly, claims no objects, and the bytes its cycle stored are then
// swept as a killed cycle's debris — under the ZERO policy, which retires no chain at all.
func TestAManifestThatNamesNoObjectsStopsTheAssembly(t *testing.T) {
	store := newMemStore()
	start := time.Date(2026, 8, 21, 6, 0, 0, 0, time.UTC)

	layBase(t, store, pruneScope+"/base", start, "0/1000000", baseCopy)
	put(t, store, start, pruneScope+"/empty-claim/changes.0000", []byte("bytes nobody will claim"))
	putJSON(t, store, start, pruneScope+"/empty-claim/"+manifestName, contract.Manifest{
		ContractVersion: contract.BackupContractVersion,
		Kind:            contract.BackupChange,
		Source:          pruneSubject,
		ReadPoint:       contract.ReadPoint{At: start.Format(time.RFC3339), From: "0/1000000", Position: "0/2000000"},
	})

	_, err := Assemble(context.Background(), store, pruneScope)
	if err == nil {
		t.Fatal("a manifest naming no objects was accepted, and the bytes under it would be swept")
	}
	if !strings.Contains(err.Error(), "empty-claim") {
		t.Errorf("the error does not name the object: %v", err)
	}
}

// A CLAIM FROM A CONTRACT VERSION THIS BUILD DOES NOT KNOW is one whose object list may not be
// fully enumerable, and the marker is what says a chain is over. Neither is a thing to delete on.
func TestAClaimFromANewerContractStopsTheAssembly(t *testing.T) {
	for _, tc := range []struct {
		name  string
		lay   func(t *testing.T, store *memStore, at time.Time)
		names string
	}{
		{
			name:  "a manifest",
			names: "newer-manifest",
			lay: func(t *testing.T, store *memStore, at time.Time) {
				putJSON(t, store, at, pruneScope+"/newer-manifest/"+manifestName, contract.Manifest{
					ContractVersion: contract.BackupContractVersion + 1,
					Kind:            contract.BackupChange,
					Source:          pruneSubject,
					ReadPoint:       contract.ReadPoint{At: at.Format(time.RFC3339), From: "0/1000000", Position: "0/2000000"},
					Artifact: contract.Artifact{
						Parts: []contract.Part{{Path: pruneScope + "/newer-manifest/changes.0000"}},
					},
				})
			},
		},
		{
			name:  "a re-base marker",
			names: "newer-marker",
			lay: func(t *testing.T, store *memStore, at time.Time) {
				putJSON(t, store, at, pruneScope+"/newer-marker/"+reBaseName, contract.ReBase{
					ContractVersion: contract.BackupContractVersion + 1,
					At:              at.Format(time.RFC3339),
					Reason:          contract.ReBaseSlotLost,
					Recoverable:     "0/2000000",
				})
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newMemStore()
			start := time.Date(2026, 8, 21, 6, 0, 0, 0, time.UTC)
			layBase(t, store, pruneScope+"/base", start, "0/1000000", baseCopy)
			tc.lay(t, store, start)

			_, err := Assemble(context.Background(), store, pruneScope)
			if err == nil {
				t.Fatal("a claim from a newer contract was read as one this build understands")
			}
			if !strings.Contains(err.Error(), tc.names) {
				t.Errorf("the error does not name the object: %v", err)
			}
		})
	}
}
