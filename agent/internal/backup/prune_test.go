package backup

// prune_test.go drives the only code in this repo that deletes a customer's backup, and every
// test here is a way of asking the one question: did anything a chain still needs go?
//
// NO AZURE AND NO POSTGRES. The container is memStore, the same fake the pipeline's tests use.
// THE VERIFIER IS THE REAL ONE — chain.Verify, asked through the real Postgres orderer over real
// LSNs — because a stand-in for it would be a second answer to "is this chain intact", and the
// deliverable of this ticket is precisely that the first one still says yes after a prune.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/manukyanv07/parity-scanner/chain"
	"github.com/manukyanv07/parity-scanner/chain/postgres"
	"github.com/manukyanv07/parity-scanner/contract"
)

// Compile-time proof the store fake is what Apply deletes through. Container has one method and
// it destroys, which is why it is not the interface the pipeline holds.
var _ Container = (*memStore)(nil)

// order is the real Postgres orderer. Every position in this file is a real LSN, so the chain
// verifier is answering about them exactly as it would in production — and a fixture that got an
// LSN wrong fails here rather than passing against a fake that agreed with it.
var order = postgres.WAL{}

const pruneScope = "install-7/pg1/orders"

// pruneSubject is the one database every fixture chain backs up. chain.Verify refuses a chain
// whose segments disagree about it, so it is one value rather than a literal per manifest.
var pruneSubject = contract.BackupSource{
	Provider:      contract.ProviderAzure,
	ResourceID:    "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.dbforpostgresql/flexibleservers/pg1",
	Database:      "orders",
	Engine:        "postgres",
	EngineVersion: "16",
}

// segment lays one cycle out the way the agent writes one: its own prefix, its objects under it,
// and manifest.json over them.
func segment(prefix string, kind contract.BackupKind, at time.Time, from, position, name string) Segment {
	return Segment{
		Path: prefix + "/" + manifestName,
		Manifest: contract.Manifest{
			ContractVersion: contract.BackupContractVersion,
			Kind:            kind,
			Source:          pruneSubject,
			ReadPoint: contract.ReadPoint{
				At:       at.Format(time.RFC3339),
				From:     from,
				Position: position,
			},
			Schema: "sha256:abc",
			Artifact: contract.Artifact{
				Format: contract.FormatPGDumpCustom,
				Bytes:  8,
				Parts: []contract.Part{{
					Path:   prefix + "/" + name + ".0000",
					Bytes:  8,
					SHA256: digest(name),
					Format: contract.FormatPGDumpCustom,
					Role:   contract.PartDatabase,
				}},
			},
			Producer: contract.Producer{Agent: "azure/0.1.0", Tool: "pglogrepl 0.0.0"},
			Transfer: contract.RouteAgentStream,
		},
	}
}

// storedChain builds one whole chain as it lies in the container — a base cycle and one change
// cycle per range — and every object it is made of, timestamped an hour apart.
//
// ranges are {from, reached} pairs in real LSNs. The base's position is the first range's from,
// which is the overlap AD-035 describes rather than a convenience: the slot is created before the
// copy is asked for, so the base and the first change file begin at the same place.
func storedChain(root string, start time.Time, ranges [][2]string) (Stored, map[string]time.Time) {
	objects := map[string]time.Time{}
	at := start

	prefix := pruneScope + "/" + root + "-base"
	segments := []Segment{segment(prefix, contract.BackupBase, at, "", ranges[0][0], "database.sql")}

	for i, r := range ranges {
		at = at.Add(time.Hour)
		prefix = pruneScope + "/" + root + "-change-" + string(rune('a'+i))
		segments = append(segments, segment(prefix, contract.BackupChange, at, r[0], r[1], "changes"))
	}

	stored := Stored{Segments: segments, Confirmed: ranges[len(ranges)-1][1]}
	for i, seg := range stored.Segments {
		when := start.Add(time.Duration(i) * time.Hour)
		objects[seg.Path] = when
		for _, part := range seg.Manifest.Artifact.Parts {
			objects[part.Path] = when
		}
	}
	return stored, objects
}

// merge is every object of several chains in one container.
func merge(sets ...map[string]time.Time) map[string]time.Time {
	all := map[string]time.Time{}
	for _, set := range sets {
		for path, when := range set {
			all[path] = when
		}
	}
	return all
}

// ends closes a chain the way rebase.go does: a marker in the cycle prefix where a manifest would
// have gone, and no manifest beside it.
func ends(s Stored, objects map[string]time.Time, when time.Time, reason contract.ReBaseReason) Stored {
	path := pruneScope + "/ended-" + string(reason) + "/" + reBaseName
	s.Ended = &Ended{
		Path: path,
		Marker: contract.ReBase{
			ContractVersion: contract.BackupContractVersion,
			At:              when.Format(time.RFC3339),
			Reason:          reason,
			Recoverable:     s.Confirmed,
		},
	}
	objects[path] = when
	return s
}

// deleted is the set of paths a plan would remove.
func deleted(p Plan) map[string]bool {
	set := map[string]bool{}
	for _, removal := range p.Delete {
		set[removal.Path] = true
	}
	return set
}

// loaded is a container holding exactly the objects given, so Apply has something real to delete.
func loaded(t *testing.T, objects map[string]time.Time) *memStore {
	t.Helper()
	store := newMemStore()
	for path := range objects {
		if err := store.Put(context.Background(), path, []byte("bytes")); err != nil {
			t.Fatalf("seed %s: %v", path, err)
		}
	}
	return store
}

// A LIVE CHAIN IS UNTOUCHED, and it is the first test because it is the failure that ends a
// company. The policy here is as aggressive as a policy gets — a retention window that has
// already closed over yesterday, and superseded chains explicitly allowed to go — and the chain
// being written right now must still come through it whole.
func TestPruneLeavesALiveChainExactlyWhereItWas(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	live, objects := storedChain("live", now.Add(-3*time.Hour),
		[][2]string{{"0/1000000", "0/2000000"}, {"0/2000000", "0/3000000"}})

	plan, err := Prune(pruneScope, now, []Stored{live}, objects,
		Policy{Before: now.Add(-24 * time.Hour), Superseded: true}, order)
	if err != nil {
		t.Fatalf("pruning a container holding one live chain failed: %v", err)
	}
	if len(plan.Delete) != 0 {
		t.Fatalf("a live chain was proposed for deletion:\n%s", plan)
	}
	if len(plan.Keep) != 1 {
		t.Fatalf("%d chains kept, want the one that is live", len(plan.Keep))
	}
}

// A PARTIAL CYCLE'S DEBRIS GOES, and it is the one genuinely easy case: B4 writes the manifest
// last and atomically, so objects with no manifest over them are what a cycle that was killed
// left behind. They cost storage forever and nothing will ever reference them.
func TestTheDebrisOfAKilledCycleGoes(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	live, objects := storedChain("live", now.Add(-3*time.Hour),
		[][2]string{{"0/1000000", "0/2000000"}})

	// A cycle that died between its first object and its manifest. Two days old, so no cycle
	// running now could still be writing it.
	debris := pruneScope + "/2026-08-19T09-00-00Z-4f2c9a1b/changes.0000"
	objects[debris] = now.Add(-48 * time.Hour)

	// And one written a minute ago, which is what a cycle that is uploading RIGHT NOW looks like:
	// objects, no manifest. Identical in shape to the debris above and the opposite in meaning.
	running := pruneScope + "/2026-08-21T11-59-00Z-77aa11bb/changes.0000"
	objects[running] = now.Add(-time.Minute)

	plan, err := Prune(pruneScope, now, []Stored{live}, objects, Policy{}, order)
	if err != nil {
		t.Fatalf("pruning failed: %v", err)
	}

	going := deleted(plan)
	if !going[debris] {
		t.Errorf("the killed cycle's object survived:\n%s", plan)
	}
	if going[running] {
		t.Errorf("an object written a minute ago was swept as debris; a cycle uploading right "+
			"now would lose the parts its manifest is about to name:\n%s", plan)
	}
	if len(going) != 1 {
		t.Errorf("%d objects proposed for deletion, want only the debris:\n%s", len(going), plan)
	}
}

// REMOVING A CHANGE FILE OUT OF THE MIDDLE IS REFUSED, and this is the rule the whole file exists
// for. It is checked where the deletion happens rather than where the plan was made, because a
// Plan is an ordinary value anybody can edit.
//
// THE OBJECT AND THE MANIFEST ARE TWO DIFFERENT FAILURES AND BOTH ARE HERE. Delete the change
// FILE and leave its manifest, and chain.Verify still passes with the data gone — the silent hole.
// Delete the MANIFEST and the chain has a gap the verifier does catch. One check sees each.
func TestTakingAChangeFileOutOfTheMiddleOfALiveChainIsRefused(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	live, objects := storedChain("live", now.Add(-4*time.Hour), [][2]string{
		{"0/1000000", "0/2000000"},
		{"0/2000000", "0/3000000"},
		{"0/3000000", "0/4000000"},
	})
	middle := live.Segments[2]

	t.Run("the change file, with its manifest left in place", func(t *testing.T) {
		store := loaded(t, objects)
		plan := Plan{
			Keep:   []Stored{live},
			Delete: []Removal{{Path: middle.Manifest.Artifact.Parts[0].Path, Why: "hand-edited"}},
		}
		err := Apply(context.Background(), store, plan, order)
		if err == nil {
			t.Fatal("a change file was deleted out of the middle of a live chain")
		}
		if !strings.Contains(err.Error(), middle.Manifest.Artifact.Parts[0].Path) {
			t.Errorf("the refusal does not name the object: %v", err)
		}
		if len(store.deletes) != 0 {
			t.Errorf("%d objects were deleted before the plan was refused: %v", len(store.deletes), store.deletes)
		}
	})

	t.Run("the manifest, leaving a chain with a hole in it", func(t *testing.T) {
		store := loaded(t, objects)
		short := live
		short.Segments = []Segment{live.Segments[0], live.Segments[1], live.Segments[3]}

		plan := Plan{
			Keep:   []Stored{short},
			Delete: []Removal{{Path: middle.Path, Why: "hand-edited"}},
		}
		err := Apply(context.Background(), store, plan, order)
		if err == nil {
			t.Fatal("a manifest was deleted out of the middle of a live chain")
		}
		if !strings.Contains(err.Error(), "0/3000000") {
			t.Errorf("the refusal does not say where the hole would be: %v", err)
		}
		if len(store.deletes) != 0 {
			t.Errorf("%d objects were deleted before the plan was refused: %v", len(store.deletes), store.deletes)
		}
	})
}

// REFUSING TO LEAVE NOTHING. Whatever the policy says, a prune that would take the last chain
// anything can be restored from is an error and not a successful prune — there is no reading of
// "retention" under which the answer is zero backups.
func TestAPolicyThatWouldLeaveNoChainAtAllIsRefused(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	old, objects := storedChain("old", now.Add(-90*24*time.Hour),
		[][2]string{{"0/1000000", "0/2000000"}})

	_, err := Prune(pruneScope, now, []Stored{old}, objects, Policy{Before: now.Add(-24 * time.Hour)}, order)
	if err == nil {
		t.Fatal("a policy that retires every chain in the container was reported as a plan")
	}
	if !strings.Contains(err.Error(), "restored") {
		t.Errorf("the refusal does not say what would be lost: %v", err)
	}
}

// The same policy is fine the moment something newer exists to fall back to: the old chain goes,
// whole, and the new one is untouched.
func TestAnOldChainGoesOnceANewerOneCanBeRestoredFrom(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	old, oldObjects := storedChain("old", now.Add(-90*24*time.Hour),
		[][2]string{{"0/1000000", "0/2000000"}})
	fresh, freshObjects := storedChain("fresh", now.Add(-3*time.Hour),
		[][2]string{{"1/1000000", "1/2000000"}})

	plan, err := Prune(pruneScope, now, []Stored{old, fresh}, merge(oldObjects, freshObjects),
		Policy{Before: now.Add(-24 * time.Hour)}, order)
	if err != nil {
		t.Fatalf("pruning failed: %v", err)
	}

	going := deleted(plan)
	for path := range oldObjects {
		if !going[path] {
			t.Errorf("%s belongs to the retired chain and survives the plan:\n%s", path, plan)
		}
	}
	for path := range freshObjects {
		if going[path] {
			t.Errorf("%s belongs to the chain inside the window and is being deleted:\n%s", path, plan)
		}
	}
}

// WITH NOTHING TO ORDER THE POSITIONS, NOTHING CAN BE RETIRED. A source that cannot order its own
// positions leaves every chain checked shape-only — well formed, and whether it has a hole in it
// unknown — and retiring one on the strength of another nobody could check is the trade this file
// does not make.
func TestNoChainIsRetiredWhenNothingCanSayWhetherOneIsWhole(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	old, oldObjects := storedChain("old", now.Add(-90*24*time.Hour),
		[][2]string{{"0/1000000", "0/2000000"}})
	fresh, freshObjects := storedChain("fresh", now.Add(-3*time.Hour),
		[][2]string{{"1/1000000", "1/2000000"}})

	_, err := Prune(pruneScope, now, []Stored{old, fresh}, merge(oldObjects, freshObjects),
		Policy{Before: now.Add(-24 * time.Hour)}, nil)
	if err == nil {
		t.Fatal("a chain was retired although nothing could check the chain that remains for holes")
	}
	if !strings.Contains(err.Error(), "order") {
		t.Errorf("the refusal does not say that nothing could order these positions: %v", err)
	}
}

// A SUPERSEDED CHAIN GOES ONLY WHEN THE POLICY SAYS SO. After a re-base the old chain is finished
// and it is STILL the only thing that restores to any point before the new base, so retiring it is
// a decision somebody makes — never a consequence of a new chain existing.
func TestASupersededChainGoesOnlyWhenThePolicySaysSo(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	dead, deadObjects := storedChain("dead", now.Add(-6*time.Hour),
		[][2]string{{"0/1000000", "0/2000000"}})
	dead = ends(dead, deadObjects, now.Add(-4*time.Hour), contract.ReBaseSchemaChanged)
	live, liveObjects := storedChain("live", now.Add(-3*time.Hour),
		[][2]string{{"1/1000000", "1/2000000"}})

	objects := merge(deadObjects, liveObjects)
	chains := []Stored{dead, live}

	plan, err := Prune(pruneScope, now, chains, objects, Policy{}, order)
	if err != nil {
		t.Fatalf("pruning failed: %v", err)
	}
	if len(plan.Delete) != 0 {
		t.Fatalf("a superseded chain was retired by a policy that never asked for it:\n%s", plan)
	}

	plan, err = Prune(pruneScope, now, chains, objects, Policy{Superseded: true}, order)
	if err != nil {
		t.Fatalf("pruning with superseded chains allowed failed: %v", err)
	}
	going := deleted(plan)
	for path := range deadObjects {
		if !going[path] {
			t.Errorf("%s belongs to the superseded chain and survives:\n%s", path, plan)
		}
	}
	if !going[dead.Ended.Path] {
		t.Errorf("the re-base marker survives the chain it ended:\n%s", plan)
	}
	for path := range liveObjects {
		if going[path] {
			t.Errorf("%s belongs to the live chain and is being deleted:\n%s", path, plan)
		}
	}
}

// THE DELIVERABLE. Prune, apply it for real, and then ask the REAL verifier whether what is left
// in the container is still a chain — and check that every object it names is still there, which
// is the half the verifier cannot see.
func TestWhatIsLeftAfterAPruneIsStillAChainTheVerifierAccepts(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

	dead, deadObjects := storedChain("dead", now.Add(-8*time.Hour),
		[][2]string{{"0/1000000", "0/2000000"}, {"0/2000000", "0/3000000"}})
	dead = ends(dead, deadObjects, now.Add(-5*time.Hour), contract.ReBaseSlotLost)
	live, liveObjects := storedChain("live", now.Add(-4*time.Hour), [][2]string{
		{"1/1000000", "1/2000000"},
		{"1/2000000", "1/3000000"},
		{"1/3000000", "1/4000000"},
	})

	objects := merge(deadObjects, liveObjects)
	debris := pruneScope + "/2026-08-19T09-00-00Z-4f2c9a1b/changes.0000"
	objects[debris] = now.Add(-48 * time.Hour)

	plan, err := Prune(pruneScope, now, []Stored{dead, live}, objects, Policy{Superseded: true}, order)
	if err != nil {
		t.Fatalf("pruning failed: %v", err)
	}

	store := loaded(t, objects)
	// PRUNE DELETED NOTHING BY ITSELF. Dry run is not a flag here, it is the shape: Prune has no
	// container to reach.
	if len(store.deletes) != 0 {
		t.Fatalf("Prune deleted %d objects on its own", len(store.deletes))
	}

	if err := Apply(context.Background(), store, plan, order); err != nil {
		t.Fatalf("applying the plan failed: %v", err)
	}

	// THE MANIFESTS GO BEFORE THE OBJECTS THEY NAME. An interrupted prune must not leave a
	// manifest pointing at bytes that are gone, which is a chain that verifies with a hole in it.
	manifest := indexOf(store.deletes, dead.Segments[1].Path)
	part := indexOf(store.deletes, dead.Segments[1].Manifest.Artifact.Parts[0].Path)
	if manifest < 0 || part < 0 || manifest > part {
		t.Errorf("the manifest was deleted at %d and the object it names at %d: %v",
			manifest, part, store.deletes)
	}

	for _, kept := range plan.Keep {
		how, err := chain.Verify(kept.chain(), order)
		if err != nil {
			t.Fatalf("what the prune left behind is not a chain the verifier accepts: %v", err)
		}
		if how != chain.CheckedWhole {
			t.Errorf("the chain that remains was checked %q, want %q", how, chain.CheckedWhole)
		}
		for _, path := range kept.objects() {
			if _, held := store.objects[path]; !held {
				t.Errorf("the chain that remains names %s and the prune deleted it", path)
			}
		}
	}

	for path := range deadObjects {
		if _, held := store.objects[path]; held {
			t.Errorf("%s belongs to the retired chain and is still being paid for", path)
		}
	}
	if _, held := store.objects[debris]; held {
		t.Error("the killed cycle's debris is still in the container")
	}
}

// indexOf is where a path was deleted, or -1.
func indexOf(paths []string, want string) int {
	for i, path := range paths {
		if path == want {
			return i
		}
	}
	return -1
}

// A chain the verifier already refuses is NOT a licence to delete it. It restores nothing, and it
// may still be the only copy of bytes somebody can salvage by hand; the cost of keeping it is
// storage and the cost of being wrong is the data. It is kept, and it does not count as the chain
// the floor above requires.
func TestAChainTheVerifierRefusesIsKeptAndDoesNotCountAsTheOneThatMustRemain(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	broken, brokenObjects := storedChain("broken", now.Add(-3*time.Hour),
		[][2]string{{"0/1000000", "0/2000000"}, {"0/2000000", "0/3000000"}})
	// A file lost out of the middle already: segment 2 begins where nothing ended. The container
	// matches — the cycle's manifest and its object are both gone, which is what "lost" means.
	lost := broken.Segments[1]
	delete(brokenObjects, lost.Path)
	delete(brokenObjects, lost.Manifest.Artifact.Parts[0].Path)
	broken.Segments = []Segment{broken.Segments[0], broken.Segments[2]}

	old, oldObjects := storedChain("old", now.Add(-90*24*time.Hour),
		[][2]string{{"1/1000000", "1/2000000"}})

	_, err := Prune(pruneScope, now, []Stored{broken, old}, merge(brokenObjects, oldObjects),
		Policy{Before: now.Add(-24 * time.Hour)}, order)
	if err == nil {
		t.Fatal("the old chain was retired although the only chain left is one the verifier refuses")
	}

	// And it must not stop the container being swept. Debris beside a chain nobody can verify is
	// still debris, and one broken chain that blocked every future prune would be the cost bomb
	// arriving through the door marked "safety".
	debris := pruneScope + "/2026-08-19T09-00-00Z-4f2c9a1b/changes.0000"
	brokenObjects[debris] = now.Add(-48 * time.Hour)

	plan, err := Prune(pruneScope, now, []Stored{broken}, brokenObjects, Policy{}, order)
	if err != nil {
		t.Fatalf("pruning a container holding one broken chain failed: %v", err)
	}
	if len(plan.Keep) != 0 {
		t.Errorf("a chain the verifier refuses was counted among the chains that can be restored from")
	}
	if len(plan.Unverifiable) != 1 {
		t.Errorf("the plan does not say a chain nobody can verify is sitting in the container:\n%s", plan)
	}
	going := deleted(plan)
	if !going[debris] {
		t.Errorf("debris beside a broken chain was left behind:\n%s", plan)
	}
	for _, path := range broken.objects() {
		if going[path] {
			t.Errorf("%s belongs to a chain the verifier refuses and was deleted rather than left "+
				"for a human:\n%s", path, plan)
		}
	}
}

// NO CHAINS OVER A CONTAINER THAT HOLDS SOMETHING IS A BROKEN ASSEMBLER, NOT AN EMPTY SCOPE — and
// it is the one shape where "delete everything" was reachable with no error anywhere. Every object
// is unclaimed, so the debris sweep proposes the whole container, and the floor never fires because
// a policy that retires no chain has retired nothing.
func TestAPruneHandedNoChainsRefusesToSweepAContainerThatHoldsSomething(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	_, objects := storedChain("live", now.Add(-90*24*time.Hour),
		[][2]string{{"0/1000000", "0/2000000"}})

	_, err := Prune(pruneScope, now, nil, objects, Policy{}, order)
	if err == nil {
		t.Fatal("a prune with no chains proposed sweeping a container full of backups")
	}
	if !strings.Contains(err.Error(), "no chains") {
		t.Errorf("the refusal does not say the chain list was empty: %v", err)
	}

	// An empty scope really being empty is fine, and stays a no-op.
	plan, err := Prune(pruneScope, now, nil, nil, Policy{}, order)
	if err != nil {
		t.Fatalf("pruning an empty scope failed: %v", err)
	}
	if len(plan.Delete) != 0 {
		t.Errorf("an empty scope produced deletions:\n%s", plan)
	}
}

// A LISTING WIDER THAN THE CHAINS IS HOW ANOTHER SOURCE'S BACKUPS BECOME THIS ONE'S DEBRIS. The
// scope is checked against the listing rather than trusted, because nothing else in the inputs
// records which prefix the listing came from.
func TestAListingReachingOutsideTheScopeIsRefused(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	live, objects := storedChain("live", now.Add(-3*time.Hour),
		[][2]string{{"0/1000000", "0/2000000"}})

	// Another database's backup, in the same container, whose chains this prune was never given.
	stranger := "install-7/pg2/invoices/cycle-a/changes.0000"
	objects[stranger] = now.Add(-72 * time.Hour)

	_, err := Prune(pruneScope, now, []Stored{live}, objects, Policy{}, order)
	if err == nil {
		t.Fatal("an object from a scope this prune knows nothing about was accepted into the sweep")
	}
	if !strings.Contains(err.Error(), stranger) {
		t.Errorf("the refusal does not name the object: %v", err)
	}
}

// THE FLOOR ASKS THE CONTAINER, NOT ONLY THE VERIFIER. chain.Verify reads manifests and never
// touches an object — this file's whole premise — so a chain whose bytes a storage lifecycle rule
// or a half-finished prune removed is checked WHOLE and restores nothing. Counting it is what would
// license deleting every other chain in favour of it.
func TestAChainWhoseObjectsAreGoneDoesNotLicenceDeletingTheOthers(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	old, oldObjects := storedChain("old", now.Add(-90*24*time.Hour),
		[][2]string{{"0/1000000", "0/2000000"}})
	fresh, freshObjects := storedChain("fresh", now.Add(-3*time.Hour),
		[][2]string{{"1/1000000", "1/2000000"}})

	objects := merge(oldObjects, freshObjects)
	// The survivor's manifests are all intact — Verify says CheckedWhole — and its base copy is
	// simply not in the container any more.
	gone := fresh.Segments[0].Manifest.Artifact.Parts[0].Path
	delete(objects, gone)

	_, err := Prune(pruneScope, now, []Stored{old, fresh}, objects,
		Policy{Before: now.Add(-24 * time.Hour)}, order)
	if err == nil {
		t.Fatal("the old chain was retired in favour of one whose base copy is not in the container")
	}

	// With the object back, the same prune is fine — so it is the absence that refused it.
	objects[gone] = now.Add(-3 * time.Hour)
	if _, err := Prune(pruneScope, now, []Stored{old, fresh}, objects,
		Policy{Before: now.Add(-24 * time.Hour)}, order); err != nil {
		t.Fatalf("pruning with the survivor's objects all present failed: %v", err)
	}
}

// AN OBJECT THE LISTING CANNOT COVER IS ABSENT UNTIL SOMEBODY LOOKED. A base copy's objects sit
// outside the scope (AD-033), so a scoped listing says nothing about them either way — and the
// unset Stored.Elsewhere is the answer "nobody looked", which must not be read as "they are there".
// A chain nobody vouched for does not hold the floor up.
//
// The same fixture with Elsewhere set is the whole difference, so this is the field and not
// something else refusing the prune. assemble_test.go is where it gets filled in from a container.
func TestAChainNobodyVouchedForDoesNotHoldTheFloorUp(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	old, oldObjects := storedChain("old", now.Add(-90*24*time.Hour),
		[][2]string{{"0/1000000", "0/2000000"}})
	fresh, freshObjects := storedChain("fresh", now.Add(-3*time.Hour),
		[][2]string{{"1/1000000", "1/2000000"}})

	// The base copy where Azure put it: named by the manifest, outside the scope, and therefore
	// invisible to the listing that bounds the debris sweep.
	copied := "restore-2026-08-21/database.sql"
	fresh.Segments[0].Manifest.Artifact.Parts = append(
		fresh.Segments[0].Manifest.Artifact.Parts, contract.Part{
			Path:   copied,
			Bytes:  8,
			SHA256: digest(copied),
			Format: contract.FormatPlainSQL,
			Role:   contract.PartDatabase,
		})
	objects := merge(oldObjects, freshObjects)

	policy := Policy{Before: now.Add(-24 * time.Hour)}
	if _, err := Prune(pruneScope, now, []Stored{old, fresh}, objects, policy, order); err == nil {
		t.Fatal("the old chain was retired in favour of one whose base copy nothing had looked for")
	}

	fresh.Elsewhere = true
	if _, err := Prune(pruneScope, now, []Stored{old, fresh}, objects, policy, order); err != nil {
		t.Fatalf("a chain whose objects outside the scope were vouched for did not hold the "+
			"floor up: %v", err)
	}
}

// A PLAN THAT DELETES AND NAMES NO CHAIN PROTECTS NOTHING. survives compares Delete against Keep
// and Unverifiable, and both are fields of the same value a caller holds — so a plan that lost them
// on the way here passes every check by having nothing left to check.
func TestApplyRefusesAPlanThatArrivedWithoutItsChains(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	live, objects := storedChain("live", now.Add(-3*time.Hour),
		[][2]string{{"0/1000000", "0/2000000"}})

	store := loaded(t, objects)
	hollow := Plan{Delete: []Removal{{Path: live.Segments[0].Path, Why: "arrived without its chains"}}}

	if err := Apply(context.Background(), store, hollow, order); err == nil {
		t.Fatal("a plan carrying only a delete list was executed")
	}
	if len(store.deletes) != 0 {
		t.Errorf("%d objects were deleted before the plan was refused: %v", len(store.deletes), store.deletes)
	}
}

// AN APPLY THAT STOPS HALFWAY MUST LEAVE THE NEXT ONE ABLE TO FINISH. The re-base marker goes LAST
// of a chain's objects: deleting it first would make a chain Apply then failed to finish look live
// again — Policy.Superseded would stop matching it — and would throw away the record of WHY the
// chain ended, which is the one thing rebase.go exists to make visible.
func TestAnApplyThatFailsPartWayThroughLeavesTheMarkerThatSaysTheChainWasSuperseded(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	dead, deadObjects := storedChain("dead", now.Add(-8*time.Hour),
		[][2]string{{"0/1000000", "0/2000000"}})
	dead = ends(dead, deadObjects, now.Add(-5*time.Hour), contract.ReBaseSlotLost)
	live, liveObjects := storedChain("live", now.Add(-3*time.Hour),
		[][2]string{{"1/1000000", "1/2000000"}})

	objects := merge(deadObjects, liveObjects)
	plan, err := Prune(pruneScope, now, []Stored{dead, live}, objects, Policy{Superseded: true}, order)
	if err != nil {
		t.Fatalf("pruning failed: %v", err)
	}

	store := loaded(t, objects)
	// The container starts refusing part way through — a throttle, a token expiry, a dropped
	// connection. Apply stops rather than carrying on past a container that will not answer.
	store.refuse[dead.Segments[1].Manifest.Artifact.Parts[0].Path] = errors.New("503 ServerBusy")

	if err := Apply(context.Background(), store, plan, order); err == nil {
		t.Fatal("a container that refused a delete was reported as a completed prune")
	}
	if _, held := store.objects[dead.Ended.Path]; !held {
		t.Error("the re-base marker went before the chain it ended was fully removed, so the next " +
			"prune cannot tell this chain was superseded")
	}
	for path := range liveObjects {
		if _, held := store.objects[path]; !held {
			t.Errorf("the live chain lost %s to a prune that was aiming at another chain", path)
		}
	}
}

// The plan is printable before it runs, because a plan nobody can read is a plan nobody will
// check — and this is the only thing standing between a policy and a customer's last backup.
func TestThePlanSaysWhatItWouldDeleteAndWhy(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)
	dead, deadObjects := storedChain("dead", now.Add(-8*time.Hour),
		[][2]string{{"0/1000000", "0/2000000"}})
	dead = ends(dead, deadObjects, now.Add(-5*time.Hour), contract.ReBaseSlotLost)
	live, liveObjects := storedChain("live", now.Add(-3*time.Hour),
		[][2]string{{"1/1000000", "1/2000000"}})

	plan, err := Prune(pruneScope, now, []Stored{dead, live}, merge(deadObjects, liveObjects),
		Policy{Superseded: true}, order)
	if err != nil {
		t.Fatalf("pruning failed: %v", err)
	}

	printed := plan.String()
	for _, want := range []string{dead.Segments[0].Path, string(contract.ReBaseSlotLost), "0/2000000"} {
		if !strings.Contains(printed, want) {
			t.Errorf("the printed plan does not mention %q:\n%s", want, printed)
		}
	}
}
