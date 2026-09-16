package backup

// prune.go is the only code in this repo that DELETES a customer's backup, and the whole file is
// one rule:
//
//	NEVER DELETE AN OBJECT A CHAIN STILL NEEDS.
//
// WHY IT EXISTS. Nothing here was ever removed. Every cycle writes objects and a manifest under a
// fresh prefix (manifest.go), every failed cycle leaves objects nobody will reference (run.go's
// storePart says so in as many words), and a re-base leaves a whole finished chain behind
// (rebase.go). The container only grows, and the customer's bill grows with it, forever —
// backup-shape.md §2 lists pruning among the shared pipeline work and nothing built it.
//
// WHY IT IS DANGEROUS IN A WAY THE REST OF THIS PACKAGE IS NOT. A chain is a base and the change
// files laid over it. Delete the base and every restore that depends on it is gone. Delete a
// change file OUT OF THE MIDDLE and the loss is worse than it looks: chain.Verify reads manifests
// and never touches an object, so the chain still verifies — perfectly — with a hole where the
// data was. The manifests parse, the ranges are contiguous, and the rows are found missing at a
// restore, by a customer, in an incident.
//
// SO THE CHAIN IS THE AUTHORITY ON WHAT IS LIVE, AND IT IS ASKED. Prune runs chain.Verify over
// every chain it is given and decides on the answer. It does not parse a prefix to guess which
// cycle belongs to which chain, and it does not read a timestamp to guess whether a chain is
// still in use — the one thing an age is trusted for here is telling a killed cycle's debris from
// a cycle that is uploading right now, which is a question no manifest can answer because the
// manifest is what is missing.
//
// DRY RUN IS THE SHAPE, NOT A FLAG. Prune produces a Plan and has no container to reach; Apply is
// a separate call and is the only thing here that deletes. Deleting a customer's only recoverable
// backup is not a mistake anybody gets to make twice.

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/manukyanv07/parity-scanner/chain"
	"github.com/manukyanv07/parity-scanner/contract"
)

// debrisGrace is how long an object with no manifest over it is left alone before it is called a
// killed cycle's debris.
//
// IT IS THE DIFFERENCE BETWEEN A KILLED CYCLE AND A RUNNING ONE, and there is no other. The
// manifest is written last and atomically (B4), so a cycle that is uploading RIGHT NOW looks
// exactly like one that died: objects, no manifest. Sweeping those would delete the parts out from
// under a manifest that is about to name them — a chain that verifies with a hole in it, which is
// the one failure this file exists to prevent.
//
// A CONSTANT AND NOT A POLICY FIELD until somebody needs a second value. Generous on purpose: the
// cost of waiting is a day of storage on objects nothing references, and the cost of being early
// is a customer's data.
const debrisGrace = 24 * time.Hour

// Container is what Apply deletes through, and it is DELIBERATELY NOT backup.Store. The
// pipeline's interface has one method and it writes; this one has one method and it destroys.
// Keeping Delete off the interface a Cycle holds means no path through a backup can reach it —
// a property of the shape rather than of a code review.
//
// Deleting an object that is already gone is SUCCESS, not an error. A prune interrupted halfway
// is resumed by running it again, and a base copy's objects are named by a manifest rather than
// found in a listing, so "it is not there" and "I removed it" are the same outcome to a caller.
type Container interface {
	Delete(ctx context.Context, path string) error
}

// Segment is one stored manifest: the manifest OBJECT's own path, and what it says.
//
// THE PATH IS NOT IN THE MANIFEST AND CANNOT BE DERIVED FROM ONE. A change cycle's objects sit
// under the same prefix as its manifest, so that one could be read back off a part — but a base
// copy's objects are where the CLOUD put them, outside the prefix its manifest lives under
// (base.go, AD-033). Deriving the prefix from a part would find nothing at all for a base, which
// is the one manifest a chain cannot survive losing.
type Segment struct {
	Path     string
	Manifest contract.Manifest
}

// Ended is the re-base marker that closed a chain (rebase.go): where it is, and what it says. A
// chain with one is SUPERSEDED — nothing more will ever be laid on it — and it is still the only
// thing that restores to any point before the new base.
type Ended struct {
	Path   string
	Marker contract.ReBase
}

// Stored is one chain as it lies in the container: its segments in replay order, how far the
// source said it was durable, and the marker that ended it if one did.
//
// IT IS HANDED IN RATHER THAN ASSEMBLED HERE, and that is chain.go's rule kept rather than a
// shortcut. The order of the segments is a claim made by whoever assembled the chain and nothing
// re-sorts it, because sorting means ordering two positions and only the source can do that
// (backup-shape.md §5). A pruner that listed the container and sorted the manifests itself would
// be making exactly the claim the verifier refuses to make — and then deleting on the strength
// of it.
//
// EVERY CHAIN IN THE SCOPE MUST BE GIVEN, live and superseded alike. An object no chain here
// claims is read as a killed cycle's debris, so a chain left out of this list is a chain whose
// objects are candidates for deletion.
type Stored struct {
	Segments  []Segment
	Confirmed string
	Ended     *Ended

	// Elsewhere says every object this chain names OUTSIDE the scope was found where its manifest
	// says it is — which means a base copy's, because they are the only ones there are: Azure wrote
	// them straight into the container at paths of its own choosing (AD-033) and the agent only
	// verified them.
	//
	// FALSE IS THE ZERO VALUE AND IT MEANS "NOBODY LOOKED", NOT "THEY ARE THERE". That is the whole
	// point of the field, and it is the safe half of a choice with two bad ends. A scoped listing
	// cannot cover these objects and `present` therefore cannot vouch for them, so before this field
	// existed they were skipped — which is to say assumed present, which is to say that a base copy
	// deleted by a lifecycle rule or a half-finished prune would still count its chain WHOLE and
	// license retiring every other chain in favour of it. Treating them as absent instead costs a
	// retirement refused until somebody looks. Only one of those two is recoverable.
	//
	// IT IS ANSWERED BY ASKING THE CONTAINER FOR ONE NAMED OBJECT, never by widening the listing:
	// everything a listing covers and no manifest claims is swept as debris, so a listing that
	// reached the container root would propose deleting every stranger's object in it. assemble.go
	// is where it is filled in, and its header argues the whole of it.
	Elsewhere bool
}

// chain is the object chain.Verify reads. The segments are passed in the order they were given,
// exactly as contract.Chain documents.
func (s Stored) chain() contract.Chain {
	segments := make([]contract.Manifest, 0, len(s.Segments))
	for _, segment := range s.Segments {
		segments = append(segments, segment.Manifest)
	}
	return contract.Chain{
		ContractVersion: contract.BackupContractVersion,
		Segments:        segments,
		Confirmed:       s.Confirmed,
	}
}

// manifests is the chain's claims: every manifest object, and the marker that ended it.
func (s Stored) manifests() []string {
	paths := make([]string, 0, len(s.Segments)+1)
	if s.Ended != nil {
		paths = append(paths, s.Ended.Path)
	}
	for _, segment := range s.Segments {
		paths = append(paths, segment.Path)
	}
	return paths
}

// contents is every object the chain's manifests name — the bytes a restore actually reads.
func (s Stored) contents() []string {
	var paths []string
	for _, segment := range s.Segments {
		for _, part := range segment.Manifest.Artifact.Parts {
			paths = append(paths, part.Path)
		}
	}
	return paths
}

// objects is everything the chain is made of. Deleting any one of them is deleting the chain.
func (s Stored) objects() []string {
	return append(s.manifests(), s.contents()...)
}

// newest is the last point this chain can still be restored to, and it is what a retention window
// is measured against.
//
// THE NEWEST AND NOT THE OLDEST, which is the base-is-the-floor rule made mechanical. A chain is a
// base and the files laid over it: drop the base and the rest restore nothing, drop the first
// change file and everything after it sits beyond a hole. There is no prefix of a chain that can
// be taken away, so a window covers a whole chain or none of it.
func (s Stored) newest() (time.Time, error) {
	if len(s.Segments) == 0 {
		return time.Time{}, errors.New("backup: this chain has no segments, so nothing says when " +
			"it reaches or whether a retention window covers it")
	}
	last := s.Segments[len(s.Segments)-1]
	at, err := time.Parse(time.RFC3339, last.Manifest.ReadPoint.At)
	if err != nil {
		return time.Time{}, fmt.Errorf("backup: %s records the instant %q, which is not an RFC3339 "+
			"time, so nothing can say whether this chain is inside the retention window: %w",
			last.Path, last.Manifest.ReadPoint.At, err)
	}
	return at, nil
}

// Policy is what a caller is willing to lose, and THE ZERO POLICY RETIRES NO CHAIN AT ALL. It
// sweeps a killed cycle's debris and nothing else, which is the conservative default this whole
// file is built around: retention is a decision somebody makes, never a default that happens.
type Policy struct {
	// Before retires a chain whose NEWEST point is older than this instant. Zero retires none.
	//
	// It applies to a whole chain because nothing smaller can be applied — see Stored.newest.
	Before time.Time

	// Superseded retires chains a re-base ended, whatever their age.
	//
	// OFF BY DEFAULT, AND THAT IS THE POINT OF THE FIELD. After a re-base the old chain is
	// finished and a new one is being written, and it is tempting to read the new one's existence
	// as permission to delete the old. It is not: the old chain is still the only thing that
	// restores to any point before the new base, so every recovery point older than the re-base
	// goes with it. Somebody decides that.
	//
	// IT IS AN OR WITH Before, NOT AN AND. Setting both does not mean "superseded chains older
	// than the window" — it means superseded chains AND chains outside the window, and a chain a
	// re-base ended four minutes ago goes. The two are independent reasons to retire a chain and
	// the field pair is shaped like a conjunction, so it is spelled out here.
	Superseded bool
}

// retires says why a chain goes, or "" for one that stays. It is asked only about chains the
// verifier accepted — see Prune for why one it refused is never deleted whatever a policy says.
//
// A CHAIN WHOSE INSTANT NOTHING CAN READ IS KEPT AND NOT REPORTED AS AN ERROR. One manifest with a
// mangled ReadPoint.At must not stop the container being swept for the rest of its life; the window
// simply cannot place that chain, so the window does not retire it.
func (p Policy) retires(s Stored) string {
	if p.Superseded && s.Ended != nil {
		return fmt.Sprintf("superseded: %s, and it restored as far as %s",
			s.Ended.Marker.Reason, s.Ended.Marker.Recoverable)
	}
	if p.Before.IsZero() {
		return ""
	}
	newest, err := s.newest()
	if err != nil {
		return ""
	}
	if newest.Before(p.Before) {
		return fmt.Sprintf("its newest point is %s and the retention window opens at %s",
			newest.Format(time.RFC3339), p.Before.Format(time.RFC3339))
	}
	return ""
}

// Removal is one object a plan would delete, and the sentence that says why. THE REASON IS THERE
// TO BE READ BEFORE ANYTHING RUNS: a plan nobody can check is a plan nobody will check, and this
// is the only thing standing between a policy and a customer's last backup.
type Removal struct {
	Path string
	Why  string
}

// Plan is what a prune WOULD do. Producing one deletes nothing.
type Plan struct {
	// Delete is every object, IN THE ORDER APPLY REMOVES THEM: one retired chain at a time — its
	// segment manifests, then the objects those manifests name, then its re-base marker — and the
	// debris last.
	//
	// MANIFESTS BEFORE THE OBJECTS THEY NAME IS THE MIRROR OF THE MANIFEST BEING WRITTEN LAST, and
	// it is what makes an interrupted prune safe: a chain whose manifests are gone is a chain
	// nothing will assemble, while the reverse order leaves a manifest naming objects that are no
	// longer there — a chain that verifies with a hole in it.
	//
	// ONE CHAIN AT A TIME, so an Apply that stops halfway leaves whole chains retired and whole
	// chains untouched, with at most one caught in between rather than every retired chain at once.
	//
	// AND THE MARKER LAST, because it is what says the chain was superseded. Deleting it first
	// would make a chain that Apply then failed to finish look live again to the next prune —
	// Policy.Superseded would stop matching it — and would throw away the record of WHY the chain
	// ended, which is the thing rebase.go exists to make visible.
	Delete []Removal

	// Keep is every chain that survives this plan AND that chain.Verify accepts. Apply re-checks
	// the plan against it: a Plan is an ordinary value a caller can edit, so the one rule is
	// enforced at the place that deletes rather than only at the place that proposed it.
	Keep []Stored

	// Unverifiable is every chain that stays because the verifier REFUSED it. It restores
	// nothing, so it is not one of the chains the floor counts — and it is not deleted either,
	// because it may still be the only copy of bytes somebody can salvage by hand.
	//
	// IT IS A SEPARATE FIELD SO THAT A HUMAN READING THE PLAN LEARNS IT IS THERE. Folded into
	// Keep it would be indistinguishable from a healthy chain, and the check below could no
	// longer demand that what is kept verifies — it cannot tell a chain this prune broke from
	// one that arrived broken.
	Unverifiable []Stored
}

// String is the plan a human reads before allowing it to run.
func (p Plan) String() string {
	var out strings.Builder
	fmt.Fprintf(&out, "prune: %d objects to delete, %d chains kept\n", len(p.Delete), len(p.Keep))
	if len(p.Delete) == 0 {
		out.WriteString("  nothing to delete\n")
	}
	for _, removal := range p.Delete {
		fmt.Fprintf(&out, "  delete %s — %s\n", removal.Path, removal.Why)
	}
	for _, stored := range p.Unverifiable {
		where := "no manifest at all"
		if len(stored.Segments) > 0 {
			where = stored.Segments[0].Path
		}
		fmt.Fprintf(&out, "  kept, and the verifier refuses it — %d segments from %s\n",
			len(stored.Segments), where)
	}
	return out.String()
}

// survives is THE ONE RULE, made mechanical: nothing being deleted may be an object a surviving
// chain still needs, and every chain this plan claims to keep must still be one chain.Verify
// accepts.
//
// BOTH HALVES ARE NEEDED AND NEITHER IMPLIES THE OTHER. Verify reads manifests and never touches
// an object, so a plan that deleted a change FILE out of the middle and left its manifest passes
// Verify with the data gone — the silent hole. A plan that dropped the middle MANIFEST and kept
// the shorter chain leaves a gap, which Verify does catch. One check sees each.
//
// THE OBJECT HALF COVERS Unverifiable TOO AND THE VERIFY HALF DOES NOT. A chain the verifier
// already refuses still holds a customer's bytes and none of them may go; demanding it verify
// would mean one broken chain stopped a container from ever being swept again.
func (p Plan) survives(order chain.Ordered) error {
	going := make(map[string]bool, len(p.Delete))
	for _, removal := range p.Delete {
		going[removal.Path] = true
	}

	for _, stored := range p.Keep {
		if err := needs(stored, going); err != nil {
			return err
		}
	}
	for _, stored := range p.Unverifiable {
		if err := needs(stored, going); err != nil {
			return err
		}
	}
	for _, stored := range p.Keep {
		if _, err := chain.Verify(stored.chain(), order); err != nil {
			return fmt.Errorf("backup: what this prune would leave behind is not a chain anything "+
				"could restore from: %w", err)
		}
	}
	return nil
}

// Prune works out what can go, AND DELETES NOTHING.
//
//   - scope is the root this prune covers — Cycle.Scope, e.g. "install-7/pg1/orders". IT BOUNDS
//     THE DEBRIS SWEEP AND NOTHING ELSE, and it is checked against the listing rather than
//     trusted: a listing wider than the chains it was handed is how another source's backups
//     become this one's debris.
//   - now is the instant the debris window is measured from.
//   - chains is EVERY chain under that scope, live and superseded — see Stored.
//   - listed is the container as it actually is: every object under the scope and when it was
//     last written (store.Blob.List).
//   - order is the source that issued these positions, and it may be nil. Nothing can then be
//     shown to be whole, and nothing will be retired.
func Prune(scope string, now time.Time, chains []Stored, listed map[string]time.Time, policy Policy, order chain.Ordered) (Plan, error) {
	if err := checkPrefix(scope); err != nil {
		return Plan{}, err
	}
	root := scope + "/"

	// THE LISTING MUST BE THE SCOPE'S AND NOTHING WIDER. Debris is "no manifest names it", and the
	// manifests are the ones the caller handed in — so an object from a scope whose chains were
	// never given is unclaimed by construction, and it is another source's backup.
	for path := range listed {
		if !strings.HasPrefix(path, root) {
			return Plan{}, fmt.Errorf("backup: the listing holds %s, which is outside the scope %s "+
				"this prune covers; nothing here was told which chains own it, so sweeping it would "+
				"delete a backup this prune cannot see", path, scope)
		}
	}
	// NO CHAINS OVER A CONTAINER THAT HOLDS SOMETHING IS A BROKEN ASSEMBLER, NOT AN EMPTY SCOPE.
	// Every object would be unclaimed, so the sweep below would propose the whole container — and
	// the floor further down never fires, because a policy that retires nothing has retired
	// nothing. It is the one shape where "delete everything" is reachable with no error anywhere.
	if len(chains) == 0 && len(listed) > 0 {
		return Plan{}, fmt.Errorf("backup: this prune was handed no chains at all and the scope %s "+
			"holds %d objects; whatever assembled the chains found none, and sweeping on that answer "+
			"would delete every backup under it", scope, len(listed))
	}

	var plan Plan
	retired, whole := 0, 0
	for _, stored := range chains {
		// THE CHAIN IS THE AUTHORITY ON WHAT IS LIVE, AND THIS IS WHERE IT IS ASKED. Nothing in
		// this function parses a prefix or reads a position to decide any of it.
		how, err := chain.Verify(stored.chain(), order)
		if err != nil {
			// A CHAIN THE VERIFIER REFUSES IS NOT A LICENCE TO DELETE IT. It restores nothing, and
			// it may still be the only copy of bytes somebody can salvage by hand: the cost of
			// keeping it is storage and the cost of being wrong is the data.
			plan.Unverifiable = append(plan.Unverifiable, stored)
			continue
		}
		why := policy.retires(stored)
		if why == "" {
			plan.Keep = append(plan.Keep, stored)
			// AND ITS OBJECTS HAVE TO ACTUALLY BE THERE. Verify reads manifests and never touches
			// an object — this file's whole premise — so a chain whose bytes a lifecycle rule or a
			// half-finished prune removed is checked WHOLE and restores nothing. Counting it here
			// is what would license deleting every other chain in favour of it.
			if how == chain.CheckedWhole && present(stored, listed, root) {
				whole++
			}
			continue
		}
		retired++
		// PER CHAIN, MANIFESTS BEFORE THE OBJECTS THEY NAME, AND THE MARKER LAST — see Plan.Delete.
		for _, segment := range stored.Segments {
			plan.Delete = append(plan.Delete, Removal{Path: segment.Path, Why: why})
		}
		for _, path := range stored.contents() {
			plan.Delete = append(plan.Delete, Removal{Path: path, Why: why})
		}
		if stored.Ended != nil {
			plan.Delete = append(plan.Delete, Removal{Path: stored.Ended.Path, Why: why})
		}
	}

	// REFUSING TO LEAVE NOTHING. Whatever the policy says, a prune that takes the last chain
	// anything can be restored from is an error and not a successful prune. Only a chain checked
	// WHOLE whose objects are present counts: shape-only means nobody could tell whether it has a
	// hole in it, and retiring a real backup in favour of one nobody could check is the trade this
	// file does not make.
	if retired > 0 && whole == 0 {
		if order == nil {
			return Plan{}, fmt.Errorf("backup: this policy retires %d of the %d chains stored here, "+
				"and nothing was supplied that can order these positions — so no chain here could be "+
				"checked for a hole in it at all, and none may be retired on the strength of another",
				retired, len(chains))
		}
		return Plan{}, fmt.Errorf("backup: this policy retires %d of the %d chains stored here and "+
			"leaves none that was checked whole with every object it names still in the container, "+
			"so the last thing anything could be restored from would go with it", retired, len(chains))
	}

	// Claimed by ANY chain, retired ones included: an object a manifest names is never debris — it
	// is either kept with its chain or deleted with it.
	claimed := map[string]bool{}
	for _, stored := range chains {
		for _, path := range stored.objects() {
			claimed[path] = true
		}
	}

	// Sorted, because a listing is a set and a plan a human reads twice should not shuffle.
	cutoff := now.Add(-debrisGrace)
	for _, path := range slices.Sorted(maps.Keys(listed)) {
		if claimed[path] || !listed[path].Before(cutoff) {
			continue
		}
		plan.Delete = append(plan.Delete, Removal{
			Path: path,
			Why: fmt.Sprintf("no manifest names it and nothing has written to it since %s, so it "+
				"is what a killed cycle left behind", listed[path].Format(time.RFC3339)),
		})
	}

	if err := plan.survives(order); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

// present reports whether every object of this chain is actually in the container: the ones under
// the scope from the listing, and the ones outside it from whoever assembled the chain.
//
// THE OUTSIDE HALF IS A BASE COPY'S, AND IT USED TO BE SKIPPED — which is to say assumed. It is
// answered by Stored.Elsewhere now, where the argument is; an unset one is "nobody looked", and the
// chain does not count towards the floor.
//
// THE SWEEP IS UNAFFECTED AND MUST BE. Nothing outside the scope is ever proposed for deletion; this
// changes only which chains are allowed to hold the floor up.
func present(s Stored, listed map[string]time.Time, root string) bool {
	for _, path := range s.objects() {
		if !strings.HasPrefix(path, root) {
			if !s.Elsewhere {
				return false
			}
			continue
		}
		if _, held := listed[path]; !held {
			return false
		}
	}
	return true
}

// needs refuses a plan that deletes an object this chain still holds.
func needs(stored Stored, going map[string]bool) error {
	for _, path := range stored.objects() {
		if going[path] {
			return fmt.Errorf("backup: %s is being deleted and a chain that is being kept still "+
				"needs it; a chain missing an object it names verifies exactly as a whole one does, "+
				"and the data is gone either way", path)
		}
	}
	return nil
}

// Apply is THE ONLY THING IN THIS REPO THAT DELETES A BACKUP OBJECT, and it re-checks the plan
// against the chains the plan says it keeps before it removes the first one. A Plan is an ordinary
// value; the rule has to hold here rather than only where the plan was made.
//
// IT STOPS AT THE FIRST FAILURE. What has already gone is a retired chain's manifests, and objects
// under no manifest are debris the next prune sweeps — so stopping is safe and carrying on past a
// container that is refusing to answer is not.
func Apply(ctx context.Context, container Container, plan Plan, order chain.Ordered) error {
	if container == nil {
		return errors.New("backup: this prune has no container, so there is nothing to delete from")
	}
	// A PLAN THAT DELETES AND KNOWS OF NO CHAIN AT ALL PROTECTS NOTHING. survives compares Delete
	// against Keep and Unverifiable, and both are fields of the same value a caller holds — so a
	// plan that lost them on the way here (a control-plane round trip, an operator's plan file, a
	// UI that hands back only the list of paths) passes every check by having nothing left to
	// check. Prune never produces one: it refuses an empty chain list over a non-empty scope.
	//
	// THIS IS NOT THE SECURITY BOUNDARY AND CANNOT BE. Apply is handed a plan and a container and
	// cannot re-derive what the container holds; Prune is where the decision is made and where the
	// chains are known. What this catches is the plan that arrived hollow.
	if len(plan.Delete) > 0 && len(plan.Keep) == 0 && len(plan.Unverifiable) == 0 {
		return errors.New("backup: this plan deletes objects and names no chain it is keeping, so " +
			"there is nothing for the check to hold the deletions against; a plan that reached here " +
			"without its chains is a plan with no protection left in it")
	}
	if err := plan.survives(order); err != nil {
		return err
	}

	for _, removal := range plan.Delete {
		if err := container.Delete(ctx, removal.Path); err != nil {
			return fmt.Errorf("backup: prune %s: %w", removal.Path, err)
		}
	}
	return nil
}
