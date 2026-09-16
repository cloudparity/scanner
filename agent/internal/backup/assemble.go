package backup

// assemble.go is what prune.go was missing: the thing that turns A REAL CONTAINER into the []Stored
// Prune consumes. Until this file, Prune was a design with no contact with reality — well tested
// against fixtures somebody typed, and reachable from nothing, because nothing anywhere could read a
// manifest back out of a container (pgchain.go says so in as many words).
//
// prune.go's own header names this file as where the design is proven or found wrong, so here is
// what it has to establish, and what it does about each.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// 1. IT NEVER ORDERS TWO POSITIONS, AND IT STILL PUTS THE SEGMENTS IN REPLAY ORDER
// ─────────────────────────────────────────────────────────────────────────────────────────────
//
// Stored says the order of the segments is a claim made by whoever assembled the chain, and that a
// pruner which listed the container and SORTED the manifests would be making exactly the claim the
// verifier refuses to make — and then deleting on the strength of it. That rules out sorting by
// prefix, by the timestamp in a prefix, by ReadPoint.At, and by the positions themselves.
//
// So nothing here sorts. A chain is FOLLOWED, by the one comparison backup-shape.md §5 allows on a
// position: equality. A change cycle records the position it resumed FROM, and that is the position
// the segment before it reached — Cycle.Run copies the caller's `from` into ReadPoint.From, and the
// caller's `from` is the last manifest's ReadPoint.Position (pgchain.go's reach). So segment n+1 is
// the one whose From EQUALS segment n's Position, and the chain is walked from its base until
// nothing matches. No LSN is parsed, no two positions are ranked, and the order that comes out is
// the order the agent wrote them in rather than one this file inferred.
//
// TWO CANDIDATES FOR THE SAME LINK STOPS THE WALK. Which of them continues the chain is exactly the
// question only the source can answer, so it is not answered: the walk ends, and both candidates
// come out below as chains of their own that the verifier will refuse. Kept, never deleted.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// 2. EVERY CLAIM IN THE SCOPE COMES OUT IN EXACTLY ONE Stored, INCLUDING THE BROKEN ONES
// ─────────────────────────────────────────────────────────────────────────────────────────────
//
// This is the rule that makes the assembler safe rather than merely correct, and it is the one an
// obvious implementation gets wrong. Prune reads "no manifest names this object" off the chains it
// is HANDED: an object no Stored claims is a killed cycle's debris and is deleted after the grace
// period. So a manifest this file quietly drops does not merely go unpruned — it and every object
// it names become candidates for deletion.
//
// Therefore: a change file whose base is gone, a marker that matches no chain, a fork where two
// segments claim the same predecessor — none of them is dropped. Each comes out as its own Stored,
// each is refused by chain.Verify, and prune.go puts a chain the verifier refuses in Plan.Unverifiable,
// which is kept and never deleted. The container stops shrinking for that chain, and nobody loses a
// backup, which is the trade this whole area makes every time.
//
// AND A CLAIM THAT WILL NOT PARSE STOPS THE WHOLE ASSEMBLY. It cannot be turned into a Stored — its
// parts are unreadable, so nothing can claim them — and carrying on would hand Prune a picture in
// which those parts are unclaimed. Pruning is optional; a customer's backup is not.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// 3. A BASE COPY'S OBJECTS ARE VOUCHED FOR BY ASKING, AND UNTIL SOMEBODY ASKS THEY ARE ABSENT
// ─────────────────────────────────────────────────────────────────────────────────────────────
//
// THE HARD PART, and it is AD-033. A base copy's objects sit where the cloud put them, outside the
// scope, so the listing that bounds the debris sweep cannot cover them — and prune.go's `present`,
// the check that makes the "never leave zero complete chains" floor mean anything, used to skip
// them, which is to say assume them. It is arranged here instead: `vouch` asks about each one BY
// NAME through Objects.Exists, and the answer rides on Stored.Elsewhere.
//
// THE WHOLE ARGUMENT — why a wider listing is the catastrophic answer, and why an unanswered
// question is read as absent rather than present — IS AT Stored.Elsewhere IN prune.go, and it is
// there once so that whoever changes the reasoning changes it in one place.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// WHAT THIS STILL CANNOT SEE, AND IT IS NOT FIXABLE FROM A CONTAINER
// ─────────────────────────────────────────────────────────────────────────────────────────────
//
// How far the source was told it was durable. contract.Chain.Confirmed exists so that a file lost
// off the END of a chain is visible — checked against its own last segment a chain always reaches
// exactly as far as it reaches, which is chain.go's own warning. Nothing in the container records
// it: the running agent holds it in memory (pgchain.go's reach) and reports it to the control
// plane (report.Send). A chain assembled from a listing therefore takes Confirmed from its last
// segment, and a manifest lost off the end of a chain is invisible to it.
//
// SAID HERE RATHER THAN DISCOVERED. It does not widen what a prune deletes — the tail is the
// newest data and no policy retires a chain because of its tail — but it does mean a chain counted
// whole may be short at the end, so the floor is weaker than it reads. Closing it needs the reach
// the control plane already stores, handed in by a caller that can reach the API, and it is a
// bigger change than this one.

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/manukyanv07/parity-scanner/contract"
)

// Objects is a container as the assembler reads it, and it is DECLARED HERE BECAUSE IT IS CONSUMED
// HERE — the same rule run.go's Store and prune.go's Container follow, and what keeps this package
// free of a storage SDK.
//
// NOTHING IN IT DELETES. Assembling is the read half and Container is the write half, and the split
// is a property of the shape: no path through an assembly can reach a Delete, because the value it
// holds has no such method.
type Objects interface {
	// List is every object under the scope and when each was last written, ANCHORED at a separator
	// (store.Blob.List). It is what bounds the debris sweep, so it must never be widened.
	List(ctx context.Context, prefix string) (map[string]time.Time, error)

	// Get reads one claim — a manifest or a re-base marker — back whole.
	Get(ctx context.Context, path string) ([]byte, error)

	// Exists says whether ONE NAMED OBJECT is in the container, without reading it and without
	// listing anything. It is how a base copy's objects are vouched for: they are outside the scope
	// (AD-033) and a listing that reached them would turn every stranger's object into this scope's
	// debris. It must not round a failure to an answer.
	Exists(ctx context.Context, path string) (bool, error)
}

// Assembled is one scope as it actually lies in a container: what Prune needs, and nothing derived
// that Prune would have to trust.
type Assembled struct {
	// Scope is the root that was read, and it is the scope Prune must be given. The two must be the
	// same string, which is why it is carried rather than left to a caller to repeat.
	Scope string

	// Chains is every chain under the scope, live and superseded and broken alike — see the rule
	// above about why the broken ones are here.
	Chains []Stored

	// Listed is the container as it is: every object under the scope and when it was last written.
	Listed map[string]time.Time
}

// Assemble reads a scope and produces what a prune runs on. IT DELETES NOTHING and it writes
// nothing; the only calls it makes are a listing, a read per claim, and one existence question per
// object that lies outside the scope.
func Assemble(ctx context.Context, objects Objects, scope string) (Assembled, error) {
	// The same check every cycle's prefix goes through, so a scope that could never have been
	// written to is refused here rather than producing an empty listing that reads as an empty
	// container.
	if err := checkPrefix(scope); err != nil {
		return Assembled{}, err
	}
	root := scope + "/"

	listed, err := objects.List(ctx, scope)
	if err != nil {
		return Assembled{}, fmt.Errorf("backup: list the scope %s: %w", scope, err)
	}
	// AN OBJECT OUTSIDE THE SCOPE IN THIS MAP IS REFUSED WHERE IT MATTERS AND NOT HERE. store.Blob
	// refuses one at the wire, and Prune refuses one on the way into the only code that deletes.
	// This function deletes nothing, and a third copy of the same comparison is a third place to
	// keep in step.

	segments, markers, err := claims(ctx, objects, listed)
	if err != nil {
		return Assembled{}, err
	}

	chains := link(segments, markers)
	for i := range chains {
		found, err := vouch(ctx, objects, chains[i], root)
		if err != nil {
			return Assembled{}, err
		}
		chains[i].Elsewhere = found
	}
	return Assembled{Scope: scope, Chains: chains, Listed: listed}, nil
}

// claims reads every manifest and every re-base marker in the listing.
//
// THE TWO OBJECT NAMES ARE THE ONLY THING HERE THAT LOOKS AT A PATH, and they are the names this
// package itself writes (manifestName, reBaseName), matched at a separator so that an object called
// "not-a-manifest.json" is not one. It is a way of finding the claims and never a way of deciding
// what a claim MEANS: which chain a manifest belongs to and where in it comes from the manifest's
// own contents, below.
func claims(ctx context.Context, objects Objects, listed map[string]time.Time) ([]Segment, []Ended, error) {
	var segments []Segment
	var markers []Ended

	// Sorted so that a container read twice produces the same chains in the same order, and so the
	// plan a human approves is the plan they read. It orders PATHS, which are not positions.
	for _, path := range slices.Sorted(maps.Keys(listed)) {
		switch {
		case strings.HasSuffix(path, "/"+manifestName):
			body, err := objects.Get(ctx, path)
			if err != nil {
				return nil, nil, fmt.Errorf("backup: read the manifest %s: %w", path, err)
			}
			var manifest contract.Manifest
			if err := json.Unmarshal(body, &manifest); err != nil {
				// STOPS EVERYTHING, and that is the safe direction. A manifest that will not parse
				// names objects nothing can enumerate, so no Stored can claim them — and an
				// assembly that carried on would hand Prune a picture in which a live chain's parts
				// are unclaimed, which is to say debris.
				return nil, nil, fmt.Errorf("backup: %s is not a manifest anything can read, so the "+
					"objects it names cannot be told from a killed cycle's debris: %w", path, err)
			}
			if manifest.ContractVersion > contract.BackupContractVersion {
				return nil, nil, fmt.Errorf("backup: %s was written against backup contract version "+
					"%d and this build reads %d, so nothing here can be sure it has enumerated every "+
					"object the manifest names", path, manifest.ContractVersion, contract.BackupContractVersion)
			}
			// A MANIFEST THAT NAMES NOTHING IS THE SAME HAZARD AS ONE THAT WILL NOT PARSE, and it
			// is the subtler of the two: this one reads perfectly and claims no objects, so the
			// bytes its cycle stored are claimed by nothing and swept as a killed cycle's debris —
			// under the ZERO policy, which retires no chain at all. manifest.go's audit refuses to
			// write one, which is exactly why reading one means something is wrong that this cannot
			// see, and deleting on the strength of it is not the answer.
			if len(manifest.Artifact.Parts) == 0 {
				return nil, nil, fmt.Errorf("backup: %s is a manifest that names no objects at all; "+
					"whatever its cycle stored is claimed by nothing, and a prune would read those "+
					"objects as debris and delete them", path)
			}
			segments = append(segments, Segment{Path: path, Manifest: manifest})

		case strings.HasSuffix(path, "/"+reBaseName):
			body, err := objects.Get(ctx, path)
			if err != nil {
				return nil, nil, fmt.Errorf("backup: read the re-base marker %s: %w", path, err)
			}
			var marker contract.ReBase
			if err := json.Unmarshal(body, &marker); err != nil {
				return nil, nil, fmt.Errorf("backup: %s is not a re-base marker anything can read, "+
					"and it is the only record of why a chain ended: %w", path, err)
			}
			// THE SAME GUARD THE MANIFEST GETS, and for a sharper reason: Recoverable is the single
			// field Policy.Superseded acts on to retire a whole chain, and this is the object that
			// says a chain is over. A marker from a version this build does not know is not one to
			// delete a chain on.
			if marker.ContractVersion > contract.BackupContractVersion {
				return nil, nil, fmt.Errorf("backup: %s was written against backup contract version "+
					"%d and this build reads %d; it is what says a chain is over, and retiring one "+
					"on a claim this build cannot fully read is not a trade to make", path,
					marker.ContractVersion, contract.BackupContractVersion)
			}
			markers = append(markers, Ended{Path: path, Marker: marker})
		}
	}
	return segments, markers, nil
}

// link follows each base to the end of its chain and accounts for everything left over.
//
// IT COMPARES POSITIONS FOR EQUALITY AND DOES NOTHING ELSE WITH THEM — see the header. What comes
// out is in path order so that two runs over one container agree.
func link(segments []Segment, markers []Ended) []Stored {
	// GROUPED BY WHAT THE MANIFEST SAYS IT BACKS UP, because two databases' positions can be equal
	// by coincidence and chaining across them would produce a chain that restores one database's
	// changes into the other. chain.Verify refuses such a chain, but it would refuse it AFTER the
	// segments of two real chains had been mixed into one and the leftovers of both dropped.
	next := map[string][]Segment{}
	for _, segment := range segments {
		from := segment.Manifest.ReadPoint.From
		if segment.Manifest.Kind == contract.BackupBase || from == "" {
			continue
		}
		key := subject(segment.Manifest) + "\x00" + from
		next[key] = append(next[key], segment)
	}

	// A MARKER SAYS THIS CHAIN STOPS HERE, AND THE WALK HAS TO KNOW IT — matching the markers up
	// afterwards is too late. A re-base is followed by a NEW base copy, and the position that base
	// reports is the slot's confirmed_flush_lsn: on an idle source it is the very position the dead
	// chain reached. The walk would then find the new chain's change files hanging off the old
	// chain's last position and TAKE them, leaving the new base as a one-segment chain that the
	// marker lands on — so a Policy.Superseded prune deletes the newest base copy, and what survives
	// is post-re-base change files laid over a pre-re-base base. For ReBaseSchemaChanged that is
	// exactly the corruption contract.ReBase exists to prevent, and it verifies clean because the
	// positions are contiguous.
	//
	// One more equality comparison and nothing else: a coincidental match truncates a live chain
	// instead, its later segments fall out as leftovers, the verifier refuses them and they are kept.
	stops := map[string]bool{}
	for _, marker := range markers {
		if marker.Marker.Recoverable != "" {
			stops[marker.Marker.Recoverable] = true
		}
	}

	used := map[string]bool{}
	var chains []Stored
	for _, base := range segments {
		if base.Manifest.Kind != contract.BackupBase {
			continue
		}
		used[base.Path] = true
		chain := Stored{Segments: []Segment{base}}

		// THE WALK. One step per link, and it stops the moment the answer is not exactly one
		// segment: no candidate means the end of the chain, and two means a question only the
		// source could answer, so neither is taken and both are left for the leftovers below.
		for {
			last := chain.Segments[len(chain.Segments)-1].Manifest
			if stops[last.ReadPoint.Position] {
				break
			}
			candidates := next[subject(last)+"\x00"+last.ReadPoint.Position]
			// used is also the only thing that ends a walk over segments that point at each other
			// or at themselves — a shape nothing writes and a container is not obliged to be free of.
			if len(candidates) != 1 || used[candidates[0].Path] {
				break
			}
			used[candidates[0].Path] = true
			chain.Segments = append(chain.Segments, candidates[0])
		}
		chains = append(chains, chain)
	}

	// EVERY LEFTOVER COMES OUT AS A CHAIN OF ITS OWN. A change file whose base has already been
	// pruned, or one of two segments claiming the same predecessor, is a manifest nothing else
	// claims — and a manifest nothing claims is an object, and every object it names is an object,
	// that the debris sweep would propose. chain.Verify refuses each of these, prune.go keeps what
	// the verifier refuses, and the objects stay.
	for _, segment := range segments {
		if !used[segment.Path] {
			chains = append(chains, Stored{Segments: []Segment{segment}})
		}
	}

	// Confirmed is the last segment's own position — the container records no independent one, and
	// the header says what that costs.
	for i := range chains {
		last := chains[i].Segments[len(chains[i].Segments)-1]
		chains[i].Confirmed = last.Manifest.ReadPoint.Position
	}

	chains = closed(chains, markers)
	slices.SortFunc(chains, func(a, b Stored) int { return strings.Compare(first(a), first(b)) })
	return chains
}

// closed attaches each re-base marker to the chain it ended, and keeps the ones that match nothing.
//
// A MARKER SAYS HOW FAR THE CHAIN STILL RESTORES (contract.ReBase.Recoverable) and rebase.go writes
// that from the position the dead cycle was resuming from — which is the position the last manifest
// of that chain reached. So the match is one equality comparison and nothing else. It carries no
// subject of its own, so an ambiguous match is left unattached rather than guessed: attaching a
// marker to the wrong chain would make a live chain look superseded, and Policy.Superseded would
// retire it.
func closed(chains []Stored, markers []Ended) []Stored {
	for _, marker := range markers {
		matched := -1
		if marker.Marker.Recoverable != "" {
			for i, chain := range chains {
				if chain.Ended == nil && chain.Confirmed == marker.Marker.Recoverable {
					if matched >= 0 {
						matched = -1
						break
					}
					matched = i
				}
			}
		}
		if matched < 0 {
			// UNATTACHED IS NOT DISCARDED. The marker is the only record of why a chain ended
			// (rebase.go), and an object no Stored claims is swept as debris. As a chain of its own
			// it has no segments, so the verifier refuses it and prune.go keeps it.
			chains = append(chains, Stored{Ended: &marker})
			continue
		}
		chains[matched].Ended = &marker
	}
	return chains
}

// vouch answers, for one chain, whether every object it names OUTSIDE THE SCOPE is in the
// container — which is a base copy's, and which the scoped listing cannot cover (AD-033).
//
// FALSE IS "IT IS NOT THERE" AND AN ERROR IS "NOBODY COULD SAY", and the two must not be collapsed:
// prune.go's floor reads the first as a chain that does not count, and the second has to stop the
// prune, because a container that will not answer is not a container to delete from.
func vouch(ctx context.Context, objects Objects, chain Stored, root string) (bool, error) {
	for _, path := range chain.objects() {
		if strings.HasPrefix(path, root) {
			continue
		}
		found, err := objects.Exists(ctx, path)
		if err != nil {
			return false, fmt.Errorf("backup: %s is named by a chain in this scope and lies outside "+
				"it, and the container would not say whether it is there; nothing can be retired on "+
				"the strength of a base copy nobody could see: %w", path, err)
		}
		if !found {
			return false, nil
		}
	}
	return true, nil
}

// subject is what a manifest says it is a backup OF, as one comparable key. The two fields
// chain.Verify already refuses a chain for disagreeing about.
func subject(m contract.Manifest) string {
	return m.Source.ResourceID + "\x00" + m.Source.Database
}

// first is a chain's earliest claim by path, which is what the chains are ordered by. A path is not
// a position, and ordering the chains among themselves is not ordering anything inside one.
func first(s Stored) string {
	if len(s.Segments) > 0 {
		return s.Segments[0].Path
	}
	if s.Ended != nil {
		return s.Ended.Path
	}
	return ""
}
