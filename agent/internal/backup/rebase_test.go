package backup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/manukyanv07/parity-scanner/contract"
)

// THE CLAIM THIS FILE TESTS: a cycle whose schema no longer matches the chain's base does not
// write a manifest. It writes a re-base marker instead, and it says so to its caller.
//
// The failure it is aimed at produces no error anywhere. Logical decoding does not carry DDL, so
// an ALTER TABLE that lands between two cycles reaches the change file as nothing at all — the
// stream keeps flowing, every object hashes, every manifest parses, and the chain reads as
// healthy right up to the restore that fails. Measured against a real server in
// postgres/rebase_docker_test.go; this file is the decision that measurement feeds.

// refusingSuffix takes every object except the one whose path ends in suffix. The re-base marker
// is written by the same retrying put as the manifest, and the question here is what a caller is
// told when the mark itself cannot be stored.
type refusingSuffix struct {
	inner  Store
	suffix string
	err    error
}

func (r *refusingSuffix) Put(ctx context.Context, path string, chunk []byte) error {
	if strings.HasSuffix(path, r.suffix) {
		return r.err
	}
	return r.inner.Put(ctx, path, chunk)
}

// reBasesIn is every re-base marker the store holds. Like manifestsIn, it never guesses a path:
// the prefix is generated per cycle, so a test that computed one would pass by looking in the
// wrong place.
func reBasesIn(m *memStore) []string {
	var found []string
	for _, path := range landed(m) {
		if strings.HasSuffix(path, "/"+reBaseName) {
			found = append(found, path)
		}
	}
	return found
}

// THE DELIVERABLE. The schema moved under a running stream: no manifest, a marker in its place,
// and a caller that is told to take a new base copy rather than left to carry on.
func TestASchemaChangeStopsTheChainAndSchedulesANewBase(t *testing.T) {
	store := newMemStore()
	c := testCycle(&Pipeline{Store: store})

	_, err := c.Run(context.Background(),
		changing("0/3", "sha256:moved", wholePart("changes.0001", "CDC-after-the-alter")), "0/2")

	if err == nil {
		t.Fatal("a cycle captured against a moved schema reported success; the chain was extended in silence")
	}
	if !errors.Is(err, ErrSchemaMoved) {
		t.Errorf("error %v does not carry ErrSchemaMoved, so nothing scheduling cycles can tell "+
			"this apart from an ordinary failure and retry it forever", err)
	}
	if got := manifestsAttemptedIn(store); len(got) != 0 {
		t.Errorf("a manifest was written for a batch captured against a moved schema: %v", got)
	}

	markers := reBasesIn(store)
	if len(markers) != 1 {
		t.Fatalf("re-base markers in the store: %v, want exactly one — without it a restarted "+
			"agent has nothing telling it the chain is dead", markers)
	}
	body, _ := object(store, markers[0])

	var mark contract.ReBase
	if err := json.Unmarshal([]byte(body), &mark); err != nil {
		t.Fatalf("the marker is not readable JSON: %v: %s", err, body)
	}
	if mark.Reason != contract.ReBaseSchemaChanged {
		t.Errorf("reason = %q, want %q", mark.Reason, contract.ReBaseSchemaChanged)
	}
	if mark.Recoverable != "0/2" {
		t.Errorf("recoverable = %q, want the position the cycle before this one reached (0/2); "+
			"a marker that does not say how far the chain still restores reads as total loss",
			mark.Recoverable)
	}
	if mark.ContractVersion != contract.BackupContractVersion {
		t.Errorf("contract version = %d, want %d", mark.ContractVersion, contract.BackupContractVersion)
	}
	// Both fingerprints, because the operator's first question is which one moved and the
	// alternative is reading two manifests to find out.
	if !strings.Contains(mark.Detail, "sha256:moved") || !strings.Contains(mark.Detail, "sha256:abc") {
		t.Errorf("detail %q names neither fingerprint", mark.Detail)
	}
	// It goes where the manifest would have gone. That is what makes it impossible to miss for
	// anything that assembles a chain by listing the container.
	if want := strings.TrimSuffix(markers[0], reBaseName) + manifestName; want == markers[0] {
		t.Errorf("the marker %q is not in the cycle's own prefix", markers[0])
	}
}

// The other half of the same claim, and it has to be asserted or the check above is satisfied by
// a cycle that never writes a manifest at all.
func TestAnUnchangedSchemaExtendsTheChain(t *testing.T) {
	store := newMemStore()
	c := testCycle(&Pipeline{Store: store})

	written, err := c.Run(context.Background(),
		changing("0/3", "sha256:abc", wholePart("changes.0001", "CDC-one")), "0/2")
	if err != nil {
		t.Fatalf("a cycle captured against the chain's own schema failed: %v", err)
	}
	if written.Schema != "sha256:abc" {
		t.Errorf("the manifest records schema %q, want the one it was captured against", written.Schema)
	}
	if got := manifestsIn(store); len(got) != 1 {
		t.Errorf("manifests in the store: %v, want exactly one", got)
	}
	if got := reBasesIn(store); len(got) != 0 {
		t.Errorf("a healthy cycle wrote a re-base marker: %v", got)
	}
}

// AN AGENT THAT LEARNED A NEW ALGORITHM DOES NOT END THE CHAIN IT INHERITS, and that is the
// deployment this test is really about. The chain's base was captured by the agent before this one,
// so it holds one untagged digest; this cycle's source computes that digest AND the newer one it has
// since learned to take. Nothing about the customer's schema changed. If the comparison were over
// the whole string, every chain in the fleet would take a fresh base copy — about nine minutes of
// cloud work each — on the first cycle after the deploy, for no reason at all.
//
// The other direction is here too, because a rollout runs both agents at once and a rollback runs
// the old one afterwards: a chain based by the NEWER agent, extended by an older one that reports
// only the untagged digest, also carries on. What ends a chain is the digests of an algorithm both
// ends hold disagreeing, and nothing else.
func TestAnAgentThatLearnedANewFingerprintAlgorithmDoesNotReBaseTheChain(t *testing.T) {
	for _, tc := range []struct {
		name          string
		base, capture string
	}{
		{"a chain based before the deploy, extended after it", "sha256:abc", "sha256:abc v2:sha256:xyz"},
		{"a chain based after the deploy, extended by an agent from before it", "sha256:abc v2:sha256:xyz", "sha256:abc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newMemStore()
			c := testCycle(&Pipeline{Store: store})
			c.BaseSchema = tc.base

			written, err := c.Run(context.Background(),
				changing("0/3", tc.capture, wholePart("changes.0001", "CDC-one")), "0/2")
			if err != nil {
				t.Fatalf("the cycle refused a chain whose schema stood still: %v", err)
			}
			if got := reBasesIn(store); len(got) != 0 {
				t.Errorf("a re-base was scheduled because the FINGERPRINT ALGORITHM changed rather "+
					"than the schema: %v", got)
			}
			if got := manifestsIn(store); len(got) != 1 {
				t.Errorf("manifests in the store: %v, want exactly one", got)
			}
			// The manifest records what THIS agent took, not what it was compared against: the next
			// agent to read this chain needs the newest algorithm it can get.
			if written.Schema != tc.capture {
				t.Errorf("the manifest records schema %q, want %q", written.Schema, tc.capture)
			}
		})
	}
}

// AND THE OTHER HALF, or the test above is satisfied by a comparison that gave up. A change only the
// NEWER algorithm can see — ALTER TABLE ... SET LOGGED moves no column and no replica identity —
// still ends the chain, provided both ends took that algorithm.
func TestAChangeOnlyTheNewerAlgorithmSeesStillStopsTheChain(t *testing.T) {
	store := newMemStore()
	c := testCycle(&Pipeline{Store: store})
	c.BaseSchema = "sha256:abc v2:sha256:xyz"

	_, err := c.Run(context.Background(),
		changing("0/3", "sha256:abc v2:sha256:moved", wholePart("changes.0001", "CDC-one")), "0/2")
	if !errors.Is(err, ErrSchemaMoved) {
		t.Fatalf("error %v does not carry ErrSchemaMoved; the older digest matching outvoted the "+
			"newer one, and a table made LOGGED mid-chain would replay onto rows the base copy "+
			"restored empty", err)
	}
	if got := reBasesIn(store); len(got) != 1 {
		t.Errorf("re-base markers in the store: %v, want exactly one", got)
	}
}

// A CYCLE THAT CANNOT COMPARE MUST NOT EXTEND. Both halves are configuration mistakes that cost
// nothing on the day they are made and everything at restore: a source fingerprinting into a
// cycle that holds no base fingerprint would sail past every schema change there ever was, which
// is the exact silence this whole ticket is about.
func TestACycleWithNothingToCompareRefusesToExtend(t *testing.T) {
	for _, tc := range []struct {
		name          string
		base, capture string
	}{
		{"the cycle was never told what the base was taken against", "", "sha256:abc"},
		{"the source stopped reporting a fingerprint", "sha256:abc", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := newMemStore()
			c := testCycle(&Pipeline{Store: store})
			c.BaseSchema = tc.base

			_, err := c.Run(context.Background(),
				changing("0/3", tc.capture, wholePart("changes.0001", "CDC-one")), "0/2")
			if err == nil {
				t.Fatal("the cycle extended a chain it could not compare a schema against")
			}
			if got := manifestsAttemptedIn(store); len(got) != 0 {
				t.Errorf("a manifest was written anyway: %v", got)
			}
		})
	}
}

// THE OTHER WAY A CHAIN DIES, AND IT ENDS IN THE SAME OBJECT. A schema change and a lost slot are
// different incidents with different remedies for the customer, and they are identical in the one
// respect that matters here: nothing more may be laid on this base. So they share the marker, the
// prefix and the rule that no manifest is written — what differs is Reason, which is the field
// somebody reads to find out what happened.
//
// A second, parallel way of saying "this chain is over" is how one of the two comes to be missed.
func TestALostSlotStopsTheChainAndSchedulesANewBase(t *testing.T) {
	store := newMemStore()
	c := testCycle(&Pipeline{Store: store})

	_, err := c.Run(context.Background(), &fakeSource{
		since: func(Position) (Batch, error) {
			return Batch{}, fmt.Errorf("postgres: slot %q is not on the server: %w", "vp_stream", ErrSlotGone)
		},
	}, "0/2")

	if err == nil {
		t.Fatal("a cycle whose slot had gone reported success")
	}
	if !errors.Is(err, ErrSlotGone) {
		t.Errorf("error %v does not carry ErrSlotGone", err)
	}
	if got := manifestsAttemptedIn(store); len(got) != 0 {
		t.Errorf("a file was added to a chain whose slot is gone: %v", got)
	}

	markers := reBasesIn(store)
	if len(markers) != 1 {
		t.Fatalf("re-base markers in the store: %v, want exactly one", markers)
	}
	body, _ := object(store, markers[0])

	var mark contract.ReBase
	if err := json.Unmarshal([]byte(body), &mark); err != nil {
		t.Fatalf("the marker is not readable JSON: %v: %s", err, body)
	}
	if mark.Reason != contract.ReBaseSlotLost {
		t.Errorf("reason = %q, want %q — a lost slot and a migration send an operator to two "+
			"different places", mark.Reason, contract.ReBaseSlotLost)
	}
	// THE DELIVERABLE OF THIS TICKET. The visible state says how far the chain still restores,
	// which is where the LAST CONFIRMED cycle reached and not where this one was going.
	if mark.Recoverable != "0/2" {
		t.Errorf("recoverable = %q, want 0/2; a marker without it reads as total loss", mark.Recoverable)
	}
	if !strings.Contains(mark.Detail, "vp_stream") {
		t.Errorf("detail %q does not name the slot that went", mark.Detail)
	}
}

// An ordinary failure is NOT a dead chain, and must not leave a marker behind: a re-base marker in
// a prefix is permanent — nothing clears it — so one written on a dropped packet retires a chain
// that was only ever going to need a retry.
func TestAnOrdinaryFailureLeavesNoReBaseMarker(t *testing.T) {
	store := newMemStore()
	c := testCycle(&Pipeline{Store: store})

	blip := errors.New("read tcp 10.0.0.1:5432: connection reset by peer")
	_, err := c.Run(context.Background(),
		&fakeSource{since: func(Position) (Batch, error) { return Batch{}, blip }}, "0/2")

	if !errors.Is(err, blip) {
		t.Fatalf("error %v is not the failure the source reported", err)
	}
	if got := reBasesIn(store); len(got) != 0 {
		t.Errorf("an ordinary failure retired the chain: %v", got)
	}
}

// A store that refuses the marker must not turn a dead chain into a healthy-looking one. The
// sentinel is what the scheduler branches on, so it has to survive being joined to the store's
// own failure — and no manifest may appear on this path either.
func TestAReBaseThatCannotBeStoredStillReachesTheCaller(t *testing.T) {
	refused := errors.New("403 from the container")
	store := newMemStore()
	c := testCycle(&Pipeline{Store: &refusingSuffix{inner: store, suffix: "/" + reBaseName, err: refused}})

	_, err := c.Run(context.Background(),
		changing("0/3", "sha256:moved", wholePart("changes.0001", "CDC-one")), "0/2")

	if err == nil {
		t.Fatal("a cycle whose re-base marker could not be stored reported success")
	}
	if !errors.Is(err, ErrSchemaMoved) {
		t.Errorf("error %v lost ErrSchemaMoved when the marker failed to store", err)
	}
	if !errors.Is(err, refused) {
		t.Errorf("error %v does not say the marker never landed, so nobody knows the container "+
			"holds no record of this", err)
	}
	if got := manifestsAttemptedIn(store); len(got) != 0 {
		t.Errorf("a manifest was written for a moved schema: %v", got)
	}
}
