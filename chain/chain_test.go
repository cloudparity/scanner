package chain

import (
	"strings"
	"testing"

	"github.com/manukyanv07/parity-scanner/contract"
)

// THE POSITIONS HERE ARE NOT LSNs AND THE FAKE ORDERER DOES NOT PARSE THEM. That is deliberate:
// if this file could only be written with Postgres-shaped strings, the verifier would have
// learned something about Postgres. ranked answers Follows from a table of positions in their
// true order, which is exactly as much as a source has to be able to do — and a position it has
// never heard of is one it cannot place, which is the honest answer and the fail-closed one.
type ranked []string

func (r ranked) Follows(later, earlier Position) bool {
	l, e := r.at(later), r.at(earlier)
	if l < 0 || e < 0 {
		return false
	}
	return l > e
}

func (r ranked) at(p Position) int {
	for i, known := range r {
		if known == string(p) {
			return i
		}
	}
	return -1
}

// order is the timeline every chain in this file is built on, coarse enough that a change file
// can start between two others.
var order = ranked{"0/100", "0/150", "0/200", "0/250", "0/300", "0/350", "0/400", "0/500"}

// base is the one full copy a chain is built on. It begins after nothing.
func base(to string) contract.Manifest {
	return segment(contract.BackupBase, "", to)
}

// change is one change file and the range it covers.
func change(from, to string) contract.Manifest {
	return segment(contract.BackupChange, from, to)
}

func segment(kind contract.BackupKind, from, to string) contract.Manifest {
	return contract.Manifest{
		ContractVersion: contract.BackupContractVersion,
		Kind:            kind,
		Source: contract.BackupSource{
			Provider:      contract.ProviderAzure,
			ResourceID:    "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.dbforpostgresql/flexibleservers/pg1",
			Database:      "orders",
			Engine:        "postgres",
			EngineVersion: "16",
		},
		ReadPoint: contract.ReadPoint{At: "2026-08-14T09:14:00Z", Position: to, From: from},
		Schema:    "9f2c4b1e7a03d568",
		Artifact: contract.Artifact{
			Format: contract.FormatPlainSQL,
			Bytes:  2048,
			Parts: []contract.Part{{
				Path:   "install-7/pg1/orders/" + strings.ReplaceAll(to, "/", "-") + "/changes.0000",
				Bytes:  2048,
				SHA256: "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce",
				Format: contract.FormatPlainSQL,
				Role:   contract.PartDatabase,
			}},
		},
		Producer: contract.Producer{Agent: "azure/0.1.0", Tool: "pglogrepl 0.0.0"},
		Transfer: contract.RouteAgentStream,
	}
}

func chainOf(confirmed string, segments ...contract.Manifest) contract.Chain {
	return contract.Chain{
		ContractVersion: contract.BackupContractVersion,
		Segments:        segments,
		Confirmed:       confirmed,
	}
}

// THE DELIVERABLE. A chain with a file missing out of the middle of it fails, and it fails
// loudly enough that a human is told which two files the hole is between.
func TestAChainWithAFileMissingFromTheMiddleFailsLoudly(t *testing.T) {
	// 0/200 → 0/300 was captured and is not here. Every segment present is internally perfect:
	// the objects hash, the manifests parse, the ranges are well formed.
	broken := chainOf("0/400", base("0/100"), change("0/100", "0/200"), change("0/300", "0/400"))

	checked, err := Verify(broken, order)
	if err == nil {
		t.Fatal("a chain missing a file verified; a restore from it would silently drop every " +
			"change between 0/200 and 0/300")
	}
	if checked != "" {
		t.Errorf("a chain that failed reported %q; nothing about it was verified", checked)
	}
	for _, want := range []string{"0/200", "0/300"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the failure does not name %s, so nobody can tell where the hole is: %v", want, err)
		}
	}
}

// The chain's ranges are checked end to end: the base's position, each file in order, and the
// last position the source was told was durable.
func TestVerifyChecksTheChainEndToEnd(t *testing.T) {
	for _, tc := range []struct {
		name  string
		chain contract.Chain
		// broken is the phrase the failure must contain. Empty means the chain is whole.
		broken string
	}{
		{
			name:  "an intact chain, every file adjacent to the last",
			chain: chainOf("0/400", base("0/100"), change("0/100", "0/200"), change("0/200", "0/400")),
		},
		{
			name: "an overlapping pair, which is what a healthy chain looks like",
			// Replay is at-least-once by construction (AD-039): after confirming nothing, every
			// transaction came back at the same LSNs. A verifier that demanded strictly adjacent
			// ranges would reject this, and this is the normal case.
			chain: chainOf("0/400", base("0/100"), change("0/100", "0/300"), change("0/200", "0/400")),
		},
		{
			name:  "a base and no changes yet, reaching exactly the confirmed position",
			chain: chainOf("0/100", base("0/100")),
		},
		{
			name: "a chain that reaches past the confirmed position",
			// Stored and not yet confirmed. The confirm happens only once the batch is durable,
			// so a file ahead of it is the ordinary window between the two, not a fault.
			chain: chainOf("0/200", base("0/100"), change("0/100", "0/400")),
		},
		{
			name:   "a file missing from the middle",
			chain:  chainOf("0/400", base("0/100"), change("0/100", "0/200"), change("0/300", "0/400")),
			broken: "nothing in this chain covers",
		},
		{
			name:   "a file missing straight after the base",
			chain:  chainOf("0/400", base("0/100"), change("0/200", "0/400")),
			broken: "nothing in this chain covers",
		},
		{
			name: "the files out of order",
			// Both overlap their predecessor, so the continuity check is satisfied and only the
			// requirement that each file MOVE THE CHAIN FORWARD catches it.
			chain:  chainOf("0/400", base("0/100"), change("0/100", "0/400"), change("0/150", "0/300")),
			broken: "does not carry the chain past",
		},
		{
			name:   "a file repeated, which carries the chain nowhere",
			chain:  chainOf("0/300", base("0/100"), change("0/100", "0/300"), change("0/100", "0/300")),
			broken: "does not carry the chain past",
		},
		{
			name:   "the last file does not reach the position the source was told was durable",
			chain:  chainOf("0/500", base("0/100"), change("0/100", "0/200")),
			broken: "was told 0/500 is durable",
		},
		{
			name:   "a position the source cannot place at all",
			chain:  chainOf("0/400", base("0/100"), change("0/100", "zzz")),
			broken: "does not carry the chain past",
		},
		{
			// The same fail-closed answer at the END of the chain, which is where the newest data
			// is. A source that cannot place the confirmed position has not said the chain reaches
			// it, and not-said is refused rather than assumed.
			name:   "a confirmed position the source cannot place at all",
			chain:  chainOf("zzz", base("0/100"), change("0/100", "0/400")),
			broken: "is durable",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checked, err := Verify(tc.chain, order)

			if tc.broken == "" {
				if err != nil {
					t.Fatalf("a healthy chain was refused: %v", err)
				}
				if checked != CheckedWhole {
					t.Errorf("checked: got %q want %q", checked, CheckedWhole)
				}
				return
			}
			if err == nil {
				t.Fatalf("a broken chain verified as %q", checked)
			}
			if !strings.Contains(err.Error(), tc.broken) {
				t.Errorf("the failure does not say %q: %v", tc.broken, err)
			}
			if checked != "" {
				t.Errorf("a chain that failed reported %q; nothing about it was verified", checked)
			}
		})
	}
}

// The shape of a chain is checkable without ordering anything, and these are the ways a chain is
// unusable whatever its ranges say.
func TestVerifyRefusesAChainNothingCouldRestore(t *testing.T) {
	for _, tc := range []struct {
		name   string
		chain  contract.Chain
		broken string
	}{
		{
			name:   "no segments at all",
			chain:  chainOf("0/100"),
			broken: "no segments",
		},
		{
			name:   "no confirmed position, so nothing says how far it should reach",
			chain:  contract.Chain{Segments: []contract.Manifest{base("0/100")}},
			broken: "records no confirmed position",
		},
		{
			name:   "it does not begin with a base",
			chain:  chainOf("0/200", change("0/100", "0/200")),
			broken: "does not begin with a base",
		},
		{
			name:   "a second base in the middle of it",
			chain:  chainOf("0/300", base("0/100"), base("0/300")),
			broken: `is a "base"`,
		},
		{
			name:   "a change file that does not say where it begins",
			chain:  chainOf("0/300", base("0/100"), change("", "0/300")),
			broken: "does not say where it begins",
		},
		{
			name:   "a segment that reached no position",
			chain:  chainOf("0/300", base("")),
			broken: "records no position",
		},
		{
			name: "a segment that lists no objects",
			chain: func() contract.Chain {
				empty := change("0/100", "0/300")
				empty.Artifact.Parts = nil
				return chainOf("0/300", base("0/100"), empty)
			}(),
			broken: "lists no objects",
		},
		{
			name: "a segment from another database",
			chain: func() contract.Chain {
				stray := change("0/100", "0/300")
				stray.Source.Database = "reporting"
				return chainOf("0/300", base("0/100"), stray)
			}(),
			broken: "backs up",
		},
		{
			name: "a segment captured against a schema the base never had",
			chain: func() contract.Chain {
				altered := change("0/100", "0/300")
				altered.Schema = "0000000000000000"
				return chainOf("0/300", base("0/100"), altered)
			}(),
			broken: "schema",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checked, err := Verify(tc.chain, order)
			if err == nil {
				t.Fatalf("a chain nothing could restore verified as %q", checked)
			}
			if !strings.Contains(err.Error(), tc.broken) {
				t.Errorf("the failure does not say %q: %v", tc.broken, err)
			}
			if checked != "" {
				t.Errorf("a chain that failed reported %q; nothing about it was verified", checked)
			}
		})
	}
}

// A source that cannot order its own positions gets an honest answer and not a guess. The shape
// is still checked; the ranges are NOT, because telling an overlap from a gap needs the source
// and there is no second-best — a verifier that assumed adjacency would reject every healthy
// chain, and one that assumed the ranges were fine would pass every broken one.
func TestVerifyIsHonestAboutASourceThatCannotOrderItsPositions(t *testing.T) {
	// The hole between 0/200 and 0/300 is real and cannot be seen without an orderer.
	holed := chainOf("0/400", base("0/100"), change("0/100", "0/200"), change("0/300", "0/400"))

	checked, err := Verify(holed, nil)
	if err != nil {
		t.Fatalf("the shape of this chain is fine and only its ranges are unknowable: %v", err)
	}
	if checked != CheckedShapeOnly {
		t.Fatalf("checked: got %q want %q — a caller cannot tell that the gaps went unchecked",
			checked, CheckedShapeOnly)
	}

	// And the shape is still refused, so an unorderable source is not a way around every check.
	if _, err := Verify(chainOf("0/400"), nil); err == nil {
		t.Error("a chain with no segments passed because its source could not order positions")
	}
}

// Verify never looks inside a position: it asks the source, and it asks it about the pairs it
// needs and no others. Pinned because the day this file parses one is the day MySQL binlog
// coordinates break it (backup-shape.md §5), and that would be caught by nothing else here.
func TestVerifyAsksTheSourceRatherThanReadingThePositions(t *testing.T) {
	spy := &countingOrder{inner: order}
	// EVERY LINK OVERLAPS, so every link needs the source. Where two positions are equal the
	// answer is settled by comparing them, which is the one thing §5 allows and which costs the
	// source nothing — an adjacent chain therefore asks fewer questions than this one.
	chain := chainOf("0/350", base("0/200"), change("0/100", "0/300"), change("0/250", "0/400"))

	if _, err := Verify(chain, spy); err != nil {
		t.Fatalf("a healthy chain was refused: %v", err)
	}
	// Two per consecutive pair — does it begin at or before the last one ended, and does it move
	// the chain forward — plus one for the confirmed position at the end.
	if want := 2*(len(chain.Segments)-1) + 1; spy.calls != want {
		t.Errorf("the source was asked %d times, want %d: a check that stopped asking is one "+
			"that started deciding for itself", spy.calls, want)
	}
}

type countingOrder struct {
	inner Ordered
	calls int
}

func (c *countingOrder) Follows(later, earlier Position) bool {
	c.calls++
	return c.inner.Follows(later, earlier)
}

// ONE RULE, TWO PLACES. This is the comparison the cycle makes at capture time and the one
// checkSegment makes at restore, and they are the same function on purpose: two answers to "did the
// schema move" is how a chain that the agent extended becomes a chain the verifier rejects, or
// worse, the other way round.
func TestWhatCountsAsTheSchemaHavingMoved(t *testing.T) {
	for _, tc := range []struct {
		name          string
		base, capture string
		moved         bool
	}{
		{"the same fingerprint twice", "sha256:a", "sha256:a", false},
		{"a different fingerprint", "sha256:a", "sha256:b", true},
		// A disk snapshot has no schema and never will. Both ends empty is that source, and
		// calling it a move would re-base it forever.
		{"a source that has no schema at either end", "", "", false},
		// NOT a move, and not healthy either: nothing was compared. The cycle refuses it
		// separately, in the agent's cycle (backup.mark), because at restore checkSegment must still tolerate a
		// manifest written by a producer that never filled the field.
		{"nothing to compare on the base's side", "", "sha256:b", false},
		{"nothing to compare on this cycle's side", "sha256:a", "", false},

		// THE ALGORITHM CHANGING IS NOT THE CUSTOMER'S SCHEMA CHANGING, and telling the two apart
		// is the whole reason a fingerprint carries more than one digest. An agent that learned to
		// read a new catalog field reports a value that shares nothing textually with the one the
		// chain's base holds; comparing the strings would re-base every chain in the fleet on the
		// first cycle after a deploy, each for about nine minutes of cloud work, for no change at
		// all. So the comparison is per algorithm, over the versions both ends actually carry.
		{"an older base against an agent that learned a newer algorithm",
			"sha256:a", "sha256:a v2:sha256:x", false},
		// The older algorithm still SEES what it always saw. A real column change moves its digest,
		// and the newer one being present changes nothing about that.
		{"an older base against a newer agent that saw a real change",
			"sha256:a", "sha256:b v2:sha256:x", true},
		// A chain based by a new agent and read by an old one — a rollback, or a mixed fleet. The
		// value the old agent produces carries only the old algorithm, and that is enough.
		{"a newer base against an agent that only knows the older algorithm",
			"sha256:a v2:sha256:x", "sha256:a", false},
		// Both ends know v2, and only v2 moved: that is exactly ALTER TABLE ... SET LOGGED, which
		// moves no column and no replica identity. The older digest matching must not outvote it.
		{"both ends tagged and only the newer algorithm moved",
			"sha256:a v2:sha256:x", "sha256:a v2:sha256:y", true},
		{"the same tagged value twice", "sha256:a v2:sha256:x", "sha256:a v2:sha256:x", false},
		// NO ALGORITHM IN COMMON IS A MOVE, and that is the conservative answer rather than the
		// honest one on purpose. Here the honest answer — "nobody knows" — reads as "carry on",
		// and carrying on past a comparison that could not be made is the silence this whole
		// mechanism exists to break. A re-base costs a base copy; the alternative costs the restore.
		{"two agents with no algorithm in common", "v2:sha256:x", "v3:sha256:y", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := SchemaMoved(tc.base, tc.capture); got != tc.moved {
				t.Errorf("SchemaMoved(%q, %q) = %v, want %v", tc.base, tc.capture, got, tc.moved)
			}
		})
	}
}
