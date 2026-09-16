package postgres

import (
	"strings"
	"testing"

	"github.com/manukyanv07/parity-scanner/chain"
	"github.com/manukyanv07/parity-scanner/contract"
)

// The whole point of the type: it is a chain.Ordered, so a verifier can ask it instead of
// reading an LSN itself.
var _ chain.Ordered = WAL{}

func TestOneLSNFollowsAnother(t *testing.T) {
	for _, tc := range []struct {
		name           string
		later, earlier string
		want           bool
	}{
		{"further along the same segment", "0/1A2B3C8", "0/1A2B000", true},
		{"and not the other way round", "0/1A2B000", "0/1A2B3C8", false},

		// Follows is STRICTLY later. Equality is the caller's, and comparing two Positions for
		// equality is the one thing backup-shape.md §5 lets it do without asking.
		{"the same position twice", "0/1A2B3C8", "0/1A2B3C8", false},

		// THE CASE THAT PROVES THESE ARE NUMBERS AND NOT STRINGS. Postgres prints an LSN half
		// without leading zeros, so a bigger number can be a shorter one, and "0/10000000" sorts
		// BEFORE "0/FFFFFFF" as text — one byte before the segment rolls over, read as a rewind.
		{"a longer number that is the larger one", "0/10000000", "0/FFFFFFF", true},
		{"and not the other way round", "0/FFFFFFF", "0/10000000", false},

		{"the first byte of the next segment", "1/0", "0/FFFFFFFF", true},
		{"and not the other way round", "0/FFFFFFFF", "1/0", false},

		// Same trap in the high half, where a chain that has been running long enough lives.
		{"a two-digit segment after a one-digit one", "10/0", "9/FFFFFFFF", true},
		{"and not the other way round", "9/FFFFFFFF", "10/0", false},

		// Postgres prints upper case; pg_lsn accepts either, and a value that has been through a
		// tool that lower-cased it is the same position, not an unreadable one.
		{"lower-case hex", "0/1a2b3c8", "0/1A2B000", true},
		{"one position in two spellings is still not after itself", "0/1a2b3c8", "0/1A2B3C8", false},
	} {
		t.Run(tc.name+": "+tc.later+" after "+tc.earlier, func(t *testing.T) {
			if got := (WAL{}).Follows(chain.Position(tc.later), chain.Position(tc.earlier)); got != tc.want {
				t.Errorf("Follows(%s, %s) = %t, want %t", tc.later, tc.earlier, got, tc.want)
			}
		})
	}
}

// A POSITION THIS CANNOT READ IS ONE IT CANNOT PLACE, AND THE HONEST ANSWER IS NO — in both
// directions, which is what makes it fail closed. chain.go asks "does the source say there is no
// gap here" rather than "does it say there is one", so an unreadable position stops the chain
// instead of passing it: the alternative is a verifier that reports a chain whole because it could
// not read the very positions that would have shown the hole.
func TestAnLSNThatCannotBeReadIsNeverPlaced(t *testing.T) {
	const good = "0/1A2B000"

	for _, malformed := range []string{
		"",
		"zzz",
		"0/",           // no low half
		"/1A2B000",     // no high half
		"1A2B000",      // no separator at all
		"0/1A2B/000",   // two separators
		"0/1G2B000",    // not hex
		" 0/1A2B000",   // whitespace the source never wrote
		"0x0/0x1A2B00", // Go's own spelling, which Postgres does not use
		"0/1FFFFFFFF",  // wider than the 32 bits a half holds
		"-1/0",         // a sign, which an LSN never carries
	} {
		t.Run("["+malformed+"]", func(t *testing.T) {
			if (WAL{}).Follows(chain.Position(malformed), good) {
				t.Errorf("%q was placed after %s; a position nobody can read must stop a chain, "+
					"not pass one", malformed, good)
			}
			if (WAL{}).Follows(good, chain.Position(malformed)) {
				t.Errorf("%s was placed after %q, which nobody can read", good, malformed)
			}
		})
	}
}

// The two halves fitting together, with real LSNs: a chain with a change file missing out of the
// middle of it fails, and it fails because THIS type answered — chain.go never read an LSN.
func TestAGapBetweenRealLSNsIsCaughtThroughTheVerifier(t *testing.T) {
	// 0/16B3740 → 0/16FE9C8 was captured and is not here. Everything present is perfect about
	// itself, which is why nothing inside one manifest could ever have caught this.
	holed := lsnChain("0/1701A50",
		lsnSegment(contract.BackupBase, "", "0/16A2B08"),
		lsnSegment(contract.BackupChange, "0/16A2B08", "0/16B3740"),
		lsnSegment(contract.BackupChange, "0/16FE9C8", "0/1701A50"),
	)

	checked, err := chain.Verify(holed, WAL{})
	if err == nil {
		t.Fatalf("a chain missing a file verified as %q", checked)
	}
	if checked != "" {
		t.Errorf("a chain that failed reported %q; nothing about it was verified", checked)
	}
	for _, want := range []string{"0/16B3740", "0/16FE9C8"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the failure does not name %s, so nobody can tell where the hole is: %v", want, err)
		}
	}

	// The same chain with the missing file back in it, overlapping its neighbour the way a real
	// one does — replay is at-least-once (AD-039), so the ranges overlap and that is health.
	whole := lsnChain("0/1701A50",
		lsnSegment(contract.BackupBase, "", "0/16A2B08"),
		lsnSegment(contract.BackupChange, "0/16A2B08", "0/16B3740"),
		lsnSegment(contract.BackupChange, "0/16B2000", "0/16FE9C8"),
		lsnSegment(contract.BackupChange, "0/16FE9C8", "0/1701A50"),
	)
	checked, err = chain.Verify(whole, WAL{})
	if err != nil {
		t.Fatalf("a healthy chain was refused: %v", err)
	}
	if checked != chain.CheckedWhole {
		t.Errorf("checked: got %q want %q", checked, chain.CheckedWhole)
	}
}

func lsnChain(confirmed string, segments ...contract.Manifest) contract.Chain {
	return contract.Chain{
		ContractVersion: contract.BackupContractVersion,
		Segments:        segments,
		Confirmed:       confirmed,
	}
}

// lsnSegment carries ONLY what Verify reads: the kind, the range, and enough of an artifact to
// be a segment at all. A full manifest here would be a second copy of chain_test.go's fixture,
// and the question this file asks is about LSNs and nothing else.
func lsnSegment(kind contract.BackupKind, from, to string) contract.Manifest {
	return contract.Manifest{
		ContractVersion: contract.BackupContractVersion,
		Kind:            kind,
		ReadPoint:       contract.ReadPoint{At: "2026-08-14T09:14:00Z", Position: to, From: from},
		Schema:          "9f2c4b1e7a03d568",
		Artifact: contract.Artifact{
			Parts: []contract.Part{{Path: "install-7/pg1/orders/" + strings.ReplaceAll(to, "/", "-") + "/changes.0000"}},
		},
	}
}
