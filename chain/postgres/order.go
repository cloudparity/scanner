package postgres

// order.go is THE ONE PLACE IN THIS REPO ALLOWED TO LOOK INSIDE A POSITION, and it is this file
// because it is this package: only Postgres knows that 0/1A2B3C8 follows 0/1A2B000
// (backup-shape.md §5). Everything above the seam — the pipeline, the manifest, the chain
// verifier — stores a Position, hands it back and compares it for equality, and asks here when it
// needs the two ordered. The day a second file parses an LSN, the first MySQL binlog coordinate
// breaks whatever it is in.
//
// It answers chain.Ordered, which AD-035 held back until it had a consumer. chain.go is that
// consumer: a hole between two change files is the difference between one file's end and the next
// one's start, and telling that difference from an overlap is a question nothing outside this
// package can answer.

import (
	"strconv"
	"strings"

	"github.com/manukyanv07/parity-scanner/chain"
)

// WAL orders two positions on a Postgres write-ahead log. It has no state and nothing to
// configure — an LSN means the same thing on every server — so it is a value, and a future
// Postgres source embeds it to become a chain.Ordered.
type WAL struct{}

// Follows reports whether later is STRICTLY after earlier. Follows(p, p) is false: equality is
// the caller's to check and it can already do that.
//
// A position it cannot read is one it cannot place, and it says no — TO BOTH QUESTIONS, which is
// what makes an unreadable position stop a chain rather than pass one. The interface has no error
// to return, and it does not need one: chain.go demands proof that there is no gap instead of
// proof that there is one, so "I cannot place this" and "there is a gap" land in the same place,
// which is the safe one.
func (WAL) Follows(later, earlier chain.Position) bool {
	l, ok := lsn(later)
	if !ok {
		return false
	}
	e, ok := lsn(earlier)
	if !ok {
		return false
	}
	return l > e
}

// lsn reads Postgres's X/Y — two 32-bit halves in hex, printed WITHOUT leading zeros — as the
// single 64-bit number it stands for. The missing zeros are why this cannot be a string
// comparison: 0/10000000 is one byte after 0/FFFFFFF and sorts before it as text, so comparing
// the strings reads the segment rolling over as the chain going backwards.
//
// Anything else is refused rather than guessed at: an empty string, a spelling from some other
// source, a half wider than the 32 bits it has. ParseUint with an explicit base 16 does most of
// the refusing — no sign, no 0x, no underscores, no surrounding space.
func lsn(p chain.Position) (uint64, bool) {
	high, low, found := strings.Cut(string(p), "/")
	if !found {
		return 0, false
	}
	h, err := strconv.ParseUint(high, 16, 32)
	if err != nil {
		return 0, false
	}
	l, err := strconv.ParseUint(low, 16, 32)
	if err != nil {
		return 0, false
	}
	return h<<32 | l, true
}
