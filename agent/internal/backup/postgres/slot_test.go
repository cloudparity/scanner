package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// The fifth argument is asked for from 17 and never below it, and THE HINGE IS THE POINT OF THIS
// TEST — not the two ends. Measured on live servers (AD-034) and again in containers across all
// five supported majors: 14, 15 and 16 reject the five-argument form by signature, 17 and 18
// accept it and the slot comes out with failover = t. So the table walks the whole range rather
// than one version either side, because an off-by-one in the comparison passes any test that only
// samples 14 and 18.
//
// THE SQL IS SPELLED OUT HERE, NOT SHARED WITH slot.go. A test built from the same constant as the
// code agrees with any typo in it — and a typo here is not a compile error, it is a statement the
// server rejects at the one moment a slot was supposed to exist.
func TestFailoverIsAskedForFrom17AndNeverBelow(t *testing.T) {
	const (
		withFailover = "SELECT pg_create_logical_replication_slot('vp_stream', 'pgoutput', false, false, true)"
		plain        = "SELECT pg_create_logical_replication_slot('vp_stream', 'pgoutput', false, false)"
	)

	for _, tc := range []struct {
		serverVersion string
		want          string
	}{
		{"14.24", plain},
		{"15.14", plain},
		{"16.10", plain},
		{"17.6", withFailover},
		{"18.6", withFailover},
		// What a Postgres built from source or packaged by a distribution reports. The major is
		// still the leading number; everything after the first dot is noise we must not trip on.
		{"16.10 (Debian 16.10-1.pgdg120+1)", plain},
		{"18.6 (Ubuntu 18.6-1.pgdg24.04+1)", withFailover},
		// Forms with no dot at all, which a split-on-the-dot reader gets wrong rather than refusing.
		{"17", withFailover},
		{"18 (Debian 18-1)", withFailover},
		{"16beta1", plain},
	} {
		t.Run(tc.serverVersion, func(t *testing.T) {
			var runner recorder
			if err := createSlot(context.Background(), runner.run, "vp_stream", tc.serverVersion); err != nil {
				t.Fatalf("createSlot: %v", err)
			}
			if len(runner.sent) != 1 {
				t.Fatalf("sent %d statements, want exactly 1: %q", len(runner.sent), runner.sent)
			}
			if runner.sent[0] != tc.want {
				t.Fatalf("sent:\n  %s\nwant:\n  %s", runner.sent[0], tc.want)
			}
		})
	}
}

// A name that is not a bare Postgres identifier is refused, AND NOTHING IS SENT. The second half
// is the whole point: a replication connection accepts the simple query protocol only (AD-036), so
// the slot name cannot be a bind parameter — it is interpolated into the statement. Interpolation
// with no validation in front of it is SQL injection with the agent's own credential, which is the
// one credential in this system that can drop a slot and stall the customer's primary.
//
// The rule matched here is Postgres's own for slot names, which is narrower than for identifiers
// generally: lower case, digits and underscore, 1 to 63 characters. Narrow is what makes this
// safe by construction rather than by escaping — there is no quote, no backslash and no semicolon
// in that alphabet, so no input can leave the string literal it is placed in.
func TestASlotNameThatWouldHaveToBeEscapedIsRefusedAndNeverSent(t *testing.T) {
	for _, name := range []string{
		"",
		"vp'; DROP TABLE customers; --",
		"vp' , 'pgoutput', false, false, true); SELECT pg_drop_replication_slot('vp",
		`vp\'`,
		"vp stream",
		"VP_STREAM",
		"vp-stream",
		"vp.stream",
		"vp\x00stream",
		"vp\nstream",
		"slot_é",
		strings.Repeat("v", 64),
	} {
		t.Run(name, func(t *testing.T) {
			var runner recorder
			err := createSlot(context.Background(), runner.run, name, "18.6")
			if err == nil {
				t.Fatal("the name was accepted; it is interpolated into the statement, so this is injection")
			}
			if len(runner.sent) != 0 {
				t.Fatalf("refused the name and sent it anyway: %q", runner.sent)
			}
		})
	}
}

// A NAME OUTSIDE OUR CONVENTION IS REFUSED AT CREATION, and nothing is sent. Every name here is a
// perfectly legal Postgres slot name, so none of them is refused for the injection reason — they
// are refused because creating one would put a slot on the customer's primary that isOurs cannot
// afterwards recognise as ours.
//
// That gap is the whole defect. Creating "parity_stream" used to succeed, and the 42710 a later
// cycle got back on it came home as a plain duplicate-object error with no ErrSlotLeaked in it: the
// C6 brake never fires, and the WAL that slot pins accumulates on the primary until Azure turns the
// server read-only. Recognition cannot be widened to close it — a rule loose enough to match that
// name also matches the customer's own slots — so creation is narrowed to what recognition knows.
func TestASlotNameOutsideOurConventionIsRefusedAtCreation(t *testing.T) {
	for _, name := range []string{
		"parity_stream",  // the measured case: legal, created happily, and unrecognisable afterwards.
		"cust_analytics", // a name the customer might already be using.
		"stream",
		"vpstream",   // no separator: "vp" is not the convention, "vp_" is.
		"xvp_stream", // the prefix has to START the name, not appear in it.
		"vp_",        // the prefix and nothing else names no install.
		"v",
		"0",
		"___",
	} {
		t.Run(name, func(t *testing.T) {
			var runner recorder
			err := createSlot(context.Background(), runner.run, name, "18.6")
			if err == nil {
				t.Fatal("the name was accepted; the slot it creates is one isOurs will not recognise, " +
					"so a leak of it never reaches the brake and its WAL piles up on the primary")
			}
			if len(runner.sent) != 0 {
				t.Fatalf("refused the name and sent it anyway: %q", runner.sent)
			}
		})
	}
}

// THE TWO RULES ARE ONE RULE, asserted over a corpus rather than by reading both functions and
// believing they agree — because they did not, and nothing failed when they stopped.
//
// A name validateSlotName accepts is a name this agent will create, and a name isOurs rejects is a
// name whose 42710 comes back without ErrSlotLeaked. Any name in the gap between them is a slot we
// put on the customer's primary and then decline to recognise. There is no safe direction to
// disagree in: the other way round, isOurs would claim slots we never created.
func TestValidateSlotNameAndIsOursCannotDisagree(t *testing.T) {
	for _, name := range []string{
		// Ours.
		"vp_stream", "vp_a", "vp_stream_2", "vp_" + strings.Repeat("v", 60),
		// Legal Postgres slot names that are not ours.
		"parity_stream", "cust_analytics", "pgoutput_slot", "vpstream", "xvp_stream",
		"vp_", "v", "0", "___", "",
		// Names Postgres itself would not take either.
		strings.Repeat("v", 64), "VP_STREAM", "vp-stream", "vp stream", "vp'; DROP TABLE customers; --",
	} {
		t.Run(name, func(t *testing.T) {
			creatable := validateSlotName(name) == nil
			if isOurs(name) != creatable {
				t.Fatalf("createSlot would accept %q = %v, isOurs says %v; a name in the gap between "+
					"them is a slot we leave on the customer's primary and then fail to recognise as "+
					"ours, so its leak never reaches the brake", name, creatable, isOurs(name))
			}
		})
	}
}

// Names Postgres itself accepts, within our convention, must not be refused here. A validator
// nobody can satisfy is not a safe validator, it is a broken one, and the failure it produces looks
// like a server problem.
func TestOrdinarySlotNamesAreAccepted(t *testing.T) {
	for _, name := range []string{"vp_stream", "vp_a", "vp_stream_2", "vp_0", "vp____", "vp_" + strings.Repeat("v", 60)} {
		t.Run(name, func(t *testing.T) {
			var runner recorder
			if err := createSlot(context.Background(), runner.run, name, "18.6"); err != nil {
				t.Fatalf("createSlot(%q): %v", name, err)
			}
			if len(runner.sent) != 1 || !strings.Contains(runner.sent[0], "'"+name+"'") {
				t.Fatalf("the name did not reach the statement: %q", runner.sent)
			}
		})
	}
}

// A server version we cannot read is an ERROR, not a reason to take the older path. Falling back
// would be the worst available behaviour: on a 17+ server it silently creates a slot WITHOUT
// failover, which looks identical to a correct one until an HA failover destroys it and takes the
// chain with it. That is discovered at restore, months later. Failing here costs one loud error.
func TestAnUnreadableServerVersionFailsRatherThanDroppingFailover(t *testing.T) {
	for _, serverVersion := range []string{"", "unknown", "v18.6", " 18.6", "eighteen"} {
		t.Run(serverVersion, func(t *testing.T) {
			var runner recorder
			err := createSlot(context.Background(), runner.run, "vp_stream", serverVersion)
			if err == nil {
				t.Fatal("an unreadable server version was accepted; the version branch is now a guess")
			}
			if len(runner.sent) != 0 {
				t.Fatalf("guessed a branch and sent it: %q", runner.sent)
			}
		})
	}
}

// The server's own error survives unwrapping, so a caller can read its SQLSTATE. It has to be the
// SQLSTATE and never the message: AD-036 measured different wordings for the same condition across
// 14 and 18, so text matching breaks on the versions we least test against.
//
// The sentinel is a REAL *pgconn.PgError, not a plain error, because errors.As through the wrap is
// the exact thing the doc comment on createSlot promises callers. A plain errors.New proves only
// that something survived; it would still pass if the wrap flattened the server's error into text,
// which is the failure that would strand every caller trying to branch on 42710.
func TestTheServersErrorIsWrappedNotReplaced(t *testing.T) {
	sentinel := &pgconn.PgError{Code: "42710", Message: `replication slot "vp_stream" already exists`}
	runner := recorder{err: sentinel}

	err := createSlot(context.Background(), runner.run, "vp_stream", "18.6")
	if !errors.Is(err, sentinel) {
		t.Fatalf("the server's error did not survive: %v", err)
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("no *pgconn.PgError in the chain, so a caller cannot read a SQLSTATE: %v", err)
	}
	if pgErr.Code != "42710" {
		t.Fatalf("SQLSTATE = %s, want 42710: %v", pgErr.Code, err)
	}
	if !strings.Contains(err.Error(), "vp_stream") {
		t.Fatalf("the wrapped error does not name the slot: %v", err)
	}
}

// isOurs decides whether a 42710 becomes a sentinel somebody may act on by dropping a slot, so it
// is worth pinning directly rather than only through the two names baseCopy's tests happen to use.
// The false cases are the ones that matter: every one of them is a slot this code must leave alone.
func TestOnlyOurOwnNamesAreRecognisedAsOurs(t *testing.T) {
	for _, tc := range []struct {
		name string
		ours bool
	}{
		{"vp_stream", true},
		{"vp_a", true}, // the shortest thing that is a prefix plus something.

		{"", false},
		{"vp_", false},        // the prefix and nothing else names no install.
		{"vpstream", false},   // no separator: "vp" is not the convention, "vp_" is.
		{"xvp_stream", false}, // the prefix has to START the name, not appear in it.
		{"cust_analytics", false},
		{"pgoutput_slot", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isOurs(tc.name); got != tc.ours {
				t.Fatalf("isOurs(%q) = %v, want %v — false positives get somebody else's slot "+
					"dropped, false negatives leave ours holding WAL on the primary", tc.name, got, tc.ours)
			}
		})
	}
}

// recorder stands in for the replication connection: it keeps every statement it is handed and
// answers with whatever the test wants the server to have said.
type recorder struct {
	sent []string
	err  error
}

func (r *recorder) run(_ context.Context, sql string) error {
	r.sent = append(r.sent, sql)
	return r.err
}

// TestDropSlotRefusesANameOutsideOurConventionBeforeItTouchesTheConnection asserts the ONE property
// that makes an exported drop safe to have at all: a name this agent would never create is refused
// before any statement exists, so this function can never be pointed at the customer's own slot.
//
// A NIL CONNECTION IS THE ASSERTION. If validateSlotName were reached after the statement were
// built, or not at all, this test would panic rather than fail — which is the loudest possible way
// of saying that a drop ran against something.
func TestDropSlotRefusesANameOutsideOurConventionBeforeItTouchesTheConnection(t *testing.T) {
	for _, name := range []string{"", "cust_analytics", "vp_", "VP_STREAM", "vp_stream; DROP"} {
		t.Run(name, func(t *testing.T) {
			if err := DropSlot(context.Background(), nil, name); err == nil {
				t.Fatalf("DropSlot accepted %q, which is a name this agent never creates and "+
					"therefore a slot that is somebody else's to remove", name)
			}
		})
	}
}

// TestASlotThatIsAlreadyGoneIsNotAFailedDrop is the case that broke a re-base: C4's dead chain IS a
// slot that already went, so dropping it on the way to a new base copy answers 42704 — and a caller
// that reads a failed drop as a leak (which it must) would stop a run over a slot holding nothing.
func TestASlotThatIsAlreadyGoneIsNotAFailedDrop(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"the slot is not there", &pgconn.PgError{Code: "42704", Message: `replication slot "vp_x" does not exist`}, true},
		{"the slot is being consumed", &pgconn.PgError{Code: "55006", Message: `replication slot "vp_x" is active`}, false},
		{"a wrapped 42704 still counts", fmt.Errorf("dropping: %w", &pgconn.PgError{Code: "42704"}), true},
		{"a broken connection is not an absent slot", errors.New("write tcp: broken pipe"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := undefinedObject(tc.err); got != tc.want {
				t.Fatalf("undefinedObject(%v) = %v, want %v — read the wrong way this either "+
					"stops a healthy re-base or hides a slot that is still holding WAL", tc.err, got, tc.want)
			}
		})
	}
}
