package postgres

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

// slotPrefix marks a replication slot as Parity's rather than the customer's. It is what every slot
// name in this repo already begins with; no decision record pins it, and this constant is the
// nearest thing to one until a ticket that generates slot names has somewhere better to put it.
const slotPrefix = "vp_"

// isOurs reports whether a slot name is one this agent creates, and it is the whole of what stands
// between "report a slot somebody may have to drop" and "leave a stranger's slot alone". Both
// mistakes are expensive and they are opposites: unrecognised, our own slot piles WAL on the
// customer's primary until Azure turns the server read-only; over-recognised, the safety brake
// drops a slot belonging to somebody else and breaks THEIR replication.
//
// HOW OURS ARE RECOGNISED — two things, and neither is sufficient alone:
//
//  1. the name was HANDED TO THIS CALL. It is the name this install was configured to create,
//     never a name read out of pg_replication_slots and judged to look familiar. Scanning the
//     catalog for names that look like ours would match a LIVE slot belonging to a sibling install
//     and call it a leak, which is the failure this whole function exists to avoid.
//  2. the name begins with slotPrefix. (1) alone proves only that the name is one WE would create,
//     which says nothing about who created the slot already sitting there under it: point the agent
//     at a name the customer already uses and 42710 comes back from THEIR slot. The prefix is what
//     makes that collision implausible rather than merely unlikely.
//
// WHAT IT DOES NOT DO, STATED PLAINLY BECAUSE THE BRAKE MUST NOT ASSUME OTHERWISE: it does not
// separate our slot from ANOTHER PARITY INSTALL'S. That needs the part after the prefix to carry an
// install identity, and nothing in this repo generates one yet — every caller today passes a fixed
// name. Two installs pointed at one database would collide, and this function would not see it. So
// "ours" here means "on our name", and dropping is left to a brake that can also establish nothing
// is consuming the slot — see alreadyOnTheServer.
//
// A name outside the convention is somebody else's, always. Erring that way under-reports a leak,
// which is recoverable; the other way destroys a slot that was never ours to touch, which is not.
//
// IT ASKS validateSlotName AND HAS NO RULE OF ITS OWN, because for a while it did and the two rules
// drifted apart: creation took any [a-z0-9_] name while recognition demanded the prefix, so
// CreateSlot(…, "parity_stream") succeeded and the 42710 a later cycle got back on that very slot
// came home as a plain duplicate-object error. The brake never fired and the WAL kept growing. The
// gap could only be closed in one direction — widening recognition would claim the customer's own
// slots — so the question is asked once, in one place, and a future edit cannot split it again.
func isOurs(name string) bool {
	return validateSlotName(name) == nil
}

// failoverFrom is the first major version whose pg_create_logical_replication_slot takes a fifth
// argument. THIS IS THE ONLY THING IN THE AGENT THAT BRANCHES ON A POSTGRES VERSION — AD-034
// settled that, and a second branch is not a small addition to it but a repeal of it.
//
// failover = true is what makes Azure synchronise the slot to the standby, so the slot survives an
// HA failover. Below 17 the argument does not exist and the call fails by signature rather than
// being ignored, which is why the version is read first instead of the five-argument form being
// tried and the failure swallowed.
const failoverFrom = 17

// The two statements, written out rather than assembled, because reading them side by side is the
// only way to see that ONE argument differs. %s is the slot name, and it is safe to interpolate
// only because validateSlotName has already restricted it to [a-z0-9_] — see there for why it is
// interpolated at all rather than bound.
const (
	createSlotWithFailover = "SELECT pg_create_logical_replication_slot('%s', 'pgoutput', false, false, true)"
	createSlotPlain        = "SELECT pg_create_logical_replication_slot('%s', 'pgoutput', false, false)"
)

// CreateSlot creates the logical replication slot the change stream will read from.
//
// It runs over the connection Connect already opened — the stream's connection — and does not open
// one of its own. AD-036 measured that a replication=database connection serves ordinary SQL as
// well as replication commands on both 14 and 18, so there is nothing a second connection would
// buy except a second credential path to get wrong.
//
// The slot is created NOT temporary and NOT two-phase, which is the false, false in both
// statements. Temporary would be exactly wrong: a temporary slot dies with the session, so the
// first reconnect would leave a hole in the middle of a chain that still looks healthy.
func CreateSlot(ctx context.Context, conn *pgconn.PgConn, name string) error {
	run := func(ctx context.Context, sql string) error {
		_, err := conn.Exec(ctx, sql).ReadAll()
		return err
	}
	// server_version comes from the startup packet, so it costs no round trip and is available
	// before any statement runs — measured present on a replication connection on 14.24 and 18.6.
	// server_version_num is NOT reported over the protocol on either (measured, empty both times),
	// which is why the human-facing string is what gets parsed.
	return createSlot(ctx, run, name, conn.ParameterStatus("server_version"))
}

// ValidateSlotName exports the rule below so an entry point can refuse a misconfigured name AT
// STARTUP, where refusing is free, rather than at the first cycle — by which time a slot under a
// name nothing can claim is already on the customer's primary. A second name for the rule and never
// a second rule: see validateSlotName for what happened the last time there were two.
func ValidateSlotName(name string) error { return validateSlotName(name) }

// DropSlot removes the replication slot this agent created, and it is the counterpart CreateSlot
// needed the moment something outside this package started a chain and had to end one.
//
// IT IS THE WHOLE OF "NEVER LEAK A SLOT" ON THE ORDINARY PATHS. An unconsumed slot accumulates WAL
// on the customer's PRIMARY and ONLY THE OWNING ROLE CAN DROP ONE — not the customer's administrator
// (AD-034) — so a run that ends without dropping the slot it created leaves behind a thing nobody
// but a future run of ours can remove. brake.go is the answer when this cannot be reached; this is
// the answer when it can.
//
// IT MUST NOT BE CALLED OVER THE STREAM'S OWN CONNECTION, and the server enforces that rather than
// this function: a slot cannot be dropped while a session holds it (55006, measured), and after
// START_REPLICATION that connection is in CopyBoth and serves no ordinary statement at all. So a
// caller closes the stream first and drops over a connection that never started replication.
//
// The name is validated before it reaches the statement, by the one rule that also decides what this
// agent will create — see validateSlotName. That is what makes interpolating it safe, and it is what
// keeps this function from ever being pointed at the customer's own slot.
// A SLOT THAT IS ALREADY GONE IS SUCCESS, and that is not leniency — it is the difference between
// this function's job and a statement's. What a caller wants is "no slot of ours on this server",
// and 42704 says exactly that. Reporting it as a failure would break the commonest re-base there
// is: C4's dead chain is a slot that ALREADY went, so dropping it on the way to a new base copy
// would come back as an error, and a caller that reads a failed drop as a leak (which it must)
// would stop a run over a slot that is holding nothing.
func DropSlot(ctx context.Context, conn *pgconn.PgConn, name string) error {
	if err := validateSlotName(name); err != nil {
		return err
	}
	const drop = "SELECT pg_drop_replication_slot('%s')"
	if _, err := conn.Exec(ctx, fmt.Sprintf(drop, name)).ReadAll(); err != nil && !undefinedObject(err) {
		return fmt.Errorf("postgres: drop replication slot %q: %w. It is still holding WAL on the "+
			"PRIMARY, and only the role that created it can drop one — an administrator cannot", name, err)
	}
	return nil
}

// undefinedObject is what the server answers when the slot named is not there.
//
// MATCHED ON THE SQLSTATE AND NEVER ON THE MESSAGE, the same rule base.go's duplicateObject
// follows: AD-036 measured that the wording differs across 14 and 18 for identical conditions.
func undefinedObject(err error) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "42704"
}

// Query builds what Brake.Query takes, for a caller outside this package — which is the brake's OWN
// connection rather than the stream's. Exported rather than left to be rewritten there, because a
// second implementation of "run a statement and read its rows as text" is a second set of edge cases
// feeding the one function in this repo that destroys a replication slot.
func Query(conn *pgconn.PgConn) func(ctx context.Context, sql string) ([][]string, error) {
	return simpleQueryRows(conn)
}

// runSQL runs one statement over the simple query protocol and reads its result to the end.
//
// pgConn.Exec is the only implementation, and the simple query protocol is not a preference: NOT
// ExecParams and not the pgx.Conn layer above this one — AD-036 measured both fail on a replication
// connection with SQLSTATE 08P01, and that restriction is upstream's, stated word for word: "only
// the simple query protocol can be used". It is also the reason the slot name is interpolated.
//
// This is a function rather than an interface because there is one operation and one real
// implementation; it exists so a test can assert the exact statement, and above all so it can
// assert that a rejected slot name produces NO statement at all.
type runSQL func(ctx context.Context, sql string) error

func createSlot(ctx context.Context, run runSQL, name, serverVersion string) error {
	if err := validateSlotName(name); err != nil {
		return err
	}
	major, err := majorVersion(serverVersion)
	if err != nil {
		return err
	}

	statement := createSlotPlain
	if major >= failoverFrom {
		statement = createSlotWithFailover
	}

	// The server's error is wrapped, never replaced. Callers that need to tell one failure from
	// another must reach a *pgconn.PgError and read its SQLSTATE — never its message, which AD-036
	// measured differs across 14 and 18 for identical conditions.
	if err := run(ctx, fmt.Sprintf(statement, name)); err != nil {
		return fmt.Errorf("postgres: create replication slot %q on server version %s: %w", name, serverVersion, err)
	}
	return nil
}

// validateSlotName refuses anything that is not a bare Postgres replication slot name OF OURS. It
// is the one rule for what this agent may create, and — through isOurs — the one rule for what it
// will afterwards recognise as its own.
//
// IT ANSWERS TWO QUESTIONS AND BOTH ARE SAFETY, NOT COURTESY:
//
//   - Can this name be interpolated? The name goes into the statement verbatim because a
//     replication connection has no bind parameters (AD-036), so this is the entirety of what
//     stands between a caller's string and arbitrary SQL running as the one role in this system
//     that can drop a slot — and dropping the wrong slot silently kills a backup chain.
//     Postgres's own rule for slot names is narrower than for identifiers generally: lower case,
//     digits and underscore, at most 63 characters. Keeping to exactly that alphabet is what makes
//     the interpolation safe BY CONSTRUCTION rather than by escaping — it contains no quote, no
//     backslash and no semicolon, so nothing that passes here can leave the string literal it is
//     placed in. Escaping instead would be a rule to get right; this is a rule to check.
//
//   - Is this name one we will still know is ours in a week? A slot outlives the process that
//     created it, and 42710 on a later cycle is the only trace it leaves. isOurs is what turns
//     that into ErrSlotLeaked and the C6 brake, and it can recognise nothing but the prefix. So a
//     name without the prefix is refused HERE, at the only moment refusing it is free — creating
//     one puts a slot on the customer's primary that nothing downstream can claim, and its WAL
//     then grows unattributed toward the 95% disk at which Azure turns the server read-only.
//
// The two rules live in one function because they were once two and drifted: see isOurs.
func validateSlotName(name string) error {
	if err := bareIdentifier("replication slot", name); err != nil {
		return err
	}
	if !strings.HasPrefix(name, slotPrefix) || len(name) == len(slotPrefix) {
		return fmt.Errorf("postgres: replication slot name %q does not begin with %q followed by "+
			"something; a slot created under any other name is one this agent cannot afterwards tell "+
			"from the customer's own, so a leak of it never reaches the brake and its WAL accumulates "+
			"on the primary", name, slotPrefix)
	}
	return nil
}

// bareIdentifier is the alphabet a name must be in to travel into a replication command verbatim,
// which is where a slot name and a publication name (since.go) both end up. A replication
// connection has no bind parameters (AD-036), so this is the entirety of what stands between a
// configured string and arbitrary SQL: the alphabet contains no quote, no backslash and no
// semicolon, so nothing that passes here can leave the string literal it is placed in. Escaping
// instead would be a rule to get right; this is a rule to check.
//
// Shared rather than written twice, and that is not tidiness — validateSlotName's own comment
// records what happened the last time two rules about one name lived in two places and drifted.
func bareIdentifier(kind, name string) error {
	const maxName = 63 // NAMEDATALEN - 1, the same limit the server enforces.

	if name == "" {
		return fmt.Errorf("postgres: the %s name is empty", kind)
	}
	if len(name) > maxName {
		return fmt.Errorf("postgres: %s name %q is %d bytes; the limit is %d", kind, name, len(name), maxName)
	}
	for _, r := range name {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' {
			continue
		}
		return fmt.Errorf("postgres: %s name %q contains %q; only lower-case letters, digits and "+
			"underscore are allowed, and the name is put into the statement verbatim because a "+
			"replication connection has no bind parameters", kind, name, r)
	}
	return nil
}

// majorVersion reads the major from what the server reports as server_version: "14.24", "18.6",
// and the packaged form "16.10 (Debian 16.10-1.pgdg120+1)".
//
// It takes the LEADING RUN OF DIGITS and discards the rest, which is deliberately looser than
// splitting on the first dot: since version 10 the major is that leading number and nothing else,
// so this reads "18.6", "18 (Debian 18-1)" and "18beta1" alike, and none of the forms a packager
// invents can turn into a wrong answer — only into no answer.
//
// AN UNREADABLE VERSION IS AN ERROR AND MUST NEVER FALL BACK TO THE OLDER PATH. Falling back is the
// worst behaviour available here: on a 17+ server it would create a slot without failover, which is
// indistinguishable from a correct one right up until an HA failover destroys it and takes the
// chain with it — found at restore, and by then unfixable. One loud error costs incomparably less.
func majorVersion(serverVersion string) (int, error) {
	end := 0
	for end < len(serverVersion) && serverVersion[end] >= '0' && serverVersion[end] <= '9' {
		end++
	}

	major, err := strconv.Atoi(serverVersion[:end])
	if err != nil || major <= 0 {
		return 0, fmt.Errorf("postgres: cannot read a major version from server_version %q; refusing "+
			"rather than guessing, because guessing low creates a slot that will not survive an HA "+
			"failover and looks correct until it does not", serverVersion)
	}
	return major, nil
}
