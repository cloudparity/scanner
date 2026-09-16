package postgres

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/manukyanv07/parity-scanner/agent/internal/backup"
)

// EVERY TEST IN THIS FILE IS A FAILURE PATH, AND THAT IS THE POINT (backup-shape.md §7). None of
// them is reachable against a real cloud: a backup that fails, a slot that will not drop, DDL
// landing inside a nine-minute window. Against Azure we could exercise the happy path and nothing
// else, and the happy path is not where this ticket's risk lives.
//
// THE ONE TEST THAT MATTERS MOST IS THE ORDER. A test asserting only that a slot was created and a
// backup was requested passes just as green under the sequence that loses data silently, so the
// journal below records both halves — the SQL and the control-plane calls — in one list, and the
// happy-path test asserts that list element by element.

const testServerVersion = "18.6"

// stub is both the fake ControlPlane and the fake server behind querySQL, sharing one journal so
// the two sides can be ordered against each other. Two separate fakes could each be asserted and
// still say nothing about which came first, which is exactly the assertion this ticket needs.
type stub struct {
	journal []string

	// schema answers the fingerprint query. It takes the call number so a test can make the
	// schema move between H0 and H1 — the DDL-in-the-window case — without any timing.
	schema func(call int) string

	// schemaErr fails the fingerprint on a chosen call: 1 is before the slot exists and must not
	// drop anything, 2 is after it does and must.
	schemaErr   error
	schemaErrOn int
	position    string
	positionErr error
	createErr   error
	dropErr     error
	backupErr   error
	restoreErr  error
	parts       []backup.Part

	schemaCalls int

	// onServer is the one thing a real server keeps that a journal cannot: WHICH SLOTS ARE
	// ACTUALLY ON IT. It exists so a test can put the server into the state a killed agent leaves
	// behind — a slot created by a run that never returned, and therefore never dropped — and then
	// run a whole later cycle against that state rather than against a canned error.
	onServer map[string]bool
}

func newStub() *stub {
	return &stub{
		schema:   func(int) string { return "public|orders|id|integer" },
		position: "0/1A2B000",
		parts:    []backup.Part{namedPart("database.sql"), namedPart("roles.sql")},
		onServer: map[string]bool{},
	}
}

func (s *stub) Backup(context.Context) (string, error) {
	s.journal = append(s.journal, "azure-backup")
	if s.backupErr != nil {
		return "", s.backupErr
	}
	return "recovery-point-1", nil
}

func (s *stub) RestoreAsFiles(_ context.Context, recoveryPoint string) ([]backup.Part, error) {
	s.journal = append(s.journal, "azure-restore-as-files")
	if s.restoreErr != nil {
		return nil, s.restoreErr
	}
	if recoveryPoint != "recovery-point-1" {
		return nil, fmt.Errorf("restore asked for recovery point %q, which no backup produced", recoveryPoint)
	}
	return s.parts, nil
}

// query stands in for the replication connection. It routes on the statement rather than on a call
// count, so a change to the order under test cannot accidentally keep the fake happy.
func (s *stub) query(_ context.Context, sql string) ([][]string, error) {
	switch {
	case strings.Contains(sql, "pg_attribute"):
		s.journal = append(s.journal, "fingerprint")
		s.schemaCalls++
		if s.schemaErr != nil && s.schemaCalls == s.schemaErrOn {
			return nil, s.schemaErr
		}
		// A ROW AS WIDE AS THE QUERY SELECTS, because fingerprint refuses one that is not: a field
		// added to the SELECT list with no algorithm hashing it would otherwise pass here. Only the
		// first field varies, which is all any test in this file needs — what they turn on is
		// whether the fingerprint moved between two calls, not what it is made of.
		return [][]string{{s.schema(s.schemaCalls), "orders", "id", "integer", "d", "", "", "p"}}, nil
	case strings.Contains(sql, "pg_create_logical_replication_slot"):
		s.journal = append(s.journal, "create-slot")
		if s.createErr != nil {
			return nil, s.createErr
		}
		name := quotedName(sql)
		if s.onServer[name] {
			// A *pgconn.PgError and not a string, because that is what a caller has to reach
			// through to read a SQLSTATE, and the SQLSTATE is the only part of this a caller may
			// match on — AD-036 measured the message wording differs across 14 and 18 for
			// identical conditions.
			return nil, &pgconn.PgError{
				Severity: "ERROR",
				Code:     "42710",
				Message:  fmt.Sprintf("replication slot %q already exists", name),
			}
		}
		s.onServer[name] = true
		return nil, nil
	case strings.Contains(sql, "pg_drop_replication_slot"):
		s.journal = append(s.journal, "drop-slot")
		if s.dropErr != nil {
			return nil, s.dropErr
		}
		delete(s.onServer, quotedName(sql))
		return nil, nil
	case strings.Contains(sql, "pg_replication_slots"):
		s.journal = append(s.journal, "slot-position")
		return [][]string{{s.position}}, s.positionErr
	}
	return nil, fmt.Errorf("the fake was sent a statement it does not know: %s", sql)
}

func (s *stub) run(t *testing.T) (backup.Batch, error) {
	t.Helper()
	return baseCopy(context.Background(), s, s.query, testServerVersion, "vp_stream")
}

// quotedName reads the slot name back out of a statement the way the fake server has to: the name
// is interpolated rather than bound (AD-036) and validateSlotName has already restricted it to
// [a-z0-9_], so the first quoted run IS the name and nothing inside it can be a quote.
func quotedName(sql string) string {
	_, rest, ok := strings.Cut(sql, "'")
	if !ok {
		return ""
	}
	name, _, _ := strings.Cut(rest, "'")
	return name
}

func namedPart(name string) backup.Part {
	return backup.Part{Name: name, Open: func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("PGDMP")), nil
	}}
}

// THE TEST THIS TICKET EXISTS FOR. Not "both happened" — the position of one against the other.
// Under the reversed sequence a row written between the backup and the slot is in neither, and the
// restored database looks perfectly healthy, so nothing downstream can catch it (AD-033).
func TestTheSlotIsCreatedBeforeTheBackupIsRequested(t *testing.T) {
	s := newStub()

	b, err := s.run(t)
	if err != nil {
		t.Fatalf("the happy path failed: %v", err)
	}

	want := []string{"fingerprint", "create-slot", "slot-position", "azure-backup", "fingerprint", "azure-restore-as-files"}
	if !slices.Equal(s.journal, want) {
		t.Fatalf("sequence was\n\t%v\nwant\n\t%v", s.journal, want)
	}

	// Stated a second time as the property rather than as the whole list, because the list will
	// grow and this is the part of it that must never move. A weaker test — both calls happened —
	// would pass under the sequence that silently loses data. The absence checks are not padding:
	// slices.Index answers -1 for a call that never happened, and -1 is less than everything, so
	// without them this passes for a run that created no slot at all.
	slot, azure := slices.Index(s.journal, "create-slot"), slices.Index(s.journal, "azure-backup")
	if slot < 0 || azure < 0 || slot > azure {
		t.Fatalf("the slot was created at step %d and the backup requested at step %d: that ordering "+
			"leaves a silent gap between the copy and the stream", slot, azure)
	}

	if b.Position != backup.Position(s.position) {
		t.Errorf("Position = %q, want the slot's own start %q", b.Position, s.position)
	}
	if b.Schema == "" {
		t.Error("Batch.Schema is empty; nothing records what the copy was consistent with")
	}
	if len(b.Parts) != 2 {
		t.Errorf("Parts = %d, want the two the restore wrote", len(b.Parts))
	}
	if s.journal[len(s.journal)-1] != "azure-restore-as-files" {
		t.Error("nothing was restored into our container")
	}
}

// The C6 scenario, prevented. A slot left behind holds WAL on the customer's PRIMARY, and Azure
// flips a Flexible Server to read-only at 95% disk — so a failed backup that leaks a slot takes
// the customer's production database down some hours later, for a backup that did not happen.
func TestAFailedBackupDropsTheSlotAndClaimsNoArtifact(t *testing.T) {
	s := newStub()
	s.backupErr = errors.New("BackupInstanceNotFound")

	b, err := s.run(t)
	if err == nil {
		t.Fatal("a failed backup produced no error")
	}
	if !strings.Contains(err.Error(), "BackupInstanceNotFound") {
		t.Errorf("the control plane's own words did not survive: %v", err)
	}
	if len(b.Parts) != 0 {
		t.Errorf("a failed backup still claimed %d parts", len(b.Parts))
	}
	if !slices.Contains(s.journal, "drop-slot") {
		t.Fatalf("the slot was not dropped after the backup failed: %v", s.journal)
	}
	if slices.Contains(s.journal, "azure-restore-as-files") {
		t.Errorf("a restore was attempted for a backup that failed: %v", s.journal)
	}
}

// THE LEAK THAT CANNOT BE CLEANED UP LATER. Measured: only the owning role can drop a replication
// slot — the customer's administrator cannot — so a slot we fail to drop is one nobody can remove
// without our credential. It has to arrive as a sentinel a caller can branch on, not as prose in a
// message, because the safety brake (C6) is what has to act on it.
func TestASlotThatCannotBeDroppedIsLoud(t *testing.T) {
	s := newStub()
	s.backupErr = errors.New("BackupInstanceNotFound")
	s.dropErr = errors.New("55006: replication slot is active for PID 42")

	_, err := s.run(t)
	if err == nil {
		t.Fatal("a leaked slot produced no error at all")
	}
	if !errors.Is(err, ErrSlotLeaked) {
		t.Fatalf("the error does not carry ErrSlotLeaked, so nothing can act on the leak: %v", err)
	}
	// Both causes, not the more recent one. The operator needs to know the backup failed AND that
	// there is now a slot on the primary; either alone sends them to the wrong place.
	for _, want := range []string{"BackupInstanceNotFound", "replication slot is active"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error lost %q: %v", want, err)
		}
	}
}

// DDL inside the window. The copy Azure took and the stream the slot carries no longer agree about
// what the tables are, and continuing would produce a base that restores and is wrong.
func TestSchemaMovingInTheWindowDiscardsAndRetries(t *testing.T) {
	s := newStub()
	// H0 on the first attempt, then ALTER TABLE, then steady. Calls 1 and 2 straddle the backup.
	s.schema = func(call int) string {
		if call == 1 {
			return "public|orders|id|integer"
		}
		return "public|orders|id|integer;public|orders|note|text"
	}

	b, err := s.run(t)
	if err != nil {
		t.Fatalf("the retry did not recover: %v", err)
	}
	if len(b.Parts) == 0 {
		t.Fatal("the second attempt produced no parts")
	}

	// Discarded, not continued: the slot from the first attempt is gone and a second backup was
	// requested. A run that carried on would show one backup and no drop.
	if got := strings.Count(strings.Join(s.journal, " "), "drop-slot"); got != 1 {
		t.Errorf("drop-slot appears %d times in %v; the discarded attempt must take its slot with it", got, s.journal)
	}
	if got := strings.Count(strings.Join(s.journal, " "), "azure-backup"); got != 2 {
		t.Errorf("azure-backup appears %d times in %v; the discarded copy must not be the one we keep", got, s.journal)
	}
	if b.Schema == "" {
		t.Error("the batch kept no fingerprint")
	}
}

// A database under continuous migration must end in an error, not in a loop. An agent spinning here
// holds a slot for a moment on every pass and never reports anything.
func TestRetriesAreBounded(t *testing.T) {
	s := newStub()
	s.schema = func(call int) string { return "schema-revision-" + strconv.Itoa(call) }

	_, err := s.run(t)
	if err == nil {
		t.Fatal("a schema that never settles produced no error")
	}
	if !strings.Contains(err.Error(), "schema moved") {
		t.Errorf("the exhausted error does not say why it gave up: %v", err)
	}
	// AND IT MUST NOT CARRY THE SENTINEL. backup.ErrSchemaMoved means "take a new base copy", and
	// this is the error that says taking one has already been tried until the bound ran out. A
	// caller acting on the sentinel here would restart the nine-minute copy from outside, which is
	// maxBaseCopyAttempts turned into an outer loop.
	if errors.Is(err, backup.ErrSchemaMoved) {
		t.Errorf("the exhausted error asks for another base copy, which is the bound undone: %v", err)
	}
	if got := strings.Count(strings.Join(s.journal, " "), "azure-backup"); got != maxBaseCopyAttempts {
		t.Errorf("asked for %d backups, want exactly %d — the bound is the whole point", got, maxBaseCopyAttempts)
	}
	if got := strings.Count(strings.Join(s.journal, " "), "drop-slot"); got != maxBaseCopyAttempts {
		t.Errorf("dropped %d slots for %d attempts; every abandoned attempt must take its slot with it", got, maxBaseCopyAttempts)
	}
}

// The restore is the step that puts bytes in our container. If it fails there is no base copy, so
// the slot has nothing to be the start of and must not be left holding WAL.
func TestAFailedRestoreDropsTheSlotToo(t *testing.T) {
	s := newStub()
	s.restoreErr = errors.New("target container is not writable")

	if _, err := s.run(t); err == nil {
		t.Fatal("a failed restore produced no error")
	}
	if !slices.Contains(s.journal, "drop-slot") {
		t.Errorf("the slot survived a failed restore: %v", s.journal)
	}
}

// Zero parts and no error is the same false claim as a manifest over nothing, arrived at from the
// other side (backup.Batch's own contract). It must be an error here, where the slot can still be
// dropped, rather than a Batch that drains clean.
func TestARestoreThatWroteNothingIsAnError(t *testing.T) {
	s := newStub()
	s.parts = nil

	if _, err := s.run(t); err == nil {
		t.Fatal("a restore that wrote no files was accepted as a base copy")
	}
	if !slices.Contains(s.journal, "drop-slot") {
		t.Errorf("the slot survived a restore that wrote nothing: %v", s.journal)
	}
}

// A LEAK MUST END THE RUN, and this is the interaction the two rules above hide between them: DDL
// in the window says "retry", a leaked slot says "stop", and they can arrive as ONE error. Retrying
// spends another nine-minute backup on top of a slot already accumulating WAL on the primary.
//
// THE ASSERTION THAT PINS THE GUARD IS THE COUNT OF create-slot, and it is worth saying why the two
// obvious ones do not. Since alreadyOnTheServer, a second attempt would hit 42710 on the slot the
// failed drop left behind and come back carrying ErrSlotLeaked anyway — and it would die there,
// before the backup — so both `errors.Is` and the backup count now read the same with the guard
// removed. Measured: create-slot appears once with it and twice without.
func TestALeakEndsTheRunEvenWhenTheSchemaAlsoMoved(t *testing.T) {
	s := newStub()
	s.schema = func(call int) string { return "schema-revision-" + strconv.Itoa(call) }
	s.dropErr = errors.New("55006: replication slot is active for PID 42")

	_, err := s.run(t)
	if err == nil {
		t.Fatal("a leaked slot produced no error")
	}
	if !errors.Is(err, ErrSlotLeaked) {
		t.Fatalf("ErrSlotLeaked was lost to the retry, so the safety brake never fires: %v", err)
	}
	if got := strings.Count(strings.Join(s.journal, " "), "create-slot"); got != 1 {
		t.Errorf("create-slot appears %d times in %v; a leak must stop the run rather than start a "+
			"second attempt against the slot it could not drop", got, s.journal)
	}
	if got := strings.Count(strings.Join(s.journal, " "), "azure-backup"); got != 1 {
		t.Errorf("asked for %d backups after leaking a slot; a leak must stop the run at the first one", got)
	}
}

// The three failure points between the slot and the backup, and the one before it. The invariant
// they hold up is a single sentence — after the slot exists, every error drops it; before it
// exists, no error drops anything — and it is the sentence a future step inserted into the middle
// of the sequence is most likely to break.
func TestEveryFailureAfterTheSlotExistsDropsIt(t *testing.T) {
	unreachable := errors.New("57P01: terminating connection due to administrator command")

	for _, tc := range []struct {
		name     string
		arrange  func(*stub)
		wantDrop bool
	}{
		// Before the slot: nothing was created, so nothing may be dropped — dropping here would
		// remove a slot belonging to a run that is still using it.
		{"the first fingerprint fails", func(s *stub) { s.schemaErr, s.schemaErrOn = unreachable, 1 }, false},

		// After it: all three hold WAL on the primary until they drop it.
		{"the slot reports no position", func(s *stub) { s.position = "" }, true},
		{"the position query fails", func(s *stub) { s.positionErr = unreachable }, true},
		{"the second fingerprint fails", func(s *stub) { s.schemaErr, s.schemaErrOn = unreachable, 2 }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newStub()
			tc.arrange(s)

			if _, err := s.run(t); err == nil {
				t.Fatalf("%s produced no error", tc.name)
			}
			if got := slices.Contains(s.journal, "drop-slot"); got != tc.wantDrop {
				t.Fatalf("%s: dropped = %v, want %v — journal %v", tc.name, got, tc.wantDrop, s.journal)
			}
		})
	}
}

// A slot that could not be created means no backup may be requested — the ordering rule read from
// its failing side. And nothing is dropped, because nothing was made.
//
// The failure here is deliberately NOT 42710: that one means a slot is already on the server and
// has its own two tests above. This is every other way a create fails, and all of them are returned
// as they came.
func TestNoBackupIsRequestedWhenTheSlotCannotBeCreated(t *testing.T) {
	s := newStub()
	s.createErr = &pgconn.PgError{
		Severity: "ERROR",
		Code:     "53400", // configuration_limit_exceeded
		Message:  "all replication slots are in use",
	}

	if _, err := s.run(t); err == nil {
		t.Fatal("a slot that could not be created produced no error")
	}
	if slices.Contains(s.journal, "azure-backup") {
		t.Fatalf("a backup was requested with no slot behind it: %v", s.journal)
	}
	if slices.Contains(s.journal, "drop-slot") {
		t.Errorf("dropped a slot that was never created: %v", s.journal)
	}
}

// THE LEAK THAT REPORTS NOTHING AT THE TIME IT HAPPENS, which is what makes it the worst failure
// here. The agent is killed — OOM, node reboot, SIGKILL — between createSlot returning and the very
// next statement. Base never returns, abandon never runs, and no error reaches anybody: the slot is
// on the customer's PRIMARY and the process that could have dropped it is gone.
//
// Everything then hangs on what the NEXT cycle makes of 42710. Read as a plain duplicate-object
// error it looks like a harmless retry, so nothing ever drops the slot while the WAL it pins grows
// toward the 95% disk at which Azure turns the server read-only. It has to arrive as ErrSlotLeaked,
// because the safety brake (C6) is what drops our own slot and it branches on the sentinel.
func TestASlotLeftBehindByAKilledAgentIsReportedAsALeak(t *testing.T) {
	s := newStub()

	// The kill. The agent got exactly as far as step 2 and then stopped existing — no position
	// read, no abandon, no error — which is precisely why nothing was ever reported.
	if err := createSlot(context.Background(), querySQL(s.query).exec(), "vp_stream", testServerVersion); err != nil {
		t.Fatalf("the slot was not created, so there is nothing left behind to test: %v", err)
	}
	s.journal = nil // the dead run's steps are not this cycle's.

	_, err := s.run(t)
	if err == nil {
		t.Fatal("a cycle that found our own slot already on the server reported success")
	}
	if !errors.Is(err, ErrSlotLeaked) {
		t.Fatalf("42710 on a slot of ours came back without the sentinel, so the safety brake never "+
			"fires and nobody ever drops it: %v", err)
	}
	// The server's own words have to survive, because 42710 is how an operator confirms the slot is
	// there rather than taking our word for it.
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42710" {
		t.Errorf("the server's 42710 did not survive the wrap: %v", err)
	}
	if slices.Contains(s.journal, "azure-backup") {
		t.Errorf("a nine-minute backup was spent on top of a slot already accumulating WAL: %v", s.journal)
	}
	// Reporting the leak is this package's job; dropping our own slot is the brake's. This call
	// created nothing, and a slot on our name may still be one a healthy sibling is streaming from.
	if slices.Contains(s.journal, "drop-slot") {
		t.Errorf("dropped a slot this cycle did not create: %v", s.journal)
	}
}

// THE SAME CATEGORY OF HARM, IN THE OTHER DIRECTION, and the scenario is a misconfiguration rather
// than anything exotic: the agent is pointed at a name the CUSTOMER already uses. Claiming it would
// end with the brake dropping a slot that was never ours, which breaks their replication.
//
// The refusal now comes EARLIER than it used to, and that is the fix rather than a weakening of the
// test. validateSlotName is what createSlot enforces, so a name outside the convention never
// reaches the server at all: no nine-minute backup is spent, and no 42710 has to be told apart
// afterwards. The classification underneath is asserted directly below, because it is still the
// thing that would have to save us if a name ever got past — and it is the half that was broken.
func TestADuplicateOnASlotOutsideOurConventionIsNotAClaimedLeak(t *testing.T) {
	s := newStub()
	const theirs = "cust_analytics" // the customer's own slot: a legal name, and not one of ours.

	// On the server long before this agent existed, so it is put there as the CUSTOMER and not
	// through anything of ours — which now refuses the name outright.
	s.onServer[theirs] = true

	_, err := baseCopy(context.Background(), s, s.query, testServerVersion, theirs)
	if err == nil {
		t.Fatal("the agent was pointed at the customer's own slot name and said nothing")
	}
	if errors.Is(err, ErrSlotLeaked) {
		t.Fatalf("a slot outside our naming convention was claimed as ours, and the brake would "+
			"drop a slot that is not ours to drop: %v", err)
	}
	if len(s.journal) != 0 {
		t.Fatalf("the name was refused and something ran anyway: %v", s.journal)
	}

	// And the judgement that stands behind it: a real duplicate-object error on a name that is not
	// ours comes back exactly as it arrived, with no sentinel added to it.
	duplicate := &pgconn.PgError{Code: duplicateObject, Message: `replication slot "cust_analytics" already exists`}
	got := alreadyOnTheServer(theirs, duplicate)
	if !errors.Is(got, duplicate) {
		t.Errorf("the server's own error did not survive, so nobody can see what really happened: %v", got)
	}
	if errors.Is(got, ErrSlotLeaked) {
		t.Errorf("42710 on a stranger's slot was labelled a leak of ours: %v", got)
	}
}

// The slot name reaches the statement verbatim (AD-036: a replication connection has no bind
// parameters), so it is checked before anything runs — including before the control plane is
// touched, since a nine-minute backup for a name we will refuse afterwards is pure waste.
func TestABadSlotNameStopsEverythingBeforeItStarts(t *testing.T) {
	s := newStub()

	_, err := baseCopy(context.Background(), s, s.query, testServerVersion, "vp_stream'); DROP DATABASE x--")
	if err == nil {
		t.Fatal("a slot name carrying SQL was accepted")
	}
	if len(s.journal) != 0 {
		t.Fatalf("something ran before the name was checked: %v", s.journal)
	}
}
