package postgres

// The decode, against a fake message stream. Every shape here is one AD-039 measured on live Azure
// 14.23 and 18.4, and the two that are traps have a test of their own: an UPDATE with no old tuple,
// and a DELETE carrying the key columns and NULL for everything else.
//
// THE MESSAGES ARE ENCODED BY HAND rather than taken from a server, because what has to be provable
// here is what the decoder does with a stream nobody can arrange on demand — a relation whose
// message never arrived, a record with no key, a commit that does not match its begin. The real
// wire is what change_docker_test.go is for, and neither test is any use without the other.

import (
	"encoding/binary"
	"math"
	"testing"
	"time"

	"github.com/jackc/pglogrepl"

	"github.com/manukyanv07/parity-scanner/contract"
)

// ---------------------------------------------------------------------------------------------
// The fake stream: pgoutput messages, built byte for byte as the server sends them.
// ---------------------------------------------------------------------------------------------

// col is one column of a relation as the RELATION message describes it.
type col struct {
	name string
	key  bool // the LOGICALREP_IS_REPLICA_IDENTITY flag
}

func begin(commit pglogrepl.LSN) []byte {
	out := []byte{'B'}
	out = binary.BigEndian.AppendUint64(out, uint64(commit))
	out = binary.BigEndian.AppendUint64(out, pgTime(time.Now()))
	return binary.BigEndian.AppendUint32(out, 42)
}

func commit(at pglogrepl.LSN) []byte {
	out := []byte{'C', 0}
	out = binary.BigEndian.AppendUint64(out, uint64(at))
	out = binary.BigEndian.AppendUint64(out, uint64(at+8)) // the end of the transaction
	return binary.BigEndian.AppendUint64(out, pgTime(time.Now()))
}

func relate(id uint32, schema, table string, columns ...col) []byte {
	out := []byte{'R'}
	out = binary.BigEndian.AppendUint32(out, id)
	out = appendString(out, schema)
	out = appendString(out, table)
	out = append(out, 'd') // relreplident: the default, meaning the primary key
	out = binary.BigEndian.AppendUint16(out, count16(len(columns)))
	for _, c := range columns {
		var flags byte
		if c.key {
			flags = 1
		}
		out = append(out, flags)
		out = appendString(out, c.name)
		out = binary.BigEndian.AppendUint32(out, 25) // text
		out = binary.BigEndian.AppendUint32(out, uint32(0xFFFFFFFF))
	}
	return out
}

// relateFull is the same relation under REPLICA IDENTITY FULL — the byte the server sends is 'f',
// and every column is flagged. Both halves matter: the flags are what a naive reading takes for a
// key, and the byte is what says it is not one.
func relateFull(id uint32, schema, table string, columns ...col) []byte {
	message := relate(id, schema, table, columns...)
	// The replica identity byte sits straight after the two null-terminated names, which follow
	// 'R' and the uint32 relation id.
	at := 5
	for names := 0; names < 2; names++ {
		for message[at] != 0 {
			at++
		}
		at++
	}
	message[at] = 'f'
	return message
}

func insert(id uint32, values ...any) []byte {
	out := []byte{'I'}
	out = binary.BigEndian.AppendUint32(out, id)
	out = append(out, 'N')
	return appendTuple(out, values...)
}

// update carries no old tuple: the ordinary case, where the key did not move.
func update(id uint32, values ...any) []byte {
	out := []byte{'U'}
	out = binary.BigEndian.AppendUint32(out, id)
	out = append(out, 'N')
	return appendTuple(out, values...)
}

// updateMoved is the one update that DOES carry a before: the key moved, so the old key comes
// first under 'K'.
func updateMoved(id uint32, old []any, values ...any) []byte {
	out := []byte{'U'}
	out = binary.BigEndian.AppendUint32(out, id)
	out = append(out, 'K')
	out = appendTuple(out, old...)
	out = append(out, 'N')
	return appendTuple(out, values...)
}

// deleteKeyOnly is what a DELETE looks like on the measured wire: the key columns, and NULL for
// every other column of the table.
func deleteKeyOnly(id uint32, values ...any) []byte {
	out := []byte{'D'}
	out = binary.BigEndian.AppendUint32(out, id)
	out = append(out, 'K')
	return appendTuple(out, values...)
}

// null and toasted are the two column kinds that are not a value: NULL, and a TOASTed value the
// server did not resend because it did not change.
type nullColumn struct{}
type toastColumn struct{}

var (
	null    = nullColumn{}
	toasted = toastColumn{}
)

func appendTuple(out []byte, values ...any) []byte {
	out = binary.BigEndian.AppendUint16(out, count16(len(values)))
	for _, v := range values {
		switch value := v.(type) {
		case nullColumn:
			out = append(out, 'n')
		case toastColumn:
			out = append(out, 'u')
		case string:
			out = append(out, 't')
			out = binary.BigEndian.AppendUint32(out, count32(len(value)))
			out = append(out, value...)
		default:
			panic("a tuple column is a string, null or toasted")
		}
	}
	return out
}

func appendString(out []byte, s string) []byte {
	out = append(out, s...)
	return append(out, 0)
}

// pgTime is the timestamp form pgoutput uses: microseconds since 2000-01-01, which the wire
// carries as the eight bytes of an int64. Every t here is time.Now(), so the value is positive and
// the bytes are the same either way; the check is what lets the conversion be written without a
// guard nobody could read.
func pgTime(t time.Time) uint64 {
	micros := t.Unix()*1000000 + int64(t.Nanosecond())/1000 - 946684800*1000000
	if micros < 0 {
		panic("pgTime: a fixture timestamp before 2000-01-01")
	}
	return uint64(micros)
}

// count16 and count32 are the length prefixes pgoutput uses, bounded by the same panic a real
// server's encoder would never need: a fixture with more than 65535 columns is a broken test.
func count16(n int) uint16 {
	if n < 0 || n > math.MaxUint16 {
		panic("count16: out of range")
	}
	return uint16(n)
}

func count32(n int) uint32 {
	if n < 0 || n > math.MaxUint32 {
		panic("count32: out of range")
	}
	return uint32(n)
}

// feed runs a whole message stream through one decoder and returns the transactions that
// committed, so a test says what went in and reads what came out.
func feed(t *testing.T, messages ...[]byte) []transaction {
	t.Helper()
	d := &decoder{}
	var out []transaction
	for i, msg := range messages {
		done, err := d.take(msg)
		if err != nil {
			t.Fatalf("message %d (%c): %v", i, msg[0], err)
		}
		if done != nil {
			out = append(out, *done)
		}
	}
	return out
}

// refused runs a stream that must NOT decode and returns the error.
func refused(t *testing.T, messages ...[]byte) error {
	t.Helper()
	d := &decoder{}
	for _, msg := range messages {
		if _, err := d.take(msg); err != nil {
			return err
		}
	}
	t.Fatal("the stream decoded without complaint, and a record nothing can locate a row by was " +
		"written into a change file for a restore to choke on months from now")
	return nil
}

// ---------------------------------------------------------------------------------------------
// The four shapes.
// ---------------------------------------------------------------------------------------------

var customers = relate(1, "sales", "customers",
	col{name: "id", key: true}, col{name: "name"}, col{name: "email"})

func TestAnInsertDecodesIntoAChangeWithItsIdentity(t *testing.T) {
	t.Parallel()

	got := feed(t,
		begin(0x1400),
		customers,
		insert(1, "999001", "c1 spike", "c1@spike.test"),
		commit(0x1400),
	)
	if len(got) != 1 || len(got[0].records) != 1 {
		t.Fatalf("decoded %+v, want one transaction of one record", got)
	}
	c := got[0].records[0]
	if c.Op != contract.ChangeInsert || c.Schema != "sales" || c.Table != "customers" {
		t.Fatalf("decoded %+v", c)
	}
	if len(c.Key) != 1 || c.Key[0] != "id" {
		t.Fatalf("Key = %v, want [id] — the identity travels with the record, because a replay has "+
			"nothing else to locate the row by", c.Key)
	}
	if c.Row["name"] == nil || *c.Row["name"] != "c1 spike" {
		t.Fatalf("Row = %v", c.Row)
	}
	if c.OldKey != nil {
		t.Fatalf("an insert carries an OldKey: %v", c.OldKey)
	}
	// EVERY RECORD IN A TRANSACTION IS AT ITS COMMIT, which is what makes a change file readable
	// in its own order: pgoutput streams transactions in commit order and the LSNs of the rows
	// inside one go backwards against the transaction before it.
	if want := positionOf(0x1400); c.Position != string(want) {
		t.Fatalf("Position = %s, want %s", c.Position, want)
	}
	if got[0].at != 0x1400 {
		t.Fatalf("the transaction reaches %s", got[0].at)
	}
}

// THE FIRST TRAP (AD-039). An update that does not move the key carries no old tuple at all, and
// the identity of the row to update is inside the NEW one.
func TestAnUpdateThatDoesNotMoveTheKeyCarriesNoOldTupleAndIsStillIdentified(t *testing.T) {
	t.Parallel()

	got := feed(t,
		begin(0x1800),
		customers,
		update(1, "999001", "c1 spike updated", "c1@spike.test"),
		commit(0x1800),
	)
	c := got[0].records[0]
	if c.Op != contract.ChangeUpdate {
		t.Fatalf("Op = %s", c.Op)
	}
	if c.OldKey != nil {
		t.Fatalf("OldKey = %v on an update that did not move the key; a replay reads OldKey only "+
			"for the update that did, and one invented here would locate the wrong row", c.OldKey)
	}
	if len(c.Key) != 1 || c.Row["id"] == nil || *c.Row["id"] != "999001" {
		t.Fatalf("the row this update means cannot be located: Key=%v Row=%v", c.Key, c.Row)
	}
}

// AND THE ONE THAT DOES. Without OldKey a key-moving update is applied as "update the row that has
// the NEW key", which matches nothing and leaves the old row behind as a silent duplicate.
func TestAnUpdateThatMovesTheKeyCarriesTheOldOne(t *testing.T) {
	t.Parallel()

	got := feed(t,
		begin(0x1C00),
		customers,
		updateMoved(1, []any{"999001", null, null}, "999009", "moved", "c1@spike.test"),
		commit(0x1C00),
	)
	c := got[0].records[0]
	if c.OldKey == nil || c.OldKey["id"] == nil || *c.OldKey["id"] != "999001" {
		t.Fatalf("OldKey = %v, want the key before the move", c.OldKey)
	}
	// ONLY THE KEY COLUMNS. The old tuple of a key-moving update is a key tuple: everything else
	// in it arrives NULL and means nothing, exactly as in a delete.
	if _, present := c.OldKey["name"]; present {
		t.Fatalf("OldKey = %v carries a non-key column, and the NULL in it is not a value", c.OldKey)
	}
	if c.Row["id"] == nil || *c.Row["id"] != "999009" {
		t.Fatalf("Row = %v, want the key after the move", c.Row)
	}
}

// THE SECOND TRAP (AD-039). A delete carries the key columns ONLY, every other column NULL, and
// those NULLs are not values — a delete built from the whole tuple matches nothing on a NOT NULL
// table and matches rows nobody deleted on a nullable one.
func TestADeleteCarriesTheKeyColumnsAndTheNullsAreNotValues(t *testing.T) {
	t.Parallel()

	got := feed(t,
		begin(0x2000),
		customers,
		deleteKeyOnly(1, "999001", null, null),
		commit(0x2000),
	)
	c := got[0].records[0]
	if c.Op != contract.ChangeDelete {
		t.Fatalf("Op = %s", c.Op)
	}
	if c.Row["id"] == nil || *c.Row["id"] != "999001" {
		t.Fatalf("Row = %v, want the key", c.Row)
	}
	for _, column := range []string{"name", "email"} {
		if _, present := c.Row[column]; present {
			t.Fatalf("Row = %v carries %q; on the wire that column is NULL and means nothing, and "+
				"a present nil is the contract's spelling of 'this column IS null'", c.Row, column)
		}
	}
}

// A RELATION IS SENT ONCE AND REFERRED TO FOREVER AFTER, including from a later transaction — the
// server does not resend it, so a decoder that forgot it between transactions could not name the
// table of a single record after the first.
func TestARelationSeenOnceIsRememberedForTheTransactionsAfterIt(t *testing.T) {
	t.Parallel()

	got := feed(t,
		begin(0x1000), customers, insert(1, "1", "a", "a@x.test"), commit(0x1000),
		begin(0x1100), insert(1, "2", "b", "b@x.test"), commit(0x1100),
		begin(0x1200), deleteKeyOnly(1, "2", null, null), commit(0x1200),
	)
	if len(got) != 3 {
		t.Fatalf("%d transactions decoded, want 3", len(got))
	}
	for i, tx := range got {
		if len(tx.records) != 1 || tx.records[0].Table != "customers" {
			t.Fatalf("transaction %d decoded %+v", i, tx.records)
		}
	}
}

// A tuple for a relation nobody described is REFUSED, not guessed at. It cannot happen on a healthy
// stream — the server sends the relation first — so a decoder that met one and carried on would be
// inventing column names for a customer's data.
func TestATupleForARelationNobodyDescribedIsRefused(t *testing.T) {
	t.Parallel()

	err := refused(t, begin(0x1000), insert(7, "1"), commit(0x1000))
	t.Logf("refused: %v", err)
}

// THE REFUSAL THE TICKET IS ABOUT. A table with nothing to identify a row by produces a record a
// replay refuses — and D2 refuses it by rolling back the WHOLE chain, months later, in the middle
// of an incident. It is knowable here, so it is refused here.
func TestARecordWithNoUsableKeyIsRefusedRatherThanApproximated(t *testing.T) {
	t.Parallel()

	// No column carries the replica-identity flag: this is REPLICA IDENTITY NOTHING, or a table
	// with no primary key and the default.
	clicks := relate(9, "ops", "clicks", col{name: "at"}, col{name: "url"})
	err := refused(t, begin(0x1000), clicks, insert(9, "2026-01-01", "/x"), commit(0x1000))
	t.Logf("refused: %v", err)

	// And a key column that arrives NULL is not an identity either: `col = NULL` is never true, so
	// a statement built on it would run, match nothing, and report a change that did not happen.
	err = refused(t, begin(0x1000), customers, insert(1, null, "a", "a@x.test"), commit(0x1000))
	t.Logf("refused: %v", err)

	// Nor is a key column the server did not resend because it did not change.
	err = refused(t, begin(0x1000), customers, update(1, toasted, "a", "a@x.test"), commit(0x1000))
	t.Logf("refused: %v", err)
}

// AN UNCHANGED TOASTED VALUE IS AN ABSENT COLUMN AND NOT A NULL. Present and nil means "this column
// is NULL"; absent means "this column did not change". Collapsing the two writes NULLs over a
// customer's data.
func TestAnUnchangedToastedValueIsAbsentAndNotNull(t *testing.T) {
	t.Parallel()

	blobs := relate(3, "archive", "blobs", col{name: "id", key: true}, col{name: "payload"}, col{name: "note"})
	got := feed(t,
		begin(0x1000), blobs,
		update(3, "1", toasted, null),
		commit(0x1000),
	)
	c := got[0].records[0]
	if _, present := c.Row["payload"]; present {
		t.Fatalf("Row = %v: the TOASTed value the server did not resend is present, so a replay "+
			"would write it over the customer's data", c.Row)
	}
	if v, present := c.Row["note"]; !present || v != nil {
		t.Fatalf("Row = %v: a column that IS null must be present and nil, or a replay cannot "+
			"tell it from one that did not change", c.Row)
	}
}

// NOTHING IS HANDED OVER UNTIL THE TRANSACTION COMMITS, which is what makes a change file a whole
// number of transactions: a batch that ended mid-transaction would otherwise carry rows whose
// commit — and therefore whose position — has not happened.
func TestRecordsAreHandedOverOnlyWhenTheTransactionCommits(t *testing.T) {
	t.Parallel()

	d := &decoder{}
	for _, msg := range [][]byte{begin(0x1000), customers, insert(1, "1", "a", "a@x.test")} {
		done, err := d.take(msg)
		if err != nil {
			t.Fatalf("take: %v", err)
		}
		if done != nil {
			t.Fatalf("a transaction was handed over before its commit: %+v", done)
		}
	}
	done, err := d.take(commit(0x1000))
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if done == nil || len(done.records) != 1 {
		t.Fatalf("the commit handed over %+v", done)
	}

	// AND A CYCLE THAT ENDED MID-TRANSACTION CARRIES IT INTO THE NEXT ONE. The session is still
	// open and the server has not resent anything, so the rows already read must not be dropped —
	// they are written whole when the commit finally arrives.
	if _, err := d.take(begin(0x1100)); err != nil {
		t.Fatalf("take: %v", err)
	}
	if _, err := d.take(insert(1, "2", "b", "b@x.test")); err != nil {
		t.Fatalf("take: %v", err)
	}
	if _, err := d.take(insert(1, "3", "c", "c@x.test")); err != nil {
		t.Fatalf("take: %v", err)
	}
	done, err = d.take(commit(0x1100))
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	if len(done.records) != 2 {
		t.Fatalf("the transaction that spanned two cycles carries %d records, want 2 — the rows "+
			"read before the cycle ended are in no file at all if they are dropped", len(done.records))
	}
}

// A SESSION IS STARTED OVER WITH A WHOLE NEW DECODER, and the relation cache is why. Relation ids
// are the SERVER'S and are reused, so one cached from a session that has ended would name a
// customer's table by an id that now means another — every value of every row filed under the
// wrong column names, with nothing anywhere saying so.
//
// This test is the assertion that clearing the transaction is not enough. The production path is
// Stream.open, which assigns a zero decoder rather than calling done().
func TestASessionThatReopensKeepsNothingFromTheOneBeforeIt(t *testing.T) {
	t.Parallel()

	d := &decoder{}
	for _, msg := range [][]byte{begin(0x1000), customers, insert(1, "1", "a", "a@x.test")} {
		if _, err := d.take(msg); err != nil {
			t.Fatalf("take: %v", err)
		}
	}
	// done() closes the transaction and DELIBERATELY leaves the cache, which is why it is not
	// what a reopen uses.
	d.done()
	if len(d.relations) != 1 {
		t.Fatalf("done() cleared the relation cache; a cycle that ended mid-transaction would "+
			"then be unable to name the table of the very next record: %v", d.relations)
	}

	// What a reopen does. The new session has described nothing, so a tuple naming the old id is
	// refused rather than filed under the columns the old session happened to give that id.
	fresh := decoder{}
	if _, err := fresh.take(begin(0x1100)); err != nil {
		t.Fatalf("take: %v", err)
	}
	if _, err := fresh.take(insert(1, "2", "b", "b@x.test")); err == nil {
		t.Fatal("a relation id from the session before was still known to the new one, so a " +
			"customer's values would be filed under whatever columns that id used to mean")
	}
}

// A DDL decodes as a transaction with nothing in it (rebase.go, measured on 14 and 18). It commits
// like any other and carries no record, which is exactly the silence C5 exists to catch.
func TestAnEmptyTransactionCommitsAndCarriesNothing(t *testing.T) {
	t.Parallel()

	got := feed(t, begin(0x1000), commit(0x1000))
	if len(got) != 1 {
		t.Fatalf("%d transactions, want 1", len(got))
	}
	if len(got[0].records) != 0 {
		t.Fatalf("an empty transaction carries %+v", got[0].records)
	}
}

// A TRUNCATE is a real change to a customer's data that a change file has no way to carry, so it is
// REFUSED rather than dropped. Dropped, it is a table that comes back full from a restore of a
// chain that verified whole — with nothing anywhere saying so.
func TestATruncateIsRefusedRatherThanDropped(t *testing.T) {
	t.Parallel()

	truncate := []byte{'T'}
	truncate = binary.BigEndian.AppendUint32(truncate, 1) // one relation
	truncate = append(truncate, 0)                        // no options
	truncate = binary.BigEndian.AppendUint32(truncate, 1) // relation 1
	err := refused(t, begin(0x1000), customers, truncate, commit(0x1000))
	t.Logf("refused: %v", err)
}

// A commit that does not match the begin it closes means the two halves of this decoder disagree
// about which transaction it is in, and every record in it would be filed at the wrong position.
func TestACommitThatDoesNotMatchItsBeginIsRefused(t *testing.T) {
	t.Parallel()

	err := refused(t, begin(0x1000), customers, insert(1, "1", "a", "a@x.test"), commit(0x2000))
	t.Logf("refused: %v", err)
}

// A tuple outside any transaction is refused for the same reason: nothing could say where it sits.
func TestARecordOutsideATransactionIsRefused(t *testing.T) {
	t.Parallel()

	err := refused(t, customers, insert(1, "1", "a", "a@x.test"))
	t.Logf("refused: %v", err)
}

// The number of columns in a tuple must match the relation it names. A mismatch is a stream this
// decoder has lost its place in, and reading it positionally would put a customer's values under
// the wrong column names.
func TestATupleThatDoesNotMatchItsRelationIsRefused(t *testing.T) {
	t.Parallel()

	err := refused(t, begin(0x1000), customers, insert(1, "1", "a"), commit(0x1000))
	t.Logf("refused: %v", err)
}

// REPLICA IDENTITY FULL IS REFUSED ON THE RELATION AND NOT ON THE ROW, and the first row with a
// NULL in it is why. The server flags EVERY column under FULL (measured, change_docker_test.go),
// which reads exactly like a key and is not one: nothing on the wire says which subset is unique,
// a NULL anywhere in the row is an ordinary value no WHERE clause can match, an out-of-line column
// the server did not resend leaves the "identity" incomplete, and a replay's ON CONFLICT would
// name every column and find no index over them.
//
// Taken at face value it would decode happily until the first NULL and then stop the stream for
// good — a cycle that fails leaves the stream broken (since.go), and the same row comes back on
// every restart. Refusing on the flag makes it the first record instead, and identity.go says the
// same thing before the publication that would break the customer's own writes even exists.
func TestAReplicaIdentityFullTableIsRefusedOnTheRelationAndNotOnTheRow(t *testing.T) {
	t.Parallel()

	full := relateFull(5, "ops", "readings", col{name: "id", key: true}, col{name: "note", key: true})

	// Every column present and not one of them NULL: the shape that passes a per-row check and is
	// still unreplayable.
	err := refused(t, begin(0x1000), full, insert(5, "1", "a"), commit(0x1000))
	t.Logf("refused: %v", err)

	// And the same table with a NULL, which is the row that would otherwise kill the stream.
	err = refused(t, begin(0x1000), full, insert(5, "1", null), commit(0x1000))
	t.Logf("refused: %v", err)

	// And an update, whose old tuple under FULL is the whole old row.
	err = refused(t, begin(0x1000), full, updateMoved(5, []any{"1", "a"}, "1", "b"), commit(0x1000))
	t.Logf("refused: %v", err)
}

// A BEGIN INSIDE AN OPEN TRANSACTION IS REFUSED, NOT SILENTLY OBEYED. It cannot happen on a healthy
// proto_version '1' stream, and a decoder that simply started the new one would drop every row of
// the old with no error anywhere — the one place in this file where rows could vanish quietly.
func TestABeginInsideAnOpenTransactionIsRefused(t *testing.T) {
	t.Parallel()

	err := refused(t, begin(0x1000), customers, insert(1, "1", "a", "a@x.test"), begin(0x2000))
	t.Logf("refused: %v", err)
}
