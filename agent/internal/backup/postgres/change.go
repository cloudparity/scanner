package postgres

// change.go turns pgoutput into contract.Change, and it is the seam between the two halves of the
// change stream that were built against a format nobody owned: since.go produced framed pgoutput
// and restore/replay.go reads parity/change-jsonl, so a chain written by one could not be read by
// the other. Nothing decoded, anywhere.
//
// THE DECODE HAPPENS HERE, IN THE BATCHER, AND NOT AT RESTORE. Three reasons, in order of weight:
//
//  1. The raw bytes are useless to anything else. A pgoutput payload names its table by a RELATION
//     ID whose meaning is carried by an earlier message in the SAME session — so a change file of
//     raw pgoutput is only readable beside the session that produced it, which no longer exists at
//     restore. Storing the raw stream defers the problem to the one moment nobody can solve it.
//  2. A record nothing can identify is knowable HERE. D2 refuses one by rolling back the whole
//     replay, months later, in the middle of an incident; the same fact is available at backup
//     time, where the customer can still act on it (identity.go).
//  3. It is what D2 already reads. Its consumer is fixed and was written first; the producer meets
//     it. Decoding at restore would mean a second decoder in restore/, which cannot import
//     agent/internal at all.
//
// The cost is the one since.go's header named: a decoding bug cannot be fixed by re-reading bytes
// we still have, because we did not keep them. That is bought back by this file being pure —
// messages in, records out, no connection anywhere near it — so its failures are reachable from a
// table test rather than from a server.
//
// EVERY RECORD IN A TRANSACTION IS FILED AT ITS COMMIT, AND THAT IS NOT COSMETIC. pgoutput streams
// transactions in COMMIT order, and the WAL positions of the rows inside one go BACKWARDS against
// a transaction that committed earlier: a transaction that began at 0/100 and committed at 0/300
// arrives after one that began at 0/200 and committed at 0/250. D2 refuses a change file whose
// positions do not advance (replay.go, eachChange) — correctly, since a file out of its own order
// is a producer bug — so filing each row at its own WALStart would produce a file no restore would
// accept. The commit LSN is the one position that is monotonic in the order the file is written,
// and it is known at BEGIN: pgoutput's begin message carries the final LSN of the transaction it
// opens, so nothing has to be buffered to learn it.
//
// AND NOTHING IS HANDED OVER BEFORE ITS COMMIT. A batch that ended mid-transaction would otherwise
// carry rows at a position the batch does not reach — which is exactly what D2's segment.covers
// refuses — and would tell Postgres that WAL is discardable while the other half of the
// transaction is still in it. A change file is therefore a whole number of transactions.

import (
	"errors"
	"fmt"

	"github.com/jackc/pglogrepl"

	"github.com/manukyanv07/parity-scanner/contract"
)

// relation is one table as the stream described it: the column names in wire order, and which of
// them the server said identify a row.
//
// THE KEY COMES FROM THE STREAM AND NOT FROM THE CATALOG, and it has to: once the connection is in
// CopyBoth no query can be run on it (AD-036), and the catalog could have moved since. pgoutput
// flags the replica-identity columns in the relation message itself, which is the server's own
// answer to "what identifies a row in this table", taken at the moment the row changed.
type relation struct {
	schema  string
	table   string
	columns []string
	key     []string

	// full is REPLICA IDENTITY FULL, and it is kept apart from key because under it the server
	// flags EVERY column (measured, change_docker_test.go) — which is the server saying "the
	// whole row is the identity" and NOT a list of columns that identify one. See identifies.
	full bool
}

// transaction is one committed transaction: its records, and the position they are all filed at.
// An empty one is not an error — a DDL decodes as a bare BEGIN/COMMIT pair (rebase.go).
type transaction struct {
	records []contract.Change
	at      pglogrepl.LSN
}

// decoder is the relation cache and the transaction in flight. ONE PER SESSION: relation ids are
// assigned by the server and reused across streams, so a cache that outlived its session would
// name a customer's table by an id that now means another one.
type decoder struct {
	// relations is every relation this session has described. A relation message is sent ONCE
	// before the first tuple that references it and is not repeated, so this cannot be per
	// transaction — after the first, nothing else says which table a record belongs to.
	relations map[uint32]relation

	// The transaction in flight. inside says a BEGIN has been seen, which is what makes a record
	// arriving outside one a stream this decoder has lost its place in rather than a stray.
	inside  bool
	at      pglogrepl.LSN
	records []contract.Change

	// held is the bytes of the values buffered for that transaction, and the batcher adds it to
	// the change file's own length before deciding a batch is full.
	//
	// WITHOUT IT defaultMaxBytes BOUNDS NOTHING. Records reach the file only at COMMIT, so the
	// file's length does not move while a transaction is being read — and a single enormous one,
	// a migration backfill or a bulk delete, would grow this decoder until the agent is killed.
	// It counts the strings rather than the rendered JSON: the punctuation is a fixed cost per
	// column and the values are what a large transaction is actually made of.
	held int
}

// done closes the transaction in flight. It is the commit path and nothing else: A SESSION IS
// STARTED OVER WITH A WHOLE NEW decoder (since.go, open), never by clearing this one, because the
// relation cache must not survive a session — relation ids are the server's and are reused, so a
// cached one would name a customer's table by an id that now means another.
func (d *decoder) done() {
	d.inside, d.at, d.records, d.held = false, 0, nil, 0
}

// take feeds one pgoutput payload in and returns a transaction when one COMMITS, and nil at every
// other message.
func (d *decoder) take(data []byte) (*transaction, error) {
	msg, err := pglogrepl.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("postgres: read a pgoutput message: %w", err)
	}

	switch m := msg.(type) {
	case *pglogrepl.BeginMessage:
		if d.inside {
			// Refused for the same reason the commit branch refuses a transaction it never
			// began, and it is the more dangerous of the two: overwriting the records here
			// would drop every row of the transaction in flight with no error anywhere.
			return nil, fmt.Errorf("postgres: the change stream began a transaction at %s while "+
				"the one at %s was still open, so this decoder has lost its place in the stream",
				positionOf(m.FinalLSN), positionOf(d.at))
		}
		// FinalLSN is the position the transaction being opened will commit at. Every record
		// below is filed at it, so nothing has to be held back to learn where it sits.
		d.inside, d.at = true, m.FinalLSN
		return nil, nil

	case *pglogrepl.CommitMessage:
		if !d.inside {
			return nil, errors.New("postgres: the change stream committed a transaction it never " +
				"began, so this decoder has lost its place in the stream")
		}
		if m.CommitLSN != d.at {
			// The two halves disagree about which transaction this is, and every record in it
			// would be filed at a position that is not where it happened.
			return nil, fmt.Errorf("postgres: a transaction opened at %s committed at %s",
				positionOf(d.at), positionOf(m.CommitLSN))
		}
		committed := transaction{records: d.records, at: d.at}
		d.done()
		return &committed, nil

	case *pglogrepl.RelationMessage:
		d.describe(m)
		return nil, nil

	case *pglogrepl.InsertMessage:
		return nil, d.add(contract.ChangeInsert, m.RelationID, m.Tuple, nil)

	case *pglogrepl.UpdateMessage:
		// The old tuple is present on EXACTLY ONE kind of update: one that moved the key
		// (AD-039). The ordinary update carries only the new row and its identity is inside it,
		// so there is nothing here to go looking for and nothing invented when there is not.
		return nil, d.add(contract.ChangeUpdate, m.RelationID, m.NewTuple, m.OldTuple)

	case *pglogrepl.DeleteMessage:
		// A delete carries the key columns and NULL for everything else, and those NULLs are not
		// values — add keeps only the identity, which is what a replay locates the row by.
		return nil, d.add(contract.ChangeDelete, m.RelationID, m.OldTuple, nil)

	case *pglogrepl.TruncateMessage:
		// REFUSED, NOT DROPPED, and the choice is deliberate. A change file has no way to carry a
		// TRUNCATE, so dropping one leaves a table that comes back FULL from a restore of a chain
		// that verified whole, with nothing anywhere saying so. Refusing costs the customer a
		// stopped stream and an error that names what happened; the alternative costs them the
		// table, silently, and they find out at the worst possible moment.
		return nil, fmt.Errorf("postgres: the change stream carried a TRUNCATE, which a change "+
			"file cannot express: a restore would bring the table back with every row a replay had "+
			"put in it. Take a new base copy. To stop them reaching the stream at all, exclude "+
			"truncate from the publication (ALTER PUBLICATION ... SET (publish = 'insert, update, "+
			"delete')). %d relation(s) affected", m.RelationNum)

	case *pglogrepl.TypeMessage, *pglogrepl.OriginMessage, *pglogrepl.LogicalDecodingMessage:
		// None of the three carries a row: a type description, a replication origin, and a
		// message the customer emitted with pg_logical_emit_message. Skipped by name rather than
		// by a default branch, so that a message shape nobody considered is refused below.
		return nil, nil
	}
	return nil, fmt.Errorf("postgres: the change stream carried a %T, which this does not decode; "+
		"refusing rather than dropping a message that may be a change to a customer's row", msg)
}

// describe records what a relation message said. It OVERWRITES, because the server resends a
// relation whose definition has changed — the same id, a different shape — and the newest
// description is the one the tuples after it are in.
func (d *decoder) describe(m *pglogrepl.RelationMessage) {
	rel := relation{
		schema: m.Namespace,
		table:  m.RelationName,
		// 'f' is REPLICA IDENTITY FULL. Read from the relation message rather than inferred from
		// the flags below, because under FULL the flags say something that looks exactly like a
		// key and is not one.
		full: m.ReplicaIdentity == 'f',
	}
	for _, c := range m.Columns {
		rel.columns = append(rel.columns, c.Name)
		// Flag 1 is LOGICALREP_IS_REPLICA_IDENTITY: the server's own answer to which columns
		// identify a row here. It is set on no column under REPLICA IDENTITY NOTHING, and under
		// the default on a table with no primary key — and MEASURED on 18, on EVERY column under
		// FULL, which identifies nothing (identifies).
		if c.Flags&1 != 0 {
			rel.key = append(rel.key, c.Name)
		}
	}
	if d.relations == nil {
		d.relations = make(map[uint32]relation)
	}
	d.relations[m.RelationID] = rel
}

// add decodes one tuple into a record of the transaction in flight.
//
// before is the old tuple, and it is non-nil on exactly one kind of record: an update that moved
// the key. It becomes OldKey, without which that update would be applied as "update the row that
// has the NEW key" — matching nothing and leaving the old row behind as a silent duplicate.
func (d *decoder) add(op contract.ChangeOp, id uint32, tuple, before *pglogrepl.TupleData) error {
	if !d.inside {
		return fmt.Errorf("postgres: an %s arrived outside any transaction, so nothing could say "+
			"where in the stream it sits", op)
	}
	rel, known := d.relations[id]
	if !known {
		// It cannot happen on a healthy stream — the server describes a relation before the first
		// tuple that references it — and a decoder that carried on would be inventing column names
		// for a customer's data.
		return fmt.Errorf("postgres: an %s names relation %d, which this stream never described; "+
			"refusing to guess which table it belongs to or what its columns are called", op, id)
	}

	row, err := readTuple(rel, tuple)
	if err != nil {
		return fmt.Errorf("postgres: the %s on %s.%s: %w", op, rel.schema, rel.table, err)
	}
	// A DELETE'S TUPLE IS NOT A ROW. It carries the key columns and NULL for the rest, so
	// everything outside the identity is dropped rather than written down as a NULL that means
	// something. contract.Change says the same at Row.
	if op == contract.ChangeDelete {
		row = onlyKey(rel, row)
	}
	if err := identifies(rel, row); err != nil {
		return err
	}

	record := contract.Change{
		Position: string(positionOf(d.at)),
		Op:       op,
		Schema:   rel.schema,
		Table:    rel.table,
		Key:      rel.key,
		Row:      row,
	}
	if before != nil {
		old, err := readTuple(rel, before)
		if err != nil {
			return fmt.Errorf("postgres: the old tuple of the %s on %s.%s: %w", op, rel.schema, rel.table, err)
		}
		record.OldKey = onlyKey(rel, old)
		if err := identifies(rel, record.OldKey); err != nil {
			return err
		}
	}
	d.records = append(d.records, record)
	d.held += weigh(record)
	return nil
}

// weigh is how much of the agent's memory one buffered record is holding.
func weigh(c contract.Change) int {
	n := len(c.Position) + len(c.Op) + len(c.Schema) + len(c.Table)
	for _, column := range c.Key {
		n += len(column)
	}
	for _, values := range []map[string]*string{c.Row, c.OldKey} {
		for name, value := range values {
			n += len(name)
			if value != nil {
				n += len(*value)
			}
		}
	}
	return n
}

// readTuple reads a tuple against the relation it names.
//
// A COLUMN THE SERVER DID NOT RESEND IS ABSENT, NOT NULL. An out-of-line value that did not change
// arrives as 'u' and carries no data at all; recording it as NULL would write a NULL over the
// customer's data at replay. contract.Change.Row is built on that distinction.
func readTuple(rel relation, tuple *pglogrepl.TupleData) (map[string]*string, error) {
	if tuple == nil {
		return nil, errors.New("carries no tuple at all, so there is no row in it")
	}
	if len(tuple.Columns) != len(rel.columns) {
		// Read positionally, so a mismatch would file a customer's values under the wrong column
		// names — which every check downstream would pass.
		return nil, fmt.Errorf("carries %d columns and the relation this stream described has %d",
			len(tuple.Columns), len(rel.columns))
	}

	row := make(map[string]*string, len(rel.columns))
	for i, column := range tuple.Columns {
		switch column.DataType {
		case pglogrepl.TupleDataTypeText:
			value := string(column.Data)
			row[rel.columns[i]] = &value
		case pglogrepl.TupleDataTypeNull:
			row[rel.columns[i]] = nil
		case pglogrepl.TupleDataTypeToast:
			// Absent. See the header of this function.
		default:
			// Binary, or something newer. proto_version '1' sends every value as text (AD-039),
			// so anything else means the stream is not the one this was built against — and a
			// value rendered by guesswork is a value written wrong into a customer's database.
			return nil, fmt.Errorf("sends %q as %q rather than as text", rel.columns[i], column.DataType)
		}
	}
	return row, nil
}

// onlyKey is a tuple cut down to the columns that identify the row. Everything else in a key tuple
// arrives NULL and means nothing.
func onlyKey(rel relation, row map[string]*string) map[string]*string {
	out := make(map[string]*string, len(rel.key))
	for _, column := range rel.key {
		if value, present := row[column]; present {
			out[column] = value
		}
	}
	return out
}

// identifies is THE REFUSAL. A record nothing can locate a row by is not written into a change
// file, because the only thing left to do with one is refuse it — and D2 does exactly that, by
// rolling back a whole replay, months later, in the middle of an incident.
//
// The customer is told about these tables at BACKUP time, before a publication that would also
// break their own writes exists (identity.go, AD-039). This is the backstop for a table that
// changed replica identity after that screen ran.
func identifies(rel relation, row map[string]*string) error {
	if rel.full {
		// REPLICA IDENTITY FULL FLAGS EVERY COLUMN, which is the server saying "match the whole
		// old row" and not a list of columns that identify one. Taking it at face value produces
		// a record a replay cannot use in three separate ways: its ON CONFLICT names every column
		// and there is no unique index over those (42P10); a NULL anywhere in the row makes the
		// WHERE clause match nothing, and under FULL a NULL is an ordinary value; and an
		// out-of-line column the server did not resend leaves the "identity" incomplete. The
		// first row with a NULL in a nullable column would otherwise stop the stream for good.
		//
		// So it is refused HERE, where the table is named and the customer can still act — the
		// same answer identity.go gives before the publication is created, and the two are the
		// same fact stated at the two moments it can be stated.
		return fmt.Errorf("postgres: %s.%s is REPLICA IDENTITY FULL, which sends the whole row as "+
			"its identity — a whole row is not a unique key, so nothing in a change file could say "+
			"WHICH row changed. Point it at one instead (ALTER TABLE %s.%s REPLICA IDENTITY DEFAULT "+
			"if it has a primary key, or REPLICA IDENTITY USING INDEX ...), or take it out of the "+
			"publication; a restore cannot repair this later",
			rel.schema, rel.table, rel.schema, rel.table)
	}
	if len(rel.key) == 0 {
		return fmt.Errorf("postgres: %s.%s has no columns that identify a row — no primary key and "+
			"no replica identity index — so a change file could say only that SOMETHING changed. "+
			"Give it one (ALTER TABLE %s.%s REPLICA IDENTITY USING INDEX ...) or take it out of the "+
			"publication; a restore cannot repair this later",
			rel.schema, rel.table, rel.schema, rel.table)
	}
	for _, column := range rel.key {
		value, present := row[column]
		switch {
		case !present:
			// An identity column the server did not resend, which is the TOASTed case. Nothing
			// downstream could locate the row, and a replay would refuse it there instead.
			return fmt.Errorf("postgres: %s.%s is identified by %v and this record carries no %q, "+
				"so nothing could locate the row it changed", rel.schema, rel.table, rel.key, column)
		case value == nil:
			// `col = NULL` is never true, so a statement built on it would run, match no row, and
			// report a change that did not happen.
			return fmt.Errorf("postgres: %s.%s is identified by %v and %q is NULL in this record; "+
				"NULL never equals anything, so nothing could locate the row it changed",
				rel.schema, rel.table, rel.key, column)
		}
	}
	return nil
}
