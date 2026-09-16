package contract

// A change file is what a backup cycle stores between two base copies: the rows that changed,
// decoded, in the order the source produced them. It is the other half of the chain — Chain says
// which files there are and what range each covers, and this says what is inside one.
//
// IT IS A WIRE FORMAT AND THAT IS WHY IT IS HERE. The agent writes these files in a customer's
// cloud and a restore reads them in the recovery region months later, so they version like a
// manifest and belong beside one. Nothing in this file is Postgres-specific except the facts it
// was shaped around, and those are measured rather than assumed (AD-039).
//
// ONE JSON OBJECT PER LINE, in the order the source decoded them. A change file is appended to as
// a stream and read back as a stream, and a single JSON array would mean a file that is invalid
// until its last byte is written — which is exactly the file a killed agent leaves behind.

// FormatChangeJSONL is Part.Format for a change file: one Change per line, UTF-8, newline
// separated. Spelled here because a producer and a restorer compare it for exact equality, and a
// second spelling of the same format reads as a broken artifact rather than as a variant.
const FormatChangeJSONL = "parity/change-jsonl"

// ChangeOp is what happened to one row.
type ChangeOp string

const (
	ChangeInsert ChangeOp = "insert"
	ChangeUpdate ChangeOp = "update"
	ChangeDelete ChangeOp = "delete"
)

// Change is one row's worth of what happened, decoded.
//
// THE TWO THINGS IT IS SHAPED BY, both measured on live Azure 14.23 and 18.4 (AD-039):
//
//   - An UPDATE that does not move the key CARRIES NO OLD TUPLE. The identity of the row being
//     updated is in the new tuple, read through Key. A replay that goes looking for a "before"
//     finds nothing, so there is nothing here for it to look in — OldKey exists only for the one
//     case that really does carry one, and is absent on the ordinary update.
//   - A DELETE CARRIES THE KEY COLUMNS ONLY, every other column NULL. Those NULLs are not values.
//     Key is what says which columns mean anything, and a replay reads the delete through it
//     rather than treating Row as a row — which would match nothing, or match everything.
type Change struct {
	// Position is where in the source's own timeline this happened — a WAL LSN for Postgres.
	// OPAQUE: stored, handed back, compared for equality, never parsed. Ordering two of them is
	// the source's job, through chain.Ordered (backup-shape.md §5).
	Position string `json:"position"`

	Op     ChangeOp `json:"op"`
	Schema string   `json:"schema"`
	Table  string   `json:"table"`

	// Key names the columns that IDENTIFY THIS ROW UNIQUELY, in the order the source lists them.
	// A primary key, or the unique index the table's replica identity names.
	//
	// EMPTY MEANS THE SOURCE COULD NOT IDENTIFY THE ROW, and it is not a shrug: a replay has
	// nothing to locate the row by, so it refuses the whole chain rather than guessing. Which
	// tables are in that state is knowable at BACKUP time, before a single change file exists,
	// and saying so there rather than here is the whole point of the screen in
	// agent/internal/backup/postgres.
	Key []string `json:"key"`

	// Row is the row's columns as text, by name.
	//
	// A NULL VALUE AND AN ABSENT COLUMN ARE DIFFERENT FACTS. Present and nil is "this column is
	// NULL"; absent is "this column did not change", which is how an unchanged out-of-line value
	// arrives — Postgres omits it rather than resending it. Collapsing the two writes NULLs over
	// a customer's data.
	//
	// On a DELETE it holds the key columns; anything else in it is ignored, because on the wire
	// those columns arrive NULL and mean nothing.
	Row map[string]*string `json:"row"`

	// OldKey is the row's identity BEFORE the change, and it is present on exactly one kind of
	// record: an UPDATE that moved the key. Absent everywhere else, because nothing else carries
	// an old tuple. Without it a key-moving update would be applied as "update the row that has
	// the NEW key", which matches nothing and leaves the old row behind — a silent duplicate.
	OldKey map[string]*string `json:"oldKey,omitempty"`
}
