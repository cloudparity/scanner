package postgres

// since.go is THE BATCHER, and the whole of it is one rule:
//
//	THE LSN IS CONFIRMED TO POSTGRES ONLY AFTER THE BATCH IS DURABLE IN BLOB.
//
// Confirming earlier tells Postgres it may discard WAL we never stored. The rows are gone, no
// error is produced anywhere, and the loss is found by a customer at restore. It is the easiest
// place in this product to lose customer data in silence, which is why the two death tests in
// since_test.go were written before any of this code was.
//
// SO THE CONFIRM IS NOT IN Since. It cannot be: durability happens after Since returns — the
// pipeline stores every object and the manifest goes LAST (manifest.go) — so a batcher that
// confirmed on its way out would be confirming bytes that are still in memory. Since hands out a
// batch and Confirm is a second, explicit act the caller performs only once the manifest is in
// the store. A stream that has handed out a batch nobody confirmed REFUSES to produce another
// one, because it cannot rewind: carrying on would hand out a file beginning where the LOST batch
// ended, which is a chain contiguous on paper with the changes in between gone.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// ANSWERING THE SERVER AND TELLING IT WAL IS SAFE TO DISCARD ARE DIFFERENT ACTS — AD-039
// ─────────────────────────────────────────────────────────────────────────────────────────────
//
// Measured against live Azure on 14.23 and 18.4: wal_sender_timeout is ONE MINUTE, the server
// asks for a reply at 30s and hangs up at 60s.
//
//	PHASE A (reply to nothing)     ReceiveMessage after 1m0s: unexpected EOF, 17 keepalives
//	PHASE B (reply with LSN 0)     still alive when the budget expired
//
// Read the rule above naively and a batch interval over a minute confirms nothing for over a
// minute, so the stream dies every minute and re-reads its batch forever — a configurable
// interval that breaks in silence above 60s. The resolution is measured rather than reasoned:
// a standby status update carrying the ZERO LSN confirms nothing and holds the connection open
// indefinitely.
//
// The distinction is carried by the link interface below and not by a comment: ReplyAlive TAKES
// NO LSN, because there is none it could carry. Acknowledge is the only function in this package
// that ever puts a position on the wire, and it is reached only from Confirm. Get it wrong in
// either direction and it is bad — never replying kills the stream every minute; replying with
// the real LSN to keep it alive is the exact data loss this file exists to prevent.
//
// AND REPLAY IS AT-LEAST-ONCE BY CONSTRUCTION. AD-039's phase A confirmed nothing and phase B
// received every transaction again at identical xids and identical LSNs. Two consecutive change
// files overlapping is health; a gap is the fault. D2 must be idempotent, and that is a
// consequence of the protocol rather than a preference.
//
// ONE STREAM IS DRIVEN BY ONE GOROUTINE. Since then Confirm, in that order, and Report must not
// call back into the stream. Nothing here is locked, and the fields that are not locked are the
// whole safety interlock: two callers interleaving can clear `unconfirmed` for a batch that was
// never stored, which is precisely the loss above.
//
// THE ONE EXCEPTION IS THE STORE WINDOW'S HEARTBEAT, AND IT HOLDS NO STATE. Between a batch being
// handed out and its Confirm, a goroutine of this stream's does nothing but call ReplyAlive on a
// ticker — it reads no field, writes no field, and cannot reach Acknowledge. It is not serialised
// against the driving goroutine by a lock but by ABSENCE: stopBeating cancels it AND WAITS FOR IT
// TO BE GONE, and every entry point that is about to touch the connection — Since, Confirm,
// Close — goes through stopBeating first. So the connection still has exactly one user at a time,
// which is what pgconn requires, and the interlock above is still read and written by one
// goroutine.
//
// WHAT IT HANDS OVER IS DECODED, AND THAT IS THE SEAM THE TWO HALVES WERE BUILT WITHOUT. The
// batcher writes contract.FormatChangeJSONL — one contract.Change per line, decoded by change.go
// on the way past — because a raw pgoutput file names its tables by relation ids whose meaning
// lives in the session that produced them, so a restore months later has nothing to read it with.
// The whole argument, and what it costs, is at the top of change.go.
//
// THE STORE WINDOW IS ANSWERED TOO, AND THAT IS THE OTHER HALF OF THE SAME MEASUREMENT. The
// keepalive branch in collect only runs while this file is reading; between Since handing a batch
// over and Confirm, the pipeline is chunking and uploading and NOTHING is on this connection at
// all. The server does not distinguish the two silences, so a batch slower to store than
// wal_sender_timeout was hung up on exactly as phase A above was — and it was seen, not merely
// predicted: an e2e run died with `unexpected EOF` draining the slot after three and a half
// minutes of heavy load. No data is lost (nothing was confirmed, and a reconnect redelivers) but
// the cycle re-reads its batch forever, and it surfaces as a network error rather than as "my
// upload outran the server's patience", which sends an operator to the wrong place entirely.
//
// So a batch that has been handed out is kept alive by beat(): a goroutine sending the SAME
// liveness reply the read half sends, on a period taken from the server's own wal_sender_timeout,
// until Confirm or Close. IT CANNOT CONFIRM ANYTHING — ReplyAlive takes no LSN, and the goroutine
// has no access to a position even if it wanted one — and stopBeating waits for it to be gone
// before Confirm puts one on the wire, so no acknowledgement and no liveness reply are ever in
// flight together. maxBytes therefore no longer has to be small enough to store inside half the
// server's timeout; it is back to being the memory bound it says it is.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/jackc/pglogrepl"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/manukyanv07/parity-scanner/agent/internal/backup"
	"github.com/manukyanv07/parity-scanner/contract"
)

// DefaultInterval is how long a cycle collects when nobody has said. It is short enough that a
// crash loses seconds of changes and long enough that a quiet database is not paying for a
// manifest a second. Any value is safe, including one far above wal_sender_timeout — see the
// header.
const DefaultInterval = 30 * time.Second

// defaultMaxBytes bounds a batch, and it is a bound this file needs and run.go does not: the
// pipeline reads a part in chunks and drops each one, but backup.Part.Open must yield a FRESH
// whole stream on every call for a retry to be worth anything, so a batch is held until the
// pipeline is done with it. A batch that reaches the cap closes early and covers less time than
// the interval asked for, which is the safe direction: the alternative is an agent in a small
// container taking itself out on a busy database.
//
// IT IS NOT THE RESIDENT COST. bytes.Buffer doubles, so reaching this cap costs about three times
// it transiently — the old buffer and the new one at once — and the finished batch keeps the full
// capacity for as long as the pipeline is uploading it. Budget accordingly, and see the header for
// the other reason to keep it small: the store window is bounded by wal_sender_timeout.
//
// IT IS ALSO OVERSHOT BY AT MOST ONE TRANSACTION, and it has to be: records reach the file only at
// their commit, so a batch that stopped in the middle of one would either write half of it — which
// is a file claiming a position half its rows are not under — or throw away work the session will
// not send again. The decoder's own buffer counts against the cap (change.go, decoder.held), so a
// transaction that is bigger than the cap on its own is read to its end and closes the batch; a
// transaction bigger than the AGENT is the case nothing here can fix.
const defaultMaxBytes = 64 << 20

// fallbackSenderTimeout is what the store window is paced by when the server's own
// wal_sender_timeout could not be read. It is deliberately far below any value anyone configures —
// the shipped default is a minute and AD-039 measured a minute on both Azure fixtures — because
// the cost of being too short is one forty-byte message every two and a half seconds and the cost
// of being too long is the stall this file exists to close.
const fallbackSenderTimeout = 10 * time.Second

// changePartName is the one part a change batch has. It becomes an object path under the cycle's
// prefix, so it is one bare path element (run.go, checkNames).
const changePartName = "changes"

// errQuiet is "the server sent nothing before the deadline", which is not a failure — it is how
// a batch ends. It exists because a real read cannot tell the caller which of the two happened:
// pgconn cancels an in-flight read by putting a deadline on the socket, so a batch interval that
// expired and a context that was cancelled arrive here identically. The batcher therefore asks
// the context rather than trusting what the read said.
var errQuiet = errors.New("postgres: the change stream was quiet until the deadline")

// walMessage is one thing the server sent, in the only two shapes this file cares about.
type walMessage struct {
	// Keepalive is the server asking whether anyone is still there. It carries no data.
	Keepalive      bool
	ReplyRequested bool

	// ServerWALEnd is how far the server had written when it sent this, and it is the only
	// thing here from which the achieved lag can be computed.
	ServerWALEnd pglogrepl.LSN

	// Data is the raw pgoutput payload. change.go decodes it before it is written down; the
	// argument and what it costs are at the top of that file.
	//
	// THE MESSAGE'S OWN WALStart IS NOT CARRIED, and that is the point rather than an omission:
	// a record is filed at its transaction's COMMIT, so a field holding where the message sat is
	// a field somebody would eventually file a record at.
	Data []byte
}

// link is everything the batcher needs from a replication connection, and it is an interface for
// the reason backup-shape.md §7 gives one level up: killing an agent mid-batch, restarting it,
// and a link that dies with bytes already read are untestable against a real server, and they are
// exactly where the silent loss lives. The real implementation is pgLink, below.
//
// THE TWO REPLIES ARE TWO METHODS, and that is the ticket's whole subject expressed in the type
// system rather than in a rule someone has to remember. A single Send(lsn) would make "keep the
// connection alive" and "this WAL is safe to discard" one call apart by an argument, and the
// wrong argument is unrecoverable and silent.
type link interface {
	// Start opens the replication session and returns WHERE THE SERVER ACTUALLY RESUMES —
	// the slot's own account, never the position the caller asked for. The two differ exactly
	// when C4 has happened, and reporting the request instead is what writes a hole up as a
	// contiguous chain.
	//
	// IT IS ALSO WHERE THE SLOT'S ABSENCE IS FOUND, and it can be nowhere else: a slot cannot be
	// dropped while our session holds it, so it always goes with the connection, and once the
	// connection is in CopyBoth the catalog is unreachable on it. A slot that is gone comes back
	// from here carrying backup.ErrSlotGone — see gone.go.
	Start(ctx context.Context) (pglogrepl.LSN, error)

	// Recv returns the next message, or errQuiet when the context's deadline passed with
	// nothing on the wire.
	Recv(ctx context.Context) (walMessage, error)

	// ReplyAlive answers a keepalive AND CONFIRMS NOTHING. It takes no LSN because there is
	// none it could carry: it sends the zero LSN, which AD-039 measured holds the connection
	// open indefinitely.
	//
	// IT IS ALSO THE ONLY METHOD HERE THE STORE WINDOW'S GOROUTINE CAN REACH, which is why the
	// signature matters more than it looks: the goroutine that keeps a batch's upload alive
	// cannot put a position on the wire because there is no method on this interface through
	// which it could.
	ReplyAlive(ctx context.Context) error

	// SenderTimeout is the server's own wal_sender_timeout, and it paces the liveness replies
	// that go out while the pipeline holds a batch. ZERO MEANS THE SERVER HAS THE TIMEOUT OFF
	// and will never hang up for want of a reply.
	//
	// REACHABLE ONLY BEFORE Start, for the same reason Fingerprint is: it is an ordinary query,
	// and once the connection is in CopyBoth no ordinary query runs on it. Read rather than
	// assumed because a constant here would be right for the one minute AD-039 measured and
	// silently wrong for a server tuned lower — which is the exact shape of the stall it paces.
	SenderTimeout(ctx context.Context) (time.Duration, error)

	// Acknowledge tells the server the WAL up to upTo may be discarded. THE ONLY PLACE A
	// POSITION IS EVER PUT ON THE WIRE, and it is reached only from Confirm.
	Acknowledge(ctx context.Context, upTo pglogrepl.LSN) error

	// Fingerprint is schema.go's fingerprint over this same connection, and it is REACHABLE ONLY
	// BEFORE Start. Measured against PostgreSQL 18 (change_docker_test.go):
	//
	//	a simple query during CopyBoth  ->  FATAL: invalid standby message type "Q" (08P01)
	//	START_REPLICATION after CopyDone -> the copy ends at once and the stream is dead
	//
	// So one connection is one replication session, with no query inside it and no second
	// session after it, and the fingerprint a batch carries is the one taken when that session
	// opened. See Stream.schema for what that does and does not detect.
	Fingerprint(ctx context.Context) (string, error)
}

// Lag is what one cycle achieved, and it is reported EVERY cycle — including the cycle that found
// nothing, which is the one where a stream that has silently stopped receiving hides: from the
// outside it looks exactly like a quiet database, and this is the only number that tells them apart.
type Lag struct {
	// Bytes is the WAL the server had already written that this batch does not carry: the
	// server's own WAL end at the last message seen, minus where the batch reached. Zero when
	// the batch caught up — AND ZERO WHEN NOTHING ARRIVED AT ALL, which is why Messages is
	// beside it rather than left to be inferred.
	Bytes int64

	// Messages is how many things the server sent during the cycle, keepalives included. ZERO
	// OVER A WHOLE INTERVAL IS THE SIGNAL: a healthy wal sender sends a keepalive every half
	// wal_sender_timeout whether or not the database is busy, so silence is the stream being
	// gone rather than the database being quiet, and Bytes alone reads the same as caught up.
	Messages int

	// Took is how long COLLECTING ran, against the configured interval. It does not include
	// storing the batch, which happens after Since returns. A cycle shorter than the interval
	// hit the size cap.
	Took time.Duration
}

// Stream is the change stream on one slot, batched. The zero value is not usable — it needs a
// connection, a slot and a publication — and everything else has a default.
//
// IT IS NOT A backup.Source YET, DELIBERATELY. Since has that interface's exact signature, so a
// future type that also carries the ControlPlane the base copy needs embeds this and satisfies
// the seam without a line changing here. Declaring a Source today would mean a Base method that
// belongs to a different credential (AD-035), for the sake of an assertion nothing consumes.
type Stream struct {
	// Conn is the replication connection Connect opened. AD-036: the agent holds ONE, and the
	// slot was created over this same one (B1).
	Conn *pgconn.PgConn

	// Slot is the replication slot to read from, and it must be one of ours — validateSlotName
	// says why in full.
	Slot string

	// Publication is what pgoutput decodes against. Nothing decodes without one, and AD-039
	// measured that the replication role CANNOT create it: it is a second thing the customer's
	// administrator does, alongside CREATE ROLE … REPLICATION.
	Publication string

	// Interval is how long one cycle collects before handing the batch over. PER CUSTOMER: an
	// RPO of five minutes and an RPO of ten seconds are the same code with a different value
	// here. Zero means DefaultInterval. Any value is safe — a value above wal_sender_timeout
	// included, which is the measurement this file is built around.
	Interval time.Duration

	// Report is called with the achieved lag at the end of EVERY cycle, including one that
	// found nothing and one that failed. Nil means nobody is listening, which is a choice a
	// caller makes rather than a default this file has an opinion about.
	//
	// A CALLBACK RATHER THAN A LOG LINE because this package has no logger and must not grow
	// one — it is the surest way not to log a secret (conn.go) — and because lag is a number
	// something upstream acts on: it is half of what C6's brake watches.
	Report func(Lag)

	// maxBytes closes a batch early rather than let one cycle's changes exhaust the agent's
	// memory. Zero means defaultMaxBytes. Unexported until something outside this package needs
	// to set it: the interval is the knob the ticket asked for, and this is a safety bound.
	maxBytes int64

	// link is the real connection wrapped, built on first use. Tests substitute it; that is the
	// whole reason it exists as a field.
	link link

	// started says the replication session is open. A session cannot seek, so it is opened once
	// and the position it opened at is the only thing that can rewind it — by reconnecting.
	started bool

	// schema is the fingerprint taken when the session opened, and it goes on EVERY batch —
	// which is what Cycle.mark compares against the chain's base on every cycle (rebase.go).
	//
	// ONE FINGERPRINT PER SESSION, AND THAT IS A LIMIT OF THE CONNECTION RATHER THAN A CHOICE.
	// C5 wants it taken beside each batch; measured on 18, that is not reachable over the one
	// connection AD-036 allows — a query inside the copy is FATAL and the copy cannot be
	// restarted (see link.Fingerprint). So what this detects is a chain whose base was captured
	// against a different schema from the one this session opened against, which covers every
	// migration on the far side of a reconnect. What it does NOT yet detect is a migration that
	// lands while one session keeps streaming; closing that needs a second connection or a
	// per-cycle reconnect, and this package is handed a connection rather than a credential
	// (AD-035), so neither is its to make. Named here because an unfilled Schema was worse: it
	// made Cycle.mark refuse every cycle, so the real Stream had never been run through one.
	schema string

	// decode is the pgoutput decoder, and it lives on the STREAM rather than on a cycle: a
	// relation is described once per session and referred to by every batch after it, so a
	// decoder rebuilt per cycle could not name the table of a single record (change.go).
	decode decoder

	// confirmed is the last position THE SERVER WAS TOLD IS DURABLE. It advances in exactly one
	// place: Confirm, after Acknowledge returned without an error.
	confirmed pglogrepl.LSN

	// pending is where the batch that was handed out and not yet confirmed reaches. While
	// unconfirmed is set, this stream will not produce another batch.
	pending     pglogrepl.LSN
	unconfirmed bool

	// senderTimeout is the server's wal_sender_timeout, read when the session opened. It paces
	// the liveness replies of the store window and nothing else. Zero means the server has no
	// timeout, and therefore that there is nothing to answer.
	senderTimeout time.Duration

	// beatStop ends the store window's liveness replies and beatDone is closed when that
	// goroutine has actually returned. Both are nil exactly when no goroutine is running, and
	// they are touched only by the one goroutine that drives this stream.
	beatStop context.CancelFunc
	beatDone chan struct{}

	// broken is set by ANY failed cycle, and it is the other half of unconfirmed. A cycle that
	// died had already consumed messages from the session, and afterwards nothing can say which
	// ones: the reads that fail recoverably — a timeout, a message that would not parse, an
	// error response — leave the connection perfectly usable, so the next cycle would carry on
	// from wherever the dead one stopped and label its file as beginning at the last CONFIRMED
	// position. Every object would hash, the manifest would parse, and the records the dead
	// cycle swallowed would be in no file at all while the chain verified whole.
	broken bool
}

// Since collects one batch of changes and hands it over. It has backup.Source.Since's exact
// signature and returns backup.ErrNoChanges when nothing happened, never an empty batch.
//
// NOTHING IS CONFIRMED HERE. The batch it returns is in memory and durable nowhere; the caller
// stores it, writes the manifest, and only then calls Confirm.
func (s *Stream) Since(ctx context.Context, from backup.Position) (backup.Batch, error) {
	// FIRST, AND ON EVERY PATH INCLUDING THE ONES THAT REFUSE. The previous batch's store window
	// is over the moment a caller asks for another batch, and this function is about to read the
	// connection a liveness reply would otherwise be writing to.
	s.stopBeating()

	want, err := lsnOf(from)
	if err != nil {
		return backup.Batch{}, err
	}
	if err := validateSlotName(s.Slot); err != nil {
		return backup.Batch{}, err
	}
	if err := validatePublicationName(s.Publication); err != nil {
		return backup.Batch{}, err
	}
	if s.broken {
		return backup.Batch{}, fmt.Errorf("postgres: a cycle on slot %q failed with messages "+
			"already read, so this session stands at a point nothing can name; reconnect and "+
			"resume from %s, which is the last position this stream told the server was durable",
			s.Slot, positionOf(s.confirmed))
	}
	if s.unconfirmed {
		// The previous batch was handed out and never confirmed, so the WAL it covers is
		// durable nowhere and the session has already read past it. Continuing would hand out a
		// file beginning where the lost one ended: a chain that verifies with a hole in it. The
		// only way back is a new connection resuming at the confirmed position, and this package
		// is given a connection rather than a credential (AD-035), so whoever owns the reconnect
		// owns this recovery.
		return backup.Batch{}, fmt.Errorf("postgres: the batch reaching %s on slot %q was never "+
			"confirmed durable, and a replication session cannot rewind; reconnect and resume "+
			"from %s, which is the last position this stream told the server was durable",
			positionOf(s.pending), s.Slot, positionOf(s.confirmed))
	}
	if err := s.open(ctx, want); err != nil {
		return backup.Batch{}, err
	}

	began := time.Now()
	got, collectErr := s.collect(ctx)
	s.report(got, began)
	if collectErr != nil {
		// EVERY failure, not only the ones that read something. Which messages a dying read
		// consumed is exactly what cannot be established afterwards, so the safe rule is the
		// one with no case analysis in it. See Stream.broken.
		s.broken = true
		return backup.Batch{}, collectErr
	}
	// Nothing new, and a redelivered record that is already durable counts as nothing new: a
	// reconnect resumes AT the confirmed position, so the record sitting on it comes back and it
	// is in the file that confirmed it.
	if got.records == 0 || got.end <= s.confirmed {
		return backup.Batch{}, backup.ErrNoChanges
	}

	// Captured so that every Open hands back a whole, fresh stream: the pipeline retries an
	// upload by re-Opening, and a second Open over a spent reader would store zero bytes with
	// every check still green (backup.Part.Open).
	body := got.file.Bytes()

	batch := backup.Batch{
		// THE SOURCE'S ACCOUNT OF WHERE THIS FILE BEGINS, which is where the session actually
		// resumed or where the last confirmed batch ended — never the argument above. A From
		// copied from the request would claim this file begins where the last one ended even
		// when the slot went back further or, worse, not far enough (C4).
		From:     positionOf(s.confirmed),
		Position: positionOf(got.end),

		// TAKEN BEFORE THIS SESSION OPENED, over this same connection, with schema.go's one
		// fingerprint and no second definition of it. Empty is what Cycle.mark refuses, and it
		// refused every cycle for as long as this field was left unset — see Stream.schema.
		Schema: s.schema,

		Parts: []backup.Part{{
			Name: changePartName,
			// WHAT D2 READS, AND IT IS CHECKED FOR EXACT EQUALITY THERE. A change file is
			// decoded records, one JSON object per line (change.go); the raw pgoutput this was
			// labelled with before was a format nothing could read back.
			Format: contract.FormatChangeJSONL,
			// AND THE ROLE, WHICH IS NOT OPTIONAL EITHER: replay.go refuses a part nobody said
			// carried changes rather than guessing from the format (AD-037). One part, and the
			// question a role answers is still asked.
			Role: contract.PartChanges,
			Open: func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil },
		}},
	}

	s.pending = got.end
	s.unconfirmed = true

	// THE STORE WINDOW OPENS HERE, and from now until Confirm nothing else will be on this
	// connection. See beat: it answers the server and it cannot confirm anything.
	s.beat()
	return batch, nil
}

// Confirm tells Postgres it may discard the WAL up to p.
//
// CALL IT ONLY ONCE THE BATCH IS DURABLE IN BLOB — after Cycle.Run has returned a manifest, not
// after the objects were stored, because a manifest that was never written means the objects are
// referenced by nothing and the backup did not happen.
//
// It refuses any position but the one this stream handed out. Confirming AHEAD is the loss this
// file exists to prevent; confirming behind or twice is a caller that has lost track of its own
// cycle, and a stream that accepted it would be reporting a durability it cannot vouch for.
func (s *Stream) Confirm(ctx context.Context, p backup.Position) error {
	if !s.unconfirmed {
		return fmt.Errorf("postgres: slot %q has no batch waiting to be confirmed, so nothing "+
			"here can vouch that %s is durable", s.Slot, p)
	}
	if p != positionOf(s.pending) {
		return fmt.Errorf("postgres: refusing to confirm %s on slot %q: the batch this stream "+
			"handed out reaches %s, and confirming anything else tells Postgres to discard WAL "+
			"that is durable nowhere", p, s.Slot, positionOf(s.pending))
	}
	// THE STORE WINDOW ENDS HERE, AFTER THE CHECKS RATHER THAN BEFORE THEM. stopBeating waits for
	// the goroutine to have returned, so from this line on the driving goroutine is again the only
	// thing on the connection — which is what makes it impossible for a liveness reply to be in
	// flight while a POSITION is going out, in either order.
	//
	// Below the guards because a REFUSED confirm has not ended anything: the batch is still handed
	// out and still durable nowhere, and a window closed by a caller passing the wrong position
	// would be a silent connection with an unconfirmed batch on it — the same stall, entered
	// through the error path.
	s.stopBeating()

	if err := s.link.Acknowledge(ctx, s.pending); err != nil {
		// confirmed does not move, so a reconnect resumes from the last position the server
		// really did acknowledge and the batch is redelivered. Losing an acknowledgement costs
		// a redelivery; sending one early costs the data.
		return fmt.Errorf("postgres: confirm %s on slot %q: %w", p, s.Slot, err)
	}
	s.confirmed = s.pending
	s.unconfirmed = false
	return nil
}

// Close stops the liveness replies of an open store window.
//
// IT DOES NOT CLOSE THE CONNECTION. This package is handed one rather than a credential (AD-035),
// so the connection is the caller's to close — and this is what the caller calls FIRST when it
// does. pgconn is not safe for concurrent use, so a liveness reply in flight and a Close on the
// same connection is a race, and the window in which one is in flight is exactly the one this
// file has just made long: a cycle that failed while storing leaves a batch handed out, never
// confirmed, and a goroutine still answering the server.
//
// Idempotent, and safe on a stream that never ran.
func (s *Stream) Close() { s.stopBeating() }

// beat answers the server while the pipeline has the batch.
//
// WHAT IT SENDS IS WHAT collect SENDS: a standby status update carrying the zero LSN, through the
// same ReplyAlive that cannot express a position. There is no branch here on what is pending and
// no way to reach Acknowledge, which is the guarantee stated in the type system rather than in a
// rule someone has to remember (see link).
//
// A GOROUTINE RATHER THAN A LOCK ON THE CONNECTION, which was the shape this file's header used to
// suggest. A shared lock would mean the pipeline's thread and this one both writing to a pgconn
// and each having to remember to take it; absence is stronger — while this goroutine runs it is
// the ONLY user of the connection, and stopBeating is what hands the connection back.
func (s *Stream) beat() {
	if s.senderTimeout <= 0 {
		// The server has the timeout switched off, so it will never hang up for want of a reply
		// and there is nothing here to do. AD-039's fixtures were at one minute; a customer who
		// has set zero has said the silence is fine.
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	s.beatStop, s.beatDone = cancel, done

	// CAPTURED, NOT READ FROM s. This goroutine shares no field with the stream that started it —
	// the only thing it touches is the link, and it has that to itself until stopBeating returns.
	//
	// context.Background rather than the cycle's: the store window outlives the call that opened
	// it by construction, and a reply that stopped because the caller's context was cancelled
	// would leave the connection silent for exactly the stretch it must not be. What ends this
	// goroutine is stopBeating, which every entry point runs.
	answer, every := s.link, beatEvery(s.senderTimeout)
	go func() {
		defer close(done)
		tick := time.NewTicker(every)
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tick.C:
				if err := answer.ReplyAlive(ctx); err != nil {
					// There is nothing to report it to — this package has no logger and must not
					// grow one (conn.go) — and nothing to do about it: the connection is already
					// broken, and the Confirm this window ends in will say so, naming the position
					// it could not acknowledge. Returning is what keeps a broken connection from
					// being written to on every tick until the process ends.
					return
				}
			}
		}
	}()
}

// stopBeating ends the liveness replies AND WAITS FOR THE GOROUTINE TO HAVE RETURNED.
//
// THE WAIT IS THE INTERLOCK. Cancelling and carrying on would leave a reply possibly in flight
// while the caller reads the connection, closes it, or — the one that costs data — puts a POSITION
// on it. After this returns there is again exactly one goroutine touching the connection, which is
// what pgconn requires and what the rest of this file is written against.
//
// ⚠ AND THE WAIT IS UNBOUNDED, ON PURPOSE. pglogrepl's standby status update ignores its context
// and writes straight to the socket, so cancelling cannot interrupt a reply already going out —
// only its return can. A deadline here would mean giving up on the wait and telling the caller the
// goroutine is gone when it might not be, which is the pgconn race this whole interlock exists to
// prevent, so the stronger property is kept. What it costs is that a caller's own budget does not
// cover this: the agent's release path allows itself a fixed slice of a container's termination
// grace period (cmd/scanner/pgchain.go) and Stream.Close sits OUTSIDE it. It takes a forty-byte
// write blocking on a full socket buffer to matter, which needs a server that has stopped reading
// our replies entirely, and the same unbounded write is already what collect and Acknowledge do.
func (s *Stream) stopBeating() {
	if s.beatStop == nil {
		return
	}
	s.beatStop()
	<-s.beatDone
	s.beatStop, s.beatDone = nil, nil
}

// beatEvery is how often a liveness reply goes out while a batch is being stored: A QUARTER of the
// server's own timeout, derived rather than chosen. The server asks for a reply at half the timeout
// and hangs up at the whole of it (AD-039), so a quarter gets two attempts inside every window the
// server is counting — which is the margin that matters, because these replies come off a ticker on
// a machine that is at that moment busy uploading.
//
// The floor is for a server configured absurdly low rather than for any real one: a ticker cannot
// be built from a non-positive period, and a stream that panicked on a strange setting would be
// worse than one that beats a little too often.
func beatEvery(timeout time.Duration) time.Duration {
	if quarter := timeout / 4; quarter > time.Millisecond {
		return quarter
	}
	return time.Millisecond
}

// collected is one cycle's work in progress. It is returned even on the failing path, because the
// lag it carries is worth reporting for a cycle that died halfway.
type collected struct {
	file    *bytes.Buffer
	records int

	// messages counts everything the server sent, keepalives included. See Lag.Messages.
	messages int

	// end is where the batch reaches: the end of the last record, not its start.
	end pglogrepl.LSN

	// serverEnd is the furthest the server said it had written, from any message.
	serverEnd pglogrepl.LSN
}

// collect reads until the interval is up, the size cap is reached, or something fails.
//
// THE KEEPALIVE BRANCH IS THE ONE THAT DECIDES THIS TICKET. It answers on the server's schedule
// and confirms nothing, which is what lets the interval above be any length at all.
//
// A BATCH IS A WHOLE NUMBER OF TRANSACTIONS. Records reach the file only when their transaction
// commits, so a cycle that ends mid-transaction writes nothing of it and reaches no further than
// the commit before it. The half it read is not lost and not written twice: it stays in the
// decoder, and the NEXT cycle — reading the same session, from where this one stopped — finishes
// it and writes it whole, at its own commit. Only a session that is (re)opened drops it, and it
// has to: the server resends an incomplete transaction from its BEGIN (change.go, decoder.forget).
//
// A file claiming a position that half its rows are not under is what this prevents, and it is
// exactly what D2 refuses per record (restore/point.go, segment.covers).
func (s *Stream) collect(ctx context.Context) (collected, error) {
	out := collected{file: &bytes.Buffer{}, end: s.confirmed}

	deadline := time.Now().Add(s.interval())
	limit := s.sizeCap()

	// THE CAP COUNTS THE FILE AND THE TRANSACTION IN FLIGHT. Records reach the file only at their
	// commit, so the file's length alone stops moving for as long as one transaction is being
	// read — and a cap that does not see the decoder's buffer is a cap on nothing at all.
	for int64(out.file.Len()+s.decode.held) < limit {
		read, cancel := context.WithDeadline(ctx, deadline)
		msg, err := s.link.Recv(read)
		cancel()

		if errors.Is(err, errQuiet) {
			// A cancelled context and an expired batch interval look identical at the read —
			// pgconn cancels by putting a deadline on the socket — so the context is asked
			// rather than the error. A batch cut short by a kill must NOT come back as a batch:
			// a manifest over it would claim an interval it does not cover.
			if ctx.Err() != nil {
				return out, fmt.Errorf("postgres: the change stream on slot %q was cut short "+
					"before its batch was complete: %w", s.Slot, ctx.Err())
			}
			break
		}
		if err != nil {
			return out, fmt.Errorf("postgres: read the change stream on slot %q: %w", s.Slot, err)
		}
		out.messages++
		if msg.ServerWALEnd > out.serverEnd {
			out.serverEnd = msg.ServerWALEnd
		}

		if msg.Keepalive {
			if msg.ReplyRequested {
				// A LIVENESS REPLY AND NOT AN ACKNOWLEDGEMENT. It carries no position because
				// the method cannot carry one; see link. Answering nothing here is a stream
				// disconnected at wal_sender_timeout that re-reads its batch forever (AD-039),
				// and answering with out.end would be telling Postgres to discard WAL that is
				// in this buffer and nowhere else.
				if err := s.link.ReplyAlive(ctx); err != nil {
					return out, fmt.Errorf("postgres: answer the keepalive on slot %q: %w", s.Slot, err)
				}
			}
			continue
		}

		done, err := s.decode.take(msg.Data)
		if err != nil {
			return out, fmt.Errorf("postgres: decode the change stream on slot %q: %w", s.Slot, err)
		}
		if done == nil {
			// Mid-transaction. Nothing is written and nothing is claimed until it commits.
			continue
		}
		if err := write(out.file, done.records); err != nil {
			return out, fmt.Errorf("postgres: write the change file for slot %q: %w", s.Slot, err)
		}
		out.records += len(done.records)

		// THE COMMIT'S OWN LSN, WHICH IS EXACTLY THE POSITION EVERY RECORD OF THIS TRANSACTION
		// CARRIES (change.go). The range this batch declares is therefore precisely the range the
		// file holds — which is what D2 checks, per record, before applying one (restore/point.go,
		// segment.covers).
		//
		// NOT WALStart + len(WALData), which is pglogrepl's own example and right only for
		// PHYSICAL replication where WALData is literally WAL bytes: under pgoutput the payload is
		// a decoded message whose length has no relation to the record it came from, so the sum
		// overshoots — and this value is what Confirm puts on the wire.
		//
		// Not the commit message's TransactionEndLSN either, which is one past the commit record
		// and would be safe: this batch is durable before anything is confirmed. It is simply the
		// more conservative of two safe values — the server resumes AT this commit and sends the
		// transaction again, so a cycle costs one redelivered transaction and never a missing one.
		// Overlap is health; a gap is the fault.
		out.end = done.at
	}
	return out, nil
}

// write appends one committed transaction's records to the change file, one JSON object per line.
//
// A LINE AT A TIME AND NOT AN ARRAY, because a change file is read back as a stream and an array
// is invalid until its last byte is written — which is exactly the file a killed agent leaves
// behind (contract/change.go).
func write(into *bytes.Buffer, records []contract.Change) error {
	for _, record := range records {
		line, err := json.Marshal(record)
		if err != nil {
			// Unreachable with the types contract.Change is made of, and returned rather than
			// ignored: a record silently dropped here is a row missing from a chain that verifies.
			return fmt.Errorf("render the %s at %s on %s.%s: %w",
				record.Op, record.Position, record.Schema, record.Table, err)
		}
		into.Write(line)
		into.WriteByte('\n')
	}
	return nil
}

// open makes sure the session is running and standing where the caller thinks it is.
func (s *Stream) open(ctx context.Context, want pglogrepl.LSN) error {
	if s.started {
		if want != s.confirmed {
			// The session cannot seek. A caller resuming from somewhere else is a caller whose
			// idea of the chain and this stream's have diverged, and the batch that came back
			// would carry a From nothing could check.
			return fmt.Errorf("postgres: the change stream on slot %q is standing at %s and was "+
				"asked to resume from %s; a replication session cannot seek, so reconnect if the "+
				"chain really begins somewhere else", s.Slot, positionOf(s.confirmed), positionOf(want))
		}
		return nil
	}
	if s.link == nil {
		if s.Conn == nil {
			return errors.New("postgres: this change stream has no connection to read through")
		}
		s.link = &pgLink{conn: s.Conn, slot: s.Slot, publication: s.Publication}
	}

	// BEFORE Start, WHICH IS THE ONLY MOMENT IT IS REACHABLE. Once START_REPLICATION has run, no
	// query can be sent on this connection and the copy cannot be ended and reopened — both
	// measured on 18, both written out at link.Fingerprint. It is also the right direction of
	// error: a fingerprint taken before a session describes the schema at or before the changes
	// that session carries, so a migration is reported one cycle early rather than one cycle late.
	schema, err := s.link.Fingerprint(ctx)
	if err != nil {
		return err
	}
	// AND AN EMPTY ONE IS REFUSED HERE, WHICH IS THE ONLY PLACE THAT CAN. schema.go's fingerprint
	// never returns one, so this guards the seam rather than that function — and it is worth
	// guarding because the failure is silent at every layer below: Cycle.mark refuses a cycle
	// where ONE end is empty, and passes one where BOTH are (rebase.go), so an empty fingerprint
	// reaching a batch of a chain whose base is also empty turns the DDL check off for the life
	// of the install with nothing anywhere saying so.
	if schema == "" {
		return fmt.Errorf("postgres: the schema fingerprint for slot %q came back empty, and an "+
			"empty one compares equal to every other, so nothing would ever say the schema had "+
			"moved under this chain", s.Slot)
	}

	// ALSO BEFORE Start, AND FOR THE SAME REASON. It is an ordinary query, and the connection is
	// about to stop accepting those.
	//
	// A READING THAT FAILS IS NOT FATAL, AND THE ASYMMETRY IS THE WHOLE ARGUMENT. A period that is
	// too LONG restores the stall this file just closed; a period that is too SHORT costs a
	// forty-byte message more often than necessary. So an unreadable setting falls back to a floor
	// short enough for any server anyone runs rather than refusing to stream at all — refusing
	// would trade a stall that costs a cycle for no backups whatsoever, which is the wrong
	// direction for a product whose entire subject is not losing data.
	senderTimeout, err := s.link.SenderTimeout(ctx)
	if err != nil {
		senderTimeout = fallbackSenderTimeout
	}

	at, err := s.link.Start(ctx)
	if err != nil {
		return err
	}
	s.schema = schema
	s.senderTimeout = senderTimeout
	// A WHOLE NEW DECODER, not a cleared one. A session that has just opened resends any
	// transaction it was in the middle of from its BEGIN, so the half-read one is dropped — and
	// the relation ids it cached are the OLD session's, which the server reassigns.
	s.decode = decoder{}
	// The slot's own resume point becomes this stream's baseline: everything before it has
	// already been acknowledged to the server, by us or by whatever ran before us. It is NOT set
	// to want — if the slot only goes back to a later point, that difference is the hole C4
	// exists to catch, and it reaches the chain through Batch.From.
	s.started = true
	s.confirmed = at
	return nil
}

// report hands the achieved lag to whoever is listening. Every cycle, on every path.
func (s *Stream) report(got collected, began time.Time) {
	if s.Report == nil {
		return
	}
	lag := Lag{Messages: got.messages, Took: time.Since(began)}
	if got.serverEnd > got.end {
		lag.Bytes = int64(got.serverEnd - got.end)
	}
	s.Report(lag)
}

func (s *Stream) interval() time.Duration {
	if s.Interval <= 0 {
		return DefaultInterval
	}
	return s.Interval
}

func (s *Stream) sizeCap() int64 {
	if s.maxBytes <= 0 {
		return defaultMaxBytes
	}
	return s.maxBytes
}

// validatePublicationName refuses anything that is not a bare identifier, for the same reason
// validateSlotName does: the name goes into START_REPLICATION verbatim because a replication
// connection has no bind parameters (AD-036), so this alphabet is the entirety of what stands
// between a configured string and arbitrary text in a replication command. It carries no prefix
// rule — the publication is the CUSTOMER'S, created by their administrator (AD-039), so a name of
// ours would be exactly wrong.
func validatePublicationName(name string) error {
	if name == "" {
		// Its own message rather than bareIdentifier's, because "you did not configure a
		// publication" and "your publication name has a quote in it" send a reader to two very
		// different places, and the first is the one AD-039 says people will hit.
		return errors.New("postgres: no publication is named, and pgoutput decodes nothing " +
			"without one; the customer's administrator creates it — the replication role cannot")
	}
	return bareIdentifier("publication", name)
}

// lsnOf reads a Position as an LSN. A position nothing can read is refused before a session is
// opened: starting one from a point we could not parse would stream from wherever the slot
// happened to be and report a range nobody could check.
func lsnOf(p backup.Position) (pglogrepl.LSN, error) {
	at, err := pglogrepl.ParseLSN(string(p))
	if err != nil {
		return 0, fmt.Errorf("postgres: %q is not a WAL position, so there is nothing to resume "+
			"the change stream from: %w", p, err)
	}
	return at, nil
}

// positionOf is the one spelling of an LSN this package hands out, so that two Positions compare
// equal exactly when they are the same point. pglogrepl prints X/Y in upper-case hex without
// leading zeros, which is Postgres's own spelling and what order.go reads back.
func positionOf(at pglogrepl.LSN) backup.Position {
	return backup.Position(at.String())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// The real link.
// ─────────────────────────────────────────────────────────────────────────────────────────────

// pgLink is the batcher's link over a live replication connection. It holds no state of its own:
// everything that has to be remembered between cycles — what is confirmed, what is pending — is
// on Stream, where the rule about when to confirm can be read in one place.
type pgLink struct {
	conn        *pgconn.PgConn
	slot        string
	publication string
}

// protoVersion is the pgoutput protocol version. ONE, because AD-039 measured it is the single
// form that works across the whole supported 14–18 range; version 2 was not measured at all and
// adopting it unmeasured would be a second thing branching on a server version, which AD-034
// settled there is exactly one of.
const protoVersion = "proto_version '1'"

// Fingerprint is schema.go's, over this same connection and this same REPLICATION role — which
// AD-036 measured can read the catalog and no customer table at all. There is no second definition
// of "the schema moved" here and there must not be: the base copy takes this one, and C5 compares
// against it (rebase.go).
func (l *pgLink) Fingerprint(ctx context.Context) (string, error) {
	return fingerprint(ctx, simpleQueryRows(l.conn))
}

// SenderTimeout asks the server how long it will wait, so the store window's replies are paced by
// the thing that is actually counting rather than by a constant of ours.
//
// pg_settings RATHER THAN `SHOW`, and the difference is the whole reason it is readable at all:
// SHOW spells the value the way it was configured — "1min" on both of AD-039's fixtures — while
// pg_settings.setting reports it in the parameter's base unit, which for this one is milliseconds.
// An integer needs no unit table here, and there is no dialect of Postgres duration to get wrong.
func (l *pgLink) SenderTimeout(ctx context.Context) (time.Duration, error) {
	const query = "SELECT setting FROM pg_settings WHERE name = 'wal_sender_timeout'"

	rows, err := simpleQueryRows(l.conn)(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("postgres: read wal_sender_timeout for slot %q: %w", l.slot, err)
	}
	if len(rows) != 1 || len(rows[0]) != 1 {
		return 0, fmt.Errorf("postgres: wal_sender_timeout came back as %v for slot %q, and a "+
			"store window paced by a guess is the stall this reading exists to close", rows, l.slot)
	}
	ms, err := strconv.Atoi(rows[0][0])
	if err != nil {
		return 0, fmt.Errorf("postgres: wal_sender_timeout came back as %q for slot %q, which is "+
			"not a number of milliseconds: %w", rows[0][0], l.slot, err)
	}
	return time.Duration(ms) * time.Millisecond, nil
}

func (l *pgLink) Start(ctx context.Context) (pglogrepl.LSN, error) {
	q := simpleQueryRows(l.conn)

	// IS THE SLOT STILL OURS AND STILL THERE — asked first, and asked on every open, which is every
	// reconnect. A slot cannot be dropped while our session holds it, so losing one always costs us
	// the connection and this is the moment we get to look; gone.go has the whole of why.
	//
	// It is asked BEFORE slotPosition rather than folded into it, because the two questions have
	// different answers to "no row": a slot that is absent means the chain is dead, while a slot
	// that is present with a null confirmed_flush_lsn is one nothing has streamed from yet.
	if err := checkSlot(ctx, q, l.slot); err != nil {
		return 0, err
	}

	// READ BEFORE THE SESSION OPENS, and it has to be: once the connection is in CopyBoth no
	// ordinary statement can run on it. This is also the honest answer to "where does this
	// stream actually begin" — the slot's own confirmed_flush_lsn, which is what the server
	// resumes from whatever we ask for.
	where, err := slotPosition(ctx, q, l.slot)
	if err != nil {
		return 0, err
	}
	at, err := lsnOf(where)
	if err != nil {
		return 0, fmt.Errorf("postgres: slot %q reports a resume point that cannot be read: %w", l.slot, err)
	}

	err = pglogrepl.StartReplication(ctx, l.conn, l.slot, at, pglogrepl.StartReplicationOptions{
		PluginArgs: []string{protoVersion, "publication_names '" + l.publication + "'"},
	})
	if err != nil {
		return 0, fmt.Errorf("postgres: start the change stream on slot %q against publication "+
			"%q: %w", l.slot, l.publication, err)
	}
	return at, nil
}

func (l *pgLink) Recv(ctx context.Context) (walMessage, error) {
	for {
		raw, err := l.conn.ReceiveMessage(ctx)
		if err != nil {
			// A read that timed out is recoverable during CopyBoth and the connection stays
			// usable; it is how a batch ends and how a cancellation arrives alike.
			if pgconn.Timeout(err) {
				return walMessage{}, errQuiet
			}
			return walMessage{}, err
		}

		switch message := raw.(type) {
		case *pgproto3.CopyData:
			if len(message.Data) == 0 {
				continue
			}
			switch message.Data[0] {
			case pglogrepl.PrimaryKeepaliveMessageByteID:
				beat, err := pglogrepl.ParsePrimaryKeepaliveMessage(message.Data[1:])
				if err != nil {
					return walMessage{}, fmt.Errorf("postgres: read a keepalive from slot %q: %w", l.slot, err)
				}
				return walMessage{
					Keepalive:      true,
					ReplyRequested: beat.ReplyRequested,
					ServerWALEnd:   beat.ServerWALEnd,
				}, nil

			case pglogrepl.XLogDataByteID:
				record, err := pglogrepl.ParseXLogData(message.Data[1:])
				if err != nil {
					return walMessage{}, fmt.Errorf("postgres: read a WAL record from slot %q: %w", l.slot, err)
				}
				// WALData aliases the connection's receive buffer, which the next read
				// reuses. The decoder copies every value out of it before the caller reads
				// again (change.go, readTuple), and nothing here holds on to it.
				//
				// record.WALStart is deliberately dropped: a record is filed at its
				// transaction's commit, which is inside the payload, and the only other
				// position this file uses is the server's own end for the lag.
				return walMessage{
					ServerWALEnd: record.ServerWALEnd,
					Data:         record.WALData,
				}, nil
			}
			// Anything else in the CopyBoth stream is not ours to interpret; wait for the
			// next message rather than guess at it.

		case *pgproto3.ErrorResponse:
			// The server ending the stream with a reason. Returned rather than skipped: it is
			// the shape a dropped slot arrives in, and C4 has to be able to see it.
			// Wrapped rather than flattened: C4 has to branch on a SQLSTATE, and AD-036
			// measured that the message text differs across 14 and 18 for identical conditions.
			return walMessage{}, fmt.Errorf("postgres: the server ended the change stream on "+
				"slot %q: %w", l.slot, pgconn.ErrorResponseToPgError(message))
		}
	}
}

// ReplyAlive sends the standby status update that confirms NOTHING.
//
// The zero LSN is the whole of it, and it is measured: AD-039 phase B replied with LSN 0 to every
// keepalive and the connection was still alive when the budget expired, while phase A replied to
// nothing and was hung up on at wal_sender_timeout with `unexpected EOF`. pglogrepl fills the
// flush and apply positions from the write position, so all three go out as zero.
func (l *pgLink) ReplyAlive(ctx context.Context) error {
	return pglogrepl.SendStandbyStatusUpdate(ctx, l.conn, pglogrepl.StandbyStatusUpdate{})
}

// Acknowledge is the other act, and the only one that puts a position on the wire. After this the
// server may discard the WAL up to upTo, and nothing can undo it.
func (l *pgLink) Acknowledge(ctx context.Context, upTo pglogrepl.LSN) error {
	return pglogrepl.SendStandbyStatusUpdate(ctx, l.conn,
		pglogrepl.StandbyStatusUpdate{WALWritePosition: upTo})
}
