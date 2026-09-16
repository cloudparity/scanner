package postgres

// THE DEATH TESTS ARE FIRST IN THIS FILE BECAUSE THEY WERE FIRST IN TIME. C3 says so, and the
// reason is that the happy path of a batcher is trivial and its failure path is the easiest
// place in this product to lose a customer's data without producing an error anywhere.
//
// Both of the ticket's two are here, and neither is reachable against a real server:
//
//  1. killing the agent mid-batch loses AT MOST the current batch, never a confirmed one;
//  2. restarting resumes from the LAST CONFIRMED position — no gap and no duplicate.
//
// The second one carries its own counterfactual: the same chain assembled from a stream that
// resumed where the dead batch REACHED rather than where the last confirmed batch ENDED, run
// through the real verifier, which reports the hole. That is the bug this design exists to
// prevent, written down as the failure it would be.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pglogrepl"

	"github.com/manukyanv07/parity-scanner/agent/internal/backup"
	chainpkg "github.com/manukyanv07/parity-scanner/chain"
	chainpg "github.com/manukyanv07/parity-scanner/chain/postgres"
	"github.com/manukyanv07/parity-scanner/contract"
)

// ---------------------------------------------------------------------------------------------
// The fake. backup-shape.md §7 one level down: a batcher that needed a real server to test would
// have exactly its failure paths — a link that dies mid-batch, a restart, a keepalive nobody
// answered — tested nowhere, and those are the paths where the loss lives.
// ---------------------------------------------------------------------------------------------

// step is one thing that happens to the reader, scripted. Three shapes, and the last two are the
// ones that matter: a batch ENDS when the server goes quiet until the deadline, and a batch DIES
// when the link fails with bytes already read.
//
// EVERY SHAPE IS A SLICE, because the unit a batcher deals in is no longer one message: a change
// file holds whole transactions, so the smallest thing a script can say is BEGIN, a row, COMMIT.
type step struct {
	msg   walMessage
	quiet bool
	err   error
}

// beatTable is the one table these scripts write to. Keyed by id, so every record they produce is
// one a replay could locate a row with — the tables that are not are change_test.go's.
var beatTable = relate(1, "ops", "beat", col{name: "id", key: true}, col{name: "note"})

// txn is one whole transaction, as the server sends it: BEGIN, the relation, one row per note, and
// the COMMIT that is the only thing which makes any of it a record. Everything in it is filed at
// the transaction's own commit LSN (change.go), which is what a test names a position by.
func txn(at pglogrepl.LSN, notes ...string) []step {
	out := []step{{msg: record(at, begin(at))}, {msg: record(at, beatTable)}}
	for _, note := range notes {
		out = append(out, step{msg: record(at, insert(1, note, note))})
	}
	return append(out, step{msg: record(at, commit(at))})
}

func beat(at pglogrepl.LSN) []step { return []step{{msg: keepalive(at)}} }
func quiet() []step                { return []step{{quiet: true}} }
func dies(err error) []step        { return []step{{err: err}} }

// script flattens what a fake link is going to be handed, so a test reads as the sequence of
// things that happen to it.
func script(parts ...[]step) []step {
	var out []step
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}

type fakeLink struct {
	// resume is what the SLOT says, which is where a real session actually begins — not what
	// the caller asked for. The two differ exactly when C4 has happened.
	resume pglogrepl.LSN

	script []step
	starts int

	// senderTimeout is what the server would report wal_sender_timeout as. ZERO IS THE DEFAULT
	// AND IT MEANS THE SERVER HAS NO TIMEOUT, so no liveness replies go out while the pipeline
	// holds a batch — which is what keeps every test here that is not about the store window
	// counting only the replies its own script provoked.
	senderTimeout time.Duration

	// senderTimeoutErr is a server that would not say. It must not stop the stream — the fallback
	// is a period short enough for any server, and no backups at all is worse than a few extra
	// forty-byte messages.
	senderTimeoutErr error

	// mu guards ONLY what the store window's replies touch. Recv is deliberately not under it:
	// it blocks until the batch's deadline, and a lock held across that block is a deadlock with
	// the very goroutine this fake exists to observe.
	mu sync.Mutex

	// The two acts, counted apart — which is not a distinction this fake had to invent. The
	// link interface cannot express a liveness reply that carries an LSN, so which slice a
	// message lands in is which method the batcher called.
	alive int
	acked []pglogrepl.LSN

	// stored is the caller saying the manifest has landed, and early is every position that went
	// on the wire BEFORE it did. Both exist for one assertion, and only the store-window tests
	// below set the first or read the second: a liveness reply keeps the connection open and must
	// never be able to tell Postgres it may discard anything.
	stored bool
	early  []pglogrepl.LSN

	// startErr is a session that cannot be opened at all, which is where the slot having gone
	// arrives: the real link checks the catalog before START_REPLICATION (gone.go).
	startErr error

	// schema is what the fingerprint answers. Empty means the ordinary one, because a stream
	// whose fingerprint is empty is refused and almost no test here is about that.
	schema       string
	schemaErr    error
	fingerprints int
}

const fakeSchema = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

func (f *fakeLink) Fingerprint(context.Context) (string, error) {
	f.fingerprints++
	if f.schemaErr != nil {
		return "", f.schemaErr
	}
	if f.schema == "" {
		return fakeSchema, nil
	}
	return f.schema, nil
}

func (f *fakeLink) Start(context.Context) (pglogrepl.LSN, error) {
	f.starts++
	if f.startErr != nil {
		return 0, f.startErr
	}
	return f.resume, nil
}

func (f *fakeLink) Recv(ctx context.Context) (walMessage, error) {
	if len(f.script) == 0 {
		// Nothing more will ever arrive, so wait the way a real read does: until the batch's
		// deadline, and then report the quiet rather than an error.
		<-ctx.Done()
		return walMessage{}, errQuiet
	}
	next := f.script[0]
	f.script = f.script[1:]
	switch {
	case next.err != nil:
		return walMessage{}, next.err
	case next.quiet:
		<-ctx.Done()
		return walMessage{}, errQuiet
	}
	return next.msg, nil
}

func (f *fakeLink) SenderTimeout(context.Context) (time.Duration, error) {
	if f.senderTimeoutErr != nil {
		return 0, f.senderTimeoutErr
	}
	return f.senderTimeout, nil
}

func (f *fakeLink) ReplyAlive(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.alive++
	return nil
}

func (f *fakeLink) Acknowledge(_ context.Context, upTo pglogrepl.LSN) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.stored {
		// THE DEATH CONDITION, RECORDED RATHER THAN RETURNED: a position went on the wire while
		// the batch carrying it was in memory and durable nowhere. Returning an error here would
		// let the batcher report it as a failed confirm, which is the one shape that would make
		// the loss look handled.
		f.early = append(f.early, upTo)
	}
	f.acked = append(f.acked, upTo)
	return nil
}

// durable is the caller's manifest landing, which is the moment — and the only moment — after
// which a position may be put on the wire.
func (f *fakeLink) durable() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.stored = true
}

// replies, positions and tooEarly read what the fake saw. They lock because the store window's
// liveness replies come from a goroutine of the batcher's, which is the whole point of them.
func (f *fakeLink) replies() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.alive
}

func (f *fakeLink) positions() []pglogrepl.LSN {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.acked)
}

func (f *fakeLink) tooEarly() []pglogrepl.LSN {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.early)
}

// record is one pgoutput message on the wire. The LSN is only how far the SERVER had written when
// it sent this — the lag, and nothing else: where a record is filed comes from its transaction's
// commit, which is inside the payload.
func record(at pglogrepl.LSN, body []byte) walMessage {
	return walMessage{ServerWALEnd: at + pglogrepl.LSN(len(body)), Data: body}
}

// keepalive is the server asking whether anyone is still there. AD-039: it comes at half the
// wal_sender_timeout and the server hangs up at the full one.
func keepalive(at pglogrepl.LSN) walMessage {
	return walMessage{Keepalive: true, ReplyRequested: true, ServerWALEnd: at}
}

// streamOver wires a batcher to a fake link with a short interval, so a test costs milliseconds.
func streamOver(link *fakeLink, interval time.Duration) *Stream {
	return &Stream{Slot: "vp_stream", Publication: "vp_all", Interval: interval, link: link}
}

// read drains a batch's single part, which is also the assertion that Open yields a whole,
// fresh stream every time it is called.
func read(t *testing.T, batch backup.Batch) []byte {
	t.Helper()
	if len(batch.Parts) != 1 {
		t.Fatalf("batch has %d parts, want exactly one", len(batch.Parts))
	}
	stream, err := batch.Parts[0].Open()
	if err != nil {
		t.Fatalf("open the change part: %v", err)
	}
	defer func() { _ = stream.Close() }()
	body, err := io.ReadAll(stream)
	if err != nil {
		t.Fatalf("read the change part: %v", err)
	}
	return body
}

// changes reads a change file back the way restore/replay.go does: one JSON object per line.
func changes(t *testing.T, file []byte) []contract.Change {
	t.Helper()
	var out []contract.Change
	for i, line := range bytes.Split(bytes.TrimRight(file, "\n"), []byte("\n")) {
		if len(line) == 0 {
			continue
		}
		var c contract.Change
		if err := json.Unmarshal(line, &c); err != nil {
			t.Fatalf("line %d of the change file does not parse as a change: %v: %s", i+1, err, line)
		}
		out = append(out, c)
	}
	return out
}

// bodies is which rows a batch carried, by the one column these scripts write.
func bodies(t *testing.T, file []byte) []string {
	t.Helper()
	var out []string
	for _, c := range changes(t, file) {
		note, present := c.Row["note"]
		if !present || note == nil {
			t.Fatalf("a record carries no note: %+v", c)
		}
		out = append(out, *note)
	}
	return out
}

// lineOf is one record's exact size in a change file, so the size-cap test can name a cap in
// records rather than in a byte count that drifts the moment a field is added to contract.Change.
func lineOf(t *testing.T, at pglogrepl.LSN, note string) int {
	t.Helper()
	value := note
	line, err := json.Marshal(contract.Change{
		Position: string(positionOf(at)),
		Op:       contract.ChangeInsert,
		Schema:   "ops",
		Table:    "beat",
		Key:      []string{"id"},
		Row:      map[string]*string{"id": &value, "note": &value},
	})
	if err != nil {
		t.Fatalf("render a record: %v", err)
	}
	return len(line) + 1
}

// ---------------------------------------------------------------------------------------------
// DEATH TEST 1 — killing the agent mid-batch loses at most the current batch, never a confirmed
// one.
// ---------------------------------------------------------------------------------------------

func TestKillingTheAgentMidBatchNeverLosesAConfirmedOne(t *testing.T) {
	t.Parallel()

	link := &fakeLink{
		resume: 0x1000,
		script: script(
			txn(0x1400, "one"),
			txn(0x1800, "two"),
			quiet(), // the first batch ends here, and it is the one that becomes durable

			txn(0x2000, "three"),
			beat(0x2400),
			dies(errors.New("connection reset by peer")), // mid-batch, bytes already read
		),
	}
	stream := streamOver(link, 50*time.Millisecond)

	first, err := stream.Since(context.Background(), "0/1000")
	if err != nil {
		t.Fatalf("first batch: %v", err)
	}
	// The pipeline stored it and the manifest went last. ONLY NOW is the LSN confirmed.
	if err := stream.Confirm(context.Background(), first.Position); err != nil {
		t.Fatalf("confirm the first batch: %v", err)
	}
	confirmed := first.Position

	// The second cycle dies with bytes already read and nothing durable anywhere.
	if _, err := stream.Since(context.Background(), confirmed); err == nil {
		t.Fatal("a batch whose link died mid-stream was returned as a batch; the pipeline would " +
			"have written a manifest over half of it")
	}

	// THE ASSERTION THIS WHOLE TEST IS FOR. Exactly one position was ever confirmed, and it is
	// the one whose bytes are durable. Anything after it is redelivered on the next connection
	// (AD-039), and anything Postgres was told to discard is gone forever.
	acks := link.positions()
	if len(acks) != 1 {
		t.Fatalf("the server was told %d positions were durable, want exactly 1: %v", len(acks), acks)
	}
	if got := positionOf(acks[0]); got != confirmed {
		t.Fatalf("confirmed %s, want %s — a position confirmed past the durable batch tells "+
			"Postgres to discard WAL nobody stored", got, confirmed)
	}

	// And the keepalive the dying batch met WAS answered — a stream that answers none is hung up
	// on at wal_sender_timeout — with a reply that confirmed nothing, which the count above
	// already proves because a liveness reply cannot carry a position.
	if got := link.replies(); got != 1 {
		t.Fatalf("%d liveness replies during the dying batch, want 1", got)
	}
}

// The other half of the same failure: a batch that was handed out and never confirmed cannot be
// followed by another one over the same session. The stream cannot rewind, so continuing would
// hand out a file beginning where the LOST batch ended — a chain contiguous on paper with the
// changes in between gone.
func TestAnUnconfirmedBatchStopsTheStreamRatherThanLeavingAHole(t *testing.T) {
	t.Parallel()

	// There is more WAL waiting after the batch that is lost, which is what makes the refusal
	// below a real refusal rather than an empty cycle wearing one's clothes.
	link := &fakeLink{resume: 0x1000, script: script(
		txn(0x1400, "one"), quiet(),
		txn(0x2000, "two"), quiet(),
		txn(0x3000, "three"), quiet(),
	)}
	stream := streamOver(link, 50*time.Millisecond)

	first, err := stream.Since(context.Background(), "0/1000")
	if err != nil {
		t.Fatalf("first batch: %v", err)
	}
	// The manifest write failed. Nothing is durable, so nothing was confirmed.

	// THE DANGEROUS CALL, AND IT IS THE NATURAL ONE: a caller whose cycle failed retries from
	// the position it last knew was durable — the same argument it passed a moment ago. The
	// session has already read past the lost batch, so a batch produced here would be labelled
	// as beginning at 0/1000 while carrying only what came AFTER the lost one. Every object
	// would hash, the manifest would parse, and the chain would verify with a hole in it.
	if _, err := stream.Since(context.Background(), "0/1000"); err == nil {
		t.Fatal("the stream carried on past a batch nobody confirmed, and the file it produced " +
			"claims a range it does not carry")
	}
	// And the same refusal from the other direction: resuming from where the LOST batch reached
	// would drop everything in it while looking perfectly contiguous.
	if _, err := stream.Since(context.Background(), first.Position); err == nil {
		t.Fatal("the stream accepted the unconfirmed batch's own position as durable")
	}
	if acks := link.positions(); len(acks) != 0 {
		t.Fatalf("something was confirmed on a path where nothing was durable: %v", acks)
	}
}

// AND THE SAME REFUSAL AFTER A CYCLE THAT FAILED, which is the more dangerous of the two because
// nothing was handed out to be suspicious about. A cycle that died had already read messages, and
// the reads that fail RECOVERABLY — a read that timed out, an error response, a message that would
// not parse — leave the connection perfectly usable. Carrying on would produce a file labelled as
// beginning at the last confirmed position while its first record is on the far side of the ones
// the dead cycle swallowed: every object hashes, the manifest parses, and the chain verifies.
func TestACycleThatFailedStopsTheStreamRatherThanSwallowingWhatItRead(t *testing.T) {
	t.Parallel()

	link := &fakeLink{resume: 0x1000, script: script(
		txn(0x1400, "lost-a"),
		txn(0x1800, "lost-b"),
		dies(errors.New("the server sent something we could not read")),

		txn(0x2000, "after"), quiet(),
	)}
	stream := streamOver(link, 50*time.Millisecond)

	if _, err := stream.Since(context.Background(), "0/1000"); err == nil {
		t.Fatal("a cycle whose link failed came back as a batch")
	}
	// The natural retry, from the position the caller last knew was durable.
	batch, err := stream.Since(context.Background(), "0/1000")
	if err == nil {
		t.Fatalf("the stream carried on after a failed cycle and produced %s..%s, which claims to "+
			"begin at 0/1000 and carries nothing that happened before %s",
			batch.From, batch.Position, batch.Position)
	}
	if acks := link.positions(); len(acks) != 0 {
		t.Fatalf("something was confirmed across a failed cycle: %v", acks)
	}
}

// ---------------------------------------------------------------------------------------------
// THE STORE WINDOW — the stretch between a batch being handed out and its manifest landing, in
// which NOTHING used to be reading or answering this connection. It is not a hypothetical: a
// `make e2e-postgres` run died with `unexpected EOF` draining the slot after three and a half
// minutes of heavy Docker load, on a diff that touched no file in the backup path. The server
// hangs up at wal_sender_timeout whether the silence is a slow database or a slow upload.
// ---------------------------------------------------------------------------------------------

// THE STALL, CLOSED. The pipeline is holding the batch and reading nothing, and the server is
// still being answered — which is the whole of the fix, stated as the behaviour rather than as a
// goroutine.
func TestTheServerIsAnsweredWhileTheBatchIsBeingStored(t *testing.T) {
	t.Parallel()

	// A server that hangs up quickly, so the window below is many timeouts long in milliseconds.
	link := &fakeLink{resume: 0x1000, senderTimeout: 40 * time.Millisecond, script: script(
		txn(0x1400, "one"), quiet(),
	)}
	stream := streamOver(link, 30*time.Millisecond)
	t.Cleanup(stream.Close)

	batch, err := stream.Since(context.Background(), "0/1000")
	if err != nil {
		t.Fatalf("collect a batch: %v", err)
	}
	collecting := link.replies()

	// THE STORE WINDOW ITSELF: the caller is chunking, hashing and uploading, which is to say it
	// is doing everything except reading this connection.
	replied := waitFor(t, 2*time.Second, func() bool { return link.replies() > collecting })
	if !replied {
		t.Fatalf("nothing answered the server while the batch was being stored: %d liveness "+
			"replies during collection and %d since, so a batch slower to upload than "+
			"wal_sender_timeout (%s here) is still a stream the server hangs up on",
			collecting, link.replies(), link.senderTimeout)
	}

	// AND THE REPLIES CONFIRMED NOTHING. They cannot — ReplyAlive takes no LSN — and this is the
	// assertion that says so from the outside.
	if acks := link.positions(); len(acks) != 0 {
		t.Fatalf("a position went on the wire while the batch was in memory and durable "+
			"nowhere: %v", acks)
	}

	link.durable()
	if err := stream.Confirm(context.Background(), batch.Position); err != nil {
		t.Fatalf("confirm after a store window: %v", err)
	}
	if acks := link.positions(); len(acks) != 1 || positionOf(acks[0]) != batch.Position {
		t.Fatalf("the server was told %v was durable, want exactly [%s]", acks, batch.Position)
	}
}

// AND THE HALF THAT MATTERS MORE. The replies go out for the whole of a long store window, and
// not one of them puts a position on the wire: the first and only acknowledgement happens after
// the caller says the manifest has landed.
//
// This is the test that fails if the stall is closed the wrong way. A keepalive answered with the
// batch's own LSN keeps the connection open just as well and tells Postgres it may discard WAL
// that is in memory and nowhere else — which is silent, permanent, and found by a customer at
// restore. The fake records every position that goes out before durability, so getting it wrong
// is a failure here rather than a bug in production.
func TestNoPositionGoesOutBeforeTheManifestLands(t *testing.T) {
	t.Parallel()

	link := &fakeLink{resume: 0x1000, senderTimeout: 20 * time.Millisecond, script: script(
		txn(0x1400, "one"), quiet(),
	)}
	stream := streamOver(link, 30*time.Millisecond)
	t.Cleanup(stream.Close)

	batch, err := stream.Since(context.Background(), "0/1000")
	if err != nil {
		t.Fatalf("collect a batch: %v", err)
	}
	collecting := link.replies()

	// A store window long enough to need answering several times over, which is what a batch that
	// outruns the server's patience actually looks like.
	const want = 5
	if !waitFor(t, 2*time.Second, func() bool { return link.replies() >= collecting+want }) {
		t.Fatalf("only %d liveness replies went out during the store window, want at least %d "+
			"more than the %d collection sent; a window this test cannot keep alive proves "+
			"nothing about what it does not confirm", link.replies(), want, collecting)
	}
	if early := link.tooEarly(); len(early) != 0 {
		t.Fatalf("%v went on the wire during the store window. Postgres has been told it may "+
			"discard WAL that is in memory and nowhere else, which is the silent loss this "+
			"whole package exists to prevent", early)
	}

	// The manifest lands, and only now is there anything to vouch for.
	link.durable()
	if err := stream.Confirm(context.Background(), batch.Position); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if early := link.tooEarly(); len(early) != 0 {
		t.Fatalf("%v went out before the manifest landed", early)
	}
	if acks := link.positions(); len(acks) != 1 || positionOf(acks[0]) != batch.Position {
		t.Fatalf("the server was told %v was durable, want exactly [%s]", acks, batch.Position)
	}
}

// A CLOSED STREAM STOPS ANSWERING, which is what the owner of the connection needs before it
// closes one: pgconn is not safe for concurrent use, so a reply in flight and a Close on the same
// connection is a race, and the window it would happen in is exactly the one now made long.
func TestClosingTheStreamStopsTheReplies(t *testing.T) {
	t.Parallel()

	link := &fakeLink{resume: 0x1000, senderTimeout: 20 * time.Millisecond, script: script(
		txn(0x1400, "one"), quiet(),
	)}
	stream := streamOver(link, 30*time.Millisecond)

	if _, err := stream.Since(context.Background(), "0/1000"); err != nil {
		t.Fatalf("collect a batch: %v", err)
	}
	if !waitFor(t, 2*time.Second, func() bool { return link.replies() > 0 }) {
		t.Fatal("no liveness reply ever went out, so this test cannot show one stopping")
	}

	stream.Close()
	// After Close returns, the goroutine is GONE rather than merely told to go: nothing more may
	// touch the connection, because the caller is about to close it.
	settled := link.replies()
	time.Sleep(5 * link.senderTimeout)
	if now := link.replies(); now != settled {
		t.Fatalf("%d more liveness replies went out after Close returned; the connection is being "+
			"written to by a goroutine its owner believes has stopped", now-settled)
	}
	// And Close is idempotent, because an owner tearing down does not track whether it already has.
	stream.Close()
}

// A CONFIRM THAT IS REFUSED HAS ENDED NOTHING. The batch is still handed out and still durable
// nowhere, so the window must go on being answered — a caller that passed the wrong position and
// left the connection silent behind it would be back in the original stall through the error path.
func TestARefusedConfirmLeavesTheStoreWindowAnswered(t *testing.T) {
	t.Parallel()

	link := &fakeLink{resume: 0x1000, senderTimeout: 20 * time.Millisecond, script: script(
		txn(0x1400, "one"), quiet(),
	)}
	stream := streamOver(link, 30*time.Millisecond)
	t.Cleanup(stream.Close)

	batch, err := stream.Since(context.Background(), "0/1000")
	if err != nil {
		t.Fatalf("collect a batch: %v", err)
	}

	// The caller has lost track of its own cycle and names a position this stream never handed
	// out, which the stream refuses — that refusal is a death test of its own, above.
	if err := stream.Confirm(context.Background(), "0/9999"); err == nil {
		t.Fatal("the stream confirmed a position it never handed out")
	}
	refused := link.replies()
	if !waitFor(t, 2*time.Second, func() bool { return link.replies() > refused }) {
		t.Fatal("a refused Confirm ended the store window: the batch is still handed out and " +
			"durable nowhere, and nothing is answering the server any more")
	}
	if early := link.tooEarly(); len(early) != 0 {
		t.Fatalf("%v went on the wire during a window nothing had confirmed", early)
	}

	// And the confirm that is right still works, and still ends the window.
	link.durable()
	if err := stream.Confirm(context.Background(), batch.Position); err != nil {
		t.Fatalf("confirm after a refused one: %v", err)
	}
	if acks := link.positions(); len(acks) != 1 || positionOf(acks[0]) != batch.Position {
		t.Fatalf("the server was told %v was durable, want exactly [%s]", acks, batch.Position)
	}
}

// A SERVER THAT WILL NOT SAY HOW LONG IT WAITS IS STILL A SERVER WE BACK UP. The period the store
// window is paced by can only be wrong in one direction that costs anything — too long — so an
// unreadable wal_sender_timeout falls back to a floor short enough for anything anyone runs
// rather than refusing to open a session at all.
func TestAnUnreadableSenderTimeoutDoesNotStopTheStream(t *testing.T) {
	t.Parallel()

	link := &fakeLink{
		resume:           0x1000,
		senderTimeoutErr: errors.New("the server would not say"),
		script:           script(txn(0x1400, "one"), quiet()),
	}
	stream := streamOver(link, 30*time.Millisecond)
	t.Cleanup(stream.Close)

	batch, err := stream.Since(context.Background(), "0/1000")
	if err != nil {
		t.Fatalf("a stream whose wal_sender_timeout could not be read refused to run, which is "+
			"no backups at all in exchange for a number that only paces a heartbeat: %v", err)
	}
	if stream.senderTimeout != fallbackSenderTimeout {
		t.Fatalf("the store window is paced at %s, want the fallback %s",
			stream.senderTimeout, fallbackSenderTimeout)
	}
	// The window IS answered, at that pace — which is the assertion above rather than one made by
	// waiting: the fallback is measured in seconds on purpose, and a test that sat out a beat of
	// it would be paying two and a half seconds to learn what the field already says.

	link.durable()
	if err := stream.Confirm(context.Background(), batch.Position); err != nil {
		t.Fatalf("confirm: %v", err)
	}
}

// waitFor polls until want is true or the budget runs out, and reports which happened. Polling
// rather than a channel because what it is waiting for is a side effect on a fake — the fake is
// deliberately not the thing under test, and giving it a notification would make it one.
func waitFor(t *testing.T, budget time.Duration, want func() bool) bool {
	t.Helper()
	for deadline := time.Now().Add(budget); time.Now().Before(deadline); {
		if want() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return want()
}

// ---------------------------------------------------------------------------------------------
// DEATH TEST 2 — restarting resumes from the last confirmed position: no gap and no duplicate.
// ---------------------------------------------------------------------------------------------

func TestRestartingResumesFromTheLastConfirmedPositionWithNoGapAndNoDuplicate(t *testing.T) {
	t.Parallel()

	// The agent's first life. One batch, stored and confirmed; a second batch under way when
	// the process is killed.
	first := &fakeLink{
		resume: 0x1000,
		script: script(
			txn(0x1400, "alpha"),
			txn(0x1800, "bravo"),
			quiet(),

			txn(0x2000, "charlie"), // read, and never durable anywhere
			dies(errors.New("SIGKILL")),
		),
	}
	live := streamOver(first, 50*time.Millisecond)

	one, err := live.Since(context.Background(), "0/1000")
	if err != nil {
		t.Fatalf("first batch: %v", err)
	}
	if err := live.Confirm(context.Background(), one.Position); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if _, err := live.Since(context.Background(), one.Position); err == nil {
		t.Fatal("the killed batch came back as a batch")
	}

	// The agent restarts. A NEW connection, a new session on the SAME slot, and the slot
	// resumes at what it was last told is durable — so everything after it comes back at the
	// same LSNs, which AD-039 measured rather than assumed.
	confirmed, err := pglogrepl.ParseLSN(string(one.Position))
	if err != nil {
		t.Fatalf("the position handed out is not an LSN: %v", err)
	}
	second := &fakeLink{
		resume: confirmed,
		script: script(
			// Everything from the confirmed position forward, at identical LSNs, INCLUDING the
			// record sitting on that position: the slot resumes AT it, so one record of overlap
			// with the confirmed file is the normal shape and not a fault (AD-039).
			txn(0x1800, "bravo"),
			txn(0x2000, "charlie"),
			txn(0x2800, "delta"),
			quiet(),
		),
	}
	restarted := streamOver(second, 50*time.Millisecond)

	two, err := restarted.Since(context.Background(), one.Position)
	if err != nil {
		t.Fatalf("the batch after the restart: %v", err)
	}
	if second.starts != 1 {
		t.Fatalf("the restarted stream opened %d sessions, want 1", second.starts)
	}

	// NO GAP: the new file begins exactly where the confirmed one ended.
	if two.From != one.Position {
		t.Fatalf("the batch after the restart begins at %s and the confirmed one ended at %s; "+
			"everything between them is in no file at all", two.From, one.Position)
	}
	// NO DUPLICATE — which means it does not go back FURTHER than the confirmed position, not
	// that it overlaps by nothing. "bravo" sits exactly on that position and comes back with it,
	// because the slot resumes AT the confirmed point; "alpha", which is behind it, does not.
	// Overlap is health and a gap is the fault (AD-039), and the overlap is resolved at replay.
	got := bodies(t, read(t, two))
	if want := []string{"bravo", "charlie", "delta"}; !slices.Equal(got, want) {
		t.Fatalf("the batch after the restart carries %q, want %q — the record lost with the "+
			"killed batch has to come back, and nothing behind the confirmed position may", got, want)
	}

	// And the chain those two files make is whole, according to the verifier that will be asked
	// at restore rather than according to this test's own arithmetic.
	assembled := chainOf(one, two)
	checked, err := chainpkg.Verify(assembled, chainpg.WAL{})
	if err != nil {
		t.Fatalf("the chain across the restart does not verify: %v", err)
	}
	if checked != chainpkg.CheckedWhole {
		t.Fatalf("the chain verified as %q, want %q", checked, chainpkg.CheckedWhole)
	}

	// THE COUNTERFACTUAL, AND IT IS THE POINT OF THE DESIGN. Had the restarted stream resumed
	// where the KILLED batch reached instead of where the confirmed one ended, every file would
	// still hash, every manifest would still parse, and the chain would have a hole.
	broken := chainOf(one, two)
	broken.Segments[2].ReadPoint.From = "0/2007" // where the killed batch had read to
	if _, err := chainpkg.Verify(broken, chainpg.WAL{}); err == nil {
		t.Fatal("a chain resuming past the confirmed position verified clean; that is the silent " +
			"loss this ticket exists to prevent and the verifier no longer sees it")
	}
}

// chainOf assembles a base and two change files into the shape a restore reads. The base is
// minimal on purpose — everything under test here is the two ranges and where they meet.
func chainOf(one, two backup.Batch) contract.Chain {
	source := contract.BackupSource{Provider: "azure", ResourceID: "/x/pg1", Database: "orders", Engine: "postgres", EngineVersion: "18"}
	segment := func(kind contract.BackupKind, from, position backup.Position) contract.Manifest {
		return contract.Manifest{
			Kind:      kind,
			Source:    source,
			ReadPoint: contract.ReadPoint{From: string(from), Position: string(position)},
			Artifact:  contract.Artifact{Parts: []contract.Part{{Path: "p", Bytes: 1}}},
		}
	}
	return contract.Chain{
		Segments: []contract.Manifest{
			segment(contract.BackupBase, "", "0/1000"),
			segment(contract.BackupChange, one.From, one.Position),
			segment(contract.BackupChange, two.From, two.Position),
		},
		Confirmed: string(two.Position),
	}
}

// ---------------------------------------------------------------------------------------------
// THE MEASUREMENT THAT DECIDES THE TICKET — AD-039. A liveness reply is not an acknowledgement.
// ---------------------------------------------------------------------------------------------

// The naive reading of C3's rule is a stream that confirms nothing for a whole batch interval and
// is therefore hung up on every wal_sender_timeout — measured at 1 minute on both Azure fixtures,
// so a batch interval over a minute would die and re-read its batch forever. This is the property
// that makes an interval of any length safe: keepalives are answered ON THE SERVER'S SCHEDULE and
// the answers confirm nothing.
//
// The interval here is ten minutes and the test takes milliseconds, which is the whole argument:
// the reply schedule is not tied to the interval. The batch ends on its size cap instead.
func TestKeepalivesAreAnsweredOnTheServersScheduleAndConfirmNothing(t *testing.T) {
	t.Parallel()

	link := &fakeLink{
		resume: 0x1000,
		script: script(
			beat(0x1000),
			txn(0x1400, "one"),
			beat(0x1400),
			txn(0x1800, "two"),
			beat(0x1800),
			txn(0x2000, "six"),
			beat(0x2400), // never reached: the cap closes the batch first
		),
	}
	stream := streamOver(link, 10*time.Minute)
	// Three records and no more. Measured from a rendered record rather than typed as a byte
	// count, so the cap still means "three" the day a field is added to contract.Change. The three
	// notes are the same length for the same reason.
	stream.maxBytes = int64(3 * lineOf(t, 0x1400, "one"))

	batch, err := stream.Since(context.Background(), "0/1000")
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	if got := bodies(t, read(t, batch)); len(got) != 3 {
		t.Fatalf("the batch carries %q; the size cap should have closed it after three", got)
	}

	// Every keepalive the server asked a reply to was answered — a stream that answers none is
	// disconnected at wal_sender_timeout with `unexpected EOF` and re-reads its batch forever.
	if got := link.replies(); got != 3 {
		t.Fatalf("%d replies were sent for the keepalives seen before the cap, want 3", got)
	}
	// And not one of them confirmed anything, which is the other half. Confirming here to keep
	// the connection alive would tell Postgres it may discard WAL that is in memory and nowhere
	// else — the exact loss this ticket exists to prevent, arrived at while trying to be helpful.
	if acks := link.positions(); len(acks) != 0 {
		t.Fatalf("a keepalive was answered with an acknowledgement at %v; a liveness reply is "+
			"not an acknowledgement", acks)
	}
}

// THE CAP MUST SEE THE TRANSACTION IN FLIGHT, or it is a cap on nothing. Records reach the change
// file only at their COMMIT, so a cycle reading ONE enormous transaction leaves the file's length
// at zero for the whole of it — and a cap that reads only the file would let the decoder grow
// until the agent in its small container is killed, which is exactly what maxBytes exists to stop.
//
// The transaction here never commits, so the file stays empty; what closes the batch is the bytes
// held for it. Without the accounting this test does not fail — it hangs on the interval and comes
// back with the whole thing buffered.
func TestOneEnormousTransactionStillMeetsTheSizeCap(t *testing.T) {
	t.Parallel()

	huge := strings.Repeat("x", 4096)
	rows := make([]step, 0, 64)
	for i := 0; i < 64; i++ {
		rows = append(rows, step{msg: record(0x1400, insert(1, fmt.Sprintf("%d", i), huge))})
	}
	link := &fakeLink{resume: 0x1000, script: script(
		[]step{{msg: record(0x1400, begin(0x1400))}, {msg: record(0x1400, beatTable)}},
		rows,
		// Never reached: the cap closes the batch long before the commit that would have made
		// any of this a record.
		[]step{{msg: record(0x1400, commit(0x1400))}},
	)}
	stream := streamOver(link, 10*time.Minute)
	stream.maxBytes = 16 << 10

	began := time.Now()
	_, err := stream.Since(context.Background(), "0/1000")
	if !errors.Is(err, backup.ErrNoChanges) {
		t.Fatalf("Since = %v, want ErrNoChanges: nothing committed, so there is no batch", err)
	}
	if took := time.Since(began); took > time.Minute {
		t.Fatalf("the cycle ran for %s against a ten-minute interval, so nothing bounded it", took)
	}
	// It stopped somewhere near the cap rather than after reading everything the server had.
	if left := len(link.script); left == 0 {
		t.Fatal("the batcher read the whole transaction: the size cap does not see the records " +
			"held for a transaction that has not committed, so it bounds nothing")
	} else {
		t.Logf("the cap closed the cycle with %d messages still unread", left)
	}
}

// ---------------------------------------------------------------------------------------------
// Done when: the interval is configurable per customer, and the achieved lag is reported every
// cycle.
// ---------------------------------------------------------------------------------------------

func TestTheIntervalIsConfigurableAndBoundsTheCycle(t *testing.T) {
	t.Parallel()

	for _, interval := range []time.Duration{20 * time.Millisecond, 120 * time.Millisecond} {
		link := &fakeLink{resume: 0x1000, script: script(txn(0x1400, "one"))}
		stream := streamOver(link, interval)

		began := time.Now()
		if _, err := stream.Since(context.Background(), "0/1000"); err != nil {
			t.Fatalf("interval %s: %v", interval, err)
		}
		took := time.Since(began)
		if took < interval {
			t.Fatalf("a cycle configured for %s returned after %s; the interval is not what "+
				"bounds it", interval, took)
		}
	}
}

// An unset interval is the default rather than a cycle that returns instantly forever.
func TestAnUnsetIntervalIsTheDefault(t *testing.T) {
	t.Parallel()
	stream := streamOver(&fakeLink{}, 0)
	if got := stream.interval(); got != DefaultInterval {
		t.Fatalf("interval = %s, want %s", got, DefaultInterval)
	}
}

// EVERY CYCLE, and the one that matters most is the cycle that found nothing: a stream that has
// silently stopped receiving looks exactly like a quiet database, and the lag is the only number
// that tells them apart.
func TestTheAchievedLagIsReportedOnEveryCycleIncludingAnEmptyOne(t *testing.T) {
	t.Parallel()

	var reported []Lag
	link := &fakeLink{
		resume: 0x1000,
		script: script(
			txn(0x1400, "one"),
			// The server has written further than this batch reaches, which is the lag.
			beat(0x5000),
			quiet(),
		),
	}
	stream := streamOver(link, 50*time.Millisecond)
	stream.Report = func(l Lag) { reported = append(reported, l) }

	batch, err := stream.Since(context.Background(), "0/1000")
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	if len(reported) != 1 {
		t.Fatalf("%d lags reported for one cycle, want 1", len(reported))
	}
	reached, err := pglogrepl.ParseLSN(string(batch.Position))
	if err != nil {
		t.Fatalf("the position handed out is not an LSN: %v", err)
	}
	if want := int64(0x5000 - reached); reported[0].Bytes != want {
		t.Fatalf("lag = %d bytes, want %d — the server had written that much more than this "+
			"batch carries", reported[0].Bytes, want)
	}
	if reported[0].Took <= 0 {
		t.Fatalf("the cycle reports it took %s", reported[0].Took)
	}

	// The empty cycle. ErrNoChanges is not an error path that skips reporting.
	if err := stream.Confirm(context.Background(), batch.Position); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if _, err := stream.Since(context.Background(), batch.Position); !errors.Is(err, backup.ErrNoChanges) {
		t.Fatalf("a cycle with nothing in it returned %v, want ErrNoChanges", err)
	}
	if len(reported) != 2 {
		t.Fatalf("%d lags reported after an empty cycle, want 2 — a stream that has stopped "+
			"receiving reports nothing at all under any other rule", len(reported))
	}
}

// ---------------------------------------------------------------------------------------------
// The rest of the seam's own promises.
// ---------------------------------------------------------------------------------------------

// From is the source's account of where the session ACTUALLY resumed, never an echo of the
// position it was asked from. The two differ exactly when C4 has happened — the slot was lost and
// a new one made at a later point — and an echo would write that up as a contiguous chain.
func TestFromIsTheSlotsOwnResumePointAndNotTheRequest(t *testing.T) {
	t.Parallel()

	// Asked for 0/1000; the slot only goes back to 0/9000. Everything between is gone.
	link := &fakeLink{resume: 0x9000, script: script(txn(0x9400, "later"), quiet())}
	stream := streamOver(link, 50*time.Millisecond)

	batch, err := stream.Since(context.Background(), "0/1000")
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	if batch.From != "0/9000" {
		t.Fatalf("From = %s, want 0/9000 — a From copied from the request claims this file "+
			"begins where the last one ended and hides the hole", batch.From)
	}
}

func TestNothingHappenedIsErrNoChangesAndNotAnEmptyBatch(t *testing.T) {
	t.Parallel()

	link := &fakeLink{resume: 0x1000, script: script(beat(0x1000), quiet())}
	stream := streamOver(link, 30*time.Millisecond)

	batch, err := stream.Since(context.Background(), "0/1000")
	if !errors.Is(err, backup.ErrNoChanges) {
		t.Fatalf("Since = %v, want ErrNoChanges; an empty batch drains clean and ends in a "+
			"manifest over nothing", err)
	}
	if len(batch.Parts) != 0 {
		t.Fatalf("a batch came back beside ErrNoChanges: %+v", batch)
	}
	// A keepalive still had to be answered, or the connection dies while the database is idle.
	if got := link.replies(); got != 1 {
		t.Fatalf("%d replies sent during an empty cycle, want 1", got)
	}
}

func TestConfirmRefusesAnythingButTheBatchItHandedOut(t *testing.T) {
	t.Parallel()

	link := &fakeLink{resume: 0x1000, script: script(txn(0x1400, "one"), quiet())}
	stream := streamOver(link, 30*time.Millisecond)

	// Nothing has been handed out yet.
	if err := stream.Confirm(context.Background(), "0/2000"); err == nil {
		t.Fatal("a position was confirmed before any batch existed")
	}

	batch, err := stream.Since(context.Background(), "0/1000")
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	// AHEAD of the batch: this is the shape of the loss. Confirming a position past what is
	// durable tells Postgres to discard WAL nobody stored.
	if err := stream.Confirm(context.Background(), "0/FFFF"); err == nil {
		t.Fatal("a position past the durable batch was confirmed")
	}
	if acks := link.positions(); len(acks) != 0 {
		t.Fatalf("a refused confirm still reached the server: %v", acks)
	}
	if err := stream.Confirm(context.Background(), batch.Position); err != nil {
		t.Fatalf("confirming the batch that was handed out: %v", err)
	}
	// And not twice: the second call has nothing to confirm.
	if err := stream.Confirm(context.Background(), batch.Position); err == nil {
		t.Fatal("the same batch was confirmed twice")
	}
}

// A cancelled context is a kill, and it must not come back as a complete batch. It arrives at the
// read as an ordinary quiet — pgconn cancels by putting a deadline on the socket — which is why
// the batcher asks the context rather than trusting what the read said.
func TestACancelledCycleIsAFailureAndNotAShortBatch(t *testing.T) {
	t.Parallel()

	link := &fakeLink{resume: 0x1000, script: script(txn(0x1400, "one"), quiet())}
	stream := streamOver(link, time.Minute)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	if _, err := stream.Since(ctx, "0/1000"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Since = %v, want a cancellation; a batch cut short by a kill and returned as "+
			"a batch is a manifest over part of an interval", err)
	}
	if acks := link.positions(); len(acks) != 0 {
		t.Fatalf("a cancelled cycle confirmed something: %v", acks)
	}
}

func TestSinceRefusesAPositionItIsNotStandingOn(t *testing.T) {
	t.Parallel()

	link := &fakeLink{resume: 0x1000, script: script(txn(0x1400, "one"), quiet())}
	stream := streamOver(link, 30*time.Millisecond)

	batch, err := stream.Since(context.Background(), "0/1000")
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	if err := stream.Confirm(context.Background(), batch.Position); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	// A caller resuming from somewhere else entirely. The session cannot seek, so carrying on
	// would deliver the WAL after the confirmed point under a From nobody can check.
	if _, err := stream.Since(context.Background(), "0/7777"); err == nil {
		t.Fatal("the stream accepted a resume position it is not standing on")
	}
}

func TestAPositionThatIsNotAnLSNIsRefusedBeforeAnythingIsOpened(t *testing.T) {
	t.Parallel()

	link := &fakeLink{resume: 0x1000}
	stream := streamOver(link, 30*time.Millisecond)

	if _, err := stream.Since(context.Background(), "not-an-lsn"); err == nil {
		t.Fatal("a position that is not an LSN was accepted")
	}
	if link.starts != 0 {
		t.Fatal("a replication session was opened for a position nothing could read")
	}
}

// A SESSION THAT CANNOT BE OPENED BECAUSE THE SLOT IS GONE ENDS THE CHAIN, and the sentinel has to
// survive the trip out of the batcher: it is what tells a scheduler to take a new base copy rather
// than retry, and retrying is precisely how the hole gets written.
//
// Nothing may be handed out and nothing may be marked pending on this path either. A batch from a
// stream that never opened would be a file whose From nothing can vouch for.
func TestASlotThatIsGoneStopsTheStreamRatherThanResumingElsewhere(t *testing.T) {
	t.Parallel()

	gone := fmt.Errorf("postgres: %q is not on the server: %w", "vp_stream", backup.ErrSlotGone)
	link := &fakeLink{resume: 0x1000, startErr: gone}
	stream := streamOver(link, 30*time.Millisecond)

	batch, err := stream.Since(context.Background(), "0/1000")
	if err == nil {
		t.Fatal("a stream whose slot had gone handed out a batch; the chain was extended over a hole")
	}
	if !errors.Is(err, backup.ErrSlotGone) {
		t.Errorf("error %v does not carry backup.ErrSlotGone, so the cycle above it writes no "+
			"marker and the chain reads as healthy", err)
	}
	if len(batch.Parts) != 0 {
		t.Errorf("a batch came back from a session that never opened: %+v", batch)
	}
	if stream.unconfirmed {
		t.Error("the stream is waiting on a confirmation for a batch it never produced")
	}
	// The stream did not quietly become usable again — nothing here creates a slot, and the next
	// call must not behave as though one appeared.
	if _, err := stream.Since(context.Background(), "0/1000"); err == nil {
		t.Error("the cycle after a lost slot carried on as if nothing had happened")
	}
}

func TestAStreamWithoutASlotOrAPublicationIsRefused(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name   string
		stream Stream
	}{
		{"no slot", Stream{Publication: "vp_all"}},
		{"slot outside our convention", Stream{Slot: "customer_slot", Publication: "vp_all"}},
		{"no publication", Stream{Slot: "vp_stream"}},
		{"publication that is not a bare identifier", Stream{Slot: "vp_stream", Publication: "all'; DROP"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			stream := tc.stream
			stream.link = &fakeLink{}
			if _, err := stream.Since(context.Background(), "0/1000"); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// THE PART D2 ACTUALLY READS. restore/replay.go compares both of these for exact equality and
// refuses anything else — which is what the batcher and the replay disagreed about until now: one
// produced framed pgoutput and the other read parity/change-jsonl, so no chain this agent wrote
// could be replayed at all.
func TestTheBatchIsTheChangeFileAReplayAccepts(t *testing.T) {
	t.Parallel()

	link := &fakeLink{
		resume: 0x1000,
		script: script(txn(0x1400, "one"), txn(0x1800, "two"), quiet()),
	}
	stream := streamOver(link, 30*time.Millisecond)

	batch, err := stream.Since(context.Background(), "0/1000")
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	if batch.Parts[0].Format != contract.FormatChangeJSONL {
		t.Fatalf("the part is labelled %q, and a replay reads %q — a part that is not a change "+
			"file is refused there rather than parsed as one",
			batch.Parts[0].Format, contract.FormatChangeJSONL)
	}
	if batch.Parts[0].Role != contract.PartChanges {
		t.Fatalf("the part has the role %q; a part nobody said carried changes is refused rather "+
			"than replayed (AD-037)", batch.Parts[0].Role)
	}

	// EVERY RECORD CARRIES THE POSITION OF THE TRANSACTION IT COMMITTED IN, and the positions
	// advance — which is the one thing D2 checks about a file before it applies a line of it
	// (replay.go, eachChange). Filing each row at its own WALStart would not: pgoutput streams
	// transactions in commit order, and the rows inside one go backwards against a transaction
	// that committed earlier.
	got := changes(t, read(t, batch))
	if len(got) != 2 {
		t.Fatalf("the file carries %d records, want 2", len(got))
	}
	if got[0].Position != string(positionOf(0x1400)) || got[1].Position != string(positionOf(0x1800)) {
		t.Fatalf("the records are at %s and %s", got[0].Position, got[1].Position)
	}
	if got[0].Op != contract.ChangeInsert || got[0].Schema != "ops" || got[0].Table != "beat" {
		t.Fatalf("the first record decoded as %+v", got[0])
	}
	if !slices.Equal(got[0].Key, []string{"id"}) {
		t.Fatalf("the first record is identified by %v; a replay has nothing else to locate the "+
			"row by, and refuses the whole chain without it", got[0].Key)
	}

	// AND THE BATCH REACHES THE LAST COMMIT AND NOT A BYTE PAST IT. That value is what Confirm
	// puts on the wire, and a position past a transaction's commit record makes Postgres skip that
	// transaction on the next session — never redelivered, never stored, and the next file's From
	// equals the same overclaimed position, so the chain verifies whole over the hole.
	if want := positionOf(0x1800); batch.Position != want {
		t.Fatalf("Position = %s, want %s", batch.Position, want)
	}
	// The range the manifest will declare therefore contains every record in the file, which is
	// what D2 checks per record before applying one (restore/point.go, segment.covers).
	if batch.From != positionOf(0x1000) {
		t.Fatalf("From = %s, want 0/1000", batch.From)
	}
}

// THE FINGERPRINT IS ON EVERY BATCH, and an empty one never reaches a cycle. Cycle.mark refuses a
// batch whose Schema is empty against a chain whose base has one — which it did on every cycle for
// as long as this field was left unset, so the real Stream had never been run through a cycle at
// all.
func TestEveryBatchCarriesTheSchemaFingerprintAndAnEmptyOneIsRefused(t *testing.T) {
	t.Parallel()

	link := &fakeLink{
		resume: 0x1000,
		schema: "sha256:abc",
		script: script(txn(0x1400, "one"), quiet(), txn(0x1800, "two"), quiet()),
	}
	stream := streamOver(link, 30*time.Millisecond)

	first, err := stream.Since(context.Background(), "0/1000")
	if err != nil {
		t.Fatalf("Since: %v", err)
	}
	if first.Schema != "sha256:abc" {
		t.Fatalf("Schema = %q", first.Schema)
	}
	if err := stream.Confirm(context.Background(), first.Position); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	second, err := stream.Since(context.Background(), first.Position)
	if err != nil {
		t.Fatalf("the second batch: %v", err)
	}
	if second.Schema != first.Schema {
		t.Fatalf("the second batch carries %q and the first %q", second.Schema, first.Schema)
	}
	// TAKEN ONCE, BEFORE THE SESSION OPENED, because that is the only moment it is reachable over
	// the one connection the agent holds: a query inside the copy is FATAL and the copy cannot be
	// reopened, both measured (change_docker_test.go). Stream.schema says what that costs.
	if link.fingerprints != 1 {
		t.Fatalf("%d fingerprints for two cycles; the second one cannot have been taken over a "+
			"connection that is in CopyBoth", link.fingerprints)
	}

	// And a fingerprint that came back empty is refused before a session is opened, because an
	// empty one compares equal to every other and would make the DDL check pass forever.
	unreachable := &fakeLink{resume: 0x1000, schemaErr: errors.New("the catalog is unreachable")}
	blank := streamOver(unreachable, 30*time.Millisecond)
	if _, err := blank.Since(context.Background(), "0/1000"); err == nil {
		t.Fatal("a stream whose fingerprint failed opened a session anyway")
	}
	if unreachable.starts != 0 {
		t.Fatal("a replication session was opened for a cycle whose schema nobody could read, and " +
			"once it is open nothing can read one")
	}
}
