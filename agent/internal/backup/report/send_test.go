package report

// Two things are being proven here, and they are not the same thing.
//
// THE MAPPING: exactly one of Manifest, ReBase and Failure describes each outcome, and no verdict
// crosses the wire. Those tests need no server — a Fact goes in and a CycleReport comes out.
//
// THE COST OF A REFUSAL: a send that fails must cost the backup nothing. That one is proven against
// the REAL upload.Client and a real HTTP server that refuses everything, because a fake Sender that
// returns an error proves only that this file's own error handling compiles.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/manukyanv07/parity-scanner/agent/internal/backup"
	"github.com/manukyanv07/parity-scanner/agent/internal/backup/schedule"
	"github.com/manukyanv07/parity-scanner/agent/internal/upload"
	"github.com/manukyanv07/parity-scanner/contract"
)

var at = time.Date(2026, 8, 21, 12, 0, 2, 0, time.UTC)

const (
	scope = "install-7/pg1/orders"

	// THE BARE IDENTIFIER, lower-case, and not the /subscriptions/{sub} path — contract.md §2.5
	// pins it, and the scanner writes it this way (collectors/azure: "a subscription GUID is a
	// key"). This is the only executable example of a CycleReport envelope in the repo, so getting
	// it wrong here is how the join to the scan of the same estate quietly stops working.
	account = "sub-1"
)

// caught is a Sender that keeps what it was handed, so a test can read the payload back.
type caught struct {
	reports []*contract.CycleReport
	err     error
}

func (c *caught) SendCycle(_ context.Context, r *contract.CycleReport) error {
	c.reports = append(c.reports, r)
	return c.err
}

func manifest() *contract.Manifest {
	return &contract.Manifest{
		ContractVersion: contract.BackupContractVersion,
		Kind:            contract.BackupChange,
		Source: contract.BackupSource{
			Provider: contract.ProviderAzure, ResourceID: "/subscriptions/sub-1/x",
			Account: account, Database: "orders", Engine: "postgres", EngineVersion: "16",
		},
		ReadPoint: contract.ReadPoint{At: "2026-08-21T12:00:00Z", Position: "0/1A2B3C8", From: "0/1A2B000"},
		Artifact:  contract.Artifact{Format: contract.FormatChangeJSONL, Bytes: 2048},
		Producer:  contract.Producer{Agent: "scanner/0.1.0"},
		Transfer:  contract.RouteAgentStream,
	}
}

// sender builds a reporter over a fake Sender, with the manifest the cycle is pretending to have
// written.
func sender(to Sender, wrote *contract.Manifest) Send {
	return Send{
		To: to, Chain: scope, Account: account,
		Manifest: func() *contract.Manifest { return wrote },
		Errs:     &strings.Builder{},
	}
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// The mapping: one Fact in, one outcome on the wire.
// ─────────────────────────────────────────────────────────────────────────────────────────────

func TestEachOutcomeReachesTheWireAsItself(t *testing.T) {
	moved := fmt.Errorf("%w: base %s, cycle %s", backup.ErrSchemaMoved, "aaa", "bbb")
	gone := fmt.Errorf("%w: vp_orders is not on the server", backup.ErrSlotGone)

	for _, tc := range []struct {
		name  string
		fact  schedule.Fact
		wrote *contract.Manifest

		sent    bool                  // a report reached the wire at all
		payload string                // which of the three describes it
		reason  contract.ReBaseReason // on a re-base
	}{
		{
			name:    "a change cycle that stored something carries its manifest",
			fact:    schedule.Fact{At: at, Kind: schedule.KindChange, OK: true, Chain: schedule.Live},
			wrote:   manifest(),
			sent:    true,
			payload: "manifest",
		},
		{
			name:    "a base copy that worked carries its manifest too",
			fact:    schedule.Fact{At: at, Kind: schedule.KindBase, OK: true, Chain: schedule.Live},
			wrote:   manifest(),
			sent:    true,
			payload: "manifest",
		},
		{
			// THE WHOLE REASON CycleFailure EXISTS. Failing every hour for a week must not encode
			// identically to never having been scheduled.
			name: "a cycle that merely failed carries a failure",
			fact: schedule.Fact{At: at, Kind: schedule.KindChange, Recoverable: "0/1A2B000",
				Chain: schedule.Live, Reason: schedule.ReasonCycleFailed,
				Err: errors.New("backup: store the object: 503")},
			sent:    true,
			payload: "failure",
		},
		{
			name: "a migration under the chain carries a re-base",
			fact: schedule.Fact{At: at, Kind: schedule.KindChange, Recoverable: "0/1A2B000",
				Chain: schedule.ReBasing, Reason: schedule.ReasonSchemaMoved, Err: moved},
			sent:    true,
			payload: "rebase",
			reason:  contract.ReBaseSchemaChanged,
		},
		{
			name: "a lost slot carries a re-base, and says so differently",
			fact: schedule.Fact{At: at, Kind: schedule.KindChange, Recoverable: "0/1A2B000",
				Chain: schedule.ReBasing, Reason: schedule.ReasonSlotGone, Err: gone},
			sent:    true,
			payload: "rebase",
			reason:  contract.ReBaseSlotLost,
		},
		{
			// The scheduler overwrites the reason with rebase-loop on the last one, so the cause
			// survives only in the error. It is still a chain that ended, and the marker for it is
			// in the store.
			name: "the last of a re-base loop still reports which cause ended the chain",
			fact: schedule.Fact{At: at, Kind: schedule.KindChange, Recoverable: "0/1A2B000",
				Chain: schedule.Stopped, Reason: schedule.ReasonReBaseLoop, Err: moved},
			sent:    true,
			payload: "rebase",
			reason:  contract.ReBaseSchemaChanged,
		},
		{
			// Cycle.Base writes no re-base marker on any path, so there is no ended chain to
			// report — there is a base copy that failed, and the run stops. Reporting it as a
			// re-base would tell whoever reads it that a new base copy is owed, when the whole
			// point is that the last one could not be taken.
			name: "a base copy that failed on a moved schema is a failure and not a re-base",
			fact: schedule.Fact{At: at, Kind: schedule.KindBase, Chain: schedule.Stopped,
				Reason: schedule.ReasonBaseFailed, Err: moved},
			sent:    true,
			payload: "failure",
		},
		{
			// Nothing was stored, so there is no manifest, and the contract says all three nil is
			// not a thing a cycle can mean. See the note on quiet in send.go.
			name:  "a quiet database produced nothing to report",
			fact:  schedule.Fact{At: at, Kind: schedule.KindChange, OK: true, Chain: schedule.Live, Reason: schedule.ReasonNoChanges},
			wrote: nil,
			sent:  false,
		},
		{
			// An ordinary stop is not a failed cycle, and schedule.go goes out of its way to say
			// so. Every rolling restart would otherwise land a cycle-failed on the wire.
			name: "a shutdown is not a cycle that failed",
			fact: schedule.Fact{At: at, Kind: schedule.KindChange, Recoverable: "0/1A2B000",
				Chain: schedule.Stopped, Reason: schedule.ReasonShutdown, Err: context.Canceled},
			sent: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			to := &caught{}
			sender(to, tc.wrote).Report(context.Background(), tc.fact)

			if !tc.sent {
				if len(to.reports) != 0 {
					t.Fatalf("a cycle with nothing to say sent %+v", to.reports[0])
				}
				return
			}
			if len(to.reports) != 1 {
				t.Fatalf("sent %d reports, want exactly 1", len(to.reports))
			}
			got := to.reports[0]

			if got.ContractVersion != contract.BackupContractVersion {
				t.Errorf("contract version %d", got.ContractVersion)
			}
			if got.Chain != scope || got.Account != account {
				t.Errorf("the envelope does not say whose chain this is: %+v", got)
			}
			if got.At != at.Format(time.RFC3339) {
				t.Errorf("at = %q, want %q", got.At, at.Format(time.RFC3339))
			}

			// EXACTLY ONE describes the outcome. All three nil says nothing happened, and two
			// would say two things happened.
			set := map[string]bool{
				"manifest": got.Manifest != nil,
				"rebase":   got.ReBase != nil,
				"failure":  got.Failure != nil,
			}
			for name, present := range set {
				if present != (name == tc.payload) {
					t.Errorf("%s present=%t, want %t: %+v", name, present, name == tc.payload, got)
				}
			}

			switch tc.payload {
			case "rebase":
				if got.ReBase.Reason != tc.reason {
					t.Errorf("re-base reason %q, want %q", got.ReBase.Reason, tc.reason)
				}
				// The field anybody acts on: a chain that is dead and one that is dead as of an
				// hour ago are different incidents.
				if got.ReBase.Recoverable != string(tc.fact.Recoverable) {
					t.Errorf("re-base recoverable %q, want %q", got.ReBase.Recoverable, tc.fact.Recoverable)
				}
				if got.ReBase.Detail == "" {
					t.Error("the re-base carries no sentence anybody can read")
				}
			case "failure":
				if got.Failure.Detail != tc.fact.Err.Error() {
					t.Errorf("failure detail %q, want the error's own words %q",
						got.Failure.Detail, tc.fact.Err)
				}
			}
		})
	}
}

// AD-021, at the seam rather than in the contract: the agent brings facts, the engine judges. The
// contract's own test pins the type; this one pins what THIS PRODUCER puts in it.
//
// Fact.Achieved is the field this test exists for. It is measured rather than configured, so it is
// arguably a fact — and it is one subtraction from "this install is behind its RPO", which is a
// verdict, and the engine cannot check it because it is arithmetic on the agent's own clock. The
// engine derives the same interval from consecutive At values, which it holds already and can
// compare against its own receive time. So Achieved stays on the log line and does not cross.
//
// Interval is left off for the same reason from the other side: it is the customer's configured RPO,
// the engine already has it, and its only use here would be to be compared with Achieved.
func TestNoVerdictLeavesThisReporter(t *testing.T) {
	// The contract's own blocklist, plus the two this producer had in its hand and did not send.
	// Kind, reason and recoverable are NOT here: they are the contract's own fields on a manifest
	// and a re-base, and they are facts in its vocabulary rather than anything derived.
	forbidden := []string{
		"verdict", "decision", "healthy", "stale", "severity", "alert", "status", "ok",
		"achievedRpo", "rpo", "rpoSeconds", "lagSeconds", "pressure", "degraded",
		"achieved", "interval",
	}

	facts := []schedule.Fact{
		{At: at, Kind: schedule.KindChange, OK: true, Chain: schedule.Live,
			Achieved: 5*time.Minute + 2*time.Second, Interval: 5 * time.Minute},
		{At: at, Kind: schedule.KindChange, Recoverable: "0/1A2B000", Chain: schedule.Live,
			Reason: schedule.ReasonCycleFailed, Achieved: 11 * time.Minute,
			Interval: 5 * time.Minute, Err: errors.New("backup: the store refused the object")},
		{At: at, Kind: schedule.KindChange, Recoverable: "0/1A2B000", Chain: schedule.ReBasing,
			Reason: schedule.ReasonSchemaMoved, Achieved: 5 * time.Minute, Interval: 5 * time.Minute,
			Err: fmt.Errorf("%w: it moved", backup.ErrSchemaMoved)},
	}

	to := &caught{}
	send := sender(to, manifest())
	for _, f := range facts {
		send.Report(context.Background(), f)
	}
	if len(to.reports) != len(facts) {
		t.Fatalf("sent %d reports for %d facts", len(to.reports), len(facts))
	}

	for _, r := range to.reports {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var generic map[string]any
		if err := json.Unmarshal(b, &generic); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		objects := []map[string]any{generic}
		for _, key := range []string{"manifest", "rebase", "failure", "slot"} {
			if obj, ok := generic[key].(map[string]any); ok {
				objects = append(objects, obj)
			}
		}
		for _, obj := range objects {
			for _, f := range forbidden {
				if _, found := obj[f]; found {
					t.Errorf("%q reached the wire — it is the engine's to derive or to decide: %s", f, b)
				}
			}
		}
	}
}

// Absent is "not measured", never zero. This build has no source for the primary's disk and the
// brake's readings never leave its goroutine, so every report says nothing about the slot rather
// than three zeroes, which would read as a full disk holding nothing.
func TestTheSlotIsAbsentRatherThanZeroed(t *testing.T) {
	to := &caught{}
	sender(to, manifest()).Report(context.Background(),
		schedule.Fact{At: at, Kind: schedule.KindChange, OK: true, Chain: schedule.Live})

	if len(to.reports) != 1 {
		t.Fatalf("sent %d reports", len(to.reports))
	}
	if to.reports[0].Slot != nil {
		t.Errorf("a slot reading nobody took reached the wire: %+v", to.reports[0].Slot)
	}
	b, err := json.Marshal(to.reports[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "slot") {
		t.Errorf("an unmeasured slot was encoded rather than omitted: %s", b)
	}
}

// The manifest is asked for ONCE PER CYCLE and never remembered. A quiet cycle after a stored one
// must not re-send the stored one's manifest, which would claim a backup that did not happen.
func TestAQuietCycleAfterAStoredOneClaimsNothing(t *testing.T) {
	wrote := manifest()
	to := &caught{}
	send := Send{
		To: to, Chain: scope, Account: account,
		Manifest: func() *contract.Manifest { return wrote },
		Errs:     &strings.Builder{},
	}

	send.Report(context.Background(),
		schedule.Fact{At: at, Kind: schedule.KindChange, OK: true, Chain: schedule.Live})
	// The chain clears what it wrote at the start of every cycle, so a cycle that stored nothing
	// answers nil.
	wrote = nil
	send.Report(context.Background(),
		schedule.Fact{At: at, Kind: schedule.KindChange, OK: true, Chain: schedule.Live,
			Reason: schedule.ReasonNoChanges})

	if len(to.reports) != 1 {
		t.Fatalf("sent %d reports; the quiet cycle re-sent the stored cycle's manifest", len(to.reports))
	}
}

// The line a human reads at 3am is written whether or not the network is, and it is written FIRST.
func TestTheLogLineIsWrittenEvenWhenTheSendIsNot(t *testing.T) {
	var lines strings.Builder
	to := &caught{err: errors.New("upload: the api returned 404")}
	send := Send{
		To: to, Chain: scope, Account: account,
		Manifest: func() *contract.Manifest { return manifest() },
		Also:     schedule.Log{To: &lines},
		Errs:     &strings.Builder{},
	}
	send.Report(context.Background(),
		schedule.Fact{At: at, Kind: schedule.KindChange, OK: true, Chain: schedule.Live,
			Achieved: 5 * time.Minute, Interval: 5 * time.Minute})

	if !strings.Contains(lines.String(), "backup change: ok=true") {
		t.Errorf("the log line did not survive a failing send: %q", lines.String())
	}
	// And Achieved is on it, which is the other half of the AD-021 decision: it is not lost, it is
	// simply not the engine's to be handed.
	if !strings.Contains(lines.String(), "achieved=5m0s") {
		t.Errorf("the measured interval left the log line too: %q", lines.String())
	}
}

// A reporter with no Sender is a run with the control plane switched off — the ordinary case for an
// install that has no API url — and it must still write its lines rather than fall over.
func TestReportingIsOptional(t *testing.T) {
	var lines strings.Builder
	send := Send{Chain: scope, Account: account, Also: schedule.Log{To: &lines}}
	send.Report(context.Background(),
		schedule.Fact{At: at, Kind: schedule.KindChange, OK: true, Chain: schedule.Live})

	if lines.Len() == 0 {
		t.Error("a run with no control plane wrote no line either")
	}
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// What a refusal costs. Against the real client and a real server.
// ─────────────────────────────────────────────────────────────────────────────────────────────

// refusing is an API that answers every request with status, counting what it was asked.
func refusing(t *testing.T, status int) (*upload.Client, func() int) {
	t.Helper()
	var mu sync.Mutex
	hits := 0
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		w.WriteHeader(status)
	}))
	t.Cleanup(s.Close)
	return &upload.Client{BaseURL: s.URL, APIKey: "parity_testkey", HTTP: s.Client()},
		func() int { mu.Lock(); defer mu.Unlock(); return hits }
}

// /v1/backups does not exist yet, so a 404 is the answer in the field TODAY. It must cost a line in
// a log and nothing else.
func TestARefusedSendCostsALineAndNothingElse(t *testing.T) {
	for _, status := range []int{
		http.StatusNotFound, http.StatusInternalServerError,
		http.StatusUnauthorized, http.StatusBadRequest,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			client, hits := refusing(t, status)
			var errs, lines strings.Builder
			send := Send{
				To: client, Chain: scope, Account: account,
				Manifest: func() *contract.Manifest { return manifest() },
				Also:     schedule.Log{To: &lines},
				Errs:     &errs,
			}

			send.Report(context.Background(),
				schedule.Fact{At: at, Kind: schedule.KindChange, OK: true, Chain: schedule.Live})

			if hits() != 1 {
				t.Errorf("the api was asked %d times", hits())
			}
			if errs.Len() == 0 {
				t.Error("a lost report was lost silently")
			}
			if !strings.Contains(lines.String(), "ok=true") {
				t.Errorf("the cycle's own line did not survive: %q", lines.String())
			}
		})
	}
}

// An API that never answers must not become an RPO that slips. Report is called on the cycle loop's
// own goroutine, between two cycles, so it bounds itself.
func TestAnApiThatNeverAnswersDoesNotHoldTheLoop(t *testing.T) {
	block := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-block }))
	defer func() { close(block); s.Close() }()

	var errs strings.Builder
	send := Send{
		To:       &upload.Client{BaseURL: s.URL, APIKey: "k", HTTP: s.Client()},
		Chain:    scope,
		Account:  account,
		Manifest: func() *contract.Manifest { return manifest() },
		Timeout:  150 * time.Millisecond,
		Errs:     &errs,
	}

	done := make(chan time.Duration, 1)
	go func() {
		began := time.Now()
		send.Report(context.Background(),
			schedule.Fact{At: at, Kind: schedule.KindChange, OK: true, Chain: schedule.Live})
		done <- time.Since(began)
	}()

	select {
	case took := <-done:
		if took > 5*time.Second {
			t.Errorf("the report held the cycle loop for %s", took)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Report never came back — a hung api is holding the backup loop open")
	}
	if errs.Len() == 0 {
		t.Error("a report abandoned on a timeout was abandoned silently")
	}
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE DELIVERABLE: the loop keeps backing up, and keeps acknowledging, while every report is
// refused. Driven through the real scheduler and the real client.
// ─────────────────────────────────────────────────────────────────────────────────────────────

// fakeChain is a chain that works. It records that each cycle ran and that each one ACKNOWLEDGED —
// which in the real chain is Confirm, called inside Cycle before it returns and therefore before
// any report is built. The counters are what the test reads to say the backup was unaffected.
type fakeChain struct {
	mu        sync.Mutex
	cycles    int
	confirmed int
	reach     backup.Position
	wrote     *contract.Manifest
}

func (f *fakeChain) Base(context.Context) (backup.Position, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cycles++
	f.reach = "0/1000000"
	f.wrote = manifest()
	f.confirmed++
	return f.reach, nil
}

func (f *fakeChain) Cycle(context.Context) (backup.Position, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cycles++
	f.reach = backup.Position(fmt.Sprintf("0/%d", 0x1000000+f.cycles))
	f.wrote = manifest()
	// The acknowledgement, and it happens HERE — inside the cycle, after the manifest — which is
	// what makes it structurally impossible for a report to block or precede it.
	f.confirmed++
	return f.reach, nil
}

func (f *fakeChain) manifest() *contract.Manifest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.wrote
}

func (f *fakeChain) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.cycles, f.confirmed
}

func TestEveryReportRefusedAndEveryBackupStillTaken(t *testing.T) {
	client, hits := refusing(t, http.StatusNotFound)
	chain := &fakeChain{}
	var errs, lines strings.Builder

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	clock := &schedule.Scheduler{
		Chain:    chain,
		Interval: time.Millisecond,
		Report: Send{
			To: client, Chain: scope, Account: account,
			Manifest: chain.manifest,
			Also:     schedule.Log{To: &lines},
			Errs:     &errs,
		},
	}

	ran := make(chan error, 1)
	go func() { ran <- clock.Run(ctx) }()

	// Let it take a handful of cycles against an API that refuses every one of them.
	deadline := time.After(10 * time.Second)
	for {
		if cycles, _ := chain.counts(); cycles >= 5 {
			break
		}
		select {
		case <-deadline:
			cycles, _ := chain.counts()
			t.Fatalf("only %d cycles ran; a refused report is stalling the loop", cycles)
		case err := <-ran:
			t.Fatalf("the run stopped on a refused report: %v", err)
		default:
			time.Sleep(time.Millisecond)
		}
	}
	cancel()

	select {
	case err := <-ran:
		// An ordinary shutdown. A run that ended in an error because the API refused a report
		// would be a send failure that failed a backup.
		if err != nil {
			t.Fatalf("the run ended in an error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the run never came back")
	}

	cycles, confirmed := chain.counts()
	if cycles != confirmed {
		t.Errorf("%d cycles ran and %d acknowledged: a refused report cost an acknowledgement",
			cycles, confirmed)
	}
	if cycles < 5 {
		t.Errorf("only %d cycles ran", cycles)
	}
	// Every cycle stored something, so every cycle had something to report, and every one of them
	// was refused. The proof that the refusals were real 404s and not a send that was skipped.
	//
	// cycles-1 rather than cycles: the counter is incremented INSIDE the cycle and the report is
	// built after it returns, so the last one is legitimately still in flight when cancel lands —
	// and a shutdown cancelling a report in flight is the documented behaviour, not a miss.
	if hits() < cycles-1 {
		t.Errorf("the api was only asked %d times for %d cycles", hits(), cycles)
	}
	if errs.Len() == 0 {
		t.Error("every report was lost and nothing said so")
	}
	if !strings.Contains(lines.String(), "ok=true") {
		t.Errorf("the cycles did not report as healthy: %q", lines.String())
	}
}
