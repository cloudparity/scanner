package schedule

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestTheLogReporterCarriesTheFactsAndPassesNoVerdict is AD-021 as a test. Everything on the line
// has to be something that happened or something that was measured; nothing on it may be this agent
// deciding, on the customer's behalf, what its own numbers mean.
func TestTheLogReporterCarriesTheFactsAndPassesNoVerdict(t *testing.T) {
	var out bytes.Buffer
	Log{To: &out}.Report(context.Background(), Fact{
		At:          epoch,
		Kind:        KindChange,
		OK:          false,
		Recoverable: "0/1A2B3C8",
		Achieved:    93 * time.Second,
		Interval:    30 * time.Second,
		Chain:       ReBasing,
		Reason:      ReasonSchemaMoved,
		Err:         errors.New("the schema moved under this chain"),
	})

	line := out.String()
	for _, want := range []string{
		"change",         // which operation
		"ok=false",       // whether it did what it set out to
		"chain=rebasing", // what the chain is now
		"0/1A2B3C8",      // the position an operator acts on during an incident
		"achieved=1m33s", // measured
		"interval=30s",   // configured, beside it, because the pair is the signal
		"reason=schema-moved",
		"the schema moved under this chain",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("the line drops %q, and it is the only place that fact reaches anything:\n%s", want, line)
		}
	}

	// NO VERDICT. These are the words an agent would use to decide for the customer, and deciding
	// is the control plane's job with the customer's own recovery objective in front of it.
	for _, never := range []string{"healthy", "unhealthy", "degraded", "critical", "severity"} {
		if strings.Contains(strings.ToLower(line), never) {
			t.Fatalf("the line passes a verdict (%q), and AD-021 says the agent brings facts:\n%s", never, line)
		}
	}
}

// A quiet cycle is not a failure and its line must not read like one.
func TestAQuietCycleLogsNoError(t *testing.T) {
	var out bytes.Buffer
	Log{To: &out}.Report(context.Background(), Fact{
		Kind: KindChange, OK: true, Chain: Live, Reason: ReasonNoChanges, Recoverable: "0/5",
	})
	line := out.String()
	if !strings.Contains(line, "ok=true") || !strings.Contains(line, "reason=no-changes") {
		t.Fatalf("a quiet cycle logged as %q", line)
	}
	if strings.Count(line, "\n") != 1 {
		t.Fatalf("a cycle with no error spilled onto a second line, which is where errors go:\n%s", line)
	}
}
