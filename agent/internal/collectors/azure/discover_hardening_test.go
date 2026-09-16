package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
)

// The SDK unmarshals the response body into `any` with encoding/json, which widens every
// JSON number to float64: 9007199254740993 comes back as ...992, permanently and
// undetectably, and a config-diffing engine then reports a phantom change forever. Decoding
// the raw body with UseNumber keeps the literal digits, which is what contract.md §2.1's
// "exactly as the cloud returned it" requires.
func TestDecodeRowsPreservingNumbersKeepsLargeIntegersExact(t *testing.T) {
	body := []byte(`{
      "totalRecords": 1,
      "count": 1,
      "data": [
        {
          "id": "/subscriptions/s/providers/Microsoft.Compute/disks/d",
          "properties": {
            "sequenceNumber": 9007199254740993,
            "diskSizeBytes": 1099511627776,
            "hugeCapacity": 2000000000000000000000,
            "ratio": 1.0
          }
        }
      ]
    }`)

	rows, err := decodeRowsPreservingNumbers(body)
	if err != nil {
		t.Fatalf("decodeRowsPreservingNumbers: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}

	// Re-marshalled, the digits must be byte-identical to what the service sent.
	encoded, err := json.Marshal(map[string]any(rows[0]))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, want := range []string{"9007199254740993", "1099511627776", "2000000000000000000000"} {
		if !strings.Contains(string(encoded), want) {
			t.Errorf("%s did not survive the round trip:\n%s", want, encoded)
		}
	}
	if strings.Contains(string(encoded), "9007199254740992") {
		t.Error("the integer was widened to float64 and lost its last digit")
	}

	// And prove the lossy path really is lossy, so this test is measuring something.
	var viaAny map[string]any
	if err := json.Unmarshal(body, &viaAny); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	lossy, err := json.Marshal(viaAny)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(lossy), "9007199254740992") {
		t.Skip("this Go version no longer widens large integers; the guard above is now belt-and-braces")
	}
}

func TestDecodeRowsPreservingNumbersRejectsNonsense(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"not json", `{{{`},
		{"data is an object", `{"data":{"id":"x"}}`},
		{"row is a scalar", `{"data":["nope"]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeRowsPreservingNumbers([]byte(tc.body)); err == nil {
				t.Error("want an error; a body we cannot read must not look like an empty page")
			}
		})
	}
	rows, err := decodeRowsPreservingNumbers([]byte(`{"totalRecords":0,"data":[]}`))
	if err != nil || len(rows) != 0 {
		t.Errorf("an empty data array is a valid empty page: %v, %d rows", err, len(rows))
	}
}

// decodePage must fall back to the SDK's decoded tree when no raw response was captured,
// which is every unit test and any SDK version that stops buffering the body.
func TestDecodePageFallsBackWithoutARawResponse(t *testing.T) {
	got, err := decodePage(nil, []any{map[string]any{"id": "a"}})
	if err != nil {
		t.Fatalf("decodePage: %v", err)
	}
	if len(got) != 1 || got[0]["id"] != "a" {
		t.Errorf("fallback lost the row: %+v", got)
	}
}

// Two alternating tokens defeat a guard that only compares against the previous one. The
// caller's context may carry no deadline, so nothing else stops the walk and the row slice
// grows without bound.
func TestQueryResourcesRefusesAlternatingTokens(t *testing.T) {
	calls := 0
	alternating := func(_ context.Context, _ armresourcegraph.QueryRequest, _ *armresourcegraph.ClientResourcesOptions) (armresourcegraph.ClientResourcesResponse, error) {
		calls++
		if calls > 50 {
			return armresourcegraph.ClientResourcesResponse{}, errors.New("the pager never stopped")
		}
		token := "even"
		if calls%2 == 1 {
			token = "odd"
		}
		return armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{
			Data:      rows("a"),
			SkipToken: &token,
		}}, nil
	}

	got, gaps, err := queryResources(context.Background(), graphFunc(alternating), "sub-1")
	if err == nil {
		t.Fatalf("want an error, got %d rows after %d calls", len(got), calls)
	}
	if !strings.Contains(err.Error(), "$skipToken already seen") {
		t.Errorf("error does not explain the loop: %q", err)
	}
	if calls > 5 {
		t.Errorf("took %d calls to notice the cycle", calls)
	}
	if got != nil || gaps != nil {
		t.Errorf("a failed scan returned a partial estate: %d rows, %d gaps", len(got), len(gaps))
	}
}

// A cancelled context must stop the walk at the top of the loop, not rely on the SDK to
// refuse the call.
func TestQueryResourcesHonoursContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	calls := 0
	counting := func(_ context.Context, _ armresourcegraph.QueryRequest, _ *armresourcegraph.ClientResourcesOptions) (armresourcegraph.ClientResourcesResponse, error) {
		calls++
		token := "t"
		return armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{
			Data: rows("a"), SkipToken: &token,
		}}, nil
	}

	if _, _, err := queryResources(ctx, graphFunc(counting), "sub-1"); err == nil {
		t.Fatal("want an error on a cancelled context")
	}
	if calls != 0 {
		t.Errorf("made %d calls with an already-cancelled context, want 0", calls)
	}
}

// Whatever the service does with tokens, the walk cannot exceed the record count it
// reported. This is the bound that does not depend on token behaviour at all.
func TestQueryResourcesBoundsTheWalkByReportedRecords(t *testing.T) {
	calls := 0
	endless := func(_ context.Context, _ armresourcegraph.QueryRequest, _ *armresourcegraph.ClientResourcesOptions) (armresourcegraph.ClientResourcesResponse, error) {
		calls++
		// A token that differs on every call, so that no dedupe short-circuits the walk.
		token := fmt.Sprintf("page-%c%c", 'a'+calls%26, 'a'+calls/26)
		return armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{
			Data:         rows("r"),
			SkipToken:    &token,
			TotalRecords: i64(3),
		}}, nil
	}

	_, _, err := queryResources(context.Background(), graphFunc(endless), "sub-1")
	if err == nil {
		t.Fatal("want an error once the page budget is spent")
	}
	if !strings.Contains(err.Error(), "page budget") {
		t.Errorf("error does not name the bound: %q", err)
	}
}

func TestExceededPageBudget(t *testing.T) {
	tests := []struct {
		name  string
		state completeness
		want  bool
	}{
		{"no total means no bound", completeness{pages: 1000}, false},
		{"inside the budget", completeness{baselineTotal: i64(2500), pages: 3}, false},
		{"slack absorbs mid-walk growth", completeness{baselineTotal: i64(1), pages: 8}, false},
		{"past the budget", completeness{baselineTotal: i64(1), pages: 10}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := exceededPageBudget(tt.state); got != tt.want {
				t.Errorf("exceededPageBudget = %v, want %v", got, tt.want)
			}
		})
	}
}

// ARG does not use Retry-After. It publishes a remaining-query count and a reset window,
// and expects the caller to wait; ignoring them burns the retry policy on a long walk and
// the scan dies with no partial estate and no resume point.
func TestParseResetWindow(t *testing.T) {
	tests := map[string]time.Duration{
		"00:00:05":    5 * time.Second,
		"00:01:30":    90 * time.Second,
		"01:00:00":    time.Hour,
		"7":           7 * time.Second,
		"  00:00:03 ": 3 * time.Second, //nolint:gocritic // mapKey: the padding is the fixture; the parser must trim it
		"":            0,
		"garbage":     0,
	}
	for value, want := range tests {
		if got := parseResetWindow(value); got != want {
			t.Errorf("parseResetWindow(%q) = %v, want %v", value, got, want)
		}
	}
}

func TestWaitForQuotaOnlyWaitsWhenExhausted(t *testing.T) {
	// No response captured (every unit test): must not wait.
	start := time.Now()
	waitForQuota(context.Background(), nil)
	if time.Since(start) > 50*time.Millisecond {
		t.Error("waited with no response to read")
	}

	// Quota remaining: must not wait.
	remaining := &http.Response{Header: http.Header{}}
	remaining.Header.Set(quotaRemainingHeader, "12")
	remaining.Header.Set(quotaResetsHeader, "00:00:05")
	start = time.Now()
	waitForQuota(context.Background(), remaining)
	if time.Since(start) > 50*time.Millisecond {
		t.Error("waited while quota remained")
	}

	// Exhausted, but a cancelled context must cut the wait short rather than sleeping.
	exhausted := &http.Response{Header: http.Header{}}
	exhausted.Header.Set(quotaRemainingHeader, "0")
	exhausted.Header.Set(quotaResetsHeader, "01:00:00")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start = time.Now()
	waitForQuota(ctx, exhausted)
	if time.Since(start) > time.Second {
		t.Error("a cancelled context did not cut the quota wait short")
	}
}

// The query must ask for every column. Narrowing it to `properties` alone would make every
// output column dynamic, and ARG then withholds $skipToken and caps the walk at one page.
func TestDiscoverQueryAsksForEveryColumn(t *testing.T) {
	if strings.Contains(discoverQuery, "| project") {
		t.Errorf("the query projects a whitelist, which silently drops kind, plan, zones, managedBy and apiVersion:\n%s", discoverQuery)
	}
	if !strings.Contains(discoverQuery, "order by id asc") {
		t.Errorf("paging is only consistent over an ordered result set:\n%s", discoverQuery)
	}
	// Measured against the live service: an unprojected query returns 16 columns and
	// apiVersion is not one of them, so it has to be named or every stored document has an
	// unknown schema version.
	if !strings.Contains(discoverQuery, "apiVersion") {
		t.Errorf("apiVersion is excluded from ARG's default columns and must be named:\n%s", discoverQuery)
	}
}

// The raw-body path is the one that actually fixes large-integer fidelity, and until now it
// had never executed in a test: the fake client returns a typed response with no
// *http.Response, so decodePage always took the fallback. That made the fix unverified
// exactly where it matters — a silent fallback restores the corruption with no signal.
//
// This builds the response the way azcore's pipeline leaves it (body buffered so it can be
// read again) and asserts decodePage prefers it.
func TestDecodePagePrefersTheRawBodyOverTheLossyTree(t *testing.T) {
	const exact = "9007199254740993"
	body := `{"totalRecords":1,"count":1,"data":[{"id":"/subscriptions/s/providers/Microsoft.Compute/disks/d","properties":{"sequenceNumber":` + exact + `}}]}`

	raw := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}

	// What the SDK would have handed us for the same payload: numbers already widened.
	var lossy map[string]any
	if err := json.Unmarshal([]byte(body), &lossy); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	rows, err := decodePage(raw, lossy["data"])
	if err != nil {
		t.Fatalf("decodePage: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}

	encoded, err := json.Marshal(map[string]any(rows[0]))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(encoded), exact) {
		t.Errorf("decodePage took the LOSSY path: %s does not contain %s\nIf azruntime.Payload stopped returning the buffered body, this is the canary.", encoded, exact)
	}
}
