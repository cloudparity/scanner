package upload

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/manukyanv07/parity-scanner/contract"
)

func estate() *contract.Estate {
	return &contract.Estate{
		ContractVersion: contract.ContractVersion,
		Scan: contract.ScanMeta{
			Provider: contract.ProviderAzure, Account: "/subscriptions/sub-1",
			ScannedAt: "2026-08-16T09:00:00Z", Collector: "azure/0.1.0", ResourceCount: 1,
		},
		Resources: []contract.Resource{{
			Provider: contract.ProviderAzure, ID: "/subscriptions/sub-1/x", Type: "microsoft.keyvault/vaults",
			Name: "kv1", Account: "/subscriptions/sub-1", Document: json.RawMessage(`{}`),
		}},
	}
}

// server returns a client pointed at a stub, bypassing the https rule that New enforces.
//
// Handlers here discard fmt.Fprint's result: a reply the client did not get fails the assertion
// on the client side, which is where every test looks.
func server(t *testing.T, h http.HandlerFunc) (*Client, *httptest.Server) {
	t.Helper()
	s := httptest.NewServer(h)
	t.Cleanup(s.Close)
	return &Client{BaseURL: s.URL, APIKey: "parity_testkey", HTTP: s.Client()}, s //gosec:disable G101 -- a stub server accepts any key; this one is a fixture
}

func TestASuccessfulUpload(t *testing.T) {
	var gotKey, gotPath, gotType string
	var gotBody []byte
	c, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
		gotKey, gotPath, gotType = r.Header.Get(KeyHeader), r.URL.Path, r.Header.Get("content-type")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprint(w, `{"scanId":"1a2b3c4d-5e6f-4a7b-8c9d-0e1f2a3b4c5d","resourceCount":1}`)
	})

	got, err := c.Send(context.Background(), estate())
	if err != nil {
		t.Fatalf("a good upload failed: %v", err)
	}
	if got.ScanID == "" || got.ResourceCount != 1 {
		t.Errorf("result %+v", got)
	}
	if gotPath != "/v1/scans" {
		t.Errorf("posted to %q", gotPath)
	}
	if gotKey != "parity_testkey" {
		t.Errorf("key header was %q", gotKey)
	}
	if gotType != "application/json" {
		t.Errorf("content-type was %q", gotType)
	}
	// The estate must arrive intact, not re-shaped on the way out.
	var round contract.Estate
	if err := json.Unmarshal(gotBody, &round); err != nil {
		t.Fatalf("what arrived was not an estate: %v", err)
	}
	if len(round.Resources) != 1 || round.Scan.Account != "/subscriptions/sub-1" {
		t.Errorf("the estate changed in transit: %+v", round.Scan)
	}
}

// THE CREDENTIAL MUST TRAVEL IN A HEADER AND NOWHERE ELSE. A key in a query string lands in access
// logs, proxy logs and browser history.
func TestTheKeyIsNeverInTheUrlOrTheBody(t *testing.T) {
	var url string
	var body []byte
	c, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
		url = r.URL.String()
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprint(w, `{"scanId":"x","resourceCount":1}`)
	})
	if _, err := c.Send(context.Background(), estate()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(url, "parity_testkey") {
		t.Errorf("the key is in the url: %s", url)
	}
	if strings.Contains(string(body), "parity_testkey") {
		t.Error("the key is in the request body")
	}
}

// A refusal must say something the person holding the key can act on.
func TestFailuresExplainThemselves(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		expect string
	}{
		{"unauthorized", 401, `{"error":"the request was not authenticated"}`, "api key was refused"},
		{"too large", 413, `{"error":"too large"}`, "too large for the api"},
		{"server error", 500, `{"error":"nope"}`, "returned 500"},
		{"gateway html", 502, "<html>Bad Gateway</html>", "returned 502"},
		{"empty body", 503, "", "(no body)"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := server(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = fmt.Fprint(w, tc.body)
			})
			_, err := c.Send(context.Background(), estate())
			if err == nil {
				t.Fatal("no error for a failed upload")
			}
			if !strings.Contains(err.Error(), tc.expect) {
				t.Errorf("error %q does not contain %q", err, tc.expect)
			}
			if strings.Contains(err.Error(), "parity_testkey") {
				t.Error("the error message leaks the api key")
			}
		})
	}
}

// A validation failure carries the exact field at fault. That is the difference between "the upload
// failed" and a message a collector author can fix.
func TestValidationProblemsAreSurfaced(t *testing.T) {
	c, _ := server(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(400)
		_, _ = fmt.Fprint(w, `{"error":"the scan did not pass validation","problems":[
			{"path":"resources[3].type","message":"required"},
			{"path":"scan.provider","message":"unknown provider \"nope\""}]}`)
	})
	_, err := c.Send(context.Background(), estate())
	if err == nil {
		t.Fatal("no error")
	}
	for _, want := range []string{"resources[3].type", "required", "scan.provider"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not mention %q: %v", want, err)
		}
	}
}

// A long list of problems must not become an unreadable wall.
func TestTooManyProblemsAreTruncated(t *testing.T) {
	var problems []string
	for i := 0; i < 40; i++ {
		problems = append(problems, fmt.Sprintf(`{"path":"resources[%d].type","message":"required"}`, i))
	}
	c, _ := server(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(400)
		_, _ = fmt.Fprintf(w, `{"error":"bad","problems":[%s]}`, strings.Join(problems, ","))
	})
	_, err := c.Send(context.Background(), estate())
	if err == nil {
		t.Fatal("no error")
	}
	if !strings.Contains(err.Error(), "and 35 more") {
		t.Errorf("a 40-problem response was not truncated: %v", err)
	}
}

// An enormous error body must not become an enormous log line.
func TestAHugeErrorBodyIsBounded(t *testing.T) {
	c, _ := server(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
		_, _ = fmt.Fprint(w, strings.Repeat("x", 5<<20))
	})
	_, err := c.Send(context.Background(), estate())
	if err == nil {
		t.Fatal("no error")
	}
	if len(err.Error()) > 1000 {
		t.Errorf("error message is %d bytes", len(err.Error()))
	}
}

// New is the gate that stops a credential and a complete infrastructure map going out in plaintext.
func TestNewRefusesUnsafeConfiguration(t *testing.T) {
	tests := []struct {
		name, url, key string
	}{
		{"no url", "", "parity_k"},
		{"no key", "https://api.example.com", ""},
		{"whitespace key", "https://api.example.com", "   "},
		{"plain http", "http://api.example.com", "parity_k"},
		{"http localhost is still http", "http://localhost:8080", "parity_k"},
		{"no scheme", "api.example.com", "parity_k"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.url, tc.key); err == nil {
				t.Errorf("New(%q, ...) was accepted", tc.url)
			}
		})
	}

	c, err := New("https://api.example.com/", "parity_k")
	if err != nil {
		t.Fatalf("a good configuration was refused: %v", err)
	}
	if strings.HasSuffix(c.BaseURL, "/") {
		t.Errorf("the trailing slash survived: %q - the path would double up", c.BaseURL)
	}
}

func report() *contract.CycleReport {
	return &contract.CycleReport{
		ContractVersion: contract.BackupContractVersion,
		Chain:           "install-7/pg1/orders",
		Account:         "/subscriptions/sub-1",
		At:              "2026-08-16T09:00:02Z",
		Manifest: &contract.Manifest{
			ContractVersion: contract.BackupContractVersion,
			Kind:            contract.BackupChange,
			Source: contract.BackupSource{
				Provider: contract.ProviderAzure, ResourceID: "/subscriptions/sub-1/x",
				Account: "/subscriptions/sub-1", Database: "orders",
				Engine: "postgres", EngineVersion: "16",
			},
			ReadPoint: contract.ReadPoint{At: "2026-08-16T09:00:00Z", Position: "0/1A2B3C8", From: "0/1A2B000"},
			Artifact:  contract.Artifact{Format: contract.FormatChangeJSONL, Bytes: 2048},
			Producer:  contract.Producer{Agent: "azure/0.1.0"},
			Transfer:  contract.RouteAgentStream,
		},
		Slot: &contract.SlotReading{RetainedBytes: 1 << 24, DiskFreeBytes: 91268055040, DiskTotalBytes: 137438953472},
	}
}

func TestASuccessfulCycleReport(t *testing.T) {
	var gotKey, gotPath, gotURL, gotType string
	var gotBody []byte
	c, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
		gotKey, gotPath, gotType = r.Header.Get(KeyHeader), r.URL.Path, r.Header.Get("content-type")
		gotURL = r.URL.String()
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
	})

	if err := c.SendCycle(context.Background(), report()); err != nil {
		t.Fatalf("a good report failed: %v", err)
	}
	if gotPath != "/v1/backups" {
		t.Errorf("posted to %q", gotPath)
	}
	// THE CREDENTIAL TRAVELS IN A HEADER AND NOWHERE ELSE, the same rule Send follows: a key in a
	// query string lands in access logs, proxy logs and browser history.
	if strings.Contains(gotURL, "parity_testkey") {
		t.Errorf("the key is in the url: %s", gotURL)
	}
	if strings.Contains(string(gotBody), "parity_testkey") {
		t.Error("the key is in the request body")
	}
	if gotKey != "parity_testkey" {
		t.Errorf("key header was %q", gotKey)
	}
	if gotType != "application/json" {
		t.Errorf("content-type was %q", gotType)
	}

	// The report must arrive intact. What the engine derives — the achieved RPO — it derives from
	// ReadPoint.At, so a report that loses it is a dashboard with nothing on it.
	var round contract.CycleReport
	if err := json.Unmarshal(gotBody, &round); err != nil {
		t.Fatalf("what arrived was not a cycle report: %v", err)
	}
	if round.Chain != "install-7/pg1/orders" || round.Account != "/subscriptions/sub-1" {
		t.Errorf("the envelope changed in transit: %+v", round)
	}
	if round.Manifest == nil || round.Manifest.ReadPoint.At != "2026-08-16T09:00:00Z" {
		t.Errorf("the read point did not arrive: %+v", round.Manifest)
	}
	if round.Slot == nil || round.Slot.RetainedBytes != 1<<24 {
		t.Errorf("the slot reading did not arrive: %+v", round.Slot)
	}
}

// A 202 is as much an acceptance as a 201. The endpoint does not exist yet, and pinning the
// success set to one exact code is how a queueing ingest later reads as a failure.
func TestAnAcceptedCycleReportIsNotAFailure(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusCreated, http.StatusAccepted, http.StatusNoContent} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			c, _ := server(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
			})
			if err := c.SendCycle(context.Background(), report()); err != nil {
				t.Errorf("a %d was treated as a failure: %v", status, err)
			}
		})
	}
}

// THE WHOLE POINT OF THIS METHOD'S ERROR CONTRACT. /v1/backups is unbuilt, and even /v1/scans is
// not deployed, so every one of these is what an agent in the field will meet today. Each must
// come back as a named, retryable send failure the caller can log — never a panic, never a
// silence, and never something a caller could mistake for the backup itself having failed.
func TestEveryFailureIsReportedToTheCaller(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		expect string
	}{
		{"the endpoint does not exist yet", 404, `{"error":"not found"}`, "returned 404"},
		{"the api is broken", 500, `{"error":"nope"}`, "returned 500"},
		{"the api key was refused", 401, `{"error":"unauthenticated"}`, "api key was refused"},
		{"a proxy answered with a page", 502, "<html>Bad Gateway</html>", "returned 502"},
		{"nothing was said at all", 503, "", "(no body)"},
		{"the body was rejected", 400, `{"error":"the report did not pass validation","problems":[
			{"path":"manifest.readPoint.position","message":"required"}]}`, "manifest.readPoint.position"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := server(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = fmt.Fprint(w, tc.body)
			})
			err := c.SendCycle(context.Background(), report())
			if err == nil {
				t.Fatal("a failed send was reported as a success — the caller would log nothing")
			}
			if !strings.Contains(err.Error(), tc.expect) {
				t.Errorf("error %q does not contain %q", err, tc.expect)
			}
			if strings.Contains(err.Error(), "parity_testkey") {
				t.Error("the error message leaks the api key")
			}
		})
	}
}

// A hung control plane must not hold a backup cycle open. The deadline is the caller's, and it
// comes back as an error like any other rather than as a process sitting on a socket.
func TestATimeoutIsAnOrdinarySendFailure(t *testing.T) {
	block := make(chan struct{})
	c, _ := server(t, func(w http.ResponseWriter, _ *http.Request) {
		<-block
		w.WriteHeader(http.StatusCreated)
	})
	// ORDER MATTERS AND t.Cleanup IS LIFO. server registered s.Close first, so this runs BEFORE it
	// and releases the handler; registered the other way round, Close would block on the in-flight
	// request and the test would hang for five seconds and then complain about itself.
	t.Cleanup(func() { close(block) })

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- c.SendCycle(ctx, report()) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a timed-out send was reported as a success")
		}
		if !strings.Contains(err.Error(), "report") {
			t.Errorf("the error does not say what failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SendCycle did not return — a hung api would hold the backup cycle open")
	}
}

// A SEND FAILURE IS NOT A LOST BACKUP. The bytes are in the store and the manifest is beside
// them before this is ever called; the only thing a 404 costs is a row on a dashboard, and the
// next cycle's report carries the same read point forward. This test is the executable form of
// that: the same report, refused and then accepted, with nothing consumed in between.
func TestAFailedSendCostsNothingButTheRow(t *testing.T) {
	var attempts int
	c, _ := server(t, func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, `{"error":"not found"}`)
			return
		}
		body, _ := io.ReadAll(r.Body)
		var got contract.CycleReport
		if err := json.Unmarshal(body, &got); err != nil || got.Manifest == nil {
			t.Errorf("the retried report was not the report: %s", body)
		}
		w.WriteHeader(http.StatusCreated)
	})

	rep := report()
	if err := c.SendCycle(context.Background(), rep); err == nil {
		t.Fatal("the 404 was swallowed")
	}
	// Unchanged by the failed attempt: the caller holds the same value and can send it again.
	if rep.Manifest == nil || rep.Manifest.ReadPoint.Position != "0/1A2B3C8" {
		t.Fatalf("the failed send mutated the report: %+v", rep)
	}
	if err := c.SendCycle(context.Background(), rep); err != nil {
		t.Fatalf("the retry failed: %v", err)
	}
}

// A cancelled context must stop the upload rather than run to the timeout.
func TestCancellationIsHonoured(t *testing.T) {
	c, _ := server(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = fmt.Fprint(w, `{"scanId":"x"}`)
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Send(ctx, estate()); err == nil {
		t.Fatal("a cancelled upload succeeded")
	}
}

// snippet is the bound on what an unexpected body contributes to a log line.
func TestSnippetBoundsTheBodyAtTwoHundredBytes(t *testing.T) {
	for name, tc := range map[string]struct{ in, want string }{
		"empty":       {"", "(no body)"},
		"whitespace":  {" \n\t", "(no body)"},
		"short":       {"  not json  ", "not json"},
		"exactly 200": {strings.Repeat("a", 200), strings.Repeat("a", 200)},
		"over 200":    {strings.Repeat("b", 201), strings.Repeat("b", 200) + "…"},
	} {
		t.Run(name, func(t *testing.T) {
			if got := snippet([]byte(tc.in)); got != tc.want {
				t.Errorf("snippet(%d bytes) = %q, want %q", len(tc.in), got, tc.want)
			}
		})
	}
}
