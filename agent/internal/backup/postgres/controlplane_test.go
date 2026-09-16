package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	azruntime "github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"

	"github.com/manukyanv07/parity-scanner/contract"
)

// NOT ONE OF THESE TESTS TOUCHES AZURE, AND THAT IS THE POINT (backup-shape.md §7). Everything
// worth proving about a nine-minute long-running operation is unreachable against the real
// service: a poll that stays InProgress, a poll that comes back Failed, a cancellation landing in
// the middle of the wait, a response that does not parse. Against a live subscription we could
// exercise the happy path and nothing else — and the happy path is not where a backup that never
// happened comes from.
//
// The fake speaks the shapes Microsoft documents, cited at each endpoint in controlplane.go: a 202
// with an Azure-AsyncOperation header, an operationStatus document with a status field, a
// recoveryPoints list, and a List Blobs XML body.

// dataProtection is the fake control plane. Each field is a knob one test turns; the rest keep the happy
// path so a test reads as the one thing it changes.
type dataProtection struct {
	t *testing.T

	// pollStatuses is consumed one per poll. The last value repeats, so a test that wants an
	// operation which never terminates gives a single "InProgress".
	pollStatuses []string
	pollError    string // the error document a Failed status carries
	pollBody     string // raw body, overriding pollStatuses — for the malformed case

	// asyncOperationHost overrides the host in the Azure-AsyncOperation header. A service that
	// pointed our poll at another host would be pointing our ARM token at it.
	asyncOperationHost string

	// retryAfter is the pacing the fake asks for, on the 202 and on every poll.
	retryAfter string

	// onPoll fires inside the handler, on the server's goroutine. It exists so a test can act on
	// the Nth poll without reading the counter from a second goroutine, which is a data race and
	// not a synchronisation the code under test provides.
	onPoll func()

	recoveryPoints string // the recoveryPoints response body, defaulted in newDataProtection

	backupBody  string // the request body the adhoc backup was asked with
	restoreBody string // and the restore
	polls       int
	journal     []string

	server *httptest.Server
}

func newDataProtection(t *testing.T) *dataProtection {
	t.Helper()
	a := &dataProtection{t: t, pollStatuses: []string{"Succeeded"}}

	mux := http.NewServeMux()
	const instance = "/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DataProtection/" +
		"backupVaults/vault-1/backupInstances/instance-1"

	mux.HandleFunc("POST "+instance+"/backup", func(w http.ResponseWriter, r *http.Request) {
		a.journal = append(a.journal, "backup")
		a.backupBody = readAll(t, r.Body)
		a.checkAPIVersion(r)
		a.accept(w, r)
	})
	mux.HandleFunc("POST "+instance+"/restore", func(w http.ResponseWriter, r *http.Request) {
		a.journal = append(a.journal, "restore")
		a.restoreBody = readAll(t, r.Body)
		a.checkAPIVersion(r)
		a.accept(w, r)
	})
	mux.HandleFunc("GET "+instance+"/recoveryPoints", func(w http.ResponseWriter, r *http.Request) {
		a.journal = append(a.journal, "recovery-points")
		a.checkAPIVersion(r)
		_, _ = io.WriteString(w, a.recoveryPoints)
	})
	mux.HandleFunc("GET /operationStatus/op-1", func(w http.ResponseWriter, _ *http.Request) {
		a.journal = append(a.journal, "poll")
		a.polls++
		if a.onPoll != nil {
			a.onPoll()
		}
		a.pace(w)
		if a.pollBody != "" {
			_, _ = io.WriteString(w, a.pollBody)
			return
		}
		status := a.pollStatuses[min(a.polls, len(a.pollStatuses))-1]
		doc := map[string]any{"id": "op-1", "name": "op-1", "status": status}
		if a.pollError != "" {
			doc["error"] = map[string]any{"code": "UserErrorTest", "message": a.pollError}
		}
		_ = json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/", func(_ http.ResponseWriter, r *http.Request) {
		t.Errorf("the control plane was asked for %s %s, which no documented endpoint of this "+
			"adapter matches", r.Method, r.URL.RequestURI())
	})

	a.server = httptest.NewServer(mux)
	t.Cleanup(a.server.Close)
	// Defaulted after the server exists, because the happy-path recovery point has to be newer
	// than the request that produced it.
	a.recoveryPoints = recoveryPointList(recoveryPoint{"rp-new", time.Now().UTC().Add(time.Minute), "Completed"})
	return a
}

// accept answers the way both long-running operations do: 202, a poll URL, and nothing that says
// the work is done. A caller that reads this as success reports a backup that never happened.
func (a *dataProtection) accept(w http.ResponseWriter, r *http.Request) {
	host := a.server.URL
	if a.asyncOperationHost != "" {
		host = a.asyncOperationHost
	}
	a.pace(w)
	w.Header().Set("Azure-AsyncOperation", host+"/operationStatus/op-1")
	w.Header().Set("Location", host+"/operationResults/op-1")
	w.WriteHeader(http.StatusAccepted)
	_ = r.Body.Close()
}

func (a *dataProtection) pace(w http.ResponseWriter) {
	if a.retryAfter != "" {
		w.Header().Set("Retry-After", a.retryAfter)
	}
}

func (a *dataProtection) checkAPIVersion(r *http.Request) {
	a.t.Helper()
	if got := r.URL.Query().Get("api-version"); got != dataProtectionAPIVersion {
		a.t.Errorf("api-version %q, want %q — ARM has no \"latest\", so an unpinned call is a "+
			"silent behaviour change", got, dataProtectionAPIVersion)
	}
}

type recoveryPoint struct {
	name  string
	taken time.Time
	state string
}

func recoveryPointList(points ...recoveryPoint) string {
	var b strings.Builder
	b.WriteString(`{"value":[`)
	for i, p := range points {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `{"name":%q,"properties":{"objectType":"AzureBackupDiscreteRecoveryPoint",
			"recoveryPointTime":%q,"recoveryPointState":%q}}`,
			p.name, p.taken.Format(time.RFC3339Nano), p.state)
	}
	b.WriteString(`]}`)
	return b.String()
}

func readAll(t *testing.T, r io.Reader) string {
	t.Helper()
	body, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read request body: %v", err)
	}
	return string(body)
}

// blobs is the fake container: the one Azure wrote into and the only place the parts can be read
// back from (AD-033 — the cloud moved the bytes, so the agent reads rather than produces them).
type blobs struct {
	t *testing.T

	// pages are returned in order, so a test can prove the listing follows NextMarker. A short
	// list is not a visible failure: it is a part missing from a batch nobody notices is short.
	pages   []string
	objects map[string]string
	listed  []string // the prefix each list call asked for

	server *httptest.Server
}

func newBlobs(t *testing.T, names ...string) *blobs {
	t.Helper()
	b := &blobs{t: t, objects: map[string]string{}}
	for _, n := range names {
		b.objects[n] = "contents of " + n
	}
	b.pages = []string{listBlobsXML("", names...)}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /staging", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("restype") != "container" || r.URL.Query().Get("comp") != "list" {
			t.Errorf("list asked with restype=%q comp=%q, which is not the documented List Blobs call",
				r.URL.Query().Get("restype"), r.URL.Query().Get("comp"))
		}
		if got := r.Header.Get("x-ms-version"); got != storageAPIVersion {
			t.Errorf("x-ms-version %q, want %q — bearer authorization needs one", got, storageAPIVersion)
		}
		b.listed = append(b.listed, r.URL.Query().Get("prefix"))
		page := len(b.listed) - 1
		if page >= len(b.pages) {
			t.Fatalf("the container was listed %d times and the fake has %d pages", len(b.listed), len(b.pages))
		}
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, b.pages[page])
	})
	mux.HandleFunc("GET /staging/{name...}", func(w http.ResponseWriter, r *http.Request) {
		body, ok := b.objects[r.PathValue("name")]
		if !ok {
			http.Error(w, "BlobNotFound", http.StatusNotFound)
			return
		}
		if r.Header.Get("Authorization") == "" {
			t.Error("the blob was read with no Authorization header")
		}
		_, _ = io.WriteString(w, body)
	})

	b.server = httptest.NewServer(mux)
	t.Cleanup(b.server.Close)
	return b
}

func listBlobsXML(nextMarker string, names ...string) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?><EnumerationResults ContainerName="staging"><Blobs>`)
	for _, n := range names {
		fmt.Fprintf(&b, `<Blob><Name>%s</Name><Properties><Content-Length>%d</Content-Length></Properties></Blob>`,
			n, len("contents of "+n))
	}
	fmt.Fprintf(&b, `</Blobs><NextMarker>%s</NextMarker></EnumerationResults>`, nextMarker)
	return b.String()
}

// staticToken stands in for azidentity. A credential and not a header, because that is the seam
// the real client authenticates through, and a test that stubbed the header would prove nothing
// about the one that ships.
type staticToken struct{}

func (staticToken) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "test-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

// testControlPlane wires the adapter to the two fakes. It builds the same struct the constructor
// does, minus the credential policy, so the code under test is the code that ships.
func testControlPlane(t *testing.T, a *dataProtection, b *blobs) *AzureBackup {
	t.Helper()
	cp, err := NewAzureBackup(staticToken{}, Vault{
		SubscriptionID:  "sub-1",
		ResourceGroup:   "rg-1",
		VaultName:       "vault-1",
		BackupInstance:  "instance-1",
		PolicyRuleName:  "BackupWeekly",
		RestoreLocation: "westeurope",
		ContainerURL:    b.server.URL + "/staging",
	})
	if err != nil {
		t.Fatalf("build the adapter: %v", err)
	}
	cp.endpoint = a.server.URL
	cp.arm = azruntime.NewPipeline("parity-scanner-test", "0.0.0", azruntime.PipelineOptions{}, nil)
	cp.blobs.http = b.server.Client()
	// The real wait is 60 seconds because that is the Retry-After Azure sends. Tests assert the
	// loop, not the clock; retryAfter is what proves the header is honoured.
	cp.pollEvery = time.Millisecond
	return cp
}

// The compile-time claim this whole file exists to make good on.
var _ ControlPlane = (*AzureBackup)(nil)

// THE TEST THIS ADAPTER EXISTS FOR. A 202 is Azure saying "I have accepted the work", and a
// nine-minute backup that returns at the 202 looks exactly like a backup that finished: an
// operation id, no error, a caller that carries on. Everything downstream then vouches for bytes
// nobody took.
func TestTheInitial202IsNotTreatedAsSuccess(t *testing.T) {
	a := newDataProtection(t)
	a.pollStatuses = []string{"InProgress", "InProgress", "Succeeded"}

	point, err := testControlPlane(t, a, newBlobs(t)).Backup(t.Context())
	if err != nil {
		t.Fatalf("Backup: %v", err)
	}
	if point != "rp-new" {
		t.Errorf("recovery point %q, want %q", point, "rp-new")
	}
	if a.polls != 3 {
		t.Errorf("polled %d times, want 3 — the operation said InProgress twice before it finished", a.polls)
	}
	want := []string{"backup", "poll", "poll", "poll", "recovery-points"}
	if got := strings.Join(a.journal, ","); got != strings.Join(want, ",") {
		t.Errorf("calls %v, want %v", a.journal, want)
	}
}

func TestTheAdhocBackupAsksForTheRuleThePolicyNames(t *testing.T) {
	a := newDataProtection(t)

	if _, err := testControlPlane(t, a, newBlobs(t)).Backup(t.Context()); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	var got struct {
		BackupRuleOptions struct {
			RuleName string `json:"ruleName"`
		} `json:"backupRuleOptions"`
	}
	if err := json.Unmarshal([]byte(a.backupBody), &got); err != nil {
		t.Fatalf("the adhoc backup body does not parse: %v (%s)", err, a.backupBody)
	}
	if got.BackupRuleOptions.RuleName != "BackupWeekly" {
		t.Errorf("ruleName %q, want %q", got.BackupRuleOptions.RuleName, "BackupWeekly")
	}
}

// A backup that FAILS must never come back with a recovery point. base.go drops the slot on this
// path; a nil error here would keep the slot and vouch for a copy that does not exist.
func TestABackupThatFailsIsReportedWithTheServicesOwnReason(t *testing.T) {
	a := newDataProtection(t)
	a.pollStatuses = []string{"InProgress", "Failed"}
	a.pollError = "the server was unreachable from the vault"

	point, err := testControlPlane(t, a, newBlobs(t)).Backup(t.Context())
	if err == nil {
		t.Fatal("a Failed operation returned no error")
	}
	if point != "" {
		t.Errorf("recovery point %q from a failed backup", point)
	}
	if !strings.Contains(err.Error(), "the server was unreachable from the vault") {
		t.Errorf("the error loses the service's own reason: %v", err)
	}
	for _, call := range a.journal {
		if call == "recovery-points" {
			t.Error("a failed backup still went looking for a recovery point")
		}
	}
}

// Nine minutes is long enough that a cancellation lands inside the wait rather than around it. If
// the loop ignores ctx, Base cannot be cut short at all — and the slot it is holding stays.
func TestACancellationInsideTheWaitEndsThePoll(t *testing.T) {
	a := newDataProtection(t)
	a.pollStatuses = []string{"InProgress"} // never terminates

	polled := make(chan struct{}, 64)
	a.onPoll = func() {
		select {
		case polled <- struct{}{}:
		default:
		}
	}

	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		<-polled // the operation is running
		<-polled // and still running
		cancel()
	}()

	_, err := testControlPlane(t, a, newBlobs(t)).Backup(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error %v, want a context.Canceled — an operation that never terminates would "+
			"otherwise poll forever", err)
	}
}

func TestAPollThatDoesNotParseIsAFailureAndNotACompletion(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{"truncated json", `{"status":`},
		{"no status at all", `{"id":"op-1"}`},
		{"a status the API does not define", `{"status":"Wobbling"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newDataProtection(t)
			a.pollBody = tc.body

			if _, err := testControlPlane(t, a, newBlobs(t)).Backup(t.Context()); err == nil {
				t.Fatal("a poll that could not be read reported success")
			}
		})
	}
}

// The poll URL comes back in a header, and the request that follows it carries our ARM token. A
// host we did not ask is a host we do not hand it to.
func TestAPollURLOnAnotherHostIsRefused(t *testing.T) {
	elsewhere := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Error("the adapter followed a poll URL onto another host, carrying its ARM token")
	}))
	defer elsewhere.Close()

	a := newDataProtection(t)
	a.asyncOperationHost = elsewhere.URL

	if _, err := testControlPlane(t, a, newBlobs(t)).Backup(t.Context()); err == nil {
		t.Fatal("a poll URL on another host was followed")
	}
}

func TestRetryAfterIsHonouredWhenTheServiceSendsOne(t *testing.T) {
	fallback := 15 * time.Second
	for _, tc := range []struct {
		header string
		want   time.Duration
	}{
		{"60", time.Minute},
		{"", fallback},
		{"not a number", fallback},
		{"0", fallback}, // a zero would turn the wait into a spin against ARM's throttle
		{"-5", fallback},
	} {
		resp := &http.Response{Header: http.Header{}}
		if tc.header != "" {
			resp.Header.Set("Retry-After", tc.header)
		}
		if got := retryAfter(resp, fallback); got != tc.want {
			t.Errorf("Retry-After %q gave %v, want %v", tc.header, got, tc.want)
		}
	}
}

// AND IT IS HONOURED WHEREVER IT ARRIVES. Azure paces both the 202 and every poll after it, and a
// loop that reads only the 202's header keeps asking every fifteen seconds for nine minutes after
// the service asked for sixty — which is how a backup earns a 429 for the whole cycle. Proved by
// making the fallback unusable: if either header were ignored this would wait an hour.
func TestTheServicesPacingIsUsedRatherThanOurOwn(t *testing.T) {
	a := newDataProtection(t)
	a.retryAfter = "1"
	a.pollStatuses = []string{"InProgress", "Succeeded"}

	cp := testControlPlane(t, a, newBlobs(t))
	cp.pollEvery = time.Hour

	started := time.Now()
	if _, err := cp.Backup(t.Context()); err != nil {
		t.Fatalf("Backup: %v", err)
	}
	// Two one-second waits: one asked for by the 202, one by the poll that said InProgress.
	if waited := time.Since(started); waited < 2*time.Second {
		t.Errorf("the whole call took %v; both Retry-After headers should have made it at least 2s", waited)
	}
}

// The recovery point is chosen, not assumed. A scheduled backup landing while ours ran would
// otherwise hand the restore somebody else's copy — one taken BEFORE the slot, which is the
// silent gap AD-033 measured, arrived at through the back door.
func TestOnlyARecoveryPointNewerThanOurOwnRequestIsAccepted(t *testing.T) {
	for _, tc := range []struct {
		name   string
		points []recoveryPoint
		want   string
	}{
		{
			name: "the newest of ours",
			points: []recoveryPoint{
				{"rp-older", time.Now().UTC().Add(time.Minute), "Completed"},
				{"rp-newest", time.Now().UTC().Add(2 * time.Minute), "Completed"},
			},
			want: "rp-newest",
		},
		{
			name:   "one taken before we asked is not ours",
			points: []recoveryPoint{{"rp-scheduled", time.Now().UTC().Add(-time.Hour), "Completed"}},
		},
		{
			name:   "a partial copy is not a base copy",
			points: []recoveryPoint{{"rp-partial", time.Now().UTC().Add(time.Minute), "Partial"}},
		},
		{
			name: "none at all",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newDataProtection(t)
			a.recoveryPoints = recoveryPointList(tc.points...)

			got, err := testControlPlane(t, a, newBlobs(t)).Backup(t.Context())
			if tc.want == "" {
				if err == nil {
					t.Fatalf("recovery point %q accepted; the backup produced nothing we may restore", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Backup: %v", err)
			}
			if got != tc.want {
				t.Errorf("recovery point %q, want %q", got, tc.want)
			}
		})
	}
}

// WHAT THE RESTORE IS ASKED FOR IS THE WHOLE OF WHERE THE FILES LAND. A wrong objectType restores
// into a SERVER rather than into files; a wrong url lands a customer's database in a container we
// did not name.
func TestTheRestoreAsksForFilesInOurContainer(t *testing.T) {
	a, b := newDataProtection(t), newBlobs(t)

	if _, err := testControlPlane(t, a, b).RestoreAsFiles(t.Context(), "rp-new"); err == nil {
		t.Fatal("a restore that wrote no files reported success")
	}

	var got struct {
		ObjectType        string `json:"objectType"`
		RecoveryPointID   string `json:"recoveryPointId"`
		SourceDataStore   string `json:"sourceDataStoreType"`
		RestoreTargetInfo struct {
			ObjectType      string `json:"objectType"`
			RecoveryOption  string `json:"recoveryOption"`
			RestoreLocation string `json:"restoreLocation"`
			TargetDetails   struct {
				FilePrefix   string `json:"filePrefix"`
				LocationType string `json:"restoreTargetLocationType"`
				URL          string `json:"url"`
			} `json:"targetDetails"`
		} `json:"restoreTargetInfo"`
	}
	if err := json.Unmarshal([]byte(a.restoreBody), &got); err != nil {
		t.Fatalf("the restore body does not parse: %v (%s)", err, a.restoreBody)
	}
	for _, check := range []struct{ field, got, want string }{
		{"objectType", got.ObjectType, "AzureBackupRecoveryPointBasedRestoreRequest"},
		{"recoveryPointId", got.RecoveryPointID, "rp-new"},
		{"sourceDataStoreType", got.SourceDataStore, "VaultStore"},
		{"restoreTargetInfo.objectType", got.RestoreTargetInfo.ObjectType, "RestoreFilesTargetInfo"},
		{"recoveryOption", got.RestoreTargetInfo.RecoveryOption, "FailIfExists"},
		{"restoreLocation", got.RestoreTargetInfo.RestoreLocation, "westeurope"},
		{"restoreTargetLocationType", got.RestoreTargetInfo.TargetDetails.LocationType, "AzureBlobs"},
		{"url", got.RestoreTargetInfo.TargetDetails.URL, b.server.URL + "/staging"},
		{"filePrefix", got.RestoreTargetInfo.TargetDetails.FilePrefix, filePrefix("rp-new")},
	} {
		if check.got != check.want {
			t.Errorf("%s = %q, want %q", check.field, check.got, check.want)
		}
	}
}

// THE LABELS ARE THE POINT (AD-037). Four files land, only one of them is the archive, and with
// nothing on the wire saying which, a restore reports success having applied the archive and
// silently dropped the roles, grants and tablespaces.
func TestEveryPartCarriesItsFormatAndRole(t *testing.T) {
	a := newDataProtection(t)
	b := newBlobs(t,
		"parity-rp-new_orders_database.sql",
		"parity-rp-new_roles.sql",
		"parity-rp-new_schema.sql",
		"parity-rp-new_tablespaces.sql",
	)

	parts, err := testControlPlane(t, a, b).RestoreAsFiles(t.Context(), "rp-new")
	if err != nil {
		t.Fatalf("RestoreAsFiles: %v", err)
	}
	if len(b.listed) != 1 || b.listed[0] != filePrefix("rp-new") {
		t.Errorf("the container was listed with %v, want the one prefix this restore wrote under", b.listed)
	}

	want := map[string]struct {
		format string
		role   contract.PartRole
	}{
		"parity-rp-new_orders_database.sql": {contract.FormatPGDumpCustom, contract.PartDatabase},
		"parity-rp-new_roles.sql":           {contract.FormatPlainSQL, contract.PartRoles},
		"parity-rp-new_schema.sql":          {contract.FormatPlainSQL, contract.PartSchema},
		"parity-rp-new_tablespaces.sql":     {contract.FormatPlainSQL, contract.PartTablespaces},
	}
	if len(parts) != len(want) {
		t.Fatalf("%d parts, want %d: %v", len(parts), len(want), parts)
	}
	for _, part := range parts {
		expected, known := want[part.Name]
		if !known {
			t.Errorf("part %q is not one of the files the restore writes", part.Name)
			continue
		}
		if part.Format != expected.format {
			t.Errorf("%s: format %q, want %q", part.Name, part.Format, expected.format)
		}
		if part.Role != expected.role {
			t.Errorf("%s: role %q, want %q — a restorer cannot tell which part is the archive",
				part.Name, part.Role, expected.role)
		}
	}
}

// EVERY PART SAYS WHERE IT ALREADY IS, and it is the blob's whole name rather than the file's.
//
// The agent did not choose these paths and cannot reconstruct them: the base manifest is the only
// record of where the four objects are, so a Path that is merely the file name points a restore
// months later at the root of a container that has nothing there. The blob here is deliberately
// nested, because with the flat names the rest of this file uses, Name and Path are the same string
// and an implementation that wrote the wrong one would pass every test.
func TestEveryPartSaysWhereTheCloudAlreadyPutIt(t *testing.T) {
	const nested = "parity-rp-new/orders/database.sql"

	a := newDataProtection(t)
	b := newBlobs(t, nested)

	parts, err := testControlPlane(t, a, b).RestoreAsFiles(t.Context(), "rp-new")
	if err != nil {
		t.Fatalf("RestoreAsFiles: %v", err)
	}
	if len(parts) != 1 {
		t.Fatalf("%d parts, want the one blob the fake holds: %v", len(parts), parts)
	}
	if parts[0].Path != nested {
		t.Errorf("the part says it is at %q; the cloud wrote it to %q, and nothing else records "+
			"where these objects are", parts[0].Path, nested)
	}
	// Still one safe path element, because Name is what the pipeline would build an object path
	// from — the two answer different questions and must not have been confused for one another.
	if parts[0].Name != "database.sql" {
		t.Errorf("the part is named %q, want the single path element %q", parts[0].Name, "database.sql")
	}

	// And the Path is the object Open actually reads, which is what the whole "never a hash it did
	// not verify" claim rests on for this route.
	stream, err := parts[0].Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer func() { _ = stream.Close() }()
	body, err := io.ReadAll(stream)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(body) != "contents of "+nested {
		t.Errorf("Open read %q, which is not the object the part's Path names", body)
	}
}

// Open yields a FRESH reader every time. The pipeline retries an upload, and a second Open handing
// back a spent reader uploads zero bytes with every check still green.
func TestEachPartOpensItsOwnBytesAndOpensThemAgain(t *testing.T) {
	a := newDataProtection(t)
	b := newBlobs(t, "parity-rp-new_orders_database.sql", "parity-rp-new_roles.sql")

	parts, err := testControlPlane(t, a, b).RestoreAsFiles(t.Context(), "rp-new")
	if err != nil {
		t.Fatalf("RestoreAsFiles: %v", err)
	}
	for _, part := range parts {
		for attempt := 1; attempt <= 2; attempt++ {
			reader, err := part.Open()
			if err != nil {
				t.Fatalf("%s: open %d: %v", part.Name, attempt, err)
			}
			body, err := io.ReadAll(reader)
			if err != nil {
				t.Fatalf("%s: read %d: %v", part.Name, attempt, err)
			}
			if err := reader.Close(); err != nil {
				t.Fatalf("%s: close %d: %v", part.Name, attempt, err)
			}
			if got, want := string(body), b.objects[part.Name]; got != want {
				t.Errorf("%s: open %d read %q, want %q", part.Name, attempt, got, want)
			}
		}
	}
}

// A short list is not a visible failure. It is a batch with a file missing, checksummed and
// manifested exactly like a whole one.
func TestTheListingFollowsNextMarkerToTheEnd(t *testing.T) {
	a := newDataProtection(t)
	b := newBlobs(t, "parity-rp-new_orders_database.sql", "parity-rp-new_roles.sql")
	b.pages = []string{
		listBlobsXML("keep-going", "parity-rp-new_orders_database.sql"),
		listBlobsXML("", "parity-rp-new_roles.sql"),
	}

	parts, err := testControlPlane(t, a, b).RestoreAsFiles(t.Context(), "rp-new")
	if err != nil {
		t.Fatalf("RestoreAsFiles: %v", err)
	}
	if len(parts) != 2 {
		t.Fatalf("%d parts, want 2 — the second page was not fetched", len(parts))
	}
	if len(b.listed) != 2 {
		t.Errorf("listed %d times, want 2", len(b.listed))
	}
}

func TestARestoreThatWroteSomethingWeCannotLabelIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name  string
		blobs []string
	}{
		{"a file with no role", []string{"parity-rp-new_orders_database.sql", "parity-rp-new_notes.txt"}},
		{"no archive at all", []string{"parity-rp-new_roles.sql"}},
		{"nothing whatsoever", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := newDataProtection(t)
			parts, err := testControlPlane(t, a, newBlobs(t, tc.blobs...)).RestoreAsFiles(t.Context(), "rp-new")
			if err == nil {
				t.Fatalf("accepted %v as a base copy", parts)
			}
		})
	}
}

func TestTheRestoreIsPolledToCompletionToo(t *testing.T) {
	a := newDataProtection(t)
	a.pollStatuses = []string{"InProgress", "Succeeded"}
	b := newBlobs(t, "parity-rp-new_orders_database.sql")

	if _, err := testControlPlane(t, a, b).RestoreAsFiles(t.Context(), "rp-new"); err != nil {
		t.Fatalf("RestoreAsFiles: %v", err)
	}
	if a.polls != 2 {
		t.Errorf("polled %d times, want 2", a.polls)
	}
	// Listed after the operation finished, never before: an early list finds a half-written
	// container and calls it a batch.
	if got := strings.Join(a.journal, ","); got != "restore,poll,poll" {
		t.Errorf("calls %q, want restore,poll,poll", got)
	}
}

func TestARestoreThatFailsNeverReturnsParts(t *testing.T) {
	a := newDataProtection(t)
	a.pollStatuses = []string{"Failed"}
	a.pollError = "the target container refused the write"

	parts, err := testControlPlane(t, a, newBlobs(t)).RestoreAsFiles(t.Context(), "rp-new")
	if err == nil {
		t.Fatal("a failed restore returned no error")
	}
	if parts != nil {
		t.Errorf("%d parts from a failed restore", len(parts))
	}
	if !strings.Contains(err.Error(), "the target container refused the write") {
		t.Errorf("the error loses the service's own reason: %v", err)
	}
}

// Nothing here is discovered. A missing field is a misconfiguration, and finding out at minute
// nine of a backup is finding out too late.
func TestTheVaultIsCheckedBeforeAnythingIsAsked(t *testing.T) {
	whole := Vault{
		SubscriptionID:  "sub-1",
		ResourceGroup:   "rg-1",
		VaultName:       "vault-1",
		BackupInstance:  "instance-1",
		PolicyRuleName:  "BackupWeekly",
		RestoreLocation: "westeurope",
		ContainerURL:    "https://acct.blob.core.windows.net/staging",
	}
	if _, err := NewAzureBackup(staticToken{}, whole); err != nil {
		t.Fatalf("a complete Vault was refused: %v", err)
	}

	for _, tc := range []struct {
		name  string
		spoil func(*Vault)
	}{
		{"no subscription", func(v *Vault) { v.SubscriptionID = "" }},
		{"no resource group", func(v *Vault) { v.ResourceGroup = "" }},
		{"no vault", func(v *Vault) { v.VaultName = "" }},
		{"no backup instance", func(v *Vault) { v.BackupInstance = "" }},
		{"no policy rule", func(v *Vault) { v.PolicyRuleName = "" }},
		{"no restore location", func(v *Vault) { v.RestoreLocation = "" }},
		{"no container", func(v *Vault) { v.ContainerURL = "" }},
		{"a container that is not a URL", func(v *Vault) { v.ContainerURL = "://nope" }},
		{"an account with no container", func(v *Vault) { v.ContainerURL = "https://acct.blob.core.windows.net" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spoiled := whole
			tc.spoil(&spoiled)
			if _, err := NewAzureBackup(staticToken{}, spoiled); err == nil {
				t.Error("accepted")
			}
		})
	}
}
