package azure

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/manukyanv07/parity-scanner/contract"
)

// refusingFetcher fails every call, so a test can prove the fetcher was never asked.
type refusingFetcher struct{}

func (refusingFetcher) Get(context.Context, string, string) ([]byte, error) {
	return nil, errors.New("the fetcher should not have been called")
}

// scriptedFetcher answers by path, and records what it was asked.
//
// The mutex is not decoration: fetchChildren calls Get from up to fetchConcurrency goroutines,
// and an unguarded append here is a data race that -race caught on the first run.
type scriptedFetcher struct {
	bodies map[string]string
	errs   map[string]error

	mu    sync.Mutex
	asked []string
	// askedVersion records the api-version each path was called with. Without it the pin in a
	// childSpec is untestable: changing one to a nonsense date leaves the whole package green,
	// while in production a rejected version is a 400 and one false gap per resource.
	askedVersion map[string]string
}

func (f *scriptedFetcher) Get(_ context.Context, path, apiVersion string) ([]byte, error) {
	f.mu.Lock()
	f.asked = append(f.asked, path)
	if f.askedVersion == nil {
		f.askedVersion = map[string]string{}
	}
	f.askedVersion[path] = apiVersion
	f.mu.Unlock()
	if err, ok := f.errs[path]; ok {
		return nil, err
	}
	if body, ok := f.bodies[path]; ok {
		return []byte(body), nil
	}
	// diagnosticSettings is fetched on EVERY resource, so every test in this file now sees these
	// calls whether or not it is about them. An unscripted one answers "none configured", which
	// is what the live service returns for the vast majority of resources. Scripting a path
	// explicitly still overrides this.
	if strings.HasSuffix(path, diagnosticSettingsPath) {
		return []byte(`{"value":[]}`), nil
	}
	return nil, errors.New("no script for " + path)
}

func responseErr(code int) error {
	return &azcore.ResponseError{StatusCode: code, RawResponse: &http.Response{StatusCode: code}}
}

func responseErrCoded(code int, errorCode string) error {
	return &azcore.ResponseError{StatusCode: code, ErrorCode: errorCode, RawResponse: &http.Response{StatusCode: code}}
}

// 400 and 404 are different facts and must never share wording, and one 400 must never be
// swallowed however optional the child is.
//
// The sharp case is the LAST one. diagnosticSettings is fetched against every resource on a
// PREVIEW api-version and is declared optional, so if Microsoft retires that preview the whole
// estate 400s, every diagnostic setting silently vanishes - and the standing gap that would
// have said so is itself suppressed, because fetchedChildTargets() reports the child as
// fetched. An estate then claims completeness it does not have, across every resource at once,
// which is precisely the failure contract.md §2.3 exists to make impossible.
func TestFetchGapTellsARejectedCallApartFromAnAbsentChild(t *testing.T) {
	parent := contract.Resource{ID: "/subscriptions/sub-1/resourcegroups/rg/providers/x/y/z"}
	required := childSpec{path: "configurations"}
	optional := childSpec{path: "queueServices/default", optional: true}

	cases := []struct {
		name       string
		spec       childSpec
		err        error
		wantGap    bool
		mustSay    []string
		mustNotSay []string
	}{
		{
			name:       "a required child that is genuinely absent still reads as absent",
			spec:       required,
			err:        responseErr(http.StatusNotFound),
			wantGap:    true,
			mustSay:    []string{"404", "not configured"},
			mustNotSay: []string{"REJECTED"},
		},
		{
			name:       "a rejected request is reported as OUR fault, not the customer's estate",
			spec:       required,
			err:        responseErrCoded(http.StatusBadRequest, "InvalidApiVersionParameter"),
			wantGap:    true,
			mustSay:    []string{"400", "InvalidApiVersionParameter"},
			mustNotSay: []string{"not configured"},
		},
		{
			// A gateway 400 with an HTML body parses to no code at all. The sentence still has
			// to read like English, because a human is the one who has to act on it.
			name:       "a 400 with no error code still produces a readable sentence",
			spec:       required,
			err:        responseErrCoded(http.StatusBadRequest, ""),
			wantGap:    true,
			mustSay:    []string{"400"},
			mustNotSay: []string{"()"},
		},
		{
			// The original, correct reason for the swallow: ARM rejects some storage children
			// outright depending on account kind, and one gap per account would bury the list.
			name:    "an optional child ARM simply does not support stays silent",
			spec:    optional,
			err:     responseErrCoded(http.StatusBadRequest, "FeatureNotSupportedForAccount"),
			wantGap: false,
		},
		{
			name:       "but a rejected api-version is reported even on an optional child",
			spec:       optional,
			err:        responseErrCoded(http.StatusBadRequest, "InvalidApiVersionParameter"),
			wantGap:    true,
			mustSay:    []string{"InvalidApiVersionParameter"},
			mustNotSay: []string{"not configured"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gap := fetchGap(parent, tc.spec, tc.err)
			if !tc.wantGap {
				if gap != nil {
					t.Fatalf("got a gap, want silence: %+v", gap)
				}
				return
			}
			if gap == nil {
				t.Fatal("no gap - this failure is now invisible in the estate")
			}
			for _, want := range tc.mustSay {
				if !strings.Contains(gap.Detail, want) {
					t.Errorf("detail does not mention %q: %s", want, gap.Detail)
				}
			}
			for _, unwanted := range tc.mustNotSay {
				if strings.Contains(gap.Detail, unwanted) {
					t.Errorf("detail wrongly says %q: %s", unwanted, gap.Detail)
				}
			}
		})
	}
}

const pe = "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.network/privateendpoints/vault-endpoint"
const zone = "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.network/privatednszones/privatelink.vaultcore.azure.net"

func endpointResource(id string) contract.Resource {
	return contract.Resource{ID: id, Type: "microsoft.network/privateendpoints", Account: "sub-1",
		Document: json.RawMessage(`{"id":"` + id + `"}`)}
}

// The flagship edge. The zone id lives on the privateDnsZoneGroups child, which no ARG table
// returns, so without the fetcher a restored private endpoint resolves nothing.
func TestFetchChildrenReadsPrivateDNSZoneGroups(t *testing.T) {
	body := `{"value":[{
      "id": "` + pe + `/privateDnsZoneGroups/vault-zone-group",
      "name": "vault-zone-group",
      "type": "Microsoft.Network/privateEndpoints/privateDnsZoneGroups",
      "properties": {"privateDnsZoneConfigs": [
        {"name":"vault","properties":{"privateDnsZoneId":"` + zone + `"}}
      ]}
    }]}`
	f := &scriptedFetcher{bodies: map[string]string{pe + "/privateDnsZoneGroups": body}}

	rows, gaps := fetchChildren(context.Background(), f, []contract.Resource{endpointResource(pe)})
	if len(gaps) != 0 {
		t.Errorf("a successful fetch reported gaps: %+v", gaps)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1: %+v", len(rows), rows)
	}
	if got := str(rows[0]["id"]); !strings.HasSuffix(got, "/privateDnsZoneGroups/vault-zone-group") {
		t.Errorf("row id = %q", got)
	}

	// The whole point: once translated, link must find the endpoint -> zone edge.
	resources, _ := translate("sub-1", rows)
	all := append([]contract.Resource{endpointResource(pe), {ID: zone, Type: "microsoft.network/privatednszones",
		Account: "sub-1", Document: json.RawMessage(`{"id":"` + zone + `"}`)}}, resources...)
	refs, _ := link(all)

	var found bool
	for _, r := range refs {
		if r.To == zone && strings.Contains(r.Via, "privateDnsZoneId") {
			found = true
			if r.Resolution != contract.ResolutionInScan {
				t.Errorf("zone edge resolved %q, want in-scan", r.Resolution)
			}
		}
	}
	if !found {
		t.Errorf("the private endpoint -> DNS zone edge was not produced: %+v", refs)
	}
}

const pgServer = "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.dbforpostgresql/flexibleservers/pg-ready"

// pg_dump backs up a DATABASE and the change stream needs wal_level, and NEITHER is in any ARG
// table - only the parent server is indexed. So a scan that stops at the server reports a
// Postgres estate it has not actually looked inside, and a plan built from it can protect a
// server while missing half its data with everything green (E6.20).
//
// The agent BRINGS, it does not JUDGE (AD-021). This test therefore asserts that the raw ARM
// values survive verbatim - "replica", "logical", isConfigPendingRestart - and deliberately
// asserts NOTHING about readiness. Deciding that wal_level=replica means "no change stream"
// needs the Knowledge Base, and the Knowledge Base is server-side.
func TestFetchChildrenReadsPostgresParametersAndDatabases(t *testing.T) {
	// The shape ARM really returns. isConfigPendingRestart is the field that matters most and
	// is the easiest to drop by accident: it is how the engine learns that a value was accepted
	// but is NOT yet running, which is the difference between "configured" and "in effect".
	configurations := `{"value":[
      {"id":"` + pgServer + `/configurations/wal_level","name":"wal_level",
       "type":"Microsoft.DBforPostgreSQL/flexibleServers/configurations",
       "properties":{"value":"logical","defaultValue":"replica","source":"user-override",
                     "isConfigPendingRestart":true,"isDynamicConfig":false}},
      {"id":"` + pgServer + `/configurations/max_worker_processes","name":"max_worker_processes",
       "type":"Microsoft.DBforPostgreSQL/flexibleServers/configurations",
       "properties":{"value":"16","defaultValue":"8","source":"user-override",
                     "isConfigPendingRestart":true,"isDynamicConfig":false}}
    ]}`

	databases := `{"value":[
      {"id":"` + pgServer + `/databases/appdb","name":"appdb",
       "type":"Microsoft.DBforPostgreSQL/flexibleServers/databases",
       "properties":{"charset":"UTF8","collation":"en_US.utf8"}},
      {"id":"` + pgServer + `/databases/azure_maintenance","name":"azure_maintenance",
       "type":"Microsoft.DBforPostgreSQL/flexibleServers/databases",
       "properties":{"charset":"UTF8","collation":"en_US.utf8"}}
    ]}`

	f := &scriptedFetcher{bodies: map[string]string{
		pgServer + "/configurations": configurations,
		pgServer + "/databases":      databases,
	}}

	rows, gaps := fetchChildren(context.Background(), f, []contract.Resource{
		{ID: pgServer, Type: "microsoft.dbforpostgresql/flexibleservers", Account: "sub-1",
			Document: json.RawMessage(`{"id":"` + pgServer + `"}`)},
	})
	if len(gaps) != 0 {
		t.Errorf("a successful fetch reported gaps: %+v", gaps)
	}
	if len(rows) != 4 {
		t.Fatalf("got %d rows, want 4 (2 parameters + 2 databases): %+v", len(rows), rows)
	}

	// The pin, not the path. An unasked path already shows up as a missing row above; a WRONG
	// api-version does not - ARM answers 400 and the estate gets one false gap per server.
	for _, path := range []string{pgServer + "/configurations", pgServer + "/databases"} {
		if got := f.askedVersion[path]; got != "2025-08-01" {
			t.Errorf("%s asked with api-version %q, want 2025-08-01", path, got)
		}
	}

	// Azure's own maintenance database is reported, NOT filtered. Hiding it is a judgment, and
	// judgments belong to the engine (AD-021) - the agent cannot know whether a customer cares.
	resources, _ := translate("sub-1", rows)
	var sawMaintenance, sawWalLevel bool
	for _, r := range resources {
		// E6.20's first acceptance criterion. parentID comes from parseARMID, which blanks it on
		// a shape it cannot read - so a child that lost its parent is a silent orphan, and the
		// engine could never join a database back to the server it has to be restored with.
		if r.ParentID != pgServer {
			t.Errorf("%s has parentId %q, want the server", r.ID, r.ParentID)
		}
		if strings.HasSuffix(r.ID, "/databases/azure_maintenance") {
			sawMaintenance = true
			if r.Type != "microsoft.dbforpostgresql/flexibleservers/databases" {
				t.Errorf("type = %q, want case-folded on the way in", r.Type)
			}
		}
		if strings.HasSuffix(r.ID, "/configurations/wal_level") {
			sawWalLevel = true
			// Verbatim, all three. The value the engine judges, Azure's default to compare it
			// against, and the flag saying it is not running yet - a restart of the customer's
			// production database still stands between this setting and the change stream.
			doc := string(r.Document)
			for _, fragment := range []string{`"value":"logical"`, `"defaultValue":"replica"`, `"isConfigPendingRestart":true`} {
				if !strings.Contains(doc, fragment) {
					t.Errorf("wal_level document lost %s: %s", fragment, doc)
				}
			}
		}
	}
	if !sawWalLevel {
		t.Error("wal_level never reached the estate, so the engine cannot report what the database is missing")
	}
	if !sawMaintenance {
		t.Error("azure_maintenance was dropped - filtering it is the engine's call, not the collector's")
	}
}

// A truncated page must never look like a complete one.
//
// Every child collected before Postgres was small - zone groups, containers, queues - so a paged
// response was theoretical. A Flexible Server exposes several hundred server parameters, which is
// the first child big enough to actually page. Keeping page one and saying nothing would put
// wal_level's absence and wal_level's non-existence into the same estate, and contract.md §2.3
// says an empty gaps list is a CLAIM of completeness.
//
// The rows are still kept: a partial answer is worth having as long as it is labelled partial.
func TestFetchChildrenReportsATruncatedPage(t *testing.T) {
	body := `{"value":[
      {"id":"` + pgServer + `/configurations/wal_level","name":"wal_level",
       "type":"Microsoft.DBforPostgreSQL/flexibleServers/configurations",
       "properties":{"value":"logical"}}
    ],"nextLink":"https://management.azure.com` + pgServer + `/configurations?api-version=2025-08-01&$skipToken=opaque"}`

	f := &scriptedFetcher{bodies: map[string]string{
		pgServer + "/configurations": body,
		pgServer + "/databases":      `{"value":[]}`,
	}}

	rows, gaps := fetchChildren(context.Background(), f, []contract.Resource{
		{ID: pgServer, Type: "microsoft.dbforpostgresql/flexibleservers", Account: "sub-1",
			Document: json.RawMessage(`{"id":"` + pgServer + `"}`)},
	})

	if len(rows) != 1 {
		t.Errorf("got %d rows, want the one row from page 1 - a partial answer is still worth keeping", len(rows))
	}

	var reported bool
	for _, g := range gaps {
		if strings.Contains(g.Target, "configurations") {
			reported = true
			if g.Reason != contract.GapNotAttempted {
				t.Errorf("truncated page reported as %q, want not-attempted", g.Reason)
			}
		}
	}
	if !reported {
		t.Error("a paged response was truncated and NOT reported; a short list is now indistinguishable from a complete one")
	}
}

// A 403 is the one failure no code change repairs, and infra-scanner §5.1 requires every one
// to become a Gap. Nothing could produce permission-denied before the fetcher existed.
func TestFetchChildrenReportsPermissionDenied(t *testing.T) {
	f := &scriptedFetcher{errs: map[string]error{pe + "/privateDnsZoneGroups": responseErr(http.StatusForbidden)}}

	rows, gaps := fetchChildren(context.Background(), f, []contract.Resource{endpointResource(pe)})
	if len(rows) != 0 {
		t.Errorf("a denied fetch returned rows: %+v", rows)
	}
	if len(gaps) != 1 {
		t.Fatalf("got %d gaps, want 1: %+v", len(gaps), gaps)
	}
	if gaps[0].Reason != contract.GapPermissionDenied {
		t.Errorf("reason = %q, want %q", gaps[0].Reason, contract.GapPermissionDenied)
	}
	if !strings.Contains(gaps[0].Detail, "granting a narrower-than-owner role") {
		t.Errorf("the gap does not say who can fix it: %q", gaps[0].Detail)
	}
}

// 404 means "probably not configured", which is a different fact from "denied" and from
// "we did not ask". ARM cannot distinguish not-configured from a wrong path, so it is
// reported rather than assumed empty.
func TestFetchChildrenDistinguishesNotFoundFromDenied(t *testing.T) {
	f := &scriptedFetcher{errs: map[string]error{pe + "/privateDnsZoneGroups": responseErr(http.StatusNotFound)}}
	_, gaps := fetchChildren(context.Background(), f, []contract.Resource{endpointResource(pe)})
	if len(gaps) != 1 || gaps[0].Reason != contract.GapNotAttempted {
		t.Fatalf("want one not-attempted gap: %+v", gaps)
	}
	if !strings.Contains(gaps[0].Detail, "404") {
		t.Errorf("the gap does not say ARM answered 404: %q", gaps[0].Detail)
	}
}

// A failed child fetch must not fail the scan. A dropped Discover page makes the whole
// resource list wrong; this loses one known child of one known resource.
func TestFetchChildrenKeepsGoingAfterOneFailure(t *testing.T) {
	const pe2 = "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.network/privateendpoints/storage-endpoint"
	f := &scriptedFetcher{
		bodies: map[string]string{pe2 + "/privateDnsZoneGroups": `{"value":[{"id":"` + pe2 + `/privateDnsZoneGroups/g","name":"g"}]}`},
		errs:   map[string]error{pe + "/privateDnsZoneGroups": responseErr(http.StatusForbidden)},
	}
	rows, gaps := fetchChildren(context.Background(), f, []contract.Resource{endpointResource(pe), endpointResource(pe2)})
	if len(rows) != 1 {
		t.Errorf("the healthy endpoint's child was lost: %+v", rows)
	}
	if len(gaps) != 1 || gaps[0].Reason != contract.GapPermissionDenied {
		t.Errorf("the denied endpoint was not reported: %+v", gaps)
	}
}

// A TYPED spec asks only its own parent type, or the fetcher costs one call per resource instead
// of one per private endpoint.
func TestFetchChildrenOnlyAsksMatchingParents(t *testing.T) {
	f := &scriptedFetcher{bodies: map[string]string{pe + "/privateDnsZoneGroups": `{"value":[]}`}}
	fetchChildren(context.Background(), f, []contract.Resource{
		endpointResource(pe),
		{ID: zone, Type: "microsoft.network/privatednszones", Account: "sub-1"},
		{ID: "/subscriptions/sub-1/providers/microsoft.keyvault/vaults/kv", Type: "microsoft.keyvault/vaults"},
	})
	var zoneGroupCalls []string
	for _, path := range f.asked {
		if strings.HasSuffix(path, "/privateDnsZoneGroups") {
			zoneGroupCalls = append(zoneGroupCalls, path)
		}
	}
	if len(zoneGroupCalls) != 1 || zoneGroupCalls[0] != pe+"/privateDnsZoneGroups" {
		t.Errorf("privateDnsZoneGroups asked %v, want only the private endpoint", zoneGroupCalls)
	}
}

// The wildcard spec is the scanner's most expensive line - one call per resource - so what it
// SKIPS is load-bearing. A child or extension type cannot carry a diagnostic setting, and asking
// anyway would multiply the call count by every such row in the estate.
func TestDiagnosticSettingsSkipsTypesThatCannotHaveThem(t *testing.T) {
	for _, skipped := range []string{
		"microsoft.network/privatednszones/a",
		"microsoft.resources/subscriptions/resourcegroups",
		"microsoft.resources/subscriptions",
		"microsoft.authorization/roleassignments",
		"microsoft.managedidentity/userassignedidentities",
	} {
		if !skipDiagnosticSettings(skipped) {
			t.Errorf("%q should be skipped by the wildcard spec", skipped)
		}
	}
	for _, asked := range []string{
		"microsoft.keyvault/vaults",
		"microsoft.storage/storageaccounts",
		"microsoft.app/containerapps",
		"microsoft.network/virtualnetworks",
		"microsoft.operationalinsights/workspaces",
	} {
		if skipDiagnosticSettings(asked) {
			t.Errorf("%q supports diagnostic settings and must be asked", asked)
		}
	}
}

// Every resource that is not skipped must be asked, or a diagnostic setting goes unseen and a
// restored estate is silently unmonitored.
func TestDiagnosticSettingsAreFetchedForEveryEligibleResource(t *testing.T) {
	f := &scriptedFetcher{bodies: map[string]string{pe + "/privateDnsZoneGroups": `{"value":[]}`}}
	fetchChildren(context.Background(), f, []contract.Resource{
		endpointResource(pe),
		{ID: "/subscriptions/sub-1/providers/microsoft.keyvault/vaults/kv", Type: "microsoft.keyvault/vaults"},
		{ID: zone + "/a/rec", Type: "microsoft.network/privatednszones/a", Account: "sub-1"},
	})
	var diag int
	for _, path := range f.asked {
		if strings.HasSuffix(path, diagnosticSettingsPath) {
			diag++
		}
		if strings.Contains(path, "/a/rec/") {
			t.Errorf("asked a child resource for diagnostic settings: %s", path)
		}
	}
	if diag != 2 {
		t.Errorf("made %d diagnosticSettings calls, want 2 (the endpoint and the vault)", diag)
	}
}

func TestFetchChildrenHandlesEmptyEstate(t *testing.T) {
	rows, gaps := fetchChildren(context.Background(), refusingFetcher{}, nil)
	if rows != nil || gaps != nil {
		t.Errorf("an empty estate asked the fetcher something: %+v %+v", rows, gaps)
	}
}

// Goroutines finish in any order; the estate must not.
func TestFetchChildrenIsDeterministic(t *testing.T) {
	var endpoints []contract.Resource
	bodies := map[string]string{}
	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"} {
		id := "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.network/privateendpoints/" + n
		endpoints = append(endpoints, endpointResource(id))
		bodies[id+"/privateDnsZoneGroups"] = `{"value":[{"id":"` + id + `/privateDnsZoneGroups/g","name":"g"}]}`
	}
	first, _ := fetchChildren(context.Background(), &scriptedFetcher{bodies: bodies}, endpoints)
	for i := range 15 {
		again, _ := fetchChildren(context.Background(), &scriptedFetcher{bodies: bodies}, endpoints)
		if len(again) != len(first) {
			t.Fatalf("run %d returned %d rows, want %d", i, len(again), len(first))
		}
		for j := range first {
			if str(first[j]["id"]) != str(again[j]["id"]) {
				t.Fatalf("row order changed on run %d at %d", i, j)
			}
		}
	}
}

// Numbers must survive the fetcher for the same reason they must survive Discover: the
// document is the source material for every later derivation.
func TestDecodeChildRowsPreservesLargeIntegers(t *testing.T) {
	rows, err := decodeChildRows([]byte(`[{"id":"/x","properties":{"seq":9007199254740993}}]`))
	if err != nil {
		t.Fatalf("decodeChildRows: %v", err)
	}
	encoded, _ := json.Marshal(map[string]any(rows[0]))
	if !strings.Contains(string(encoded), "9007199254740993") {
		t.Errorf("the integer was widened: %s", encoded)
	}
}

func TestDecodeChildRowsShapes(t *testing.T) {
	for name, body := range map[string]string{"empty": "", "null": "null"} {
		if rows, err := decodeChildRows([]byte(body)); err != nil || rows != nil {
			t.Errorf("%s: got %v, %v; want no rows and no error", name, rows, err)
		}
	}
	if rows, err := decodeChildRows([]byte(`{"id":"/x"}`)); err != nil || len(rows) != 1 {
		t.Errorf("a bare object should be one row: %v %v", rows, err)
	}
	if _, err := decodeChildRows([]byte(`"nope"`)); err == nil {
		t.Error("a scalar body should be an error, not an empty page")
	}
}

// childSpecs and unreadGaps must not drift: a fetched child reported as unread is a false
// claim, and an unfetched child not reported is a silent hole.
func TestFetchedChildrenAreNotAlsoReportedUnread(t *testing.T) {
	fetched := fetchedChildTargets()
	if len(fetched) == 0 {
		t.Fatal("no child specs")
	}
	for _, g := range unreadGaps(allTypesPresent()) {
		if fetched[g.Target] {
			t.Errorf("%q is fetched and also reported unread", g.Target)
		}
	}
	for _, spec := range childSpecs() {
		if spec.apiVersion == "" {
			t.Errorf("%s/%s has no pinned api-version; ARM has no 'latest' and an unpinned call is a silent behaviour change", spec.parentType, spec.path)
		}
		if spec.gapTarget == "" {
			t.Errorf("%s/%s names no gap target, so it cannot be kept in sync with unreadGaps", spec.parentType, spec.path)
		}
	}
}

// The knob exists so a real estate can be tuned without a rebuild, and a bad value must never
// become 0 - that would deadlock the worker pool rather than slow it down.
func TestFetchConcurrencyIsTunableAndSafe(t *testing.T) {
	cases := map[string]int{
		"":         defaultFetchConcurrency,
		"  ":       defaultFetchConcurrency,
		"nonsense": defaultFetchConcurrency,
		"0":        defaultFetchConcurrency,
		"-5":       defaultFetchConcurrency,
		"1":        1,
		"24":       24,
		"9999":     maxFetchConcurrency,
	}
	for value, want := range cases {
		t.Setenv("PARITY_FETCH_CONCURRENCY", value)
		if got := fetchConcurrency(); got != want {
			t.Errorf("PARITY_FETCH_CONCURRENCY=%q -> %d, want %d", value, got, want)
		}
	}
}

// A CHILD MUST CARRY THE VERSION IT WAS READ WITH.
//
// Discover gets apiVersion from the Resource Graph for every top-level resource. An ARM REST
// response does not echo it back, so children arrived without one - 21 of 84 resources in a real
// estate had no version at all.
//
// It went unnoticed until something tried to USE the estate: ARM rejects a template resource with no
// apiVersion, so no restore could be generated for any child. Recording what a document was read
// with is the same promise Discover already makes for its half.
func TestFetchedChildrenCarryTheirApiVersion(t *testing.T) {
	body := `{"value":[{
        "id": "` + pe + `/privateDnsZoneGroups/g",
        "name": "g",
        "type": "Microsoft.Network/privateEndpoints/privateDnsZoneGroups",
        "properties": {}
      }]}`
	f := &scriptedFetcher{bodies: map[string]string{pe + "/privateDnsZoneGroups": body}}

	rows, gaps := fetchChildren(context.Background(), f, []contract.Resource{endpointResource(pe)})
	if len(gaps) != 0 {
		t.Fatalf("unexpected gaps: %+v", gaps)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(rows))
	}
	version := str(rows[0]["apiVersion"])
	if version == "" {
		t.Fatal("the child carries no apiVersion, so it cannot appear in a restore template")
	}
	// It must be the version the SPEC used, not an invented one.
	var want string
	for _, spec := range childSpecs() {
		if strings.HasSuffix(spec.path, "privateDnsZoneGroups") {
			want = spec.apiVersion
		}
	}
	if version != want {
		t.Errorf("apiVersion = %q, want the %q the fetch actually used", version, want)
	}
}

// A response that already states its own version keeps it: what the provider says beats what we
// asked for.
func TestAChildKeepsAnApiVersionItAlreadyHas(t *testing.T) {
	body := `{"value":[{
        "id": "` + pe + `/privateDnsZoneGroups/g",
        "name": "g",
        "apiVersion": "1999-01-01",
        "type": "Microsoft.Network/privateEndpoints/privateDnsZoneGroups"
      }]}`
	f := &scriptedFetcher{bodies: map[string]string{pe + "/privateDnsZoneGroups": body}}

	rows, _ := fetchChildren(context.Background(), f, []contract.Resource{endpointResource(pe)})
	if len(rows) != 1 {
		t.Fatalf("got %d rows", len(rows))
	}
	if got := str(rows[0]["apiVersion"]); got != "1999-01-01" {
		t.Errorf("apiVersion = %q, want the one the response declared", got)
	}
}
