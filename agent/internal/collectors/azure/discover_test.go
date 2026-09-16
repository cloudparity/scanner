package azure

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/manukyanv07/parity-scanner/contract"
)

// page is one canned Resource Graph response, handed back in order.
type page struct {
	data      any    // the response body; nil means the service returned null
	skipToken string // continuation token; "" ends pagination
	truncated bool   // the service capped the result
	total     *int64 // TotalRecords, when the test cares
	err       error
}

// fakeGraph answers from a script of pages and records every request it received.
//
// It exists because CONTRIBUTING.md forbids network in unit tests. Note what it deliberately
// does NOT do: it picks its page by call index rather than by the token it was sent, so
// it cannot express a stale or repeated token. That case is covered separately by
// TestQueryResourcesRefusesToPageForever, which drives the loop from the token instead.
type fakeGraph struct {
	pages []page
	got   []armresourcegraph.QueryRequest
}

func (f *fakeGraph) Resources(_ context.Context, q armresourcegraph.QueryRequest, _ *armresourcegraph.ClientResourcesOptions) (armresourcegraph.ClientResourcesResponse, error) {
	f.got = append(f.got, q)
	if len(f.got) > len(f.pages) {
		return armresourcegraph.ClientResourcesResponse{},
			fmt.Errorf("call %d: the fake scripted only %d page(s) — the pager did not stop", len(f.got), len(f.pages))
	}
	p := f.pages[len(f.got)-1]
	if p.err != nil {
		return armresourcegraph.ClientResourcesResponse{}, p.err
	}

	truncated := armresourcegraph.ResultTruncatedFalse
	if p.truncated {
		truncated = armresourcegraph.ResultTruncatedTrue
	}
	resp := armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{
		Data:            p.data,
		ResultTruncated: &truncated,
		TotalRecords:    p.total,
	}}
	if p.skipToken != "" {
		resp.SkipToken = &p.skipToken
	}
	return resp, nil
}

// rows builds a response body. discover reads none of it, which is the point.
func rows(ids ...string) []any {
	out := make([]any, 0, len(ids))
	for _, id := range ids {
		out = append(out, map[string]any{"id": id, "name": id})
	}
	return out
}

func i64(n int64) *int64 { return &n }

func gotIDs(rows []armResource) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, fmt.Sprint(r["id"]))
	}
	return out
}

// Every row in the subscription must come back, which means following $skipToken until
// the service stops handing one out. A pager that quits early loses resources silently,
// and a resource missing from the estate is indistinguishable from one that was deleted.
func TestQueryResourcesReturnsEveryRow(t *testing.T) {
	tests := []struct {
		name       string
		pages      []page
		wantIDs    []string
		wantTokens []string // the $skipToken on each request in order; "" means none
		wantGaps   int
	}{
		{
			name:       "a single page needs one call",
			pages:      []page{{data: rows("a", "b")}},
			wantIDs:    []string{"a", "b"},
			wantTokens: []string{""},
		},
		{
			name: "three pages are followed to exhaustion, in order",
			pages: []page{
				{data: rows("a", "b"), skipToken: "t1"},
				{data: rows("c"), skipToken: "t2"},
				{data: rows("d", "e")},
			},
			wantIDs:    []string{"a", "b", "c", "d", "e"},
			wantTokens: []string{"", "t1", "t2"},
		},
		{
			name: "an empty page still carrying a token is not the end",
			pages: []page{
				{data: []any{}, skipToken: "t1"},
				{data: rows("a")},
			},
			wantIDs:    []string{"a"},
			wantTokens: []string{"", "t1"},
		},
		{
			// Not an error, but not silence either — see the zero-row gap below.
			name:       "an empty result is reported, not assumed empty",
			pages:      []page{{data: []any{}}},
			wantIDs:    []string{},
			wantTokens: []string{""},
			wantGaps:   1,
		},
		{
			name:       "a null result body is zero rows, and is also reported",
			pages:      []page{{}},
			wantIDs:    []string{},
			wantTokens: []string{""},
			wantGaps:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeGraph{pages: tt.pages}

			got, gaps, err := queryResources(context.Background(), f, "sub-1")
			if err != nil {
				t.Fatalf("queryResources: %v", err)
			}

			if ids := gotIDs(got); !slices.Equal(ids, tt.wantIDs) {
				t.Errorf("rows: got %v want %v", ids, tt.wantIDs)
			}
			if len(f.got) != len(tt.wantTokens) {
				t.Fatalf("calls: got %d want %d", len(f.got), len(tt.wantTokens))
			}
			for i, want := range tt.wantTokens {
				var sent string
				if o := f.got[i].Options; o != nil && o.SkipToken != nil {
					sent = *o.SkipToken
				}
				if sent != want {
					t.Errorf("call %d $skipToken: got %q want %q", i, sent, want)
				}
			}
			// An empty gap list is a claim that the scan was complete (contract.md §4),
			// so a scan that read everything must report nothing.
			if len(gaps) != tt.wantGaps {
				t.Errorf("gaps: got %d want %d (%+v)", len(gaps), tt.wantGaps, gaps)
			}
		})
	}
}

// The query is pinned by a golden file rather than by the production constant. Comparing
// against discoverQuery would only prove the request carried whatever the package happens
// to hold — it passes even with a column deleted from the constant itself. The whole
// string is compared, so `order by id asc` is covered too.
// Regenerate deliberately by editing testdata/discover.kql.
func TestQueryResourcesSendsTheSpeccedQuery(t *testing.T) {
	golden, err := os.ReadFile(filepath.Join("testdata", "discover.kql"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	want := strings.TrimSuffix(string(golden), "\n")

	f := &fakeGraph{pages: []page{
		{data: rows("a"), skipToken: "t1"},
		{data: rows("b")},
	}}
	if _, _, err := queryResources(context.Background(), f, "sub-1"); err != nil {
		t.Fatalf("queryResources: %v", err)
	}
	if len(f.got) != 2 {
		t.Fatalf("calls: got %d want 2", len(f.got))
	}

	first := f.got[0]
	if first.Query == nil || *first.Query != want {
		t.Errorf("query does not match testdata/discover.kql:\n--- got ---\n%v\n--- want ---\n%s", first.Query, want)
	}
	if len(first.Subscriptions) != 1 || first.Subscriptions[0] == nil || *first.Subscriptions[0] != "sub-1" {
		t.Errorf("query was not scoped to the subscription: %+v", first.Subscriptions)
	}
	// Without objectArray the body comes back in table form and every row is a
	// positional array instead of an object.
	if first.Options == nil || first.Options.ResultFormat == nil || *first.Options.ResultFormat != armresourcegraph.ResultFormatObjectArray {
		t.Errorf("result format is not objectArray: %+v", first.Options)
	}
	// Asserted as a literal, not against pageSize: comparing a constant to itself would
	// pass no matter what the constant became. 1000 is the service's per-page maximum.
	if first.Options.Top == nil || *first.Options.Top != 1000 {
		t.Errorf("page size: got %v want 1000", first.Options.Top)
	}
	if first.Options.SkipToken != nil {
		t.Errorf("the first request must not carry a continuation token: %q", *first.Options.SkipToken)
	}
	// The service requires the identical query alongside a $skipToken; a query that
	// drifts between pages silently pages through a different result set.
	if *f.got[1].Query != *first.Query {
		t.Errorf("query changed between pages:\n page 1: %s\n page 2: %s", *first.Query, *f.got[1].Query)
	}
}

// The row is handed on exactly as the service returned it. discover decodes nothing and
// folds nothing — deciding what any of it means is translate's job and the engine's.
func TestQueryResourcesKeepsRowsVerbatim(t *testing.T) {
	in := map[string]any{
		"id":            "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1",
		"type":          "Microsoft.KeyVault/vaults", // mixed case survives; folding is translate's call
		"name":          "kv1",
		"location":      "eastus",
		"resourceGroup": "rg",
		"tags":          map[string]any{"tier": "prod"},
		"sku":           map[string]any{"family": "A", "name": "standard"},
		"identity":      nil,
		"properties":    map[string]any{"accessPolicies": []any{}, "enableSoftDelete": true},
	}

	f := &fakeGraph{pages: []page{{data: []any{in}}}}
	got, _, err := queryResources(context.Background(), f, "sub-1")
	if err != nil {
		t.Fatalf("queryResources: %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("rows: got %d want 1", len(got))
	}
	if !reflect.DeepEqual(map[string]any(got[0]), in) {
		t.Errorf("row altered in discovery:\n got %#v\nwant %#v", map[string]any(got[0]), in)
	}
}

// Silence is never a verdict (contract.md §2.3). Anything the service would not let us
// read has to arrive as a Gap, because a resource that was never read and one that was
// deleted look identical on the wire otherwise.
func TestQueryResourcesReportsWhatItCouldNotRead(t *testing.T) {
	tests := []struct {
		name       string
		pages      []page
		wantRows   int
		wantReason contract.GapReason
		wantDetail string
	}{
		{
			// The documented short-read signal: count < totalRecords.
			name:       "the service reported more records than we read",
			pages:      []page{{data: rows("a", "b"), total: i64(5)}},
			wantRows:   2,
			wantReason: contract.GapNotAttempted,
			wantDetail: "reported 5 records but the scan read only 2",
		},
		{
			// ARG is fed by continuous ARM notifications, so the matching count moves
			// under a walk. That is drift, not unread resources, and a count that GREW
			// must never be reported as "we read more than exist".
			name: "the estate changed while it was read",
			pages: []page{
				{data: rows("a"), total: i64(1), skipToken: "t1"},
				{data: rows("b"), total: i64(2)},
			},
			wantRows:   2,
			wantReason: contract.GapNotAttempted,
			wantDetail: "changed while it was being read",
		},
		{
			// ARG filters silently: 200 with only the rows the principal can see, and
			// TotalRecords counts only those, so no internal check can fire.
			name:       "no resources at all points at the credential",
			pages:      []page{{data: []any{}}},
			wantRows:   0,
			wantReason: contract.GapPermissionDenied,
			wantDetail: "the credential can read nothing inside it",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeGraph{pages: tt.pages}

			got, gaps, err := queryResources(context.Background(), f, "sub-1")
			if err != nil {
				t.Fatalf("queryResources: %v", err)
			}
			if len(got) != tt.wantRows {
				t.Errorf("rows: got %d want %d", len(got), tt.wantRows)
			}
			if len(gaps) != 1 {
				t.Fatalf("gaps: got %d want 1 (%+v)", len(gaps), gaps)
			}
			if gaps[0].Reason != tt.wantReason {
				t.Errorf("reason: got %q want %q", gaps[0].Reason, tt.wantReason)
			}
			if !strings.Contains(gaps[0].Target, "sub-1") {
				t.Errorf("target does not name what went unread: %q", gaps[0].Target)
			}
			if !strings.Contains(gaps[0].Detail, tt.wantDetail) {
				t.Errorf("detail does not explain the gap to a human:\n got %q\nwant it to contain %q", gaps[0].Detail, tt.wantDetail)
			}
		})
	}

	t.Run("a complete scan reports nothing", func(t *testing.T) {
		f := &fakeGraph{pages: []page{{data: rows("a", "b"), total: i64(2)}}}
		_, gaps, err := queryResources(context.Background(), f, "sub-1")
		if err != nil {
			t.Fatalf("queryResources: %v", err)
		}
		if len(gaps) != 0 {
			t.Errorf("a complete scan claimed gaps: %+v", gaps)
		}
	})

	// Microsoft documents resultTruncated as true "when there are less resources available
	// than a query is requesting" — which is the LAST page of every walk, and the only page
	// of any subscription smaller than $top. Reading it as "the service dropped rows" made
	// every complete scan claim it was cut short, and taught operators to ignore the gap
	// list. The count check above is the documented equivalent and the only one we use.
	t.Run("resultTruncated on a complete scan is not a gap", func(t *testing.T) {
		for _, tc := range []struct {
			name  string
			pages []page
		}{
			{"single short page", []page{{data: rows("a", "b"), total: i64(2), truncated: true}}},
			{"last page of a walk", []page{
				{data: rows("a"), total: i64(2), skipToken: "t1"},
				{data: rows("b"), total: i64(2), truncated: true},
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, gaps, err := queryResources(context.Background(), &fakeGraph{pages: tc.pages}, "sub-1")
				if err != nil {
					t.Fatalf("queryResources: %v", err)
				}
				for _, g := range gaps {
					if strings.Contains(g.Detail, "truncat") {
						t.Errorf("a complete scan claimed truncation: %q", g.Detail)
					}
				}
				if len(gaps) != 0 {
					t.Errorf("a complete scan claimed gaps: %+v", gaps)
				}
			})
		}
	})
}

// A token that never advances would page forever. The caller's context may carry no
// deadline, so nothing else would stop it and the row slice grows without bound.
func TestQueryResourcesRefusesToPageForever(t *testing.T) {
	// Unlike fakeGraph, this one always hands back the same token, so it can repeat.
	// It gives up after a bound so that a regression fails this test in milliseconds
	// instead of spinning until the go test timeout.
	calls := 0
	stuck := func(_ context.Context, _ armresourcegraph.QueryRequest, _ *armresourcegraph.ClientResourcesOptions) (armresourcegraph.ClientResourcesResponse, error) {
		calls++
		if calls > 10 {
			return armresourcegraph.ClientResourcesResponse{}, errors.New("the pager never stopped")
		}
		token := "always-the-same"
		return armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{
			Data:      rows("a"),
			SkipToken: &token,
		}}, nil
	}

	got, gaps, err := queryResources(context.Background(), graphFunc(stuck), "sub-1")
	if err == nil {
		t.Fatalf("want an error, got %d rows", len(got))
	}
	if !strings.Contains(err.Error(), "$skipToken already seen") {
		t.Errorf("error does not explain the loop: %q", err)
	}
	if got != nil || gaps != nil {
		t.Errorf("a failed scan returned a partial estate: %d rows, %d gaps", len(got), len(gaps))
	}
}

// graphFunc adapts a function to graphClient.
type graphFunc func(context.Context, armresourcegraph.QueryRequest, *armresourcegraph.ClientResourcesOptions) (armresourcegraph.ClientResourcesResponse, error)

func (g graphFunc) Resources(ctx context.Context, q armresourcegraph.QueryRequest, o *armresourcegraph.ClientResourcesOptions) (armresourcegraph.ClientResourcesResponse, error) {
	return g(ctx, q, o)
}

// A failed scan must fail, not return a short estate. Half a subscription that looks
// whole is worse than no scan at all: the engine cannot tell it from a deletion.
func TestQueryResourcesFailsLoudly(t *testing.T) {
	boom := errors.New("403 Forbidden")

	tests := []struct {
		name    string
		pages   []page
		wantErr []string
	}{
		{
			name:    "the first call fails",
			pages:   []page{{err: boom}},
			wantErr: []string{"403", "page 1"},
		},
		{
			name: "a later page fails and the rows already read are discarded",
			pages: []page{
				{data: rows("a"), skipToken: "t1"},
				{err: boom},
			},
			wantErr: []string{"403", "page 2", "1 rows read"},
		},
		{
			name:    "the result body is not a row array",
			pages:   []page{{data: map[string]any{"unexpected": true}}},
			wantErr: []string{"row array"},
		},
		{
			name:    "a row is not an object",
			pages:   []page{{data: []any{"not-an-object"}}},
			wantErr: []string{"object"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := &fakeGraph{pages: tt.pages}

			got, gaps, err := queryResources(context.Background(), f, "sub-1")
			if err == nil {
				t.Fatalf("want an error, got %d rows", len(got))
			}
			for _, want := range tt.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error lost its context: got %q want it to mention %q", err, want)
				}
			}
			if got != nil || gaps != nil {
				t.Errorf("a failed scan returned a partial estate: %d rows, %d gaps", len(got), len(gaps))
			}
		})
	}
}

// infra-scanner §3 allows no third option: a thing is either READ or REPORTED. This asserts
// that invariant directly rather than pinning a hardcoded list, so adding a table to
// scanTables() without removing its gap - or removing a gap without adding the query - fails
// here instead of becoming a silent hole or a false claim.
//
// §12 measured the cost of the missing one: no authorizationresources meant no role
// assignments in the restored estate, with every dashboard green.
func TestEveryTableIsEitherQueriedOrGapped(t *testing.T) {
	queried := map[string]bool{}
	for _, table := range scanTables() {
		queried[table.name] = true
		if !strings.Contains(table.query, table.name) {
			t.Errorf("table %q's query does not mention it: %q", table.name, table.query)
		}
		if !strings.Contains(table.query, "order by id asc") {
			t.Errorf("table %q is paged without a stable order, so a $skipToken walk can step over rows", table.name)
		}
		if !strings.Contains(table.query, "apiVersion") {
			t.Errorf("table %q does not name apiVersion, which ARG excludes from its default columns", table.name)
		}
	}

	gapped := map[string]bool{}
	for _, g := range unreadGaps(allTypesPresent()) {
		gapped[g.Target] = true
	}

	// Every ARG table this collector knows about. Verified to exist against the live service.
	for _, table := range []string{
		"resources", "resourcecontainers", "authorizationresources", "policyresources",
		"networkresources", "appserviceresources", "recoveryservicesresources", "dnsresources",
		"insightsresources", "securityresources", "guestconfigurationresources",
	} {
		switch {
		case queried[table] && gapped[table]:
			t.Errorf("%q is both queried and reported unread - one of them is a lie", table)
		case !queried[table] && !gapped[table]:
			t.Errorf("%q is neither queried nor reported - that is a silent hole (§3)", table)
		}
	}

	// The seven closed by the cheap tier.
	for _, table := range []string{
		"resourcecontainers", "authorizationresources", "policyresources",
		"networkresources", "appserviceresources", "recoveryservicesresources", "dnsresources",
	} {
		if !queried[table] {
			t.Errorf("%q should be queried by the cheap tier", table)
		}
	}

	// Exactly one table's emptiness is suspicious.
	var primary int
	for _, table := range scanTables() {
		if table.primary {
			primary++
		}
	}
	if primary != 1 {
		t.Errorf("%d primary tables, want exactly 1 - only `resources` being empty is a credential signal", primary)
	}

	// What remains needs a per-resource ARM call, not another paged query, and each carries
	// the reason that names the OWNER of the fix.
	valid := map[contract.GapReason]bool{
		contract.GapNotAttempted: true, contract.GapDataPlane: true, contract.GapNoCollector: true,
	}
	for _, g := range unreadGaps(allTypesPresent()) {
		if !valid[g.Reason] {
			t.Errorf("%q: reason %q is not one a collector should emit here", g.Target, g.Reason)
		}
		if g.Detail == "" {
			t.Errorf("%q carries no detail for a human", g.Target)
		}
	}
	// privateDnsZoneGroups moved to the fetcher, so it must NOT be here any more.
	for _, fetched := range fetchedChildTargets() {
		_ = fetched
	}
	for target := range fetchedChildTargets() {
		if gapped[target] {
			t.Errorf("%q is fetched now, so reporting it unread is a false claim", target)
		}
	}
	for _, want := range []string{
		"microsoft.containerservice/managedclusters",
	} {
		if !gapped[want] {
			t.Errorf("%q is still unfetched and must stay reported", want)
		}
	}
}

// policyresources is 95% compliance EVALUATION results, not configuration. Measured on an
// otherwise-empty subscription: 22 rows, 21 of them microsoft.policyinsights/policystates. On
// a real estate that is tens of thousands of rows of churn no recovery plan reads.
func TestPolicyQueryExcludesComplianceState(t *testing.T) {
	var query string
	for _, table := range scanTables() {
		if table.name == "policyresources" {
			query = table.query
		}
	}
	if query == "" {
		t.Fatal("policyresources is not queried")
	}
	if !strings.Contains(query, `where type startswith "microsoft.authorization/policy"`) {
		t.Errorf("policyresources is unfiltered, so policystates will flood the estate:\n%s", query)
	}
}

// allTypesPresent is every type a conditional gap depends on, so a test that asserts the CONTENT
// of unreadGaps sees the whole list rather than a filtered one. Conditionality itself is tested
// separately, in TestGapsAreConditionalOnTypesBeingPresent.
func allTypesPresent() map[string]bool {
	return map[string]bool{
		"microsoft.web/sites":                              true,
		"microsoft.storage/storageaccounts":                true,
		"microsoft.servicebus/namespaces":                  true,
		"microsoft.managedidentity/userassignedidentities": true,
		"microsoft.keyvault/vaults":                        true,
		"microsoft.appconfiguration/configurationstores":   true,
		"microsoft.containerservice/managedclusters":       true,
		"microsoft.dbforpostgresql/flexibleservers":        true,
	}
}
