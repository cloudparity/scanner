package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	armruntime "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	azruntime "github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/manukyanv07/parity-scanner/contract"
)

// The fetcher is a different mechanism from Discover, not a different query.
//
// Resource Graph is one call against Microsoft's own index that returns up to a thousand
// resources. The fetcher is a direct ARM control-plane GET against ONE resource, because
// some children exist in no ARG table at all and the only way to see them is to ask the
// resource provider:
//
//	ARG      POST /providers/Microsoft.ResourceGraph/resources   1 call -> 1000 rows
//	fetcher  GET  {resourceId}/privateDnsZoneGroups?api-version= 1 call -> 1 resource
//
// That is why this is the expensive tier: cost scales with the estate, not with the scan. On
// a large customer estate a per-endpoint fetch is hundreds of calls and a per-resource fetch
// is thousands, which is why each child type is listed explicitly rather than fetched
// speculatively.
//
// What it buys is the product's own first-named DR-critical edge. A private endpoint's link
// to its private DNS zone lives on the privateDnsZoneGroups child, and without it a restored
// private endpoint resolves nothing: every app that reaches its Key Vault or database
// privately fails, while the endpoint itself looks healthy.

// armFetcher performs one authenticated ARM GET. An interface so the fetch logic can be
// proven without a network, the same reason graphClient exists.
type armFetcher interface {
	Get(ctx context.Context, path, apiVersion string) ([]byte, error)
}

// childSpec names one child collection that no ARG table returns.
//
// Each entry costs one ARM call per matching parent, so the list is deliberate. apiVersion is
// pinned per child: ARM has no "latest" and an unpinned call is a silent behaviour change
// whenever the provider ships a new version.
type childSpec struct {
	// parentType is a case-folded parent type matched against Resource.Type. The empty string
	// means EVERY top-level resource, which only diagnosticSettings needs.
	parentType string
	path       string // appended to the parent's id
	apiVersion string
	// gapTarget is the unreadGaps entry this spec closes, so the two cannot drift. Several specs
	// may share one target when a single gap covers a family of children.
	gapTarget string
	// optional marks a child that most parents legitimately do not have. A 404 then states a
	// fact - "not configured" - rather than a hole, and reporting it would bury the gaps list
	// under one entry per resource. A 403 is still always a gap: that is a permission problem
	// regardless of how common the child is.
	optional bool
}

// childSpecs is the expensive tier of #6, in the order it was justified.
//
// Every entry costs one ARM call per matching parent, so cost scales with the estate. That is
// the whole reason this list is explicit rather than discovered: adding a line here multiplies
// the scan's call count by the number of resources of that type.
func childSpecs() []childSpec {
	return []childSpec{
		{
			// The flagship edge. properties.privateDnsZoneConfigs[*].properties.privateDnsZoneId
			// is a bare resourceId, so once the row exists link finds the edge with no extra work.
			parentType: "microsoft.network/privateendpoints",
			path:       "privateDnsZoneGroups",
			apiVersion: "2024-05-01",
			gapTarget:  "microsoft.network/privateendpoints/privatednszonegroups",
		},

		// --- storage. A recovered account with no containers is an empty shell, and the service
		// properties carry versioning, soft delete and CORS, none of which survive a bare create.
		{
			parentType: "microsoft.storage/storageaccounts",
			path:       "blobServices/default",
			apiVersion: "2023-05-01",
			gapTarget:  "microsoft.storage/storageaccounts/blobservices",
		},
		{
			parentType: "microsoft.storage/storageaccounts",
			path:       "blobServices/default/containers",
			apiVersion: "2023-05-01",
			gapTarget:  "microsoft.storage/storageaccounts/blobservices",
		},
		{
			// The file SERVICE, not just its shares. Measured: fetching only the shares left every
			// share's parentId pointing at fileServices/default, which nothing had fetched, so the
			// engine could not join a share to its account. blobServices already fetched both
			// levels; the other three services now match it.
			parentType: "microsoft.storage/storageaccounts",
			path:       "fileServices/default",
			apiVersion: "2023-05-01",
			gapTarget:  "microsoft.storage/storageaccounts/blobservices",
		},
		{
			parentType: "microsoft.storage/storageaccounts",
			path:       "fileServices/default/shares",
			apiVersion: "2023-05-01",
			gapTarget:  "microsoft.storage/storageaccounts/blobservices",
		},
		{
			parentType: "microsoft.storage/storageaccounts",
			path:       "queueServices/default",
			apiVersion: "2023-05-01",
			gapTarget:  "microsoft.storage/storageaccounts/blobservices",
			optional:   true,
		},
		{
			parentType: "microsoft.storage/storageaccounts",
			path:       "queueServices/default/queues",
			apiVersion: "2023-05-01",
			gapTarget:  "microsoft.storage/storageaccounts/blobservices",
			// Absent unless the account has queues at all.
			optional: true,
		},
		{
			parentType: "microsoft.storage/storageaccounts",
			path:       "tableServices/default",
			apiVersion: "2023-05-01",
			gapTarget:  "microsoft.storage/storageaccounts/blobservices",
			optional:   true,
		},
		{
			parentType: "microsoft.storage/storageaccounts",
			path:       "tableServices/default/tables",
			apiVersion: "2023-05-01",
			gapTarget:  "microsoft.storage/storageaccounts/blobservices",
			optional:   true,
		},
		{
			// Lifecycle management. Deletes data on a schedule, so a restore that loses it
			// silently changes retention.
			parentType: "microsoft.storage/storageaccounts",
			path:       "managementPolicies/default",
			apiVersion: "2023-05-01",
			gapTarget:  "microsoft.storage/storageaccounts/blobservices",
			optional:   true,
		},

		// --- postgres. The parent server is indexed by ARG; nothing inside it is (E6.20).
		//
		// Both are addressed under the PARENT's api-version: ARM registers only flexibleServers
		// and flexibleServers/migrations as types, which is the same fact that keeps these two out
		// of Resource Graph in the first place. Verified against the live provider, 2026-08-16 -
		// but note that means the version is right for the PARENT; that these two child paths
		// accept it has not been proven against a live server. A 400 here says so out loud.
		{
			parentType: "microsoft.dbforpostgresql/flexibleservers",
			path:       "databases",
			apiVersion: "2025-08-01",
			gapTarget:  "microsoft.dbforpostgresql/flexibleservers/databases",
		},
		{
			// Every server parameter, with Azure's own defaultValue, source and - the one that is
			// easiest to lose and hardest to live without - isConfigPendingRestart. That flag is
			// how the engine tells "the customer set wal_level=logical" apart from "wal_level is
			// actually logical right now", which are different by exactly one restart of a
			// production database.
			parentType: "microsoft.dbforpostgresql/flexibleservers",
			path:       "configurations",
			apiVersion: "2025-08-01",
			gapTarget:  "microsoft.dbforpostgresql/flexibleservers/configurations",
		},

		// --- service bus. A restored namespace with no queues or topics routes nothing.
		{
			parentType: "microsoft.servicebus/namespaces",
			path:       "queues",
			apiVersion: "2021-11-01",
			gapTarget:  "microsoft.servicebus/namespaces/queues",
		},
		{
			parentType: "microsoft.servicebus/namespaces",
			path:       "topics",
			apiVersion: "2021-11-01",
			gapTarget:  "microsoft.servicebus/namespaces/queues",
		},

		// --- workload identity. Without the federated credential the trust between the cluster's
		// service account and the identity is gone, so every pod using workload identity fails to
		// authenticate after a restore while the identity itself looks intact.
		{
			parentType: "microsoft.managedidentity/userassignedidentities",
			path:       "federatedIdentityCredentials",
			apiVersion: "2023-01-31",
			gapTarget:  "microsoft.managedidentity/userassignedidentities/federatedidentitycredentials",
			optional:   true,
		},

		// --- diagnostic settings, on EVERY resource.
		//
		// The empty parentType is deliberate and this is the only spec that uses it. Measured
		// against the live service: insightsresources does not hold diagnosticSettings, so there
		// is no query that returns them and a per-resource call is the only way. That makes this
		// the single most expensive line in the scanner - one call per resource - which is why
		// it is stated here rather than hidden.
		//
		// optional, because most resource types have none and many do not support them at all.
		{
			parentType: "",
			path:       diagnosticSettingsPath,
			apiVersion: "2021-05-01-preview",
			gapTarget:  "microsoft.insights/diagnosticsettings",
			optional:   true,
		},
	}
}

// diagnosticSettingsPath is an extension-resource path, hence the second /providers/ segment.
const diagnosticSettingsPath = "providers/Microsoft.Insights/diagnosticSettings"

// skipDiagnosticSettings lists type prefixes that never carry a diagnostic setting, so the
// wildcard spec does not spend a call proving it.
//
// Cost control, not correctness: a skipped call would have returned 404 or an empty list. Child
// and extension resources are excluded wholesale because diagnostic settings attach to top-level
// resources, and on any real estate those are the majority of rows.
func skipDiagnosticSettings(resourceType string) bool {
	if strings.Count(resourceType, "/") > 1 {
		// A child or extension type - "microsoft.network/privatednszones/a",
		// "microsoft.resources/subscriptions/resourcegroups".
		return true
	}
	for _, prefix := range []string{
		"microsoft.authorization/",
		"microsoft.resources/",
		"microsoft.managedidentity/",
		"microsoft.azurebusinesscontinuity/",
		"microsoft.insights/",
	} {
		if strings.HasPrefix(resourceType, prefix) {
			return true
		}
	}
	return false
}

// defaultFetchConcurrency bounds in-flight ARM calls. ARM throttles per subscription and per
// principal, and a thousand parallel GETs earns a 429 for the whole scan rather than a fast
// one. Modest on purpose: the fetcher is already the expensive tier and correctness of the
// estate matters more than the wall clock.
const defaultFetchConcurrency = 8

// maxFetchConcurrency caps whatever an operator asks for. Past a certain point more parallelism
// only converts a slow scan into a throttled one, and a 429 storm costs the whole scan.
const maxFetchConcurrency = 64

// fetchConcurrency reads PARITY_FETCH_CONCURRENCY, falling back to the default.
//
// Tunable without a rebuild ON PURPOSE. diagnosticSettings costs one ARM call per resource, so on a
// large estate this number is the dominant wall-clock cost - but the right value depends on how that
// subscription is throttled, which cannot be known from here. Guessing higher would trade a slow
// scan for a failed one, so the default stays conservative and the knob exists to be turned against
// a real estate while watching for 429s.
func fetchConcurrency() int {
	raw := strings.TrimSpace(os.Getenv("PARITY_FETCH_CONCURRENCY"))
	if raw == "" {
		return defaultFetchConcurrency
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		// A malformed value must not silently become 0, which would deadlock the worker pool.
		return defaultFetchConcurrency
	}
	if n > maxFetchConcurrency {
		return maxFetchConcurrency
	}
	return n
}

// newARMFetcher builds the real ARM client. Separated from fetchChildren so the end-to-end
// test drives the fetch logic through the armFetcher seam rather than reimplementing it.
func newARMFetcher() (armFetcher, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azure credential: %w", err)
	}
	pipeline, err := armruntime.NewPipeline("parity-scanner", collectorVersion, cred, azruntime.PipelineOptions{}, &arm.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			Retry: policy.RetryOptions{MaxRetries: 5},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("arm pipeline: %w", err)
	}
	return &armGet{pipeline: pipeline}, nil
}

// collectorVersion is stamped into the ARM user agent so a customer reading their Activity
// Log can tell which build made the call.
const collectorVersion = "0.1.0"

type armGet struct {
	pipeline azruntime.Pipeline
}

func (a *armGet) Get(ctx context.Context, path, apiVersion string) ([]byte, error) {
	request, err := azruntime.NewRequest(ctx, http.MethodGet, "https://management.azure.com"+path)
	if err != nil {
		return nil, err
	}
	query := request.Raw().URL.Query()
	query.Set("api-version", apiVersion)
	request.Raw().URL.RawQuery = query.Encode()
	request.Raw().Header.Set("Accept", "application/json")

	response, err := a.pipeline.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, azruntime.NewResponseError(response)
	}
	return azruntime.Payload(response)
}

// fetchChildren asks the resource providers for every child collection ARG does not return,
// and reports what it could not read rather than letting an unread thing look absent.
//
// A failed fetch does NOT fail the scan, unlike a failed Discover page. The distinction is
// deliberate: a dropped Discover page means the resource LIST is wrong and every count and
// closure built on it is wrong, so shipping it would be a false claim of completeness. A
// failed child fetch loses one known child of one known resource, and saying so precisely is
// more useful than discarding an otherwise-good estate.
func fetchChildren(ctx context.Context, fetcher armFetcher, resources []contract.Resource) ([]armResource, []contract.Gap) {
	type job struct {
		parent contract.Resource
		spec   childSpec
	}
	var jobs []job
	for _, spec := range childSpecs() {
		for _, r := range resources {
			if !specMatches(spec, r) {
				continue
			}
			jobs = append(jobs, job{parent: r, spec: spec})
		}
	}
	if len(jobs) == 0 {
		return nil, nil
	}

	type result struct {
		rows []armResource
		gap  *contract.Gap
	}
	results := make([]result, len(jobs))

	var wait sync.WaitGroup
	slots := make(chan struct{}, fetchConcurrency())
	for i, j := range jobs {
		wait.Add(1)
		go func(i int, j job) {
			defer wait.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			results[i].rows, results[i].gap = fetchOne(ctx, fetcher, j.parent, j.spec)
		}(i, j)
	}
	wait.Wait()

	var rows []armResource
	var gaps []contract.Gap
	for _, r := range results {
		rows = append(rows, r.rows...)
		if r.gap != nil {
			gaps = append(gaps, *r.gap)
		}
	}
	// Goroutines finish in whatever order they finish; the estate must not.
	sort.Slice(rows, func(a, b int) bool { return str(rows[a]["id"]) < str(rows[b]["id"]) })
	sort.Slice(gaps, func(a, b int) bool { return gaps[a].Target < gaps[b].Target })
	return rows, gaps
}

// specMatches decides whether one spec applies to one resource.
func specMatches(spec childSpec, r contract.Resource) bool {
	if spec.parentType != "" {
		return r.Type == spec.parentType
	}
	// The wildcard spec - diagnosticSettings. Skipping types that cannot carry one keeps the
	// call count proportional to top-level resources rather than to every row in the estate.
	return !skipDiagnosticSettings(r.Type)
}

// fetchOne reads one child collection off one parent.
func fetchOne(ctx context.Context, fetcher armFetcher, parent contract.Resource, spec childSpec) ([]armResource, *contract.Gap) {
	path := parent.ID + "/" + spec.path
	body, err := fetcher.Get(ctx, path, spec.apiVersion)
	if err != nil {
		return nil, fetchGap(parent, spec, err)
	}

	// ARM wraps a child collection in {"value": [...]}. A single child is returned bare.
	//
	// nextLink is read but NOT followed. Following it needs the whole absolute URL including its
	// opaque skipToken, and Get rebuilds the query string from the api-version alone - so passing
	// a nextLink through it would silently drop the token and re-fetch page one forever. Widening
	// the interface for a page nobody has yet observed is the wrong trade; declaring the
	// truncation is not. If this gap ever appears against a live estate, that is the evidence
	// that earns the interface change.
	var envelope struct {
		Value    json.RawMessage `json:"value"`
		NextLink string          `json:"nextLink"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, &contract.Gap{
			Reason: contract.GapNotAttempted,
			Target: path,
			Detail: fmt.Sprintf("the %s response could not be parsed, so this child is absent from the estate: %v", spec.path, err),
		}
	}
	payload := envelope.Value
	if len(payload) == 0 {
		payload = body
	}

	rows, err := decodeChildRows(payload)
	if err != nil {
		return nil, &contract.Gap{
			Reason: contract.GapNotAttempted,
			Target: path,
			Detail: fmt.Sprintf("the %s response was not the expected shape, so this child is absent from the estate: %v", spec.path, err),
		}
	}

	// STAMP THE VERSION WE READ WITH. Discover gets apiVersion from the Resource Graph for every
	// top-level resource; an ARM REST response does not echo it back, so children arrived without
	// one and 21 of 84 resources in a real estate had no version at all.
	//
	// That only surfaced when something tried to USE the estate: ARM rejects a template resource
	// with no apiVersion, so a restore could not be generated for any child. The version is right
	// here in the spec that fetched them, and recording what a document was read with is the same
	// promise Discover already makes.
	//
	// Before the truncation check below, not after: a truncated page still returns its rows, and
	// rows that reach the estate unstamped are exactly the ones a restore cannot rebuild.
	for _, row := range rows {
		if _, present := row["apiVersion"]; !present {
			row["apiVersion"] = spec.apiVersion
		}
	}

	// Both, deliberately. The rows are real and worth keeping; the gap is what stops a short list
	// from being read as a complete one.
	if envelope.NextLink != "" {
		return rows, &contract.Gap{
			Reason: contract.GapNotAttempted,
			Target: path,
			Detail: fmt.Sprintf("ARM returned %d %s and a nextLink, which this collector does not follow; the list is TRUNCATED and anything past the first page is missing from the estate", len(rows), spec.path),
		}
	}
	return rows, nil
}

// fetchGap turns a failed fetch into the gap reason that names who can fix it. A 403 is a
// product decision about what to ask a customer for; a 404 usually means the child simply is
// not configured, which is a fact rather than a hole.
func fetchGap(parent contract.Resource, spec childSpec, err error) *contract.Gap {
	path := parent.ID + "/" + spec.path

	var responseErr *azcore.ResponseError
	if errors.As(err, &responseErr) {
		switch responseErr.StatusCode {
		case http.StatusNotFound, http.StatusBadRequest:
			// 400 and 404 are NOT the same fact and must not share wording. ARM answers an
			// unsupported api-version with 400 InvalidApiVersionParameter, and calling that
			// "probably not configured" is a false statement printed once per resource - which is
			// exactly the not-configured-versus-wrong-call ambiguity §5.1 exists to remove.
			if responseErr.StatusCode == http.StatusBadRequest {
				// azcore leaves ErrorCode empty when nothing parses - a gateway 400 with an HTML
				// body, say - and "(%s)" of nothing reads as a typo rather than a fact.
				code := responseErr.ErrorCode
				if code == "" {
					code = "no error code returned"
				}
				// A version ARM refuses is OUR bug, and it is reported EVEN ON AN OPTIONAL CHILD.
				// That exception is the important half: diagnosticSettings is optional and pinned
				// to a preview api-version, and it is fetched against every resource in the
				// estate. The day that preview retires, every call 400s, every diagnostic setting
				// silently disappears - and the standing gap that would have said so is suppressed
				// too, because fetchedChildTargets() counts the child as fetched. The estate would
				// then claim completeness it does not have, everywhere at once.
				if !spec.optional || code == "InvalidApiVersionParameter" {
					return &contract.Gap{
						Reason: contract.GapNotAttempted,
						Target: path,
						Detail: fmt.Sprintf("ARM REJECTED the request for %s with HTTP 400 (%s); this is our call being wrong - most often an api-version the provider does not accept for this child - not a statement about the customer's estate", spec.path, code),
					}
				}
			}
			if spec.optional {
				// Declared optional: most parents do not have this child, and many types do not
				// support it at all. One gap per resource would bury every real finding, and §2.3
				// is only worth relying on if the gaps list stays readable. A 403 still becomes
				// a gap below, so a permission problem is never swallowed by this.
				return nil
			}
			// Nothing configured. ARM answers "no such child" the same way for "not set up"
			// and "wrong path", so this is reported rather than assumed empty.
			return &contract.Gap{
				Reason: contract.GapNotAttempted,
				Target: path,
				Detail: fmt.Sprintf("ARM returned 404 for %s; the child is probably not configured on this resource, but ARM does not distinguish that from a wrong path", spec.path),
			}
		case http.StatusForbidden, http.StatusUnauthorized:
			// The one reason no code change repairs. infra-scanner §5.1 requires every 403 to
			// become a Gap, and until the fetcher existed nothing could produce one.
			return &contract.Gap{
				Reason: contract.GapPermissionDenied,
				Target: path,
				Detail: fmt.Sprintf("the credential was denied %s on this resource (HTTP %d), so this child and every dependency it names are absent from the estate. This is fixable by granting a narrower-than-owner role, which is a product decision rather than a code one", spec.path, responseErr.StatusCode),
			}
		}
	}
	return &contract.Gap{
		Reason: contract.GapNotAttempted,
		Target: path,
		Detail: fmt.Sprintf("fetching %s failed, so this child is absent from the estate: %v", spec.path, err),
	}
}

// decodeChildRows reads a child collection, preserving number literals for the same reason
// Discover does: the document is the source material for every later derivation, and a
// float64 round-trip corrupts large integers permanently.
func decodeChildRows(payload []byte) ([]armResource, error) {
	trimmed := strings.TrimSpace(string(payload))
	if trimmed == "" || trimmed == "null" {
		return nil, nil
	}

	decoder := json.NewDecoder(strings.NewReader(trimmed))
	decoder.UseNumber()

	if strings.HasPrefix(trimmed, "[") {
		var rows []armResource
		if err := decoder.Decode(&rows); err != nil {
			return nil, err
		}
		return rows, nil
	}

	var single armResource
	if err := decoder.Decode(&single); err != nil {
		return nil, err
	}
	if len(single) == 0 {
		return nil, nil
	}
	return []armResource{single}, nil
}

// fetchedChildTargets is the set of unreadGaps entries the fetcher now closes, so the gap
// list and childSpecs cannot drift apart.
func fetchedChildTargets() map[string]bool {
	closed := map[string]bool{}
	for _, spec := range childSpecs() {
		closed[spec.gapTarget] = true
	}
	return closed
}
