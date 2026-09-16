package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	azruntime "github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/manukyanv07/parity-scanner/contract"
)

// armResource is one row as Azure Resource Graph returns it, before translation.
//
// A bare map on purpose: discover decodes nothing and folds nothing, so no field name is
// baked in here. Restating these facts in the contract's vocabulary is translate's job
// (infra-scanner §4).
type armResource map[string]any

// discoverQuery asks for every column, not a projection.
//
// The previous `| project id, type, name, location, resourceGroup, tags, sku, identity,
// properties` was a whitelist that silently discarded seven columns, and infra-scanner §4
// says the scanner "keeps everything and throws away nothing". The dropped ones were
// load-bearing: `plan` is the marketplace purchase plan, and a marketplace resource
// redeployed without it FAILS outright; `kind` is the only thing separating a Function App
// from a Web App and StorageV2 from BlobStorage; `zones` is availability-zone placement;
// `managedBy` says which resource owns this one; `apiVersion` is the schema the document
// was read under, without which a later re-derivation is guessing.
//
// The `order by` is not cosmetic. Resource Graph paging is only consistent over a
// deterministically ordered result set; without one a $skipToken walk can step over rows,
// and a skipped row is a resource missing from the recovery plan.
//
// The `extend` is not redundant. Measured against the live service: an unprojected
// `resources` query returns 16 columns and apiVersion is NOT among them, yet it is
// queryable once named. Without it every stored document has an unknown schema version,
// and infra-scanner §4's promise that a Knowledge Base improvement re-derives every held
// estate with no re-scan becomes guesswork. The self-reference is what surfaces the column
// without also adding an aliased duplicate.
//
// Do NOT narrow this to `properties` alone: ARG withholds $skipToken and sets
// resultTruncated when every output column is dynamic or null, which silently caps the
// walk at one page.
//
// testdata/discover.kql pins this string independently, so editing it shows up as a
// reviewable diff rather than a one-character change inside a test.
const discoverQuery = `resources
| extend apiVersion = apiVersion
| order by id asc`

// scanTable is one Azure Resource Graph table this collector reads.
//
// ARG splits the estate across 45 tables and `resources` is only one of them. Reading it
// alone left whole categories invisible - most sharply the authorization graph, which
// scanner-engine.md §12 measured as the failure that mattered: a recovered app came up with
// no role assignments while every dashboard stayed green.
//
// Verified against the live service: all seven tables exist, every one returns the SAME
// 16-column schema as `resources`, and `resources` returns ZERO role or policy assignments,
// so there is no id overlap and no deduplication to do.
type scanTable struct {
	name  string
	query string
	// primary marks the table whose emptiness is suspicious. Zero rows in `resources` means
	// an empty subscription or a credential that can read nothing; zero rows in dnsresources
	// is just a subscription with no DNS.
	primary bool
}

// scanTables is the cheap tier of #6: one paged query each, no per-resource fan-out.
func scanTables() []scanTable {
	const tail = "\n| extend apiVersion = apiVersion\n| order by id asc"
	return []scanTable{
		{name: "resources", query: "resources" + tail, primary: true},
		{name: "resourcecontainers", query: "resourcecontainers" + tail},
		// The authorization graph. §12's measured failure, and one query closes it.
		{name: "authorizationresources", query: "authorizationresources" + tail},
		// FILTERED, deliberately. Measured on an otherwise-empty subscription:
		// policyresources returned 22 rows, 21 of them microsoft.policyinsights/policystates
		// - per-resource compliance EVALUATION results, not configuration. On a real estate
		// that is tens of thousands of rows of churn that no recovery plan reads. Only the
		// authorization/policy* types describe what is configured.
		{name: "policyresources", query: `policyresources
| where type startswith "microsoft.authorization/policy"` + tail},
		{name: "networkresources", query: "networkresources" + tail},
		{name: "appserviceresources", query: "appserviceresources" + tail},
		// The estate's EXISTING backup and site-recovery posture. For a disaster-recovery
		// product this was the strangest thing to be missing.
		{name: "recoveryservicesresources", query: "recoveryservicesresources" + tail},
		{name: "dnsresources", query: "dnsresources" + tail},
		// The last three ARG tables. Each costs one paged query, and all three were verified
		// against the live service: they exist and answer 0 rows on a subscription with none of
		// their content, rather than erroring, so querying them is safe everywhere.
		//
		// insightsresources does NOT hold Microsoft.Insights/diagnosticSettings - measured, with
		// two diagnostic settings present and 15 minutes of propagation time, it still returned
		// zero. That is why diagnosticSettings is a per-resource fetch in childSpecs() and not
		// one more query here. What this table does hold is the rest of Azure Monitor:
		// autoscale settings, action groups, metric alerts and webtests, each of which is
		// configuration a recovered estate needs.
		{name: "insightsresources", query: "insightsresources" + tail},
		// In-guest policy assignments on VMs and Arc machines. Empty until the VM flavour exists,
		// and one query either way.
		{name: "guestconfigurationresources", query: "guestconfigurationresources" + tail},
	}
}

// pageSize is Resource Graph's per-page maximum ($top has a documented max of 1000).
const pageSize = 1000

// graphClient is the one Resource Graph call this collector makes. It mirrors
// *armresourcegraph.Client so the real client satisfies it as-is, and exists so the pager
// can be proven without a network (CONTRIBUTING.md: no network in unit tests).
type graphClient interface {
	Resources(ctx context.Context, query armresourcegraph.QueryRequest, options *armresourcegraph.ClientResourcesOptions) (armresourcegraph.ClientResourcesResponse, error)
}

// discover reads every resource in the subscription and reports everything it did not read
// as a gap, so that an unread thing never looks like an absent one (infra-scanner §3).
func discover(ctx context.Context, client graphClient, subscription string) ([]armResource, []contract.Gap, error) {
	var rows []armResource
	var gaps []contract.Gap
	for _, table := range scanTables() {
		read, tableGaps, err := queryTable(ctx, client, subscription, table)
		if err != nil {
			return nil, nil, err
		}
		rows = append(rows, read...)
		gaps = append(gaps, tableGaps...)
	}
	// unreadGaps is NOT appended here. It needs to know which resource types the estate
	// actually holds, which is only true after translate, so Collect appends it.
	return rows, gaps, nil
}

// newGraphClient builds the real Resource Graph client. Separated from discover so the
// end-to-end test can drive the whole collector through the graphClient seam instead of
// reimplementing Collect's body.
//
// Retry is stated explicitly rather than inherited: azcore's default is 3 attempts, which
// is thin for a walk of 60+ back-to-back pages sharing one throttling quota.
func newGraphClient() (graphClient, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azure credential: %w", err)
	}
	client, err := armresourcegraph.NewClient(cred, &arm.ClientOptions{
		ClientOptions: azcore.ClientOptions{
			// Stated, not inherited. azcore defaults to 3 attempts with an 800ms base,
			// which is thin for a walk of 60+ back-to-back pages sharing one ARG quota.
			// ARG publishes its own quota headers rather than Retry-After, so waitForQuota
			// does the primary pacing and this is the backstop for genuine transients.
			Retry: policy.RetryOptions{
				MaxRetries:    6,
				RetryDelay:    2 * time.Second,
				MaxRetryDelay: 60 * time.Second,
			},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("resource graph client: %w", err)
	}
	return client, nil
}

// unreadGaps is everything this collector does not fetch. infra-scanner §3 allows no third
// option — a thing that is neither read nor reported is a silent hole in the recovery plan
// — so each is reported on every scan until a ticket fetches it (E1.4, #6).
//
// The measured cost of getting this wrong: a naive scan never pulled
// authorizationresources, so the whole authorization graph was invisible and a recovered
// app came up with no role assignments while every dashboard stayed green
// (scanner-engine.md §12).
//
// Each entry carries the reason that describes its OWNER, because the fix differs:
// not-attempted is a bug we can close with code, data-plane is permanent and deliberate,
// no-collector needs a collector that does not exist yet.
// gapCondition pairs a gap with the resource type whose ABSENCE makes it irrelevant.
type gapCondition struct {
	gap contract.Gap
	// requiresType, when set, means the gap is only reported if the estate holds at least one
	// resource of this type. Empty means always report.
	requiresType string
}

func unreadGaps(present map[string]bool) []contract.Gap {
	// Anything the fetcher now reads is filtered out at the end, so childSpecs() and this
	// list cannot drift into claiming a child is unread when it is fetched.
	conditional := []gapCondition{
		// The seven ARG tables that used to be listed here are now QUERIED - see
		// scanTables(). What remains needs a per-resource ARM call rather than one more
		// paged query, which is a different cost tier: one call per resource rather than one
		// query per table, so the cost scales with the estate instead of being flat.

		{
			gap: contract.Gap{
				Reason: contract.GapNotAttempted,
				Target: "microsoft.web/sites/config/*",
				Detail: "App Service and Function App setting VALUES are masked by Azure as ####### in sites/config, and reading them needs POST .../config/appsettings/list - an action, so no read-only role can ever reach it (Website Contributor, or a custom role holding just that action). What IS collected on Reader alone: every setting NAME, and for any setting backed by a vault the full pointer - which vault, which secret, which identity resolves it, and whether it currently resolves. So a Key Vault-backed setting is fully rebuildable and only a plain literal value has to be re-supplied by the customer",
			},
			requiresType: "microsoft.web/sites",
		},

		// Defender / security posture, deliberately never collected. Declared because §3 allows no
		// third option, and because a customer WILL ask whether we scan security posture. Reading
		// securityresources cost one query and returned 294 out-of-scan references to global
		// assessment metadata on a real estate - it describes how secure an estate is, not how to
		// stand it back up, so it is noise in a recovery catalogue rather than signal.
		{
			gap: contract.Gap{
				Reason: contract.GapNotAttempted,
				Target: "securityresources",
				Detail: "Microsoft Defender assessments, secure scores and security contacts are deliberately not collected. They describe security POSTURE, not recoverable configuration, so they cannot contribute to standing an application back up in a new subscription - and on a measured estate they contributed 294 references to global assessment metadata, drowning the real dependency graph. Use Defender itself for posture",
			},
		},

		// The other half of endpoint.go. Dependencies written as a hostname resolve only when some
		// scanned resource declares that hostname as its own, which is what keeps the match a
		// lookup against observed fact instead of a guess - but it leaves two holes, and neither
		// is detectable from inside a scan.
		{
			gap: contract.Gap{
				Reason: contract.GapNotAttempted,
				Target: "endpoint-fqdn-resolution",
				Detail: "dependencies written as a hostname rather than a resource id are resolved only when a scanned resource declares that hostname; two cases stay unlinked and cannot be told apart from here. A hostname belonging to a resource in an un-onboarded account carries no subscription or resource group, so it cannot be resolved without onboarding that account (AD-013) - synthesizing an id would fabricate a resource. And a hostname whose owner does not declare it, such as an AKS cluster's generated fqdn, is not indexed, because claiming a hostname whose leading label is not the resource's own name would invent an edge. Every hostname survives in Document either way, so the engine can resolve both once the resource-type table names which field holds each type's endpoint",
			},
		},

		// --- tables that exist but this collector does not read ---
		// Verified to exist against the live service. Not in the cheap tier, but §3 allows no
		// third option, so they are declared rather than silently skipped. An earlier version
		// of this list omitted all three, and the queried-or-gapped invariant test caught it.

		// --- children no ARG table returns: a per-resource ARM call each ---
		{
			gap: contract.Gap{
				Reason: contract.GapNotAttempted,
				Target: "microsoft.storage/storageaccounts/blobservices",
				Detail: "blob services and containers (and file shares, queues, tables, lifecycle policies) are in no ARG table and were not fetched; a restored storage account would have no containers",
			},
			requiresType: "microsoft.storage/storageaccounts",
		},
		{
			gap: contract.Gap{
				Reason: contract.GapNotAttempted,
				Target: "microsoft.dbforpostgresql/flexibleservers/databases",
				Detail: "the databases inside a Postgres Flexible Server are in no ARG table and were not fetched; a plan built from that estate protects the server and misses its data",
			},
			requiresType: "microsoft.dbforpostgresql/flexibleservers",
		},
		{
			gap: contract.Gap{
				Reason: contract.GapNotAttempted,
				Target: "microsoft.dbforpostgresql/flexibleservers/configurations",
				Detail: "Postgres server parameters are in no ARG table and were not fetched; nothing downstream can tell a server that supports a change stream from one that does not",
			},
			requiresType: "microsoft.dbforpostgresql/flexibleservers",
		},
		{
			gap: contract.Gap{
				Reason: contract.GapNotAttempted,
				Target: "microsoft.insights/diagnosticsettings",
				Detail: "diagnostic settings are in no ARG table and were not fetched; a restored estate would be unmonitored",
			},
		},
		{
			gap: contract.Gap{
				Reason: contract.GapNotAttempted,
				Target: "microsoft.servicebus/namespaces/queues",
				Detail: "Service Bus queues, topics and subscriptions are in no ARG table and were not fetched; a restored namespace would be empty",
			},
			requiresType: "microsoft.servicebus/namespaces",
		},
		{
			gap: contract.Gap{
				Reason: contract.GapNotAttempted,
				Target: "microsoft.managedidentity/userassignedidentities/federatedidentitycredentials",
				Detail: "federated identity credentials are in no ARG table and were not fetched; workload-identity authentication would fail after a restore",
			},
			requiresType: "microsoft.managedidentity/userassignedidentities",
		},

		// --- deliberate and permanent: we never read these ---
		{
			gap: contract.Gap{
				Reason: contract.GapDataPlane,
				Target: "microsoft.appconfiguration/configurationstores/keyvalues",
				Detail: "App Configuration key-values were not fetched, and cannot be on Reader. " +
					"Measured against a live store rather than inferred: there is NO ARM list " +
					"operation for key-values at any api-version (2023-03-01, 2024-06-01 and " +
					"2025-08-01-preview all return 404), so enumeration exists only on the data " +
					"plane, behind Microsoft.AppConfiguration/configurationStores/keyValues/read - " +
					"a dataAction that Reader's */read wildcard cannot reach and that subscription " +
					"Owner does not hold either (Owner's dataActions list is empty; enumerating with " +
					"an Owner token returns Forbidden). The single-item ARM GET " +
					".../keyValues/{key} IS control-plane and does work on Reader, but it requires " +
					"the key name in advance, which is the thing being discovered. So the KEY NAMES " +
					"and the VALUES sit behind one identical permission: there is no way to learn " +
					"what configuration exists without also being able to read it. Rather than hold " +
					"a data-plane role and promise not to use it, we hold neither and the store is " +
					"restored empty for the customer to repopulate. Upgrading would mean granting " +
					"App Configuration Data Reader (516239f1-63e1-4d78-a4de-a74fb236a071), or a " +
					"custom role with just that one dataAction",
			},
			requiresType: "microsoft.appconfiguration/configurationstores",
		},

		// --- needs a collector that does not exist yet (AD-012) ---
		{
			gap: contract.Gap{
				Reason: contract.GapNoCollector,
				Target: "microsoft.containerservice/managedclusters",
				Detail: "objects inside a Kubernetes cluster (Deployments, Services, Ingresses, ConfigMaps, Secrets) need the Kubernetes collector, which does not exist yet, so a recovered cluster is an empty control plane",
			},
			requiresType: "microsoft.containerservice/managedclusters",
		},
	}

	fetched := fetchedChildTargets()
	out := make([]contract.Gap, 0, len(conditional))
	for _, c := range conditional {
		// A gap for a type the estate does not contain is noise, and noise in the gaps list is
		// expensive: §2.3 makes that list the scanner's own statement about what it missed, so a
		// reader has to be able to trust every line. Reporting "objects inside a Kubernetes
		// cluster were not read" to a customer with no Kubernetes cluster teaches them to skim.
		if c.requiresType != "" && !present[c.requiresType] {
			continue
		}
		if fetched[c.gap.Target] {
			continue
		}
		out = append(out, c.gap)
	}
	return out
}

// completeness describes what the service said about the walk, separately from what we
// read, so a disagreement can be reported as the specific thing it is.
type completeness struct {
	baselineTotal *int64 // TotalRecords from the FIRST page — the count for this snapshot
	lastTotal     *int64 // TotalRecords from the final page
	pages         int
}

// queryResources pages the Resource Graph query to exhaustion and hands back the rows
// untouched, plus a gap for anything the service did not let it read.
//
// A failed page fails the whole scan. Returning the rows read so far would emit an estate
// that claims to be a complete subscription, and the engine cannot tell a resource that
// was never read from one that was deleted.
func queryResources(ctx context.Context, client graphClient, subscription string) ([]armResource, []contract.Gap, error) {
	return queryTable(ctx, client, subscription, scanTable{name: "resources", query: discoverQuery, primary: true})
}

// queryTable pages one table to exhaustion.
func queryTable(ctx context.Context, client graphClient, subscription string, table scanTable) ([]armResource, []contract.Gap, error) {
	var (
		rows  []armResource
		gaps  []contract.Gap
		sent  string // the $skipToken on the last request; "" means none
		seen  = map[string]struct{}{}
		state completeness
	)

	for {
		// The caller's context may carry a deadline the SDK would honour, but the loop
		// bound must not depend on that: a rotating token would otherwise keep allocating.
		if err := ctx.Err(); err != nil {
			return nil, nil, fmt.Errorf("resource graph query (%s, subscription %s, page %d, %d rows read): %w", table.name, subscription, state.pages+1, len(rows), err)
		}

		options := &armresourcegraph.QueryRequestOptions{
			ResultFormat: to.Ptr(armresourcegraph.ResultFormatObjectArray),
			Top:          to.Ptr(int32(pageSize)),
		}
		if sent != "" {
			options.SkipToken = to.Ptr(sent)
		}

		// Capture the raw response so the quota headers and the untouched body are both
		// reachable. The typed response exposes neither.
		var raw *http.Response
		pageCtx := policy.WithCaptureResponse(ctx, &raw)

		resp, err := client.Resources(pageCtx, armresourcegraph.QueryRequest{
			Query:         to.Ptr(table.query),
			Subscriptions: []*string{&subscription},
			Options:       options,
		}, nil)
		if err != nil {
			return nil, nil, fmt.Errorf("resource graph query (%s, subscription %s, page %d, %d rows read): %w", table.name, subscription, state.pages+1, len(rows), err)
		}
		state.pages++

		decoded, err := decodePage(raw, resp.Data)
		if err != nil {
			return nil, nil, fmt.Errorf("resource graph response (%s, subscription %s, page %d): %w", table.name, subscription, state.pages, err)
		}
		rows = append(rows, decoded...)

		if resp.TotalRecords != nil {
			if state.baselineTotal == nil {
				state.baselineTotal = resp.TotalRecords
			}
			state.lastTotal = resp.TotalRecords
		}

		// resultTruncated is deliberately NOT read here. Microsoft documents it as true
		// "when there are less resources available than a query is requesting", which is
		// the normal state of the LAST page of every walk and of any subscription under
		// $top rows. Treating it as "the service dropped rows" made every complete scan
		// claim it was cut short. The documented equivalent test for a genuinely capped
		// result is count < totalRecords, which is the check below.

		next := ""
		if resp.SkipToken != nil {
			next = *resp.SkipToken
		}
		if next == "" {
			break
		}
		// Comparing only against the immediately preceding token lets two alternating
		// tokens page forever, so every token is remembered.
		if _, repeat := seen[next]; repeat {
			return nil, nil, fmt.Errorf("resource graph query (%s, subscription %s): the service re-issued a $skipToken already seen, after page %d and %d rows; refusing to page forever", table.name, subscription, state.pages, len(rows))
		}
		seen[next] = struct{}{}
		sent = next

		// A hard ceiling independent of the token: whatever the service does, the walk
		// cannot exceed the record count it told us about.
		if over, limit := exceededPageBudget(state); over {
			return nil, nil, fmt.Errorf("resource graph query (%s, subscription %s): read %d rows over %d pages, past the %d-page budget for a reported %d records; refusing to continue", table.name, subscription, len(rows), state.pages, limit, *state.baselineTotal)
		}

		waitForQuota(ctx, raw)
	}

	gaps = append(gaps, completenessGaps(subscription, table, state, len(rows))...)
	return rows, gaps, nil
}

// exceededPageBudget bounds the walk by the service's own record count, with slack for
// rows created mid-walk.
func exceededPageBudget(state completeness) (bool, int) {
	if state.baselineTotal == nil {
		return false, 0
	}
	limit := int((*state.baselineTotal+pageSize-1)/pageSize) + 8
	return state.pages > limit, limit
}

// completenessGaps turns a disagreement between what the service counted and what we read
// into the specific claim it actually is.
func completenessGaps(subscription string, table scanTable, state completeness, read int) []contract.Gap {
	var gaps []contract.Gap
	target := "/subscriptions/" + subscription

	if state.baselineTotal != nil {
		baseline := *state.baselineTotal

		// ARG is fed by continuous ARM notifications, so the matching-record count moves
		// under a walk. A count that GREW means the estate changed while we read it, which
		// is drift, not unread resources — and reporting "read more than exist" as a gap
		// was incoherent to a human.
		if state.lastTotal != nil && *state.lastTotal != baseline {
			gaps = append(gaps, contract.Gap{
				Reason: contract.GapNotAttempted,
				Target: target,
				Detail: fmt.Sprintf("the estate changed while it was being read: resource graph reported %d records on the first page and %d on the last, so this scan is a smear across that window rather than one instant", baseline, *state.lastTotal),
			})
		}

		// A genuine short read: fewer rows than the service said matched. This is the
		// documented equivalent of a capped result, and it catches a dropped page, an
		// overlapping token walk, or a page that returned fewer rows than it claimed.
		if int64(read) < baseline {
			gaps = append(gaps, contract.Gap{
				Reason: contract.GapNotAttempted,
				Target: target,
				Detail: fmt.Sprintf("resource graph reported %d records but the scan read only %d; %d resources are missing from this estate", baseline, read, baseline-int64(read)),
			})
		}
	}

	// Zero rows. A subscription that does not exist, sits in another tenant, or is
	// invisible to the credential returns 403 and never reaches here — that path errors
	// out above. So what remains is a genuinely empty subscription, or one where the
	// credential can read no resource inside it. Those two are still indistinguishable
	// from here, and RBAC filtering is silent: ARG returns 200 with only the rows the
	// principal can see, and TotalRecords counts only those, so no internal check fires.
	if read == 0 && table.primary {
		gaps = append(gaps, contract.Gap{
			Reason: contract.GapPermissionDenied,
			Target: target,
			Detail: "resource graph returned no resources at all; the subscription is genuinely empty, or the credential can read nothing inside it — resource graph filters silently, so these are indistinguishable from here. Verify the credential holds Reader at subscription scope before treating this estate as complete",
		})
	}

	return gaps
}

// quotaHeaders are ARG's throttling contract. It does not use Retry-After: it publishes a
// remaining-query count and a reset window, and the caller is expected to wait.
const (
	quotaRemainingHeader = "x-ms-user-quota-remaining"
	quotaResetsHeader    = "x-ms-user-quota-resets-after"
)

// waitForQuota sleeps when ARG says the caller has spent its query allowance.
//
// Without this a 60-page walk fires 60 back-to-back queries against a quota of roughly 15
// per 5 seconds, burns the retry policy's attempts, and dies with no partial estate and no
// resume point — so a large tenant has no successful attempt rather than a slow one. Each
// paginated query costs one unit of quota.
func waitForQuota(ctx context.Context, raw *http.Response) {
	if raw == nil {
		return
	}
	if remaining := strings.TrimSpace(raw.Header.Get(quotaRemainingHeader)); remaining == "" || remaining != "0" {
		return
	}
	wait := parseResetWindow(raw.Header.Get(quotaResetsHeader))
	if wait <= 0 {
		wait = 5 * time.Second
	}
	select {
	case <-ctx.Done():
	case <-time.After(wait):
	}
}

// parseResetWindow reads ARG's hh:mm:ss reset window, tolerating a bare seconds count.
func parseResetWindow(value string) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	var h, m, s int
	if n, err := fmt.Sscanf(value, "%d:%d:%d", &h, &m, &s); err == nil && n == 3 {
		return time.Duration(h)*time.Hour + time.Duration(m)*time.Minute + time.Duration(s)*time.Second
	}
	if n, err := fmt.Sscanf(value, "%d", &s); err == nil && n == 1 {
		return time.Duration(s) * time.Second
	}
	return 0
}

// decodePage prefers the response's untouched bytes over the SDK's decoded tree.
//
// The SDK unmarshals Data into `any` with encoding/json, which turns every JSON number into
// a float64 — so 9007199254740993 comes back as ...992, permanently and undetectably. A
// config-diffing engine then reports a phantom change forever. Decoding the raw body with
// UseNumber keeps the literal digits, which is what contract.md §2.1's "exactly as the
// cloud returned it" actually requires.
//
// Falls back to the decoded tree when the raw body is unavailable (notably in unit tests,
// where the fake client returns a typed response and no HTTP response at all).
func decodePage(raw *http.Response, data any) ([]armResource, error) {
	if raw != nil {
		if body, err := azruntime.Payload(raw); err == nil && len(body) > 0 {
			rows, err := decodeRowsPreservingNumbers(body)
			if err == nil {
				return rows, nil
			}
			// A body we cannot parse is not a reason to lose the page; the typed tree is
			// lossy for large integers but structurally the same.
		}
	}
	return decodeRows(data)
}

// decodeRowsPreservingNumbers pulls the `data` array out of a raw ARG response body without
// widening any number to float64.
func decodeRowsPreservingNumbers(body []byte) ([]armResource, error) {
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()

	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := decoder.Decode(&envelope); err != nil {
		return nil, fmt.Errorf("response envelope: %w", err)
	}
	if len(envelope.Data) == 0 {
		return nil, nil
	}

	rowDecoder := json.NewDecoder(strings.NewReader(string(envelope.Data)))
	rowDecoder.UseNumber()
	var rows []armResource
	if err := rowDecoder.Decode(&rows); err != nil {
		return nil, fmt.Errorf("response rows: %w", err)
	}
	return rows, nil
}

// decodeRows unwraps one objectArray response body. Anything other than an array of
// objects means we are not reading what we think we are reading, so it is an error rather
// than an empty page.
func decodeRows(data any) ([]armResource, error) {
	if data == nil {
		return nil, nil
	}
	list, ok := data.([]any)
	if !ok {
		return nil, fmt.Errorf("got %T, want a row array", data)
	}

	rows := make([]armResource, 0, len(list))
	for i, item := range list {
		row, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("row %d is %T, want an object", i, item)
		}
		rows = append(rows, row)
	}
	return rows, nil
}
