package azure

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
	"github.com/manukyanv07/parity-scanner/contract"
)

// End-to-end through the collector: canned Resource Graph pages in, a marshalled
// contract.Estate out.
//
// It calls the REAL Collect through the graphClient seam rather than reimplementing its
// body. An earlier version of this file duplicated Collect's wiring and had already
// drifted from it — the copy's gap text no longer matched production's — so the suite was
// proving that the test's own pipeline composed. The only seam left uncovered is
// credential and client construction, which needs a subscription (E5's job).
//
// link() is still a stub (E1.3, #5), so references are expected empty. Asserted
// explicitly, so the day link lands this fails and gets updated deliberately.
func collectFromPages(t *testing.T, subscription string, pages []page) contract.Estate {
	t.Helper()

	// discover reads several ARG tables now, so the fake has to answer per table rather than
	// by call index: the scripted pages belong to `resources`, and every other table is
	// legitimately empty in this fixture.
	collector := &Collector{
		subscription: subscription,
		client:       &tableGraph{resources: pages},
		// No private endpoints in this fixture, so the fetcher is never asked anything; a
		// fetcher that refuses every call proves that.
		fetcher: refusingFetcher{},
	}
	resources, references, gaps, err := collector.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	// Assembled the way agent/cmd/scanner/main.go assembles it.
	return contract.Estate{
		ContractVersion: contract.ContractVersion,
		Scan: contract.ScanMeta{
			Provider:      contract.Provider(collector.Plane()),
			Account:       subscription,
			ScannedAt:     "2026-08-11T12:00:00Z",
			Collector:     "azure/0.1.0",
			ResourceCount: len(resources),
			Gaps:          gaps,
		},
		Resources:    resources,
		Dependencies: references,
	}
}

// tableGraph answers the `resources` query from a script and every other table with an empty
// page, so a multi-table scan can be driven without inventing fixtures for tables this
// fixture has nothing in.
type tableGraph struct {
	resources []page
	seen      int
}

func (g *tableGraph) Resources(ctx context.Context, q armresourcegraph.QueryRequest, o *armresourcegraph.ClientResourcesOptions) (armresourcegraph.ClientResourcesResponse, error) {
	if q.Query == nil || !strings.HasPrefix(*q.Query, "resources") {
		return armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{
			Data: []any{}, TotalRecords: i64(0),
		}}, nil
	}
	if g.seen >= len(g.resources) {
		return armresourcegraph.ClientResourcesResponse{}, fmt.Errorf("the resources script ran out after %d pages", g.seen)
	}
	p := g.resources[g.seen]
	g.seen++
	resp := armresourcegraph.ClientResourcesResponse{QueryResponse: armresourcegraph.QueryResponse{
		Data: p.data, TotalRecords: p.total,
	}}
	if p.skipToken != "" {
		resp.SkipToken = &p.skipToken
	}
	return resp, nil
}

// estatePages is a deliberately awkward two-page subscription: mixed ARM casing, a
// top-level resource, a child, an extension resource, a global resource, and a
// secret-bearing web app.
func estatePages() []page {
	first := []any{
		map[string]any{
			"id":            "/subscriptions/SUB-1/resourceGroups/RG/providers/Microsoft.Network/virtualNetworks/VNet1",
			"type":          "Microsoft.Network/virtualNetworks",
			"name":          "VNet1",
			"location":      "eastus",
			"resourceGroup": "RG",
			"tags":          map[string]any{"dr-tier": "gold"},
			"properties":    map[string]any{"addressSpace": map[string]any{"addressPrefixes": []any{"10.10.0.0/16"}}},
		},
		map[string]any{
			"id":            "/subscriptions/SUB-1/resourceGroups/RG/providers/Microsoft.Network/virtualNetworks/VNet1/subnets/db",
			"type":          "Microsoft.Network/virtualNetworks/subnets",
			"name":          "db",
			"location":      "eastus",
			"resourceGroup": "RG",
			"properties":    map[string]any{"addressPrefix": "10.10.1.0/24"},
		},
		map[string]any{
			// An extension resource: ARM nests a second /providers/. Role assignments have
			// this shape, and the authorizationresources table is already in unreadGaps().
			"id":            "/subscriptions/SUB-1/resourceGroups/RG/providers/Microsoft.ContainerService/managedClusters/aks1/providers/Microsoft.KubernetesConfiguration/extensions/flux",
			"type":          "Microsoft.KubernetesConfiguration/extensions",
			"name":          "flux",
			"location":      "eastus",
			"resourceGroup": "RG",
		},
	}
	second := []any{
		map[string]any{
			"id":            "/subscriptions/SUB-1/resourceGroups/RG/providers/Microsoft.Web/sites/MyWebApp",
			"type":          "Microsoft.Web/sites",
			"name":          "MyWebApp",
			"location":      "East US",
			"resourceGroup": "RG",
			"properties": map[string]any{
				"siteConfig": map[string]any{
					"appSettings": []any{
						map[string]any{"name": "DB_PASSWORD", "value": "hunter2"},
					},
				},
				// Three references, one per resolution, so the split is proven end to end:
				//   in-scan          - the subnet IS a row in this fixture
				//   child-of-scanned - subnets/other is NOT a row, but VNet1 is
				//   out-of-scan      - another subscription entirely
				"virtualNetworkSubnetId": "/subscriptions/SUB-1/resourceGroups/RG/providers/Microsoft.Network/virtualNetworks/VNet1/subnets/db",
				"backupSubnetId":         "/subscriptions/SUB-1/resourceGroups/RG/providers/Microsoft.Network/virtualNetworks/VNet1/subnets/other",
				"sharedVaultId":          "/subscriptions/OTHER-SUB/resourceGroups/hub/providers/Microsoft.KeyVault/vaults/hubkv",
				// Not an ARM id, so it must NOT become a reference - and redaction must not
				// touch it either, since the graph is built from join keys like this.
				"keyVaultUri": "https://kv.vault.azure.net/",
			},
		},
		map[string]any{
			"id":            "/subscriptions/SUB-1/resourceGroups/RG/providers/Microsoft.Network/privateDnsZones/privatelink.vaultcore.azure.net",
			"type":          "Microsoft.Network/privateDnsZones",
			"name":          "privatelink.vaultcore.azure.net",
			"location":      "global",
			"resourceGroup": "RG",
		},
	}
	return []page{
		{data: first, skipToken: "page-2", total: i64(5)},
		{data: second, total: i64(5)},
	}
}

const (
	e2eVNet   = "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.network/virtualnetworks/vnet1"
	e2eSubnet = e2eVNet + "/subnets/db"
	e2eAKS    = "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.containerservice/managedclusters/aks1"
	e2eFlux   = e2eAKS + "/providers/microsoft.kubernetesconfiguration/extensions/flux"
	e2eWeb    = "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.web/sites/mywebapp"
	e2eZone   = "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.network/privatednszones/privatelink.vaultcore.azure.net"
)

func TestE2EResourceGraphToEstate(t *testing.T) {
	estate := collectFromPages(t, "sub-1", estatePages())

	// Round-trip the wire format: what the engine receives is what we assert on.
	encoded, err := json.Marshal(estate)
	if err != nil {
		t.Fatalf("marshal estate: %v", err)
	}
	var decoded contract.Estate
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal estate: %v", err)
	}

	if decoded.ContractVersion != 1 {
		t.Errorf("contractVersion = %d, want 1", decoded.ContractVersion)
	}
	if decoded.Scan.ResourceCount != 5 || len(decoded.Resources) != 5 {
		t.Fatalf("resourceCount = %d, resources = %d, want 5 and 5 (both pages translated)",
			decoded.Scan.ResourceCount, len(decoded.Resources))
	}

	byID := map[string]contract.Resource{}
	for _, r := range decoded.Resources {
		if r.ID != strings.ToLower(r.ID) {
			t.Errorf("id %q left the collector un-normalized", r.ID)
		}
		if r.Provider != contract.ProviderAzure {
			t.Errorf("%s has provider %q", r.ID, r.Provider)
		}
		// Must equal ScanMeta.Account, or the estate cannot join to itself.
		if r.Account != decoded.Scan.Account {
			t.Errorf("%s account %q != scan.account %q", r.ID, r.Account, decoded.Scan.Account)
		}
		if r.Type != strings.ToLower(r.Type) {
			t.Errorf("%s type %q is not case-folded", r.ID, r.Type)
		}
		byID[r.ID] = r
	}

	for _, want := range []string{e2eVNet, e2eSubnet, e2eFlux, e2eWeb, e2eZone} {
		if _, ok := byID[want]; !ok {
			t.Fatalf("estate is missing %s", want)
		}
	}

	// Ancestry is resolved by the collector so no engine-side code parses an id.
	if got := byID[e2eSubnet].ParentID; got != e2eVNet {
		t.Errorf("subnet parentId = %q, want %q", got, e2eVNet)
	}
	if got := byID[e2eVNet].ParentID; got != "" {
		t.Errorf("vnet parentId = %q, want empty", got)
	}

	// The extension resource: typed from the LAST /providers/, parented to its scope.
	flux := byID[e2eFlux]
	if flux.Type != "microsoft.kubernetesconfiguration/extensions" {
		t.Errorf("extension type = %q, want microsoft.kubernetesconfiguration/extensions", flux.Type)
	}
	if flux.ParentID != e2eAKS {
		t.Errorf("extension parentId = %q, want the cluster %q", flux.ParentID, e2eAKS)
	}

	// Name keeps its casing; only keys are normalized.
	if got := byID[e2eWeb].Name; got != "MyWebApp" {
		t.Errorf("web app Name = %q, want MyWebApp", got)
	}
	if got := byID[e2eWeb].Group; got != "RG" {
		t.Errorf("web app Group = %q, want RG", got)
	}

	// Region is folded, and a global resource carries none.
	if got := byID[e2eWeb].Region; got != "eastus" {
		t.Errorf("web app region = %q, want eastus (folded, spaces stripped)", got)
	}
	if got := byID[e2eZone].Region; got != "" {
		t.Errorf("private dns zone region = %q, want empty", got)
	}
	if got := byID[e2eVNet].Tags["dr-tier"]; got != "gold" {
		t.Errorf("vnet lost its dr-tier tag: %v", byID[e2eVNet].Tags)
	}

	// The secret is withheld; the join keys that make the graph are not.
	app := byID[e2eWeb]
	if len(app.Redactions) != 1 || app.Redactions[0].Path != "properties.siteConfig.appSettings[0].value" {
		t.Errorf("web app redactions = %v, want exactly the app setting value", app.Redactions)
	}
	var appDoc map[string]any
	if err := json.Unmarshal(app.Document, &appDoc); err != nil {
		t.Fatalf("web app document: %v", err)
	}
	properties := appDoc["properties"].(map[string]any)
	const subnetRef = "/subscriptions/SUB-1/resourceGroups/RG/providers/Microsoft.Network/virtualNetworks/VNet1/subnets/db"
	if properties["virtualNetworkSubnetId"] != subnetRef {
		t.Errorf("virtualNetworkSubnetId did not survive verbatim: %v", properties["virtualNetworkSubnetId"])
	}
	if properties["keyVaultUri"] != "https://kv.vault.azure.net/" {
		t.Errorf("keyVaultUri did not survive: %v", properties["keyVaultUri"])
	}

	// Silence is never a verdict: the tables discover did not query are reported.
	if len(decoded.Scan.Gaps) == 0 {
		t.Fatal("no gaps reported; an empty list claims the scan was complete")
	}
	targets := map[string]bool{}
	for _, g := range decoded.Scan.Gaps {
		targets[g.Target] = true
		if g.Reason == "" {
			t.Errorf("gap on %q has no reason", g.Target)
		}
	}
	// The seven cheap-tier tables are now QUERIED, so they must no longer appear as gaps -
	// that would be a false claim in the other direction. What remains needs a per-resource
	// ARM call, or a collector that does not exist.
	for _, wrong := range []string{
		"authorizationresources", "resourcecontainers", "policyresources",
		"networkresources", "appserviceresources", "recoveryservicesresources", "dnsresources",
	} {
		if targets[wrong] {
			t.Errorf("%q is queried now, so reporting it unread is a false claim", wrong)
		}
	}
	// The fixture HAS a web app, so the app-settings gap applies to it.
	if !targets["microsoft.web/sites/config/*"] {
		t.Error("gap list does not mention microsoft.web/sites/config/* despite a web app in the estate")
	}
	// And it has NO Key Vault and NO Kubernetes cluster as resources - the cluster appears only
	// inside an extension's id and the vault only inside a private DNS zone name. Reporting
	// "Key Vault secrets were not read" or "objects inside a Kubernetes cluster were not read" to
	// an estate that contains neither is a standing false claim, and it teaches a reader to skim
	// the one list §2.3 needs them to trust.
	for _, absent := range []string{
		"microsoft.containerservice/managedclusters",
	} {
		if targets[absent] {
			t.Errorf("%q is reported as a gap, but the estate holds no resource of that type", absent)
		}
	}
	// The completeness guard must be quiet: every discovered row was translated. Matched
	// against production's own wording, because this now runs the real Collect.
	for _, g := range decoded.Scan.Gaps {
		if strings.Contains(g.Detail, "but translated") {
			t.Errorf("the completeness guard fired: %s", g.Detail)
		}
	}

	// link() is live: the collector now emits references with a resolution stated relative
	// to this scan. The 32/64/2 shape of the measured estate is what these three cases are.
	if len(decoded.Dependencies) != 3 {
		t.Fatalf("references = %d, want 3: %+v", len(decoded.Dependencies), decoded.Dependencies)
	}
	byVia := map[string]contract.Dependency{}
	for _, ref := range decoded.Dependencies {
		if ref.From != e2eWeb {
			t.Errorf("reference from %q, want the web app", ref.From)
		}
		if ref.To != strings.ToLower(ref.To) {
			t.Errorf("reference target %q left the collector un-normalized", ref.To)
		}
		byVia[ref.Via] = ref
	}

	wantRefs := map[string]struct {
		to         string
		resolution contract.Resolution
	}{
		"properties.virtualNetworkSubnetId": {e2eSubnet, contract.ResolutionInScan},
		"properties.backupSubnetId":         {e2eVNet + "/subnets/other", contract.ResolutionChildOfScanned},
		"properties.sharedVaultId":          {"/subscriptions/other-sub/resourcegroups/hub/providers/microsoft.keyvault/vaults/hubkv", contract.ResolutionOutOfScan},
	}
	for via, want := range wantRefs {
		got, ok := byVia[via]
		if !ok {
			t.Errorf("no reference recorded at %s", via)
			continue
		}
		if got.To != want.to {
			t.Errorf("%s -> %q, want %q", via, got.To, want.to)
		}
		if got.Resolution != want.resolution {
			t.Errorf("%s resolved %q, want %q", via, got.Resolution, want.resolution)
		}
	}
	// A URL is not an ARM id and must never become an edge.
	for _, ref := range decoded.Dependencies {
		if strings.HasPrefix(ref.To, "https://") {
			t.Errorf("a URL became a reference: %+v", ref)
		}
	}
}

// The guarantee "nothing is silently dropped" is the collector's central claim, so the
// guard that backs it needs a test that watches it fire. A row with no id cannot be
// translated, and the count difference must reach the estate as a gap.
func TestE2EDroppedRowIsReportedNotHidden(t *testing.T) {
	pages := []page{{data: []any{
		map[string]any{"id": "/subscriptions/SUB-1/resourceGroups/RG/providers/Microsoft.KeyVault/vaults/kv1",
			"type": "Microsoft.KeyVault/vaults", "name": "kv1"},
		map[string]any{"name": "no id at all"},
	}, total: i64(2)}}

	estate := collectFromPages(t, "sub-1", pages)

	if len(estate.Resources) != 1 {
		t.Fatalf("got %d resources, want 1 translated", len(estate.Resources))
	}
	var reported bool
	for _, g := range estate.Scan.Gaps {
		if strings.Contains(g.Detail, "but translated") {
			reported = true
			if g.Reason != contract.GapNotAttempted {
				t.Errorf("drop gap reason = %q, want %q", g.Reason, contract.GapNotAttempted)
			}
			if !strings.Contains(g.Detail, "2") || !strings.Contains(g.Detail, "1") {
				t.Errorf("drop gap does not state the counts: %q", g.Detail)
			}
		}
	}
	if !reported {
		t.Errorf("a row was dropped and no gap said so; gaps = %+v", estate.Scan.Gaps)
	}
}

// The scan payload carries observations, never judgments. contract has its own version of
// this over a hand-built sample; this one runs it over an estate the collector produced.
func TestE2EProducedEstateCarriesNoJudgment(t *testing.T) {
	estate := collectFromPages(t, "sub-1", estatePages())

	encoded, err := json.Marshal(estate)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(encoded, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	forbidden := []string{"buckets", "drStrategy", "strength", "configHash", "ruleSetVersion", "verdict"}
	objects := []map[string]any{generic, generic["scan"].(map[string]any)}
	for _, item := range generic["resources"].([]any) {
		// document is the cloud's own JSON — we make no claims about the keys inside it.
		bare := map[string]any{}
		for k, v := range item.(map[string]any) {
			if k != "document" {
				bare[k] = v
			}
		}
		objects = append(objects, bare)
	}
	for _, object := range objects {
		for _, field := range forbidden {
			if _, found := object[field]; found {
				t.Errorf("judgment field %q leaked into a collector-produced payload", field)
			}
		}
	}
}

// A scan that reads nothing must say so. An empty subscription and one the credential
// cannot see are indistinguishable from inside the collector, and reporting zero resources
// as a complete scan is the strongest false claim the contract can make.
func TestE2EEmptySubscriptionIsReportedNotAssumed(t *testing.T) {
	estate := collectFromPages(t, "sub-1", []page{{data: []any{}, total: i64(0)}})

	if len(estate.Resources) != 0 {
		t.Fatalf("got %d resources from an empty page", len(estate.Resources))
	}
	var explained bool
	for _, g := range estate.Scan.Gaps {
		if strings.Contains(g.Detail, "returned no resources") {
			explained = true
		}
	}
	if !explained {
		t.Errorf("an empty scan did not explain itself; gaps = %+v", estate.Scan.Gaps)
	}
}
