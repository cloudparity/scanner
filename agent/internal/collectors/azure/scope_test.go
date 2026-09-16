package azure

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/manukyanv07/parity-scanner/contract"
)

func scopeRes(id, resourceType, group string) contract.Resource {
	return contract.Resource{
		Provider: contract.ProviderAzure,
		ID:       id,
		Type:     resourceType,
		Group:    group,
		Account:  "sub-1",
		Document: json.RawMessage(`{"id":"` + id + `"}`),
	}
}

// A scan that reports the scanner is measuring itself.
func TestScopeExcludesTheScannersOwnStack(t *testing.T) {
	resources := []contract.Resource{
		scopeRes("/s/1/rg/app/providers/microsoft.web/sites/app", "microsoft.web/sites", "app-rg"),
		scopeRes("/s/1/rg/scan/providers/microsoft.app/jobs/scanner", "microsoft.app/jobs", "cloud-parity-scanner-rg"),
		scopeRes("/s/1/rg/scan/providers/microsoft.storage/storageaccounts/est", "microsoft.storage/storageaccounts", "cloud-parity-scanner-rg"),
	}
	kept, report := scopeEstate(resources, []string{"cloud-parity-scanner-rg"}, false)
	if len(kept) != 1 || kept[0].Type != "microsoft.web/sites" {
		t.Fatalf("kept %d resources, want only the web app: %+v", len(kept), kept)
	}
	if len(report.ownStack) != 2 {
		t.Errorf("report.ownStack = %d, want 2", len(report.ownStack))
	}
}

// The group name's casing is not stable between an ARM id and the resourceGroup column, so the
// match cannot be case-sensitive or the exclusion silently stops working.
func TestScopeMatchesTheOwnGroupCaseInsensitively(t *testing.T) {
	resources := []contract.Resource{
		scopeRes("/s/1/x/providers/microsoft.app/jobs/scanner", "microsoft.app/jobs", "CLOUD-PARITY-SCANNER-RG"),
	}
	kept, report := scopeEstate(resources, []string{"cloud-parity-scanner-rg"}, false)
	if len(kept) != 0 {
		t.Errorf("kept %d, want 0 - the exclusion did not match on casing", len(kept))
	}
	if len(report.ownStack) != 1 {
		t.Errorf("ownStack = %d, want 1", len(report.ownStack))
	}
}

// Azure creates, names and owns these. Recreating the owner recreates them, so there is nothing
// for a recovery plan to do with them.
func TestScopeExcludesPlatformManagedResources(t *testing.T) {
	resources := []contract.Resource{
		scopeRes("/s/1/a/providers/microsoft.web/sites/app", "microsoft.web/sites", "app-rg"),
		// The Container Apps environment's infrastructure group.
		scopeRes("/s/1/b/providers/microsoft.network/loadbalancers/capp-svc-lb",
			"microsoft.network/loadbalancers", "ME_cloud-parity-environment_app-rg_eastus"),
		scopeRes("/s/1/c/providers/microsoft.network/publicipaddresses/capp-svc-lb-ip",
			"microsoft.network/publicipaddresses", "ME_cloud-parity-environment_app-rg_eastus"),
		// AKS node resource group.
		scopeRes("/s/1/d/providers/microsoft.compute/virtualmachinescalesets/vmss",
			"microsoft.compute/virtualmachinescalesets", "MC_app-rg_aks_eastus"),
		// Recreated automatically per region, in a group Azure names.
		scopeRes("/s/1/e/providers/microsoft.network/networkwatchers/nw",
			"microsoft.network/networkwatchers", "NetworkWatcherRG"),
		// Defender posture, excluded by TYPE wherever it lives.
		scopeRes("/s/1/f/providers/microsoft.security/assessments/a1",
			"microsoft.security/assessments", "app-rg"),
	}
	kept, report := scopeEstate(resources, nil, false)
	if len(kept) != 1 || kept[0].Type != "microsoft.web/sites" {
		t.Fatalf("kept %d, want only the web app: %+v", len(kept), kept)
	}
	if len(report.platform) != 5 {
		t.Errorf("report.platform = %d, want 5", len(report.platform))
	}
}

// Excluding by TYPE matters independently of the group: a Defender assessment sits in the
// customer's own resource group, so a group-prefix rule alone would keep it.
func TestScopeExcludesPlatformTypesEvenInACustomerGroup(t *testing.T) {
	kept, _ := scopeEstate([]contract.Resource{
		scopeRes("/s/1/a/providers/microsoft.security/securescores/ss",
			"microsoft.security/securescores", "my-own-rg"),
	}, nil, false)
	if len(kept) != 0 {
		t.Errorf("kept %d, want 0 - a platform TYPE must be excluded regardless of its group", len(kept))
	}
}

// The exclusion is a product decision, so it has to be reversible for anyone who wants to look.
func TestScopeCanKeepPlatformManagedWhenAsked(t *testing.T) {
	resources := []contract.Resource{
		scopeRes("/s/1/b/providers/microsoft.network/loadbalancers/lb",
			"microsoft.network/loadbalancers", "ME_env_rg_eastus"),
		scopeRes("/s/1/e/providers/microsoft.network/networkwatchers/nw",
			"microsoft.network/networkwatchers", "NetworkWatcherRG"),
	}
	kept, report := scopeEstate(resources, nil, true)
	if len(kept) != 2 {
		t.Errorf("kept %d, want 2 when platform-managed resources are requested", len(kept))
	}
	if len(report.platform) != 0 {
		t.Errorf("report.platform = %d, want 0", len(report.platform))
	}
}

// An exclusion is still something the estate does not contain, and §2.3 makes the gaps list the
// scanner's own statement about that. Silently dropping rows would be the one thing it must not do.
func TestScopeDeclaresWhatItExcluded(t *testing.T) {
	_, report := scopeEstate([]contract.Resource{
		scopeRes("/s/1/rg/scan/providers/microsoft.app/jobs/scanner", "microsoft.app/jobs", "scanner-rg"),
		scopeRes("/s/1/b/providers/microsoft.network/loadbalancers/lb",
			"microsoft.network/loadbalancers", "ME_env_rg_eastus"),
	}, []string{"scanner-rg"}, false)

	gaps := scopeGaps(report)
	if len(gaps) != 2 {
		t.Fatalf("got %d gaps, want one per category: %+v", len(gaps), gaps)
	}
	byTarget := map[string]contract.Gap{}
	for _, g := range gaps {
		byTarget[g.Target] = g
		// EXCLUDED, and the distinction is load-bearing rather than pedantic.
		//
		// This asserted out-of-scope until a real Azure scan showed what that costs. The coverage
		// manifest's blindsUs() treats out-of-scope as blinding and excluded as not, so every
		// platform-managed resource was being reported to a customer as "we cannot see this" when the
		// truth is "we can see it and chose not to collect it". --include-platform-managed proves we
		// can read them.
		//
		// out-of-scope means an account this scan was never invited into. That is not this.
		if g.Reason != contract.GapExcluded {
			t.Errorf("%q reason = %q, want excluded - out-of-scope makes the coverage manifest "+
				"report a deliberate choice as blindness", g.Target, g.Reason)
		}
		if g.Detail == "" {
			t.Errorf("%q carries no detail", g.Target)
		}
	}
	if _, ok := byTarget["cloud-parity-scanner-own-stack"]; !ok {
		t.Error("the scanner's own stack exclusion was not declared")
	}
	own := byTarget["cloud-parity-scanner-own-stack"]
	if !strings.Contains(own.Detail, "scanner-rg") {
		t.Errorf("the declaration does not name the excluded group: %q", own.Detail)
	}
	if _, ok := byTarget["azure-platform-managed"]; !ok {
		t.Error("the platform-managed exclusion was not declared")
	}
}

func TestScopeDeclaresNothingWhenNothingWasExcluded(t *testing.T) {
	_, report := scopeEstate([]contract.Resource{
		scopeRes("/s/1/a/providers/microsoft.web/sites/app", "microsoft.web/sites", "app-rg"),
	}, []string{"scanner-rg"}, false)
	if gaps := scopeGaps(report); len(gaps) != 0 {
		t.Errorf("got %d gaps for an estate with no exclusions: %+v", len(gaps), gaps)
	}
}

// THE point of the conditional gap list. Reporting "objects inside a Kubernetes cluster were not
// read" to a customer with no Kubernetes cluster is a standing false claim, and it trains them to
// skim the one list they need to trust.
func TestGapsAreConditionalOnTypesBeingPresent(t *testing.T) {
	target := func(gaps []contract.Gap) map[string]bool {
		m := map[string]bool{}
		for _, g := range gaps {
			m[g.Target] = true
		}
		return m
	}

	// An estate with nothing but a virtual network.
	bare := target(unreadGaps(map[string]bool{"microsoft.network/virtualnetworks": true}))
	for _, absent := range []string{
		"microsoft.containerservice/managedclusters",
		"microsoft.web/sites/config/*",
		"microsoft.appconfiguration/configurationstores/keyvalues",
		"microsoft.servicebus/namespaces/queues",
	} {
		if bare[absent] {
			t.Errorf("%q reported for an estate that holds no such type", absent)
		}
	}
	// Unconditional ones must still be there: they describe the collector, not the estate.
	for _, always := range []string{"endpoint-fqdn-resolution", "securityresources"} {
		if !bare[always] {
			t.Errorf("%q is unconditional and must always be reported", always)
		}
	}

	// Add a cluster and a vault, and exactly their gaps appear.
	withBoth := target(unreadGaps(map[string]bool{
		"microsoft.containerservice/managedclusters": true,
		"microsoft.keyvault/vaults":                  true,
	}))
	if !withBoth["microsoft.containerservice/managedclusters"] {
		t.Error("a cluster is present but its gap is missing")
	}
	// No secrets gap any more: secret NAMES are read from the vault data plane, and a failure to
	// read them produces a per-vault permission gap instead of a standing declaration.
	if withBoth["microsoft.keyvault/vaults/secrets"] {
		t.Error("the standing vault-secrets gap is back; names are collected now")
	}
	if withBoth["microsoft.web/sites/config/*"] {
		t.Error("the app-settings gap appeared without any web app")
	}
}

// Defender is no longer queried, so it must not be silently absent either.
func TestSecurityResourcesIsDeclaredRatherThanQueried(t *testing.T) {
	for _, table := range scanTables() {
		if table.name == "securityresources" {
			t.Fatal("securityresources is queried again; it was removed deliberately")
		}
	}
	var found bool
	for _, g := range unreadGaps(map[string]bool{}) {
		if g.Target == "securityresources" {
			found = true
			if !strings.Contains(g.Detail, "POSTURE") {
				t.Errorf("the declaration does not say why it is excluded: %q", g.Detail)
			}
		}
	}
	if !found {
		t.Error("securityresources is neither queried nor declared")
	}
}

func TestTypesPresentIsTheSetOfTypesInTheEstate(t *testing.T) {
	got := typesPresent([]contract.Resource{
		scopeRes("/a", "microsoft.web/sites", "rg"),
		scopeRes("/b", "microsoft.web/sites", "rg"),
		scopeRes("/c", "microsoft.keyvault/vaults", "rg"),
	})
	if len(got) != 2 || !got["microsoft.web/sites"] || !got["microsoft.keyvault/vaults"] {
		t.Errorf("typesPresent = %v, want the two distinct types", got)
	}
}
