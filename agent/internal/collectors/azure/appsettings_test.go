package azure

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/manukyanv07/parity-scanner/contract"
)

const refSite = "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.web/sites/fn"

func siteResource(id string) contract.Resource {
	return contract.Resource{
		Provider: contract.ProviderAzure, ID: id, Type: "microsoft.web/sites",
		Name: "fn", Account: "sub-1", Group: "rg", Region: "eastus",
		Document: json.RawMessage(`{"id":"` + id + `"}`),
	}
}

// The shape the live service returned, verbatim from a Reader-only call.
const refBody = `{"value":[{
  "id": "` + refSite + `/config/configreferences/appsettings/DB_PASSWORD",
  "name": "DB_PASSWORD",
  "properties": {
    "reference": "@Microsoft.KeyVault(SecretUri=https://cloud-parity-vault.vault.azure.net/secrets/db-password/)",
    "vaultName": "cloud-parity-vault",
    "secretName": "db-password",
    "identityType": "UserAssigned",
    "status": "Resolved"
  }}]}`

func TestVaultReferencesAreCollectedWithTheVaultAndSecretNamed(t *testing.T) {
	f := &scriptedFetcher{bodies: map[string]string{
		refSite + "/config/configreferences/appsettings": refBody,
	}}
	got, gaps := collectVaultReferences(context.Background(), f, []contract.Resource{siteResource(refSite)})
	if len(gaps) != 0 {
		t.Fatalf("unexpected gaps: %+v", gaps)
	}
	if len(got) != 1 {
		t.Fatalf("got %d rows, want 1", len(got))
	}
	r := got[0]
	if r.Name != "DB_PASSWORD" {
		t.Errorf("name = %q", r.Name)
	}
	// The whole point: a restore needs to know WHICH vault and WHICH secret.
	var d map[string]any
	if err := json.Unmarshal(r.Document, &d); err != nil {
		t.Fatal(err)
	}
	p, _ := d["properties"].(map[string]any)
	for key, want := range map[string]string{
		"vaultName":    "cloud-parity-vault",
		"secretName":   "db-password",
		"identityType": "UserAssigned",
		"status":       "Resolved",
	} {
		if got := p[key]; got != want {
			t.Errorf("properties.%s = %v, want %q", key, got, want)
		}
	}
}

// Parented to the SITE, not to the non-existent …/config/configreferences that dropping the last
// id pair would produce. That mistake produced dangling parents once already.
func TestVaultReferenceIsParentedToTheSite(t *testing.T) {
	f := &scriptedFetcher{bodies: map[string]string{
		refSite + "/config/configreferences/appsettings": refBody,
	}}
	got, _ := collectVaultReferences(context.Background(), f, []contract.Resource{siteResource(refSite)})
	if got[0].ParentID != refSite {
		t.Errorf("parentId = %q, want the site %q", got[0].ParentID, refSite)
	}
}

// The reference string is an ADDRESS. It must survive verbatim, because that is what lets the FQDN
// index resolve this row to the vault as a dependency with no extra code.
func TestVaultReferenceKeepsThePointerSoItLinksToTheVault(t *testing.T) {
	vaultID := "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.keyvault/vaults/cloud-parity-vault"
	vaultDoc, _ := json.Marshal(map[string]any{
		"id": vaultID, "name": "cloud-parity-vault",
		"properties": map[string]any{"vaultUri": "https://cloud-parity-vault.vault.azure.net/"},
	})
	f := &scriptedFetcher{bodies: map[string]string{
		refSite + "/config/configreferences/appsettings": refBody,
	}}
	refs, _ := collectVaultReferences(context.Background(), f, []contract.Resource{siteResource(refSite)})

	estate := append([]contract.Resource{
		siteResource(refSite),
		{Provider: contract.ProviderAzure, ID: vaultID, Type: "microsoft.keyvault/vaults",
			Name: "cloud-parity-vault", Account: "sub-1", Group: "rg", Document: vaultDoc},
	}, refs...)

	deps, _ := link(estate)
	var found bool
	for _, d := range deps {
		if strings.Contains(d.From, "configreferences") && d.To == vaultID {
			found = true
			if d.Resolution != contract.ResolutionInScan {
				t.Errorf("resolution = %q, want in-scan", d.Resolution)
			}
		}
	}
	if !found {
		t.Error("the setting does not link to the vault it points at")
	}
}

// Most apps use no Key Vault references at all. One gap per such app would bury every real finding.
func TestAppWithNoVaultReferencesProducesNoGap(t *testing.T) {
	f := &scriptedFetcher{errs: map[string]error{
		refSite + "/config/configreferences/appsettings": responseErr(404),
	}}
	got, gaps := collectVaultReferences(context.Background(), f, []contract.Resource{siteResource(refSite)})
	if len(got) != 0 || len(gaps) != 0 {
		t.Errorf("got %d rows and %d gaps, want none", len(got), len(gaps))
	}
}

// A denial here means the credential holds LESS than Reader, which is worth saying plainly because
// the usual assumption would be that it needs more.
func TestDeniedVaultReferencesSaysReaderIsEnough(t *testing.T) {
	f := &scriptedFetcher{errs: map[string]error{
		refSite + "/config/configreferences/appsettings": responseErr(403),
	}}
	_, gaps := collectVaultReferences(context.Background(), f, []contract.Resource{siteResource(refSite)})
	if len(gaps) != 1 || gaps[0].Reason != contract.GapPermissionDenied {
		t.Fatalf("gaps = %+v, want one permission-denied", gaps)
	}
	if !strings.Contains(gaps[0].Detail, "Reader is sufficient") {
		t.Errorf("the gap does not say Reader suffices: %q", gaps[0].Detail)
	}
}

func TestOnlySitesAreAskedForVaultReferences(t *testing.T) {
	f := &scriptedFetcher{bodies: map[string]string{
		refSite + "/config/configreferences/appsettings": `{"value":[]}`,
	}}
	collectVaultReferences(context.Background(), f, []contract.Resource{
		siteResource(refSite),
		{Type: "microsoft.compute/virtualmachines", ID: "/vm", Document: json.RawMessage(`{}`)},
	})
	for _, p := range f.asked {
		if !strings.HasPrefix(p, refSite) {
			t.Errorf("asked a non-site: %s", p)
		}
	}
	if len(f.asked) != 1 {
		t.Errorf("asked %d paths, want 1", len(f.asked))
	}
}
