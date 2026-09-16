package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/manukyanv07/parity-scanner/contract"
)

// Which app settings point at a Key Vault secret, and at which secret.
//
// The problem this closes. An App Service or Function App setting holding
// "@Microsoft.KeyVault(SecretUri=https://kv.vault.azure.net/secrets/db-password/)" is a POINTER,
// not a secret - and it is the single most valuable app setting to recover, because once the
// customer refills the vault the app works with no further input. But Azure masks every setting
// VALUE as "#######" in sites/config, so the pointer is masked along with the real secrets, and a
// restored app has no idea it was ever wired to a vault.
//
// The fix is a different endpoint that exists for exactly this purpose:
//
//	GET {siteId}/config/configreferences/appsettings
//	  -> { "name": "DB_PASSWORD", "properties": {
//	         "vaultName": "cloud-parity-vault", "secretName": "db-password",
//	         "identityType": "UserAssigned", "status": "Resolved" } }
//
// Measured, with a service principal holding ONLY Reader at subscription scope: it returns the
// setting name, the vault, the secret inside it, which identity resolves it, and whether the app
// can currently reach it. No extra permission, and no secret value anywhere in the response - the
// endpoint reports the POINTER and its health, never the target.
//
// It is not in `az provider operation show --namespace Microsoft.Web`, so it cannot be found by
// reading the operations list; it was found by calling it. Treat its absence from that list as a
// documentation gap rather than evidence it needs elevated rights - the Reader-only test is the
// evidence.
//
// Why this is not a childSpec. The generic child fetcher derives ParentID by dropping the last
// type/name pair off the child's id, and these ids are
// …/sites/{site}/config/configreferences/appsettings/{name}, which would derive a parent of
// …/config/configreferences - a resource that does not exist. That is the same dangling-parent
// defect that fetching storage shares without their service level produced, so the parent is set
// explicitly to the site here.

// vaultReferencesAPIVersion is pinned like every other ARM call in this collector.
const vaultReferencesAPIVersion = "2022-03-01"

// vaultReferenceType is what the service calls these rows, used verbatim so the estate reflects
// Azure's own vocabulary rather than one we invented.
const vaultReferenceType = "microsoft.web/sites/config/configreferences"

// collectVaultReferences asks every web app and function app which of its settings point at a vault.
func collectVaultReferences(ctx context.Context, fetcher armFetcher, resources []contract.Resource) ([]contract.Resource, []contract.Gap) {
	var out []contract.Resource
	var gaps []contract.Gap

	for _, site := range resources {
		if site.Type != "microsoft.web/sites" {
			continue
		}
		path := site.ID + "/config/configreferences/appsettings"
		body, err := fetcher.Get(ctx, path, vaultReferencesAPIVersion)
		if err != nil {
			if gap := vaultReferenceGap(site, path, err); gap != nil {
				gaps = append(gaps, *gap)
			}
			continue
		}

		var envelope struct {
			Value []struct {
				ID         string         `json:"id"`
				Name       string         `json:"name"`
				Properties map[string]any `json:"properties"`
			} `json:"value"`
		}
		if err := json.Unmarshal(body, &envelope); err != nil {
			gaps = append(gaps, contract.Gap{
				Reason: contract.GapNotAttempted,
				Target: path,
				Detail: fmt.Sprintf("the Key Vault reference list for this app could not be parsed, so settings backed by a vault are absent from the estate: %v", err),
			})
			continue
		}

		for _, row := range envelope.Value {
			if row.Name == "" {
				continue
			}
			out = append(out, vaultReferenceResource(site, row.ID, row.Name, row.Properties))
		}
	}

	sort.Slice(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	return out, gaps
}

// vaultReferenceResource builds the estate row for one Key Vault-backed setting.
func vaultReferenceResource(site contract.Resource, id, name string, properties map[string]any) contract.Resource {
	if id == "" {
		id = site.ID + "/config/configreferences/appsettings/" + name
	}
	id = strings.ToLower(strings.TrimRight(id, "/"))

	// properties holds vaultName, secretName, identityType, status, details and the reference
	// string. The reference string is the @Microsoft.KeyVault(SecretUri=…) pointer - an address,
	// not a secret - and keeping it verbatim is what lets the FQDN index resolve this row to the
	// vault with no extra work.
	document := map[string]any{
		"id":         id,
		"name":       name,
		"type":       vaultReferenceType,
		"properties": properties,
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		encoded = json.RawMessage(`{"id":"` + id + `","name":"` + name + `"}`)
	}

	return contract.Resource{
		Provider: contract.ProviderAzure,
		// The SITE, explicitly. Deriving it from the id would point at
		// …/config/configreferences, which is not a resource.
		ParentID: site.ID,
		ID:       id,
		Type:     vaultReferenceType,
		Name:     name,
		Account:  site.Account,
		Group:    site.Group,
		Region:   site.Region,
		Document: encoded,
	}
}

// vaultReferenceGap explains a failed read, or stays silent when there is nothing to explain.
func vaultReferenceGap(site contract.Resource, path string, err error) *contract.Gap {
	var responseErr *azcore.ResponseError
	if errors.As(err, &responseErr) {
		switch responseErr.StatusCode {
		case http.StatusNotFound, http.StatusBadRequest:
			// No Key Vault references configured on this app. A fact, not a hole, and reporting
			// it would put one gap on every app that simply does not use the feature.
			return nil
		case http.StatusForbidden, http.StatusUnauthorized:
			return &contract.Gap{
				Reason: contract.GapPermissionDenied,
				Target: path,
				Detail: fmt.Sprintf("the credential was denied the Key Vault reference list on this app (HTTP %d), so settings backed by a vault cannot be rebuilt after a restore. Subscription Reader is sufficient for this call - a denial means the credential holds less than that", responseErr.StatusCode),
			}
		}
	}
	return &contract.Gap{
		Reason: contract.GapNotAttempted,
		Target: path,
		Detail: fmt.Sprintf("reading the Key Vault reference list for this app failed, so settings backed by a vault are absent from the estate: %v", err),
	}
}
