package azure

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	azruntime "github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/manukyanv07/parity-scanner/contract"
)

// Key Vault secret NAMES. Never values.
//
// Why this is worth a permission at all: recreating a Key Vault gives you an empty vault. Every
// application that reads a secret from it fails, and the customer is left trying to remember what
// used to be in there. Knowing the names turns an unanswerable question into a form to fill in -
// "this vault held db-password, api-key and connection-string; supply their values".
//
// It is structurally impossible for this code to read a value, and that is the point:
//
//   - The LIST operation (GET {vault}/secrets) returns ids, attributes and tags. It has no value
//     field at all. Reading a value needs a separate GET on each secret's own url.
//   - The role we ask for is Key Vault Reader, whose data permissions are exactly
//     vaults/*/read and vaults/secrets/readMetadata/action. It does NOT include
//     vaults/secrets/getSecret/action, which is the only action that returns a value. A customer
//     can verify that themselves with `az role definition list --name "Key Vault Reader"`.
//
// So the claim "we cannot read your secret values" is not a policy promise that code could break
// later - the role does not grant the action, and the call we make does not return the field.

// vaultTokenScope is the Key Vault data plane audience. Distinct from ARM: a management-plane
// token is rejected here, which is why this needs its own credential call rather than reusing the
// ARM pipeline.
const vaultTokenScope = "https://vault.azure.net/.default"

// vaultAPIVersion is pinned for the same reason every childSpec pins one: an unpinned call is a
// silent behaviour change whenever the service ships a new version.
const vaultAPIVersion = "7.4"

// secretLister reads secret metadata out of one vault. An interface so the logic is testable
// without a network, matching graphClient and armFetcher.
type secretLister interface {
	ListSecrets(ctx context.Context, vaultURI string) ([]vaultSecret, error)
}

// vaultSecret is one secret's metadata as the data plane returns it. There is deliberately no
// value field: adding one would be the only way this type could ever carry a secret, so its
// absence is the safeguard.
type vaultSecret struct {
	ID          string            `json:"id"`
	Attributes  map[string]any    `json:"attributes"`
	Tags        map[string]string `json:"tags"`
	ContentType string            `json:"contentType"`
	Managed     bool              `json:"managed"`
}

// collectSecretNames lists the secrets in every scanned vault.
//
// Emits one resource per secret, parented to its vault, so the estate answers "what must exist in
// this vault after a restore" without ever holding what those secrets contain.
func collectSecretNames(ctx context.Context, lister secretLister, resources []contract.Resource) ([]contract.Resource, []contract.Gap) {
	var out []contract.Resource
	var gaps []contract.Gap

	for _, vault := range resources {
		if vault.Type != "microsoft.keyvault/vaults" {
			continue
		}
		uri := vaultURI(vault)
		if uri == "" {
			gaps = append(gaps, contract.Gap{
				Reason: contract.GapNotAttempted,
				Target: vault.ID + "/secrets",
				Detail: "this vault's document carries no vaultUri, so its secret names could not be listed and a restored vault has nothing to refill from",
			})
			continue
		}

		secrets, err := lister.ListSecrets(ctx, uri)
		if err != nil {
			gaps = append(gaps, secretGap(vault, err))
			continue
		}
		for _, s := range secrets {
			name := secretName(s.ID)
			if name == "" {
				continue
			}
			out = append(out, secretResource(vault, name, s))
		}
	}

	// Goroutine-free, but vault order comes from the estate and secret order from the service.
	// Sorted so two scans of one unchanged vault produce identical bytes.
	sort.Slice(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	return out, gaps
}

// secretResource builds the estate row for one secret. Document holds metadata only.
func secretResource(vault contract.Resource, name string, s vaultSecret) contract.Resource {
	// An ARM-shaped child id, so ParentID resolves against the vault in-scan exactly like every
	// other child, and so the engine never has to special-case a data-plane row.
	id := vault.ID + "/secrets/" + strings.ToLower(name)

	document := map[string]any{
		"id":   id,
		"name": name,
		"type": "microsoft.keyvault/vaults/secrets",
		"properties": map[string]any{
			// attributes carries enabled, created, updated, exp, nbf - the facts that decide
			// whether a restored secret is even usable. No value, because the list operation
			// does not return one.
			"attributes":  s.Attributes,
			"contentType": s.ContentType,
			// managed means Key Vault created it for a certificate; it must NOT be recreated by
			// hand, which is a real restore instruction.
			"managed": s.Managed,
		},
		"tags": s.Tags,
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		// A map of strings and bools cannot fail to marshal; keep the row rather than lose it.
		encoded = json.RawMessage(`{"id":"` + id + `","name":"` + name + `"}`)
	}

	return contract.Resource{
		Provider: contract.ProviderAzure,
		ID:       id,
		ParentID: vault.ID,
		Type:     "microsoft.keyvault/vaults/secrets",
		Name:     name,
		Account:  vault.Account,
		Group:    vault.Group,
		Region:   vault.Region,
		Tags:     s.Tags,
		Document: encoded,
	}
}

// secretGap turns a failed list into the gap that names who can fix it.
//
// A vault answers 403 for two unrelated reasons and the remedies are opposite:
//
//	ForbiddenByRbac        the credential lacks Key Vault Reader     -> grant the role
//	ForbiddenByConnection  public network access is disabled          -> a NETWORK problem;
//	                                                                     the role changes nothing
//
// Measured: sealing a testbed vault to its private endpoint produced the second, and because this
// function only looked for the string "403" it reported the first - telling the customer to grant a
// role that was already granted. A gap that sends someone down the wrong path is worse than a
// vague one, so when Azure's code does not settle it, both causes are named.
//
// A vault the network refuses outright - the name does not resolve, the dial times out, the
// connection is refused - is the same limit said without a status code, and it goes to the same
// reason (see networkGap). It is not not-attempted: the collector looked.
func secretGap(vault contract.Resource, err error) contract.Gap {
	message := err.Error()
	lower := strings.ToLower(message)
	denied := strings.Contains(message, "403") || strings.Contains(lower, "forbidden")

	// Network denial. The scanner's job has no VNet, so a vault reachable only through a private
	// endpoint is unreachable from it no matter what roles it holds.
	networkBlocked := strings.Contains(lower, "forbiddenbyconnection") ||
		strings.Contains(lower, "public network access is disabled") ||
		strings.Contains(lower, "not allowed from your ip") ||
		strings.Contains(lower, "private link") ||
		strings.Contains(lower, "trusted service")

	switch {
	case denied && networkBlocked:
		return networkGap(vault, "this vault refused the connection rather than the credential: its public network access is disabled, so it is reachable only through its private endpoint", "Azure said: "+truncate(message, 300))
	case denied && strings.Contains(lower, "forbiddenbyrbac"):
		return contract.Gap{
			Reason: contract.GapPermissionDenied,
			Target: vault.ID + "/secrets",
			Detail: fmt.Sprintf("the credential was denied permission to list this vault's secret names, so a restored vault has nothing to refill from. Granting Key Vault Reader on the vault closes this: that role reads names and metadata only, and does not include getSecret, so it cannot return a secret value. Azure said: %s", truncate(message, 300)),
		}
	case denied:
		// A 403 whose code we do not recognise. Naming both causes beats guessing one.
		return contract.Gap{
			Reason: contract.GapPermissionDenied,
			Target: vault.ID + "/secrets",
			Detail: fmt.Sprintf("this vault returned 403 for a secret-name listing, and the response does not say which of the two causes applies. Either the credential lacks Key Vault Reader - which reads names and metadata only, never values - or the vault's public network access is disabled and it is reachable only through a private endpoint, in which case no role change helps. Check the vault's publicNetworkAccess before granting anything. Azure said: %s", truncate(message, 300)),
		}
	case unreachable(err):
		return networkGap(vault, "this vault's host could not be reached at all - the name did not resolve, or nothing answered - which is what a vault reachable only through its private endpoint looks like from outside the network that endpoint lives in", "The network said: "+truncate(message, 300))
	}
	// A failure this collector does not understand. That IS ours to look at, which is what
	// not-attempted means - and the detail must not blame the customer's network for something
	// it never established.
	return contract.Gap{
		Reason: contract.GapNotAttempted,
		Target: vault.ID + "/secrets",
		Detail: fmt.Sprintf("listing this vault's secret names failed for a reason this collector does not recognise, so a restored vault has nothing to refill from: %v", err),
	}
}

// networkGap is the gap for a vault the scanner has no route to.
//
// The reason is no-collector, and that choice is deliberate: contract.GapReason has no word for
// "reachable only from inside the customer's network". Of the reasons it does have, this is the
// one whose owner and fix match. The collector that CAN read this vault is one that runs inside
// that network - a VNet-injected Container Apps job with the vault's private DNS zone linked - and
// it does not exist yet; that is Cloud Parity's to build, not the customer's to grant. The
// alternatives all say something false: not-attempted says nobody looked (the console renders it
// as a bug on our side, and §10.4 says its count must be zero); permission-denied says grant a role
// (the wrong path, measured); out-of-scope says onboard the subscription (it is in the onboarded
// subscription); data-plane says we never read it by design (we read secret names by design).
//
// If the contract ever gains a network-unreachable reason, this is the one place to move.
func networkGap(vault contract.Resource, cause, said string) contract.Gap {
	return contract.Gap{
		Reason: contract.GapNoCollector,
		Target: vault.ID + "/secrets",
		Detail: fmt.Sprintf("%s. The scanner's job has no route into that network, so this is a limit of where the scanner runs and not a bug in what it reads; secret names could not be listed, and a restored vault has nothing to refill from. Granting a role changes NOTHING here. Closing it needs the scanner to run inside the customer's network - VNet-injecting the Container Apps environment and linking the vault's private DNS zone - which is a collector that does not exist yet. %s", cause, said),
	}
}

// unreachable says whether err is the network refusing to carry the request at all, as opposed
// to the vault answering it. The real pipeline wraps a *net.OpError (DNS failures included) in a
// *url.Error, so errors.As settles it; the string forms cover an error flattened to text on its
// way here. Context errors are deliberately NOT matched: a cancelled scan is not a network limit.
func unreachable(err error) bool {
	var op *net.OpError
	var dns *net.DNSError
	if errors.As(err, &op) || errors.As(err, &dns) {
		return true
	}
	lower := strings.ToLower(err.Error())
	for _, sign := range []string{"dial tcp", "no such host", "i/o timeout", "connection refused", "network is unreachable", "no route to host"} {
		if strings.Contains(lower, sign) {
			return true
		}
	}
	return false
}

// truncate keeps a service message readable inside a gap.
func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// vaultURI reads properties.vaultUri out of the vault's stored document.
func vaultURI(vault contract.Resource) string {
	var document map[string]any
	if err := json.Unmarshal(vault.Document, &document); err != nil {
		return ""
	}
	properties, _ := document["properties"].(map[string]any)
	uri, _ := properties["vaultUri"].(string)
	return strings.TrimRight(uri, "/")
}

// secretName takes the last path segment of a secret id.
func secretName(id string) string {
	id = strings.TrimRight(id, "/")
	if i := strings.LastIndex(id, "/"); i >= 0 {
		return id[i+1:]
	}
	return id
}

// vaultClient is the real data-plane reader.
type vaultClient struct {
	pipeline azruntime.Pipeline
}

func newSecretLister() (secretLister, error) {
	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("azure credential: %w", err)
	}
	pipeline := azruntime.NewPipeline("parity-scanner", collectorVersion,
		azruntime.PipelineOptions{}, &policy.ClientOptions{
			PerRetryPolicies: []policy.Policy{
				azruntime.NewBearerTokenPolicy(credential, []string{vaultTokenScope}, nil),
			},
			Retry: policy.RetryOptions{MaxRetries: 4},
		})
	return &vaultClient{pipeline: pipeline}, nil
}

// ListSecrets walks every page of the vault's secret list.
func (v *vaultClient) ListSecrets(ctx context.Context, vaultURI string) ([]vaultSecret, error) {
	url := vaultURI + "/secrets?api-version=" + vaultAPIVersion
	var all []vaultSecret

	// Bounded, for the same reason the Resource Graph pager is: a service that keeps handing back
	// a nextLink must not turn a scan into an unbounded loop.
	for page := 0; page < 100 && url != ""; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		request, err := azruntime.NewRequest(ctx, http.MethodGet, url)
		if err != nil {
			return nil, err
		}
		request.Raw().Header.Set("Accept", "application/json")

		response, err := v.pipeline.Do(request)
		if err != nil {
			return nil, err
		}
		if response.StatusCode != http.StatusOK {
			// The body is read and attached deliberately. A 403 from a vault means one of two
			// completely different things - RBAC denial, or public network access disabled - and
			// only Azure's error code distinguishes them. Discarding it produced a gap telling the
			// customer to grant a role they had already granted.
			body, readErr := azruntime.Payload(response)
			if readErr == nil && len(body) > 0 {
				return nil, fmt.Errorf("HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(body)))
			}
			return nil, azruntime.NewResponseError(response)
		}
		body, err := azruntime.Payload(response)
		if err != nil {
			return nil, err
		}
		var page struct {
			Value    []vaultSecret `json:"value"`
			NextLink string        `json:"nextLink"`
		}
		if err := json.Unmarshal(body, &page); err != nil {
			return nil, err
		}
		all = append(all, page.Value...)
		url = page.NextLink
	}
	return all, nil
}
