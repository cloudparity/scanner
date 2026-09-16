package azure

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/manukyanv07/parity-scanner/contract"
)

const (
	epVault   = linkRG + "/providers/microsoft.keyvault/vaults/cloud-parity-vault"
	epStore   = linkRG + "/providers/microsoft.storage/storageaccounts/cloudparitysa"
	epConfig  = linkRG + "/providers/microsoft.appconfiguration/configurationstores/cloud-parity-appconfig"
	epApp     = linkRG + "/providers/microsoft.app/containerapps/cloud-parity-container"
	epNIC     = linkRG + "/providers/microsoft.network/networkinterfaces/cloud-parity-vault-endpoint.nic.3558f2f4"
	epSQL     = linkRG + "/providers/microsoft.sql/servers/cloud-parity-sql"
	epCluster = linkRG + "/providers/microsoft.containerservice/managedclusters/aks"
)

// resourceNamed builds a resource whose document carries a name, which is what the self-endpoint
// rule matches a hostname's first label against.
func resourceNamed(id, name string, properties map[string]any) contract.Resource {
	document := map[string]any{"id": id, "name": name, "properties": properties}
	encoded, err := json.Marshal(document)
	if err != nil {
		panic(err)
	}
	return contract.Resource{Provider: contract.ProviderAzure, ID: id, Name: name, Document: encoded}
}

func TestHostOfExtractsTheHostname(t *testing.T) {
	cases := map[string]string{
		"https://cloud-parity-vault.vault.azure.net/":                    "cloud-parity-vault.vault.azure.net",
		"https://cloud-parity-vault.vault.azure.net/secrets/db-password": "cloud-parity-vault.vault.azure.net",
		"https://cloudparitysa.blob.core.windows.net":                    "cloudparitysa.blob.core.windows.net",
		"cloud-parity-vault.vault.azure.net":                             "cloud-parity-vault.vault.azure.net",
		"HTTPS://Cloud-Parity-Vault.Vault.Azure.NET/":                    "cloud-parity-vault.vault.azure.net",
		"https://myacct.documents.azure.com:443/":                        "myacct.documents.azure.com",
		"https://user:pass@host.vault.azure.net/x":                       "host.vault.azure.net",
		"tcp://sql1.database.windows.net,1433":                           "sql1.database.windows.net",
		"cloudparitysa.privatelink.blob.core.windows.net":                "cloudparitysa.blob.core.windows.net",
		"https://cloudparitysa.privatelink.blob.core.windows.net/config": "cloudparitysa.blob.core.windows.net",
		"":                                       "",
		"not a host":                             "",
		"/subscriptions/sub-1/resourcegroups/rg": "",
		"10.10.2.4":                              "",
		"localhost":                              "",
	}
	for input, want := range cases {
		t.Run(input, func(t *testing.T) {
			if got := hostOf(input); got != want {
				t.Errorf("hostOf(%q) = %q, want %q", input, got, want)
			}
		})
	}
}

// A connection string embeds the host inside a longer value, so whole-string parsing loses it.
func TestHostsInExtractsEveryHostFromACompoundValue(t *testing.T) {
	value := "DefaultEndpointsProtocol=https;AccountName=cloudparitysa;" +
		"BlobEndpoint=https://cloudparitysa.blob.core.windows.net/;" +
		"QueueEndpoint=https://cloudparitysa.queue.core.windows.net/;AccountKey=REDACTED"
	got := hostsIn(value)
	sort.Strings(got)
	want := []string{"cloudparitysa.blob.core.windows.net", "cloudparitysa.queue.core.windows.net"}
	if len(got) != len(want) {
		t.Fatalf("hostsIn = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("hostsIn = %v, want %v", got, want)
		}
	}
}

// The whole point of option 2: the estate declares its own endpoints, so nothing is guessed.
func TestEndpointIndexHarvestsSelfDeclaredEndpoints(t *testing.T) {
	resources := []contract.Resource{
		resourceNamed(epVault, "cloud-parity-vault", map[string]any{
			"vaultUri": "https://cloud-parity-vault.vault.azure.net/",
		}),
		resourceNamed(epConfig, "cloud-parity-appconfig", map[string]any{
			"endpoint": "https://cloud-parity-appconfig.azconfig.io",
		}),
		resourceNamed(epStore, "cloudparitysa", map[string]any{
			"primaryEndpoints": map[string]any{
				"blob":  "https://cloudparitysa.blob.core.windows.net/",
				"queue": "https://cloudparitysa.queue.core.windows.net/",
			},
		}),
		resourceNamed(epSQL, "cloud-parity-sql", map[string]any{
			"fullyQualifiedDomainName": "cloud-parity-sql.database.windows.net",
		}),
	}
	index := endpointIndex(resources)
	for host, want := range map[string]string{
		"cloud-parity-vault.vault.azure.net":    epVault,
		"cloud-parity-appconfig.azconfig.io":    epConfig,
		"cloudparitysa.blob.core.windows.net":   epStore,
		"cloudparitysa.queue.core.windows.net":  epStore,
		"cloud-parity-sql.database.windows.net": epSQL,
	} {
		if got := index[host]; got != want {
			t.Errorf("index[%q] = %q, want %q", host, got, want)
		}
	}
}

// A hostname whose first label is not the resource's own name is somebody ELSE's endpoint, and
// claiming it would invent an edge. AKS is the real case: fqdn is aks-dns-1a2b3c.hcp...
func TestEndpointIndexIgnoresHostnamesThatAreNotSelfEvident(t *testing.T) {
	resources := []contract.Resource{
		resourceNamed(epCluster, "aks", map[string]any{
			"fqdn": "aks-dns-1a2b3c.hcp.eastus.azmk8s.io",
		}),
		// A container app naming the VAULT's endpoint must not claim that host as its own.
		resourceNamed(epApp, "cloud-parity-container", map[string]any{
			"configuration": map[string]any{"secrets": []any{
				map[string]any{"keyVaultUrl": "https://cloud-parity-vault.vault.azure.net/secrets/db-password"},
			}},
		}),
	}
	index := endpointIndex(resources)
	if id, ok := index["aks-dns-1a2b3c.hcp.eastus.azmk8s.io"]; ok {
		t.Errorf("claimed a non-self-evident host for %q", id)
	}
	if id, ok := index["cloud-parity-vault.vault.azure.net"]; ok {
		t.Errorf("the container app claimed the vault's endpoint as its own: %q", id)
	}
}

// The highest-confidence source in the whole estate: a private endpoint NIC states the target's
// FQDN and the target's ARM id in the SAME document, so the pair needs no inference at all.
func TestEndpointIndexTrustsPrivateEndpointNICPairs(t *testing.T) {
	nic := resourceNamed(epNIC, "cloud-parity-vault-endpoint.nic.3558f2f4", map[string]any{
		"ipConfigurations": []any{map[string]any{
			"properties": map[string]any{
				"privateLinkConnectionProperties": map[string]any{
					"fqdns":                []any{"cloud-parity-vault.vault.azure.net"},
					"requiredMemberName":   "default",
					"groupId":              "vault",
					"privateLinkServiceId": epVault,
				},
			},
		}},
	})
	index := endpointIndex([]contract.Resource{nic})
	if got := index["cloud-parity-vault.vault.azure.net"]; got != epVault {
		t.Errorf("NIC pair not indexed: got %q, want %q", got, epVault)
	}
}

// The payoff, measured on the shape the live scan actually produced.
func TestLinkResolvesEndpointReferencesToScannedResources(t *testing.T) {
	resources := []contract.Resource{
		resourceNamed(epVault, "cloud-parity-vault", map[string]any{
			"vaultUri": "https://cloud-parity-vault.vault.azure.net/",
		}),
		resourceNamed(epConfig, "cloud-parity-appconfig", map[string]any{
			"endpoint": "https://cloud-parity-appconfig.azconfig.io",
		}),
		resourceNamed(epApp, "cloud-parity-container", map[string]any{
			"configuration": map[string]any{"secrets": []any{
				map[string]any{"keyVaultUrl": "https://cloud-parity-vault.vault.azure.net/secrets/db-password"},
			}},
			"template": map[string]any{"containers": []any{map[string]any{
				"env": []any{map[string]any{
					"name":  "APPCONFIG_ENDPOINT",
					"value": "https://cloud-parity-appconfig.azconfig.io",
				}},
			}}},
		}),
	}
	refs, _ := link(resources)

	want := map[string]string{
		"properties.configuration.secrets[0].keyVaultUrl": epVault,
		"properties.template.containers[0].env[0].value":  epConfig,
	}
	found := map[string]string{}
	for _, r := range refs {
		if r.From == epApp {
			found[r.Via] = r.To
		}
	}
	for via, to := range want {
		if found[via] != to {
			t.Errorf("edge via %q = %q, want %q (all: %v)", via, found[via], to, found)
		}
	}
	for _, r := range refs {
		if r.From == epApp && r.Resolution != contract.ResolutionInScan {
			t.Errorf("endpoint edge %q resolution = %q, want in-scan", r.Via, r.Resolution)
		}
	}
}

// A resource's own endpoint is its identity, not a dependency. Self-edges are noise.
func TestLinkEmitsNoSelfEdgeFromAResourcesOwnEndpoint(t *testing.T) {
	refs, _ := link([]contract.Resource{
		resourceNamed(epVault, "cloud-parity-vault", map[string]any{
			"vaultUri": "https://cloud-parity-vault.vault.azure.net/",
		}),
	})
	for _, r := range refs {
		if r.From == r.To {
			t.Fatalf("self-edge emitted via %q", r.Via)
		}
	}
}

// An endpoint naming something outside the scan must not become a Reference, because Reference.To
// is a normalized ARM id by contract and a bare hostname there would break every consumer that
// parses it - foreignAccountGaps among them. The limitation is declared statically in unreadGaps(allTypesPresent()).
func TestLinkNeverPutsAHostnameInReferenceTo(t *testing.T) {
	refs, _ := link([]contract.Resource{
		resourceNamed(epApp, "cloud-parity-container", map[string]any{
			"secretUri": "https://someone-elses-vault.vault.azure.net/secrets/x",
		}),
	})
	for _, r := range refs {
		if !armResourceID.MatchString(r.To) {
			t.Fatalf("Reference.To is not an ARM id: %q (via %s)", r.To, r.Via)
		}
	}
}

// The limitation must be stated somewhere, or an unlinked endpoint is a silent hole. §2.3: an
// empty gaps list is a claim the scan was complete.
func TestUnreadGapsDeclaresEndpointResolutionLimits(t *testing.T) {
	for _, g := range unreadGaps(allTypesPresent()) {
		if g.Target == "endpoint-fqdn-resolution" {
			if g.Reason != contract.GapNotAttempted || g.Detail == "" {
				t.Errorf("gap is malformed: %+v", g)
			}
			return
		}
	}
	t.Error("unreadGaps(allTypesPresent()) does not declare endpoint-fqdn-resolution")
}

// Same estate in, same references out - the index must not make link order-dependent.
func TestLinkEndpointResolutionIsDeterministic(t *testing.T) {
	resources := []contract.Resource{
		resourceNamed(epVault, "cloud-parity-vault", map[string]any{
			"vaultUri": "https://cloud-parity-vault.vault.azure.net/",
		}),
		resourceNamed(epStore, "cloudparitysa", map[string]any{
			"primaryEndpoints": map[string]any{"blob": "https://cloudparitysa.blob.core.windows.net/"},
		}),
		resourceNamed(epApp, "cloud-parity-container", map[string]any{
			"a": "https://cloud-parity-vault.vault.azure.net/secrets/x",
			"b": "https://cloudparitysa.blob.core.windows.net/config",
		}),
	}
	first, _ := link(resources)
	for i := 0; i < 20; i++ {
		again, _ := link(resources)
		if len(again) != len(first) {
			t.Fatalf("run %d produced %d references, first produced %d", i, len(again), len(first))
		}
		for j := range first {
			if again[j] != first[j] {
				t.Fatalf("run %d differs at %d: %+v vs %+v", i, j, again[j], first[j])
			}
		}
	}
}

// An ARM id must keep winning. It is the stronger signal, and double-emitting would inflate
// every edge count in the product.
func TestARMIDTakesPrecedenceOverEndpointMatching(t *testing.T) {
	refs, _ := link([]contract.Resource{
		resourceNamed(epVault, "cloud-parity-vault", map[string]any{
			"vaultUri": "https://cloud-parity-vault.vault.azure.net/",
		}),
		resourceNamed(epApp, "cloud-parity-container", map[string]any{
			"vaultId": epVault,
		}),
	})
	var n int
	for _, r := range refs {
		if r.From == epApp && r.To == epVault {
			n++
		}
	}
	if n != 1 {
		t.Errorf("got %d edges app->vault, want exactly 1", n)
	}
}

// Two resources claiming one hostname must resolve the same way every run. Without an explicit
// tie-break, map iteration order decides, and two scans of one unchanged estate disagree.
func TestEndpointIndexBreaksTiesDeterministically(t *testing.T) {
	shared := "shared.vault.azure.net"
	lower := linkRG + "/providers/microsoft.keyvault/vaults/aaa"
	higher := linkRG + "/providers/microsoft.keyvault/vaults/zzz"
	resources := []contract.Resource{
		resourceNamed(higher, "shared", map[string]any{"vaultUri": "https://" + shared}),
		resourceNamed(lower, "shared", map[string]any{"vaultUri": "https://" + shared}),
	}
	for i := 0; i < 20; i++ {
		if got := endpointIndex(resources)[shared]; got != lower {
			t.Fatalf("run %d: index[%q] = %q, want the lowest id %q", i, shared, got, lower)
		}
	}
}

// A NIC states the FQDN and the target id together, so it is fact rather than inference and must
// win over a name-based guess that disagrees with it.
func TestEndpointIndexPrefersTheExplicitPairOverInference(t *testing.T) {
	host := "cloud-parity-vault.vault.azure.net"
	// An unrelated resource that happens to be NAMED cloud-parity-vault would otherwise claim it.
	impostor := linkRG + "/providers/microsoft.storage/storageaccounts/aaa-sorts-first"
	resources := []contract.Resource{
		resourceNamed(impostor, "cloud-parity-vault", map[string]any{"someUri": "https://" + host}),
		resourceNamed(epNIC, "nic", map[string]any{
			"ipConfigurations": []any{map[string]any{"properties": map[string]any{
				"privateLinkConnectionProperties": map[string]any{
					"fqdns":                []any{host},
					"privateLinkServiceId": epVault,
				},
			}}},
		}),
	}
	if got := endpointIndex(resources)[host]; got != epVault {
		t.Errorf("index[%q] = %q, want the explicitly paired %q", host, got, epVault)
	}
}

// The same resource declaring one hostname twice must not accumulate duplicate claims.
func TestEndpointIndexDeduplicatesRepeatedClaims(t *testing.T) {
	host := "cloudparitysa.blob.core.windows.net"
	r := resourceNamed(epStore, "cloudparitysa", map[string]any{
		"primaryEndpoints":   map[string]any{"blob": "https://" + host},
		"secondaryEndpoints": map[string]any{"blob": "https://" + host},
	})
	if got := endpointIndex([]contract.Resource{r})[host]; got != epStore {
		t.Errorf("index[%q] = %q, want %q", host, got, epStore)
	}
}

// An unreadable document yields no endpoints rather than a panic. link() already reports that
// resource with GapNotAttempted, so the omission is not silent.
func TestEndpointIndexSkipsUnreadableDocuments(t *testing.T) {
	index := endpointIndex([]contract.Resource{
		{Provider: contract.ProviderAzure, ID: epVault, Name: "cloud-parity-vault", Document: []byte("{not json")},
	})
	if len(index) != 0 {
		t.Errorf("index = %v, want empty", index)
	}
}

// A pathological value is not worth tokenizing. The guard exists so one absurd string cannot
// dominate a scan of thousands of resources.
func TestHostsInIgnoresOversizedValues(t *testing.T) {
	huge := strings.Repeat("a.b.example.net ", 400)
	if len(huge) <= 4096 {
		t.Fatalf("test input is only %d bytes, raise it above the guard", len(huge))
	}
	if got := hostsIn(huge); got != nil {
		t.Errorf("hostsIn returned %d hosts for an oversized value, want none", len(got))
	}
}

// One connection string names the blob and queue endpoint of the SAME account, so both hostnames
// resolve to one id at one path. That must be one edge, not two.
func TestLinkDeduplicatesEdgesFromOneCompoundValue(t *testing.T) {
	refs, _ := link([]contract.Resource{
		resourceNamed(epStore, "cloudparitysa", map[string]any{
			"primaryEndpoints": map[string]any{
				"blob":  "https://cloudparitysa.blob.core.windows.net/",
				"queue": "https://cloudparitysa.queue.core.windows.net/",
			},
		}),
		resourceNamed(epApp, "cloud-parity-container", map[string]any{
			"connectionString": "DefaultEndpointsProtocol=https;AccountName=cloudparitysa;" +
				"BlobEndpoint=https://cloudparitysa.blob.core.windows.net/;" +
				"QueueEndpoint=https://cloudparitysa.queue.core.windows.net/",
		}),
	})
	var n int
	for _, r := range refs {
		if r.From == epApp && r.To == epStore {
			n++
		}
	}
	if n != 1 {
		t.Errorf("got %d edges app->storage from one connection string, want exactly 1", n)
	}
}
