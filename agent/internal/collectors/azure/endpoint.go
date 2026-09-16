package azure

import (
	"encoding/json"
	"regexp"
	"sort"
	"strings"

	"github.com/manukyanv07/parity-scanner/contract"
)

// Endpoint references: resolving a dependency written as a HOSTNAME rather than an ARM id.
//
// The problem, measured on a live scan. A Container App holds its Key Vault dependency as a URL:
//
//	properties.configuration.secrets[0].keyVaultUrl
//	  = "https://cloud-parity-vault.vault.azure.net/secrets/db-password"
//
// and its App Configuration dependency as a plain environment variable pointing at
// "https://cloud-parity-appconfig.azconfig.io". Neither is an ARM id, so the structural matcher
// in link.go saw nothing, and two hard DR edges were missing from a 106-reference estate: after a
// restore the app authenticates against a vault that is not there, and reads configuration from a
// store that is not there.
//
// What this does NOT do, deliberately: it never SYNTHESIZES an ARM id from a hostname. The
// obvious move is to turn "cloud-parity-vault.vault.azure.net" into
// "/subscriptions/{sub}/resourceGroups/???/providers/Microsoft.KeyVault/vaults/cloud-parity-vault",
// and it is wrong, because a hostname carries no resource group and none can be derived. The
// result would be a fabricated id that downstream code cannot distinguish from a real one.
//
// What it does instead: the estate already states its own endpoints. Every resource that has one
// declares it -- vaults in properties.vaultUri, storage in properties.primaryEndpoints.*, App
// Configuration in properties.endpoint, SQL in properties.fullyQualifiedDomainName. So the
// hostname-to-resource map is BUILT FROM THE SCAN, and a match is a lookup against observed fact
// rather than a guess. Nothing is invented, and there is no table of Azure DNS suffixes to
// maintain, which also means this same mechanism works unchanged for AWS and GCP.

// hostLabels is deliberately strict. Every label is a DNS label and the last one is alphabetic,
// which is what keeps type strings and dotted property paths out of the index: "microsoft.keyvault"
// and "microsoft.network/privatednszones" tokenize to two-label candidates and are rejected.
var hostLabels = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}$`)

// minHostLabels rejects two-label candidates. This is the false-positive guard, and it is set
// here rather than at one label because ARM type strings are exactly two dotted labels
// ("microsoft.keyvault", "microsoft.storage") and appear in almost every document. The cost is
// that a custom domain written as a bare apex ("example.com") is not indexed; written as a URL
// with a subdomain, as App Service hostNames are in practice, it is.
const minHostLabels = 3

// hostsIn returns every hostname in a value, lowercased and normalized.
//
// It tokenizes rather than parsing a URL, because the hostname is often not the whole value and
// often not in a URL at all. A storage connection string carries two of them between semicolons,
// a SQL connection target appends ",1433", and a URL may carry userinfo and a port. Splitting on
// everything that cannot appear in a hostname and then validating each token handles all of those
// with no format-specific code.
func hostsIn(value string) []string {
	if value == "" || len(value) > 4096 {
		return nil
	}
	lowered := strings.ToLower(value)
	tokens := strings.FieldsFunc(lowered, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '.' && r != '-'
	})
	var hosts []string
	seen := map[string]struct{}{}
	for _, token := range tokens {
		host, ok := validHost(token)
		if !ok {
			continue
		}
		if _, dup := seen[host]; dup {
			continue
		}
		seen[host] = struct{}{}
		hosts = append(hosts, host)
	}
	return hosts
}

// hostOf returns the first hostname in a value, or "" if it holds none.
func hostOf(value string) string {
	hosts := hostsIn(value)
	if len(hosts) == 0 {
		return ""
	}
	return hosts[0]
}

// validHost reports whether a token is a hostname, and returns it normalized.
func validHost(token string) (string, bool) {
	token = strings.Trim(token, ".-")
	if !hostLabels.MatchString(token) {
		return "", false
	}
	labels := strings.Split(token, ".")
	if len(labels) < minHostLabels {
		return "", false
	}
	return normalizeHost(labels), true
}

// normalizeHost drops the "privatelink" label so that the public and private spellings of the
// same endpoint are the same key.
//
// A privately-linked resource is reachable as both "acct.blob.core.windows.net" and
// "acct.privatelink.blob.core.windows.net" -- the public name CNAMEs to the private one. They are
// one endpoint on one resource, and without this they would be two index entries, so a reference
// written in whichever spelling the estate did not declare would silently fail to resolve.
func normalizeHost(labels []string) string {
	kept := labels[:0:len(labels)]
	for _, label := range labels {
		if label == "privatelink" {
			continue
		}
		kept = append(kept, label)
	}
	return strings.Join(kept, ".")
}

// endpointClaim is one resource asserting that a hostname is its own.
type endpointClaim struct {
	id string
	// explicit marks a claim the cloud stated outright, as opposed to one inferred from the
	// hostname's first label matching the resource's name.
	explicit bool
}

// endpointIndex maps a hostname to the id of the resource that owns it.
//
// Two sources, and the ordering between them is a confidence ordering:
//
//  1. EXPLICIT, from a private endpoint's NIC. Its document states the target's FQDN and the
//     target's ARM id in the same object:
//
//     ipConfigurations[].properties.privateLinkConnectionProperties = {
//     "fqdns": ["cloud-parity-vault.vault.azure.net"],
//     "privateLinkServiceId": "/subscriptions/.../vaults/cloud-parity-vault" }
//
//     That is a verified pair with zero inference, and it is already present in every estate
//     that uses private endpoints.
//
//  2. INFERRED, from a resource declaring a hostname whose first label is its own name. This is
//     the self-evidence rule, and it is deliberately conservative: a hostname whose first label
//     is NOT the resource's name is somebody else's endpoint, and claiming it would invent an
//     edge. The cost is false negatives -- an AKS cluster's fqdn is
//     "aks-dns-1a2b3c.hcp.eastus.azmk8s.io", which does not start with the cluster's name, so it
//     is not indexed. For a disaster-recovery product a missed edge that shows up as a gap is
//     recoverable; a fabricated edge that gets planned for is not.
func endpointIndex(resources []contract.Resource) map[string]string {
	claims := map[string][]endpointClaim{}
	claim := func(host, id string, explicit bool) {
		if host == "" || id == "" {
			return
		}
		for _, existing := range claims[host] {
			if existing.id == id && existing.explicit == explicit {
				return
			}
		}
		claims[host] = append(claims[host], endpointClaim{id: id, explicit: explicit})
	}

	for _, r := range resources {
		// A document that cannot be read back yields no endpoints. link() already reports that
		// resource with GapNotAttempted, so failing quietly here does not hide it.
		var document map[string]any
		if err := json.Unmarshal(r.Document, &document); err != nil {
			continue
		}
		collectPrivateLinkPairs(document, claim)
		if r.Name != "" {
			collectSelfEndpoints(document, r.Name, r.ID, claim)
		}
	}

	index := make(map[string]string, len(claims))
	for host, candidates := range claims {
		// Deterministic: explicit wins, then lowest id. Map iteration order must never decide
		// what the estate says, or two scans of one unchanged estate would disagree.
		sort.Slice(candidates, func(a, b int) bool {
			if candidates[a].explicit != candidates[b].explicit {
				return candidates[a].explicit
			}
			return candidates[a].id < candidates[b].id
		})
		index[host] = candidates[0].id
	}
	return index
}

// collectPrivateLinkPairs finds every object holding both fqdns and privateLinkServiceId.
func collectPrivateLinkPairs(node any, claim func(host, id string, explicit bool)) {
	switch typed := node.(type) {
	case map[string]any:
		target, _ := typed["privateLinkServiceId"].(string)
		fqdns, _ := typed["fqdns"].([]any)
		if target != "" && len(fqdns) > 0 {
			// The id is normalized the same way Resource.ID is, so equality is the identity test.
			normalized := strings.ToLower(strings.TrimRight(target, "/"))
			for _, entry := range fqdns {
				if fqdn, ok := entry.(string); ok {
					claim(hostOf(fqdn), normalized, true)
				}
			}
		}
		for _, value := range typed {
			collectPrivateLinkPairs(value, claim)
		}
	case []any:
		for _, value := range typed {
			collectPrivateLinkPairs(value, claim)
		}
	}
}

// collectSelfEndpoints records hostnames whose first label is the resource's own name.
func collectSelfEndpoints(node any, name, id string, claim func(host, id string, explicit bool)) {
	switch typed := node.(type) {
	case map[string]any:
		for _, value := range typed {
			collectSelfEndpoints(value, name, id, claim)
		}
	case []any:
		for _, value := range typed {
			collectSelfEndpoints(value, name, id, claim)
		}
	case string:
		for _, host := range hostsIn(typed) {
			if label := host[:strings.IndexByte(host+".", '.')]; strings.EqualFold(label, name) {
				claim(host, id, false)
			}
		}
	}
}

// A hostname that resolves to nothing is NOT reported per-occurrence, and the reason is worth
// recording because the first implementation did report it and had to be removed.
//
// The idea was: keep a small list of Azure service suffixes, and if an unresolved hostname matches
// one, raise a gap naming it. Measured against the 47-resource live estate, that gap fired on
// three hostnames and all three were noise:
//
//	agreeablebay-e7fc82a5.eastus.azurecontainerapps.io   a Container Apps environment's OWN
//	                                                     defaultDomain - self, not a dependency,
//	                                                     missed only because the generated first
//	                                                     label is not the resource's name
//	blob.core.windows.net                                a private DNS ZONE name, which is a DNS
//	                                                     suffix and not an endpoint at all - and
//	                                                     an artifact of normalizeHost stripping
//	                                                     "privatelink" from the zone's own name
//
// Separating those from a genuine endpoint pointing at an unscanned resource needs to know, per
// type, which fields hold a resource's own endpoint versus somebody else's. That is a
// resource-type fact, which AD-021 puts in the KB and not here. A gap that is 100% false on a
// real estate is worse than no gap: it teaches the reader to skip the gaps list, which is the one
// thing §2.3 relies on being trustworthy.
//
// The limitation is instead declared once, statically, in unreadGaps() alongside every other
// known hole. Document retains every hostname either way, so the engine can revisit all of this
// with no re-scan.
