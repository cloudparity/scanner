package azure

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/manukyanv07/parity-scanner/contract"
)

// armResourceID recognises a string that points at something ARM addresses. Widened beyond
// contract.md §2.5's original pattern, which required BOTH /subscriptions/ and /providers/.
//
// Measured against the live service, that requirement made every pointer field on a role or
// policy assignment unmatched, so pulling authorizationresources gave us the rows and zero
// edges:
//
//	roleDefinitionId    /providers/Microsoft.Authorization/RoleDefinitions/{guid}   no /subscriptions/
//	policyDefinitionId  /providers/Microsoft.Authorization/policySetDefinitions/…   no /subscriptions/
//	scope               /subscriptions/{sub}                                        no /providers/
//
// Three alternatives now, and the second two are what the original missed:
//
//  1. a subscription- or tenant-scoped RESOURCE, one or more type/name pairs after the
//     namespace. This also covers an extension resource, whose id nests a second /providers/,
//     and a management-group-scoped policy definition.
//  2. a bare SCOPE - /subscriptions/{sub} or /subscriptions/{sub}/resourceGroups/{rg}. These
//     are real dependencies: an RBAC assignment's scope, a lock's scope, a policy
//     assignment's scope, and Databricks managedResourceGroupId, which attaches an entire
//     managed resource group - VNet, NSG, storage - through that one field. Now that
//     resourcecontainers is queried, both forms resolve in-scan instead of vanishing.
//  3. a tenant-scoped resource with no subscription at all - every built-in role and policy
//     definition. These resolve out-of-scan, correctly: they are global, and parseARMID
//     yields no account for them so they do not trigger a spurious out-of-scope gap.
var armResourceID = regexp.MustCompile(`(?i)^(?:` +
	`/subscriptions/[^/]+(?:/resourcegroups/[^/]+)?/providers/[^/]+(?:/[^/]+/[^/]+)+` + `|` +
	`/subscriptions/[^/]+(?:/resourcegroups/[^/]+)?` + `|` +
	`/providers/[^/]+(?:/[^/]+/[^/]+)+` +
	`)$`)

// maxAncestorWalk bounds the parent-chain walk. parseARMID always returns a strictly shorter
// id, so the walk terminates on its own; this is a backstop against a future parser change
// turning a scan into a hang.
const maxAncestorWalk = 32

// link records every pointer one resource holds to another as a contract.Dependency
// (infra-scanner §5).
//
// L1 structural only: it walks every string field and recognises the ARM resourceId shape.
// That is format translation, not judgment — recognising an ARM id is cloud-specific parsing,
// which AD-020 confines to the collector. A dependency says *this field pointed there*; it
// never says whether that matters.
//
// It assigns no strength. Hard-versus-soft is a KB type-pair fact plus customer policy, and
// the same dependency is optional in general and mandatory under a compliance mandate
// (AD-021).
//
// It also emits no principal-GUID or name/FQDN dependencies. Finding those needs per-type
// knowledge of where a type keeps its principal or its endpoint, which is a resource-type
// row. The GUIDs and FQDNs are all present in Document, so the engine derives them later
// with no re-scan.
func link(resources []contract.Resource) ([]contract.Dependency, []contract.Gap) {
	scanned := make(map[string]struct{}, len(resources))
	accounts := make(map[string]struct{}, 1)
	for _, r := range resources {
		scanned[r.ID] = struct{}{}
		if r.Account != "" {
			accounts[r.Account] = struct{}{}
		}
	}

	// Built once from the whole estate, because a dependency written as a hostname can only be
	// resolved against what the OTHER resources declared about themselves.
	walk := linkWalk{
		scanned:   scanned,
		endpoints: endpointIndex(resources),
	}

	var dependencies []contract.Dependency
	var gaps []contract.Gap
	for _, r := range resources {
		// Re-decoding here is safe even though the SDK's decoder widens numbers: link reads
		// string leaves only and never re-emits the document, so no fidelity is at stake.
		// Document was produced by json.Marshal in translate, so this cannot fail.
		var document map[string]any
		if err := json.Unmarshal(r.Document, &document); err != nil {
			// "this resource has no dependencies" and "this resource's dependencies were never
			// read" are the same bytes unless one of them says so. The invariant that
			// Document is always valid JSON holds today, which is why this is a guard rather
			// than an error path - but a comment is not an enforcement mechanism.
			gaps = append(gaps, contract.Gap{
				Reason: contract.GapNotAttempted,
				Target: r.ID,
				Detail: "the stored document could not be read back, so this resource's dependencies were never scanned",
			})
			continue
		}
		walk.out = &dependencies
		collectReferences(r.ID, document, "", &walk)
	}

	// Map iteration is random, so without this the dependency list — and any golden test or
	// config hash over it — would differ between runs of the same scan.
	sort.Slice(dependencies, func(a, b int) bool {
		if dependencies[a].From != dependencies[b].From {
			return dependencies[a].From < dependencies[b].From
		}
		if dependencies[a].Via != dependencies[b].Via {
			return dependencies[a].Via < dependencies[b].Via
		}
		return dependencies[a].To < dependencies[b].To
	})
	dependencies = dedupeDependencies(dependencies)

	return dependencies, append(gaps, foreignAccountGaps(dependencies, accounts)...)
}

// contains is a tiny helper so referrers stay distinct without pulling in slices for one call.
func contains(haystack []string, needle string) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}

// dedupeDependencies collapses identical (from, via, to) triples.
//
// One string can now yield more than one edge: a storage connection string names the blob and the
// queue endpoint of the SAME account, so both hostnames resolve to one id at one path. Without
// this that appears as a duplicated dependency and inflates every edge count downstream. Runs on
// the sorted slice, so duplicates are always adjacent.
func dedupeDependencies(sorted []contract.Dependency) []contract.Dependency {
	if len(sorted) < 2 {
		return sorted
	}
	kept := sorted[:1]
	for _, ref := range sorted[1:] {
		last := kept[len(kept)-1]
		if ref.From == last.From && ref.Via == last.Via && ref.To == last.To {
			continue
		}
		kept = append(kept, ref)
	}
	return kept
}

// foreignAccountGaps reports every account this scan referenced but was never invited into.
//
// contract.GapOutOfScope is defined as "belongs to an account this scan was not invited
// into", and AD-013 says subscriptions are onboarded, never auto-adopted. An out-of-scan
// reference into another subscription is exactly that, and until now nothing emitted the
// reason at all - it was defined and referenced nowhere, so the enum made a promise the
// collector never kept. §2.3's "an empty gaps list is a claim the scan was complete" was
// therefore violated on any estate with a shared hub VNet or a central Key Vault.
//
// One gap per distinct ACCOUNT, not per reference: the measured estate had ~150 such
// references and the actionable fact is which subscription to onboard, not which field
// mentioned it. Same-account out-of-scan targets are NOT reported here - those are resources
// inside the scanned subscription that ARG did not return, which is a coverage gap already
// named by unreadGaps(), not an un-onboarded account.
func foreignAccountGaps(dependencies []contract.Dependency, accounts map[string]struct{}) []contract.Gap {
	foreign := map[string][]string{}
	// referrers names the resources in THIS estate that point outward, which is what makes the
	// gap diagnosable. Measured: the only foreign account in a live scan was reached from
	// capp-svc-lb, a load balancer Azure itself created for a Container Apps environment, and
	// the target was Microsoft's own platform subscription. Naming the referrer is what lets a
	// reader tell that apart from a shared hub VNet in a sibling subscription.
	referrers := map[string][]string{}
	for _, ref := range dependencies {
		if ref.Resolution != contract.ResolutionOutOfScan {
			continue
		}
		account := parseARMID(ref.To).account
		if account == "" {
			continue
		}
		if _, scanned := accounts[account]; scanned {
			continue
		}
		if len(foreign[account]) < 3 {
			foreign[account] = append(foreign[account], ref.To)
		}
		if len(referrers[account]) < 3 && !contains(referrers[account], ref.From) {
			referrers[account] = append(referrers[account], ref.From)
		}
	}
	if len(foreign) == 0 {
		return nil
	}

	names := make([]string, 0, len(foreign))
	for account := range foreign {
		names = append(names, account)
	}
	sort.Strings(names)

	gaps := make([]contract.Gap, 0, len(names))
	for _, account := range names {
		gaps = append(gaps, contract.Gap{
			Reason: contract.GapOutOfScope,
			Target: "/subscriptions/" + account,
			Detail: fmt.Sprintf("this estate references resources in account %s, which this scan was not invited into, so those resources and everything they depend on are absent from any recovery plan. If it is another of the customer's subscriptions, onboarding it closes this (AD-013). If it is a PLATFORM-managed subscription - Azure creates one behind managed environments, AKS and similar services - it is Microsoft-owned, cannot be onboarded, and needs no recovery plan, so the right answer is to ignore it. Referenced by: %s. Examples: %s",
				account, strings.Join(referrers[account], ", "), strings.Join(foreign[account], ", ")),
		})
	}
	return gaps
}

// linkWalk carries the state one document walk needs. It exists so that adding endpoint
// resolution did not turn collectReferences into a six-parameter function whose call sites are
// impossible to read.
type linkWalk struct {
	scanned   map[string]struct{}
	endpoints map[string]string
	out       *[]contract.Dependency
}

// collectReferences walks one document, recording every string that holds an ARM resourceId
// along with the property path it was found at.
func collectReferences(from string, node any, path string, walk *linkWalk) {
	scanned := walk.scanned
	out := walk.out
	switch typed := node.(type) {
	case map[string]any:
		for key, value := range typed {
			at := key
			if path != "" {
				at = path + "." + key
			}
			// A reference can live in the KEY, not only the value. ARM's identity envelope
			// is the case that matters:
			//
			//	"identity": { "userAssignedIdentities": {
			//	    "/subscriptions/.../userAssignedIdentities/mi1": {"principalId":…,"clientId":…} } }
			//
			// The managed identity's resourceId is the object key and the value is a pair of
			// GUIDs. Walking values only found nothing here, silently, on every type that
			// supports a user-assigned identity — AKS, App Service, Functions, Container
			// Apps, storage with CMK, Data Factory, VMs, VMSS — and each of those is a hard
			// DR edge, because the workload does not authenticate after a restore without
			// its identity attached. Some types also repeat the id in a value position
			// (AKS properties.identityProfile.kubeletidentity.resourceId), which made the
			// loss look patchy rather than systematic.
			if to, ok := referenceTarget(key); ok && to != from {
				resolution, ancestor := resolve(to, scanned)
				// Via is the path to the CONTAINING object, not `at`. Putting the key in the
				// path yields "identity.userAssignedIdentities./subscriptions/…/mi1" - a
				// dotted path containing dots and slashes, which no consumer can parse, and
				// two different structures can stringify to the same string. Nothing is lost:
				// To already carries the id, so (via, to) says exactly where and what.
				*out = append(*out, contract.Dependency{
					From:       from,
					To:         to,
					Via:        path,
					ResolvedTo: ancestor,
					Resolution: resolution,
				})
			}
			collectReferences(from, value, at, walk)
		}
	case []any:
		for i, value := range typed {
			collectReferences(from, value, fmt.Sprintf("%s[%d]", path, i), walk)
		}
	case string:
		to, ok := referenceTarget(typed)
		if !ok {
			// Not an ARM id, but it may still be a dependency written as a HOSTNAME, which is how
			// Key Vault references, App Configuration endpoints and connection strings carry one.
			collectEndpointReferences(from, typed, path, walk)
			return
		}
		if to == from {
			// A resource's document contains its own id. That is its identity, not a
			// pointer at something else, and a self-edge is noise in every consumer.
			return
		}
		resolution, ancestor := resolve(to, scanned)
		*out = append(*out, contract.Dependency{
			From:       from,
			To:         to,
			Via:        path,
			ResolvedTo: ancestor,
			Resolution: resolution,
		})
	}
}

// collectEndpointReferences resolves a dependency written as a hostname.
//
// Reached only when the string is not an ARM id, so an ARM id always wins: it is the stronger
// signal, and matching both would double-count every edge that happens to be expressed twice.
//
// Resolution is always ResolutionInScan, because the index is built exclusively from resources
// this scan returned - a hostname that resolves here provably belongs to something we hold. A
// hostname that does not resolve is never emitted as a reference, because Reference.To is a
// normalized ARM id by contract; it accumulates into a gap instead.
func collectEndpointReferences(from, value, path string, walk *linkWalk) {
	for _, host := range hostsIn(value) {
		to, ok := walk.endpoints[host]
		if !ok {
			// Not resolvable from a hostname alone. Declared statically in unreadGaps() rather
			// than reported here - see the note in endpoint.go.
			continue
		}
		if to == from {
			// The resource's own endpoint. Its identity, not a dependency.
			continue
		}
		*walk.out = append(*walk.out, contract.Dependency{
			From:       from,
			To:         to,
			Via:        path,
			Resolution: contract.ResolutionInScan,
		})
	}
}

// referenceTarget reports whether a string is an ARM resourceId, and returns it normalized
// the same way Resource.ID is, so equality is the correct identity test.
func referenceTarget(value string) (string, bool) {
	// Cheap gate before the regex: every ARM id starts with a slash, and most strings in a
	// document do not. On a large estate this is the difference between scanning every string
	// and matching every string.
	if len(value) == 0 || value[0] != '/' {
		return "", false
	}
	// A resourceId contains none of these. [^/]+ happily accepts them, so without this
	// gate the following all matched and became references to resources that cannot exist:
	//
	//	…/vaults/kv1?api-version=2023-02-01   an ARM request URL
	//	…/vaults/kv1#fragment                 a fragment
	//	…/vaults/kv1\n                        a trailing newline
	//	…/virtualNetworks/v1;…/virtualNetworks/v2   a DELIMITED LIST - one ghost edge
	//	                                            REPLACING two real ones
	//	/subscriptions/@{parameters('sub')}/…  a Logic App expression
	//	/subscriptions/{subscriptionId}/…      an ARM template placeholder
	if strings.ContainsAny(value, "?#,;'{}@ \t\r\n") {
		return "", false
	}
	// Trimmed BEFORE matching, not after: the pattern's trailing group needs complete
	// type/name pairs, so a reference written with a trailing slash would not match at all
	// and the edge would be silently lost. Translate trims ids the same way, so the two
	// agree on identity.
	trimmed := strings.TrimRight(value, "/")
	if !armResourceID.MatchString(trimmed) {
		return "", false
	}
	return strings.ToLower(trimmed), true
}

// resolve states the target's status RELATIVE TO THIS SCAN, which is what makes it
// actionable: "we did not scan it" is fixable by onboarding the account (AD-013); "it does
// not exist" is not.
//
// Step 2 is the whole ticket. ARG's resources table does not return sub-resources as rows —
// a subnet lives inside its vnet's properties — so a reference to one can never match
// exactly. In the measured estate the single most-referenced thing was a subnet with 503
// references, and resolving these turned 68% dangling into 96% resolved: 32% in-scan, 64%
// child-of-scanned, 2% out-of-scan.
func resolve(to string, scanned map[string]struct{}) (contract.Resolution, string) {
	if _, ok := scanned[to]; ok {
		return contract.ResolutionInScan, ""
	}
	current := to
	for range maxAncestorWalk {
		parsed := parseARMID(current)
		// translate refuses to parent a malformed id because a floored pair count "would
		// silently produce a confident wrong answer". resolve had no such guard, so the two
		// consumers of parseARMID disagreed about the same id.
		if parsed.malformed {
			break
		}
		parent := parsed.parentID
		if parent == "" {
			break
		}
		if _, ok := scanned[parent]; ok {
			// Naming the ancestor is what keeps id parsing on this side of the boundary, and
			// what lets the engine decide whether "hangs off" means "already recovered".
			return contract.ResolutionChildOfScanned, parent
		}
		current = parent
	}
	return contract.ResolutionOutOfScan, ""
}
