package azure

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/manukyanv07/parity-scanner/contract"
)

const (
	linkSub    = "/subscriptions/sub-1"
	linkRG     = linkSub + "/resourcegroups/rg"
	linkVNet   = linkRG + "/providers/microsoft.network/virtualnetworks/vnet1"
	linkSubnet = linkVNet + "/subnets/db"
	linkVault  = linkRG + "/providers/microsoft.keyvault/vaults/kv1"
	linkWeb    = linkRG + "/providers/microsoft.web/sites/web"
	linkOther  = "/subscriptions/other-sub/resourcegroups/rg/providers/microsoft.keyvault/vaults/elsewhere"
)

// resourceWith builds a translated resource whose document is the given tree, so link can be
// driven without going through discover or translate.
func resourceWith(id string, properties map[string]any) contract.Resource {
	document := map[string]any{"id": id, "properties": properties}
	encoded, err := json.Marshal(document)
	if err != nil {
		panic(err)
	}
	return contract.Resource{Provider: contract.ProviderAzure, ID: id, Document: encoded}
}

// contract.md §2.5 specifies exactly what counts as a reference. A false negative loses an
// edge silently; a false positive invents a dependency that will be planned for.
func TestReferenceTargetRecognisesARMIDsOnly(t *testing.T) {
	valid := map[string]string{
		"top level":                    linkVault,
		"child":                        linkSubnet,
		"grandchild":                   linkRG + "/providers/microsoft.storage/storageaccounts/sa/blobservices/default/containers/c1",
		"subscription level, no group": linkSub + "/providers/microsoft.authorization/policyassignments/pa",
		"extension resource":           linkRG + "/providers/microsoft.storage/storageaccounts/sa/providers/microsoft.authorization/roleassignments/1111",
		"mixed case is recognised":     "/subscriptions/SUB-1/resourceGroups/RG/providers/Microsoft.KeyVault/vaults/KV1",
		"trailing slash":               linkVault + "/",
		// Widened deliberately: these are real dependencies that the original pattern lost.
		"subscription scope":            linkSub,
		"resource group scope":          linkRG,
		"tenant-scoped role definition": "/providers/Microsoft.Authorization/RoleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
		"management group scope":        "/providers/Microsoft.Management/managementGroups/mg1",
		"mg-scoped policy definition":   "/providers/Microsoft.Management/managementGroups/mg1/providers/Microsoft.Authorization/policyDefinitions/p1",
	}
	for name, value := range valid {
		t.Run("valid/"+name, func(t *testing.T) {
			got, ok := referenceTarget(value)
			if !ok {
				t.Fatalf("%q was not recognised as an ARM id", value)
			}
			if got != strings.ToLower(strings.TrimRight(value, "/")) {
				t.Errorf("target = %q, want it lowercased and trimmed", got)
			}
		})
	}

	invalid := map[string]string{
		"empty":                     "",
		"plain text":                "hello world",
		"a URL":                     "https://kv1.vault.azure.net/",
		"an FQDN":                   "db.postgres.database.azure.com",
		"a GUID":                    "6aaf6f9a-fc9a-4c60-89e2-03e80e4b437c",
		"a relative path":           "properties/subnets/db",
		"namespace with no pair":    linkRG + "/providers/microsoft.keyvault",
		"unpaired trailing segment": linkRG + "/providers/microsoft.web/sites/web/config",
		"a connection string":       "Server=db.postgres.database.azure.com;Password=x",
	}
	for name, value := range invalid {
		t.Run("invalid/"+name, func(t *testing.T) {
			if got, ok := referenceTarget(value); ok {
				t.Errorf("%q was wrongly read as the ARM id %q", value, got)
			}
		})
	}
}

// The three resolutions, stated relative to THIS scan. That framing is what makes them
// actionable: "we did not scan it" is fixable by onboarding the account; "it does not exist"
// is not.
func TestResolveCoversAllThreeCases(t *testing.T) {
	scanned := map[string]struct{}{linkVNet: {}, linkVault: {}}

	tests := map[string]struct {
		to   string
		want contract.Resolution
	}{
		"exact match is in-scan":                        {linkVNet, contract.ResolutionInScan},
		"a subnet resolves to its vnet":                 {linkSubnet, contract.ResolutionChildOfScanned},
		"a deep child walks up to a scanned ancestor":   {linkVNet + "/subnets/db/ipconfigurations/ipc1", contract.ResolutionChildOfScanned},
		"another subscription is out-of-scan":           {linkOther, contract.ResolutionOutOfScan},
		"unscanned sibling is out-of-scan":              {linkRG + "/providers/microsoft.storage/storageaccounts/sa", contract.ResolutionOutOfScan},
		"a child of an unscanned parent is out-of-scan": {linkRG + "/providers/microsoft.storage/storageaccounts/sa/blobservices/default", contract.ResolutionOutOfScan},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got, _ := resolve(tc.to, scanned); got != tc.want {
				t.Errorf("resolve(%s) = %q, want %q", tc.to, got, tc.want)
			}
		})
	}
}

// The ticket's own words: "Step 2 is the ticket." ARG never returns a subnet as a row, so a
// reference to one can only ever resolve by walking up. Skipping it leaves 68% of the graph
// dangling, and the most-referenced thing in the measured estate was a subnet with 503 refs.
func TestLinkResolvesReferencesToSubResourcesThatAreNeverRows(t *testing.T) {
	// Deliberately NO subnet resource: ARG does not return one.
	resources := []contract.Resource{
		resourceWith(linkVNet, map[string]any{"addressSpace": map[string]any{"addressPrefixes": []any{"10.0.0.0/16"}}}),
		resourceWith(linkWeb, map[string]any{"virtualNetworkSubnetId": linkSubnet}),
	}

	got, _ := link(resources)
	if len(got) != 1 {
		t.Fatalf("got %d references, want 1: %+v", len(got), got)
	}
	ref := got[0]
	if ref.From != linkWeb || ref.To != linkSubnet {
		t.Errorf("reference = %s -> %s, want %s -> %s", ref.From, ref.To, linkWeb, linkSubnet)
	}
	if ref.Via != "properties.virtualNetworkSubnetId" {
		t.Errorf("via = %q, want the property path", ref.Via)
	}
	if ref.Resolution != contract.ResolutionChildOfScanned {
		t.Errorf("resolution = %q, want %q — the vnet IS in the estate, so this is not dangling",
			ref.Resolution, contract.ResolutionChildOfScanned)
	}
}

// via must be the real property path, including array indices, or a human cannot tell which
// of forty rules produced the edge. The golden file's example is exactly this shape.
func TestLinkRecordsTheRealPropertyPath(t *testing.T) {
	resources := []contract.Resource{
		resourceWith(linkVault, map[string]any{
			"networkAcls": map[string]any{
				"virtualNetworkRules": []any{
					// Both must be complete type/name pairs. An odd trailing segment is not
					// an ARM id and is correctly not recognised.
					map[string]any{"id": linkVNet + "/subnets/web"},
					map[string]any{"id": linkSubnet},
				},
			},
		}),
		resourceWith(linkVNet, nil),
	}

	got, _ := link(resources)
	if len(got) != 2 {
		t.Fatalf("got %d references, want 2: %+v", len(got), got)
	}
	want := []string{
		"properties.networkAcls.virtualNetworkRules[0].id",
		"properties.networkAcls.virtualNetworkRules[1].id",
	}
	for i, ref := range got {
		if ref.Via != want[i] {
			t.Errorf("via[%d] = %q, want %q", i, ref.Via, want[i])
		}
	}
}

// A resource's document carries its own id. That is identity, not a pointer, and a self-edge
// is noise in every consumer of the graph.
func TestLinkSkipsSelfReferences(t *testing.T) {
	got, _ := link([]contract.Resource{resourceWith(linkVault, map[string]any{
		"vaultUri":   "https://kv1.vault.azure.net/",
		"selfTarget": linkVault,
	})})
	for _, ref := range got {
		if ref.From == ref.To {
			t.Errorf("emitted a self-reference at %s", ref.Via)
		}
	}
	if len(got) != 0 {
		t.Errorf("got %d references, want none: %+v", len(got), got)
	}
}

// A reference written with different casing must still match a scanned resource, because id
// equality is the identity test and ARM's casing is inconsistent.
func TestLinkNormalisesTargetCasing(t *testing.T) {
	got, _ := link([]contract.Resource{
		resourceWith(linkVault, nil),
		resourceWith(linkWeb, map[string]any{
			"vault": "/subscriptions/SUB-1/resourceGroups/RG/providers/Microsoft.KeyVault/vaults/KV1",
		}),
	})
	if len(got) != 1 {
		t.Fatalf("got %d references, want 1: %+v", len(got), got)
	}
	if got[0].To != linkVault {
		t.Errorf("to = %q, want the lowercased id %q", got[0].To, linkVault)
	}
	if got[0].Resolution != contract.ResolutionInScan {
		t.Errorf("resolution = %q, want in-scan — casing must not stop the match", got[0].Resolution)
	}
}

// Map iteration is random. Without the sort, the same scan emits a different reference order
// every run and any golden test or hash over the estate flakes.
func TestLinkIsDeterministic(t *testing.T) {
	resources := []contract.Resource{
		resourceWith(linkVNet, nil),
		resourceWith(linkVault, nil),
		resourceWith(linkWeb, map[string]any{
			"a": linkVault, "b": linkSubnet, "c": linkOther,
			"nested": map[string]any{"d": linkVNet},
		}),
	}
	first, _ := link(resources)
	if len(first) != 4 {
		t.Fatalf("got %d references, want 4: %+v", len(first), first)
	}
	for i := range 20 {
		again, _ := link(resources)
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("reference order changed on run %d:\n%+v\n%+v", i, first, again)
		}
	}
}

// All three resolutions must be reachable from one estate, which is the shape the measured
// 32/64/2 split describes.
func TestLinkProducesAllThreeResolutionsFromOneEstate(t *testing.T) {
	got, _ := link([]contract.Resource{
		resourceWith(linkVNet, nil),
		resourceWith(linkVault, nil),
		resourceWith(linkWeb, map[string]any{
			"inScan":         linkVault,
			"childOfScanned": linkSubnet,
			"outOfScan":      linkOther,
		}),
	})

	seen := map[contract.Resolution]int{}
	for _, ref := range got {
		seen[ref.Resolution]++
	}
	for _, want := range []contract.Resolution{
		contract.ResolutionInScan, contract.ResolutionChildOfScanned, contract.ResolutionOutOfScan,
	} {
		if seen[want] == 0 {
			t.Errorf("no reference resolved %q: %+v", want, got)
		}
	}
}

// The scanner records the observation and stops. Strength is a KB type-pair fact plus
// customer policy, so a reference must never carry one (AD-021).
func TestLinkEmitsNoJudgment(t *testing.T) {
	got, _ := link([]contract.Resource{
		resourceWith(linkVault, nil),
		resourceWith(linkWeb, map[string]any{"vault": linkVault}),
	})
	if len(got) != 1 {
		t.Fatalf("got %d references", len(got))
	}
	encoded, err := json.Marshal(got[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(encoded, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// in-scan carries 4; resolvedTo appears only for child-of-scanned, via omitempty.
	if len(generic) != 4 {
		t.Errorf("an in-scan reference carries %d fields, want from/to/via/resolution: %s", len(generic), encoded)
	}
	for _, forbidden := range []string{"strength", "source", "kind", "weight", "required"} {
		if _, found := generic[forbidden]; found {
			t.Errorf("judgment field %q leaked onto a reference", forbidden)
		}
	}
}

func TestLinkHandlesEmptyAndMalformedInput(t *testing.T) {
	if got, _ := link(nil); len(got) != 0 {
		t.Errorf("link(nil) = %+v, want empty", got)
	}
	if got, _ := link([]contract.Resource{}); len(got) != 0 {
		t.Errorf("link(empty) = %+v, want empty", got)
	}
	// A resource whose document is not an object must not take the scan down with it.
	got, _ := link([]contract.Resource{
		{ID: linkVault, Document: json.RawMessage(`"not an object"`)},
		{ID: linkWeb, Document: nil},
		resourceWith(linkVNet, map[string]any{"target": linkVault}),
	})
	if len(got) != 1 {
		t.Fatalf("got %d references, want the one from the valid document: %+v", len(got), got)
	}
}

// Non-string leaves are not references, and a number that happens to look id-shaped is not
// one either.
func TestLinkIgnoresNonStringLeaves(t *testing.T) {
	got, _ := link([]contract.Resource{resourceWith(linkWeb, map[string]any{
		"count":   float64(3),
		"enabled": true,
		"nothing": nil,
		"list":    []any{float64(1), true, nil},
	})})
	if len(got) != 0 {
		t.Errorf("got %+v, want no references", got)
	}
}

// ARM's identity envelope puts the managed identity's resourceId in the KEY position, with
// the value being a pair of GUIDs:
//
//	"identity": { "userAssignedIdentities": {
//	    "/subscriptions/.../userAssignedIdentities/mi1": {"principalId":…,"clientId":…} } }
//
// Walking values only found nothing here, on every type that supports a user-assigned
// identity, and each is a hard DR edge: the workload does not authenticate after a restore
// without its identity attached. An adversarial audit caught it; this pins it.
func TestLinkFindsReferencesInMapKeys(t *testing.T) {
	const identity = linkRG + "/providers/microsoft.managedidentity/userassignedidentities/mi1"

	got, _ := link([]contract.Resource{
		resourceWith(identity, nil),
		{
			ID: linkWeb,
			Document: json.RawMessage(`{
			  "id": "` + linkWeb + `",
			  "identity": {
			    "type": "UserAssigned",
			    "userAssignedIdentities": {
			      "` + identity + `": {
			        "principalId": "7c89d1e3-03db-491e-8ec2-6fa53dcb787c",
			        "clientId": "6aaf6f9a-fc9a-4c60-89e2-03e80e4b437c"
			      }
			    }
			  }
			}`),
		},
	})

	if len(got) != 1 {
		t.Fatalf("got %d references, want 1 — the identity id is in the KEY: %+v", len(got), got)
	}
	ref := got[0]
	if ref.From != linkWeb || ref.To != identity {
		t.Errorf("reference = %s -> %s, want %s -> %s", ref.From, ref.To, linkWeb, identity)
	}
	if ref.Resolution != contract.ResolutionInScan {
		t.Errorf("resolution = %q, want in-scan — the identity IS a scanned resource", ref.Resolution)
	}
	// Via is the CONTAINING path, not the key. Embedding the id in the path would put dots
	// and slashes inside a dotted path, and To already carries the id.
	if ref.Via != "identity.userAssignedIdentities" {
		t.Errorf("via = %q, want identity.userAssignedIdentities", ref.Via)
	}
	if strings.Contains(ref.Via, "/") {
		t.Errorf("via %q embeds a resource id, making the path unparseable", ref.Via)
	}
	// The GUIDs beside it are not references, and must not become any.
	for _, r := range got {
		if strings.Contains(r.To, "7c89d1e3") || strings.Contains(r.To, "6aaf6f9a") {
			t.Errorf("a principal/client GUID became a reference: %+v", r)
		}
	}
}

// Two identities on one resource: both keys must be found, and the pair must stay ordered.
func TestLinkFindsEveryMapKeyReference(t *testing.T) {
	const mi1 = linkRG + "/providers/microsoft.managedidentity/userassignedidentities/mi1"
	const mi2 = linkRG + "/providers/microsoft.managedidentity/userassignedidentities/mi2"

	resources := []contract.Resource{
		resourceWith(mi1, nil), resourceWith(mi2, nil),
		{ID: linkWeb, Document: json.RawMessage(`{"id":"` + linkWeb + `","identity":{"userAssignedIdentities":{"` + mi1 + `":{},"` + mi2 + `":{}}}}`)},
	}
	first, _ := link(resources)
	if len(first) != 2 {
		t.Fatalf("got %d references, want 2: %+v", len(first), first)
	}
	for i := range 10 {
		again, _ := link(resources)
		if !reflect.DeepEqual(first, again) {
			t.Fatalf("order changed on run %d", i)
		}
	}
}

// A key that is not an ARM id must not become a reference, or every property name in every
// document becomes an edge.
func TestLinkIgnoresOrdinaryMapKeys(t *testing.T) {
	got, _ := link([]contract.Resource{{
		ID:       linkWeb,
		Document: json.RawMessage(`{"id":"` + linkWeb + `","properties":{"tags":{"env":"prod","costCentre":"R&D"}}}`),
	}})
	if len(got) != 0 {
		t.Errorf("got %+v, want none — ordinary keys are not references", got)
	}
}

// [^/]+ accepts characters a resourceId never contains, so without a gate an ARM request
// URL, a trailing newline, or a comma-delimited LIST of two ids all matched and became one
// reference to a resource that cannot exist. The list case is the worst: one fabricated edge
// REPLACES two real ones.
func TestReferenceTargetRejectsDirtyStrings(t *testing.T) {
	dirty := map[string]string{
		"api-version query string": linkVault + "?api-version=2023-02-01",
		"fragment":                 linkVault + "#frag",
		"trailing newline":         linkVault + "\n",
		"trailing space":           linkVault + " ",
		"semicolon-delimited pair": linkVNet + ";" + linkVault,
		"comma-delimited pair":     linkSubnet + "," + linkVNet + "/subnets/web",
		"logic app expression":     "/subscriptions/@{parameters('sub')}/resourcegroups/rg/providers/microsoft.web/sites/web",
		"arm template placeholder": "/subscriptions/{subscriptionId}/resourcegroups/rg/providers/microsoft.web/sites/{name}",
	}
	for name, value := range dirty {
		t.Run(name, func(t *testing.T) {
			if got, ok := referenceTarget(value); ok {
				t.Errorf("%q became the reference target %q", value, got)
			}
		})
	}
}

// translate refuses to parent a malformed id because a floored pair count would invent a
// confident wrong answer. resolve must agree, or the two consumers of parseARMID disagree
// about the same id.
func TestResolveRespectsTheMalformedGuard(t *testing.T) {
	// A resource literally named "providers" makes the segment count odd after the last one.
	const malformed = linkRG + "/providers/ns1/t1/providers/ns2/t2/n2/x"
	scanned := map[string]struct{}{linkRG + "/providers/ns1/t1/providers/ns2/t2/n2": {}}
	if got, _ := resolve(malformed, scanned); got != contract.ResolutionOutOfScan {
		t.Errorf("resolve on a malformed id = %q, want out-of-scan rather than a claimed ancestor", got)
	}
}

// §2.5: "if engine code ever needs to split a string on `/`, the boundary has been
// violated." For child-of-scanned the target is not a row, so without naming the ancestor
// the engine has to parse the id to learn what to actually include. The collector computes
// it while resolving; discarding it just moved the parsing downstream.
func TestLinkNamesTheResolvingAncestor(t *testing.T) {
	got, _ := link([]contract.Resource{
		resourceWith(linkVNet, nil),
		resourceWith(linkVault, nil),
		resourceWith(linkWeb, map[string]any{
			"childOfScanned": linkSubnet,                                     // -> vnet1
			"deepChild":      linkVNet + "/subnets/db/ipconfigurations/ipc1", // -> vnet1
			"inScan":         linkVault,
			"outOfScan":      linkOther,
		}),
	})
	if len(got) != 4 {
		t.Fatalf("got %d references, want 4: %+v", len(got), got)
	}

	byVia := map[string]contract.Dependency{}
	for _, r := range got {
		byVia[r.Via] = r
	}
	for _, via := range []string{"properties.childOfScanned", "properties.deepChild"} {
		ref := byVia[via]
		if ref.Resolution != contract.ResolutionChildOfScanned {
			t.Errorf("%s resolved %q, want child-of-scanned", via, ref.Resolution)
		}
		if ref.ResolvedTo != linkVNet {
			t.Errorf("%s resolvedTo = %q, want the vnet %q", via, ref.ResolvedTo, linkVNet)
		}
	}
	// Empty for every other resolution, so `omitempty` keeps it off the wire.
	for _, via := range []string{"properties.inScan", "properties.outOfScan"} {
		if got := byVia[via].ResolvedTo; got != "" {
			t.Errorf("%s carries resolvedTo %q, want empty", via, got)
		}
	}
}

// An extension resource resolves to its SCOPE, and the collector says so rather than
// implying coverage. A subnet comes back with its vnet; a role assignment scoped to a storage
// account does not come back when that account is recreated. Both are child-of-scanned, and
// only the resource-type table knows which is which (AD-021) - so naming the ancestor is the
// observation and deciding what it means is the engine's judgment.
func TestLinkNamesTheScopeForAnExtensionResource(t *testing.T) {
	const storage = linkRG + "/providers/microsoft.storage/storageaccounts/sa"
	const assignment = storage + "/providers/microsoft.authorization/roleassignments/1111"

	got, _ := link([]contract.Resource{
		resourceWith(storage, nil),
		resourceWith(linkWeb, map[string]any{"grant": assignment}),
	})
	if len(got) != 1 {
		t.Fatalf("got %d references: %+v", len(got), got)
	}
	if got[0].Resolution != contract.ResolutionChildOfScanned {
		t.Errorf("resolution = %q", got[0].Resolution)
	}
	if got[0].ResolvedTo != storage {
		t.Errorf("resolvedTo = %q, want the storage account it is scoped to %q", got[0].ResolvedTo, storage)
	}
}

// GapOutOfScope was defined and referenced nowhere: link is the only path that could ever
// populate it, so the enum made a promise the collector never kept, and §2.3's "an empty gaps
// list is a claim the scan was complete" was violated on any estate with a shared hub.
func TestLinkReportsAccountsItWasNotInvitedInto(t *testing.T) {
	const hubVault = "/subscriptions/hub-sub/resourcegroups/hub/providers/microsoft.keyvault/vaults/hubkv"
	const hubZone = "/subscriptions/hub-sub/resourcegroups/hub/providers/microsoft.network/privatednszones/z"
	const thirdParty = "/subscriptions/third-sub/resourcegroups/x/providers/microsoft.storage/storageaccounts/sa"

	local := resourceWith(linkWeb, map[string]any{"a": hubVault, "b": hubZone, "c": thirdParty})
	local.Account = "sub-1"

	_, gaps := link([]contract.Resource{local})

	var outOfScope []contract.Gap
	for _, g := range gaps {
		if g.Reason == contract.GapOutOfScope {
			outOfScope = append(outOfScope, g)
		}
	}
	// One per ACCOUNT, not per reference: three references, two foreign accounts.
	if len(outOfScope) != 2 {
		t.Fatalf("got %d out-of-scope gaps, want 2 (one per foreign account): %+v", len(outOfScope), gaps)
	}
	if outOfScope[0].Target != "/subscriptions/hub-sub" || outOfScope[1].Target != "/subscriptions/third-sub" {
		t.Errorf("targets = %q, %q; want the two foreign subscriptions, sorted",
			outOfScope[0].Target, outOfScope[1].Target)
	}
	for _, g := range outOfScope {
		// Both remedies must be stated. Telling a reader to onboard a subscription is wrong when
		// the account is Microsoft's own platform-managed one, which is what a live scan actually
		// produced: the reference came from a load balancer Azure created for a Container Apps
		// environment, pointing into a subscription nobody can onboard.
		if !strings.Contains(g.Detail, "onboarding it closes this") {
			t.Errorf("the gap does not offer onboarding as a remedy: %q", g.Detail)
		}
		if !strings.Contains(g.Detail, "PLATFORM-managed") {
			t.Errorf("the gap does not warn that the account may be Microsoft-owned: %q", g.Detail)
		}
		// Naming the referrer is what lets a reader tell those two cases apart.
		if !strings.Contains(g.Detail, "Referenced by:") || !strings.Contains(g.Detail, linkWeb) {
			t.Errorf("the gap does not name the resource that points outward: %q", g.Detail)
		}
	}
}

// A target inside the SCANNED account that simply was not returned is a coverage gap
// unreadGaps() already names, not an un-onboarded account. Reporting it as out-of-scope would
// tell the customer to onboard a subscription they already onboarded.
func TestLinkDoesNotCallItsOwnAccountOutOfScope(t *testing.T) {
	// microsoft.storage/storageaccounts/sa is in sub-1 but is not a scanned row.
	local := resourceWith(linkWeb, map[string]any{"a": linkRG + "/providers/microsoft.storage/storageaccounts/sa"})
	local.Account = "sub-1"

	got, gaps := link([]contract.Resource{local})
	if len(got) != 1 || got[0].Resolution != contract.ResolutionOutOfScan {
		t.Fatalf("expected one out-of-scan reference: %+v", got)
	}
	for _, g := range gaps {
		if g.Reason == contract.GapOutOfScope {
			t.Errorf("the scanned account was reported as out-of-scope: %+v", g)
		}
	}
}

// "This resource has no references" and "this resource's references were never read" are the
// same bytes unless one of them says so.
func TestLinkReportsADocumentItCouldNotRead(t *testing.T) {
	_, gaps := link([]contract.Resource{
		{ID: linkVault, Account: "sub-1", Document: json.RawMessage(`"not an object"`)},
		resourceWith(linkVNet, nil),
	})
	var reported bool
	for _, g := range gaps {
		if g.Target == linkVault && g.Reason == contract.GapNotAttempted {
			reported = true
			if !strings.Contains(g.Detail, "never scanned") {
				t.Errorf("detail does not explain it: %q", g.Detail)
			}
		}
	}
	if !reported {
		t.Errorf("an unreadable document produced no gap: %+v", gaps)
	}
}
