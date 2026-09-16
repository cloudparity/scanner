package azure

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unicode"

	"github.com/manukyanv07/parity-scanner/contract"
)

// Fuzz targets for the parsers that read bytes this collector did not author.
//
// Everything in this file takes input from Resource Graph - an id, a document, a string leaf -
// and the collector's job is to survive whatever comes back and state something true about
// it. The unit tests pin what the parsers say about well-formed input; these pin what they
// must NEVER do on any input: panic, produce an id that fails its own normalization, record a
// redaction that did not happen, or mutate the row they were handed.
//
// Run one for longer than the seed corpus with:
//
//	go test -run='^$' -fuzz=FuzzParseARMID -fuzztime=60s ./agent/internal/collectors/azure/
//
// A crasher lands in testdata/fuzz/<FuzzName>/ and is then a regression test that `go test`
// runs forever after. Commit it with the fix.

// armIDSeeds are the id shapes the unit tests pin, plus every dirty string
// TestReferenceTargetRejectsDirtyStrings names. The fuzzer mutates from here.
var armIDSeeds = []string{
	"",
	"/",
	"//",
	"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1",
	"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1/",
	"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/db",
	"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Web/sites/web/config/appsettings",
	"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa/blobServices/default/containers/c1",
	"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/aks1/providers/Microsoft.KubernetesConfiguration/extensions/flux",
	"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa/providers/Microsoft.Authorization/roleAssignments/11111111-2222-3333-4444-555555555555",
	"/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/pa1",
	"/subscriptions/sub-1/resourceGroups/MyRG",
	"/subscriptions/sub-1",
	"/providers/Microsoft.Management/managementGroups/mg1",
	"/providers/Microsoft.Management/managementGroups/mg1/providers/Microsoft.Authorization/policyDefinitions/p1",
	"/providers/Microsoft.Authorization/RoleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
	"/subscriptions/sub-1/providers/Microsoft.Foo",
	"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Web/sites/web/config",
	"/subscriptions/sub-1/resourceGroups/rg/providers/ns1/t1/providers/ns2/t2/n2/x",
	"/subscriptions/SUB-1/resourceGroups/RG/providers/Microsoft.KeyVault/vaults/KV1",
	"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1?api-version=2023-02-01",
	"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1#frag",
	"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1\n",
	"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1 ",
	"/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.network/virtualnetworks/vnet1;/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.keyvault/vaults/kv1",
	"/subscriptions/@{parameters('sub')}/resourcegroups/rg/providers/microsoft.web/sites/web",
	"/subscriptions/{subscriptionId}/resourcegroups/rg/providers/microsoft.web/sites/{name}",
	"providers/Microsoft.Web/sites/web",
	"/subscriptions//providers///",
	"/PROVIDERS/PROVIDERS/PROVIDERS/PROVIDERS",
	"https://kv1.vault.azure.net/",
	"db.postgres.database.azure.com",
	"Server=db.postgres.database.azure.com;Password=x",
}

// FuzzParseARMID pins what parseARMID promises whatever the id looks like.
//
// The promises that matter downstream: every key it returns is already lowercased, so string
// equality is the identity test; a parent is always a strict prefix of its child and strictly
// shorter, so resolve's ancestor walk terminates on its own; and the parse is insensitive to
// the casing of the input, so ARM's inconsistent spelling cannot split one resource into two.
func FuzzParseARMID(f *testing.F) {
	for _, seed := range armIDSeeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, id string) {
		got := parseARMID(id)

		for name, key := range map[string]string{"account": got.account, "resourceType": got.resourceType, "parentID": got.parentID} {
			if key != strings.ToLower(key) {
				t.Errorf("parseARMID(%q).%s = %q is not lowercased", id, name, key)
			}
		}

		// The parent is rebuilt from the id's own segments, so it is a prefix of the id with the
		// same slash normalization translate applies, and the cut lands on a segment boundary.
		if got.parentID != "" {
			normalized := strings.ToLower("/" + strings.TrimPrefix(strings.TrimRight(id, "/"), "/"))
			if !strings.HasPrefix(normalized, got.parentID+"/") {
				t.Errorf("parseARMID(%q).parentID = %q is not a segment-aligned prefix of %q", id, got.parentID, normalized)
			}
		}

		// The walk resolve performs, with the property that makes maxAncestorWalk a backstop
		// rather than the thing that stops it: every parent has strictly fewer segments.
		// Counted in segments, not bytes - lowercasing can lengthen a string (an invalid
		// byte becomes the three-byte U+FFFD, and some letters fold to longer ones), which
		// is how the fuzzer found a parent that was longer than its child and still an
		// ancestor.
		current := id
		for {
			parsed := parseARMID(current)
			if parsed.parentID == "" {
				break
			}
			if strings.Count(parsed.parentID, "/") >= strings.Count(current, "/") {
				t.Fatalf("parent %q has no fewer segments than %q; the ancestor walk would never terminate", parsed.parentID, current)
			}
			current = parsed.parentID
		}

		// Case-insensitive on every keyword and every key, so folding the input first changes
		// nothing except the two display values it deliberately preserves.
		folded := parseARMID(strings.ToLower(id))
		if folded.account != got.account || folded.resourceType != got.resourceType ||
			folded.parentID != got.parentID || folded.malformed != got.malformed ||
			folded.group != strings.ToLower(got.group) || folded.name != strings.ToLower(got.name) {
			t.Errorf("parseARMID is not case-insensitive:\n  %q -> %+v\n  %q -> %+v", id, got, strings.ToLower(id), folded)
		}

		// A type without a name, or a name without a type, is a parse that half-happened.
		if (got.resourceType == "") != (got.name == "") {
			t.Errorf("parseARMID(%q) returned type %q with name %q; both or neither", id, got.resourceType, got.name)
		}
	})
}

// FuzzReferenceTarget pins the recogniser link.go runs over every string leaf in the estate.
//
// A recognised target is normalized exactly as Resource.ID is - lowercased, no trailing slash
// - and recognising it AGAIN yields the same string, so an id can pass through translate, into
// a document, back out through link and still equal itself.
func FuzzReferenceTarget(f *testing.F) {
	for _, seed := range armIDSeeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		got, ok := referenceTarget(value)
		if !ok {
			if got != "" {
				t.Errorf("referenceTarget(%q) rejected the value but returned %q", value, got)
			}
			return
		}
		if want := strings.ToLower(strings.TrimRight(value, "/")); got != want {
			t.Errorf("referenceTarget(%q) = %q, want the lowercased, trimmed input %q", value, got, want)
		}
		if strings.ContainsAny(got, "?#,;'{}@ \t\r\n") {
			t.Errorf("referenceTarget(%q) = %q carries a character no resourceId contains", value, got)
		}
		again, ok := referenceTarget(got)
		if !ok || again != got {
			t.Errorf("referenceTarget is not stable: %q -> %q -> (%q, %v)", value, got, again, ok)
		}
		// Resolving it against an empty estate must terminate and never claim an ancestor.
		if resolution, ancestor := resolve(got, nil); resolution != contract.ResolutionOutOfScan || ancestor != "" {
			t.Errorf("resolve(%q, nothing scanned) = (%q, %q), want out-of-scan and no ancestor", got, resolution, ancestor)
		}
	})
}

// FuzzHostsIn pins the hostname tokenizer endpoint.go builds its index from.
//
// Every host it returns has to be one it would return again if it met the same string on its
// own, or an endpoint the index holds could never be matched by a reference to it.
func FuzzHostsIn(f *testing.F) {
	for _, seed := range []string{
		"",
		"https://cloud-parity-vault.vault.azure.net/secrets/db-password",
		"HTTPS://Cloud-Parity-Vault.Vault.Azure.NET/",
		"https://user:pass@host.vault.azure.net/x",
		"tcp://sql1.database.windows.net,1433",
		"cloudparitysa.privatelink.blob.core.windows.net",
		"DefaultEndpointsProtocol=https;AccountName=sa;AccountKey=abc==;EndpointSuffix=core.windows.net",
		"BlobEndpoint=https://sa.blob.core.windows.net/;QueueEndpoint=https://sa.queue.core.windows.net/",
		"microsoft.keyvault/vaults",
		"privatelink.blob.core.windows.net",
		"a.privatelink.com",
		"10.10.2.4",
		"localhost",
		"-a-.-b-.-c-",
		"...",
		strings.Repeat("a.", 2048) + "com",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		hosts := hostsIn(value)
		seen := map[string]struct{}{}
		for _, host := range hosts {
			if _, dup := seen[host]; dup {
				t.Errorf("hostsIn(%q) returned %q twice", value, host)
			}
			seen[host] = struct{}{}

			if host != strings.ToLower(host) {
				t.Errorf("hostsIn(%q) returned %q, which is not lowercased", value, host)
			}
			labels := strings.Split(host, ".")
			if len(labels) < minHostLabels {
				t.Errorf("hostsIn(%q) returned %q with %d labels, below the %d the index requires", value, host, len(labels), minHostLabels)
			}
			for _, label := range labels {
				if label == "privatelink" {
					t.Errorf("hostsIn(%q) returned %q with its privatelink label still in place", value, host)
				}
			}
			if !hostLabels.MatchString(host) {
				t.Errorf("hostsIn(%q) returned %q, which fails its own hostname grammar", value, host)
			}
			if again := hostsIn(host); len(again) != 1 || again[0] != host {
				t.Errorf("hostsIn is not stable: %q -> %q -> %q", value, host, again)
			}
		}
		if got := hostOf(value); (len(hosts) == 0 && got != "") || (len(hosts) > 0 && got != hosts[0]) {
			t.Errorf("hostOf(%q) = %q disagrees with hostsIn = %q", value, got, hosts)
		}
	})
}

// documentSeeds are the row shapes the unit tests drive translate with: every seed-listed
// redaction path, the join keys a naive sweep would destroy, and the App Insights row that
// motivated screening.
var documentSeeds = []string{
	`{}`,
	`[]`,
	`null`,
	`"just a string"`,
	`{"id":"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1","type":"Microsoft.KeyVault/vaults","name":"kv1","location":"East US","tags":{"tier":"prod","empty":null,"n":1},"properties":{"enableSoftDelete":true,"vaultUri":"https://kv1.vault.azure.net/","networkAcls":{"virtualNetworkRules":[{"id":"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/db"}]}}}`,
	`{"id":"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Web/sites/web","properties":{"siteConfig":{"appSettings":[{"name":"DB","value":"Server=db;Password=x"},{"name":"EMPTY","value":""}],"connectionStrings":[{"name":"main","connectionValue":"Server=db;Password=y","type":"SQLAzure"}]},"administratorLoginPassword":"hunter2","storage":{"primaryKey":"k1","secondaryKey":"k2","accessKey":"k3","keyVaultUri":"https://kv.vault.azure.net/"}}}`,
	`{"id":"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Insights/components/ai","type":"Microsoft.Insights/components","name":"ai","properties":{"InstrumentationKey":"00000000-1111-2222-3333-444444444444","ConnectionString":"InstrumentationKey=00000000-1111;IngestionEndpoint=https://eastus-1.in.applicationinsights.azure.com/","ApplicationId":"aaaabbbb-cccc","RetentionInDays":90}}`,
	`{"id":"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa","properties":{"primaryKey":{"nested":"object"},"accessKey":["list"],"secondaryKey":null,"sshPublicKey":"ssh-rsa AAAA","privateDnsZoneArmResourceId":"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/privateDnsZones/z"}}`,
	`{"id":"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.ManagedIdentity/x/y","identity":{"userAssignedIdentities":{"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mi1":{"principalId":"p","clientId":"c"}}}}`,
	`{"id":"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/networkInterfaces/nic","properties":{"ipConfigurations":[{"properties":{"privateLinkConnectionProperties":{"fqdns":["cloud-parity-vault.vault.azure.net"],"privateLinkServiceId":"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/cloud-parity-vault/"}}}]}}`,
	`{"id":"/providers/Microsoft.Management/managementGroups/mg","location":"global","properties":{"a.b":{"c[0]":"dotted keys","password":"p"},"secret":123,"token":true,"apiKey":""}}`,
	`{"id":42,"type":["not","a","string"],"name":{"x":1},"location":7,"tags":"flat","properties":"leaf"}`,
	`{"id":"/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Sql/servers/s","properties":{"administratorLoginPassword":"","fullyQualifiedDomainName":"s.database.windows.net","deep":{"deeper":{"deepest":{"secondaryKey":3.5}}}}}`,
}

// decodeDocument turns fuzz bytes into the shape discover hands translate, or reports that the
// bytes are not an object at all - which is the one input shape the collector never sees, since
// Resource Graph rows are always objects.
func decodeDocument(data []byte) (armResource, bool) {
	var decoded any
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil, false
	}
	object, ok := decoded.(map[string]any)
	if !ok {
		return nil, false
	}
	return armResource(object), true
}

// FuzzTranslateRow drives the whole row path - id parsing, redaction, screening and linking -
// with an arbitrary Resource Graph document.
//
// What it pins: nothing panics; the row handed in is never mutated; the same row translates
// the same way twice; every key on the resource is already normalized; the document ships as
// valid JSON; and the gap screening raises, if any, names this resource and nothing else.
func FuzzTranslateRow(f *testing.F) {
	for _, seed := range documentSeeds {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		row, ok := decodeDocument(data)
		if !ok {
			return
		}
		before, err := json.Marshal(row)
		if err != nil {
			return
		}

		resources, gaps := translate(testSubscription, []armResource{row})
		again, gapsAgain := translate(testSubscription, []armResource{row})
		if !reflect.DeepEqual(resources, again) || !reflect.DeepEqual(gaps, gapsAgain) {
			t.Errorf("translate is not deterministic on %s", before)
		}

		if after, _ := json.Marshal(row); !bytes.Equal(before, after) {
			t.Errorf("translate mutated its input:\n before: %s\n after:  %s", before, after)
		}

		if len(resources) > 1 || len(gaps) > len(resources) {
			t.Fatalf("one row produced %d resources and %d gaps", len(resources), len(gaps))
		}
		if len(resources) == 0 {
			if id := strings.TrimRight(str(row["id"]), "/"); id != "" {
				t.Errorf("a row with id %q was dropped", id)
			}
			return
		}
		r := resources[0]

		if r.ID == "" || r.ID != strings.ToLower(r.ID) || strings.HasSuffix(r.ID, "/") {
			t.Errorf("ID %q is not lowercased and trimmed", r.ID)
		}
		if r.Type != strings.ToLower(r.Type) {
			t.Errorf("Type %q is not lowercased", r.Type)
		}
		if r.ParentID != strings.ToLower(r.ParentID) {
			t.Errorf("ParentID %q is not lowercased", r.ParentID)
		}
		if r.Account == "" || r.Account != strings.ToLower(r.Account) {
			t.Errorf("Account %q is empty or not lowercased; a resource attributed to nothing is unfilterable", r.Account)
		}
		if r.Region != strings.ToLower(r.Region) || strings.ContainsFunc(r.Region, unicode.IsSpace) {
			t.Errorf("Region %q is not lowercased and space-free; it is the DR-pairing key", r.Region)
		}
		if r.Provider != contract.ProviderAzure {
			t.Errorf("Provider = %q", r.Provider)
		}
		if !json.Valid(r.Document) {
			t.Errorf("Document is not valid JSON: %s", r.Document)
		}
		for i := 1; i < len(r.Redactions); i++ {
			if r.Redactions[i-1].Path > r.Redactions[i].Path {
				t.Errorf("Redactions are not sorted by path: %+v", r.Redactions)
			}
		}
		for _, g := range gaps {
			if g.Target != r.ID || g.Reason != contract.GapUnscreened {
				t.Errorf("translate raised a gap that is not this resource's screening gap: %+v", g)
			}
		}

		// The translated resource is what link reads, so a row that translates must also link
		// without incident, and every dependency it yields must point away from itself at a
		// target that is itself a recognised id.
		dependencies, linkGaps := link([]contract.Resource{r})
		if len(linkGaps) > 0 && linkGaps[0].Reason == contract.GapNotAttempted {
			t.Errorf("link could not read back a document translate produced: %+v", linkGaps)
		}
		for _, d := range dependencies {
			if d.From != r.ID {
				t.Errorf("dependency from %q on a resource with id %q", d.From, r.ID)
			}
			if d.To == r.ID {
				t.Errorf("self-edge on %q via %q", r.ID, d.Via)
			}
			if _, ok := referenceTarget(d.To); !ok {
				t.Errorf("dependency target %q is not a recognised ARM id", d.To)
			}
		}
	})
}

// FuzzRedactedDocument pins the seed-list redaction against any document shape.
//
// A redaction REPLACES; it never deletes and never touches a neighbour. So the output tree
// has exactly the shape of the input, differs from it at exactly as many leaves as it
// recorded, holds RedactedValue at each of those and nothing else, and running the rules a
// second time over the output changes nothing.
func FuzzRedactedDocument(f *testing.F) {
	for _, seed := range documentSeeds {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		row, ok := decodeDocument(data)
		if !ok {
			return
		}

		encoded, redactions, err := redactedDocument(row)
		if err != nil {
			t.Fatalf("a decoded row failed to re-encode: %v", err)
		}
		var out map[string]any
		if err := json.Unmarshal(encoded, &out); err != nil {
			t.Fatalf("redacted document is not valid JSON: %v", err)
		}

		replaced, ok := replacedLeaves(map[string]any(row), out)
		if !ok {
			t.Fatalf("redaction changed the document's shape:\n in:  %v\n out: %s", row, encoded)
		}
		if replaced != len(redactions) {
			t.Errorf("document differs at %d leaves but %d redactions were recorded: %+v", replaced, len(redactions), redactions)
		}
		for _, r := range redactions {
			if r.Path == "" || r.Reason == "" {
				t.Errorf("redaction with an empty path or reason: %+v", r)
			}
		}

		// Idempotent on the bytes: the second pass finds the same paths (RedactedValue is a
		// non-empty string, so it is matched again) and writes the same document.
		twice, redactionsAgain, err := redactedDocument(armResource(out))
		if err != nil {
			t.Fatalf("re-encoding the redacted document failed: %v", err)
		}
		if !bytes.Equal(encoded, twice) {
			t.Errorf("redaction is not idempotent:\n once:  %s\n twice: %s", encoded, twice)
		}
		if !reflect.DeepEqual(redactions, redactionsAgain) {
			t.Errorf("a second redaction pass recorded different paths:\n once:  %+v\n twice: %+v", redactions, redactionsAgain)
		}
	})
}

// replacedLeaves walks two trees in step and counts the leaves at which they differ, requiring
// that every difference is the output holding RedactedValue where the input held a
// non-empty scalar. It reports false if the trees differ in shape.
func replacedLeaves(in, out any) (int, bool) {
	switch typed := in.(type) {
	case map[string]any:
		object, ok := out.(map[string]any)
		if !ok || len(object) != len(typed) {
			return 0, false
		}
		total := 0
		for key, value := range typed {
			counterpart, present := object[key]
			if !present {
				return 0, false
			}
			n, ok := replacedLeaves(value, counterpart)
			if !ok {
				return 0, false
			}
			total += n
		}
		return total, true
	case []any:
		list, ok := out.([]any)
		if !ok || len(list) != len(typed) {
			return 0, false
		}
		total := 0
		for i, value := range typed {
			n, ok := replacedLeaves(value, list[i])
			if !ok {
				return 0, false
			}
			total += n
		}
		return total, true
	default:
		if reflect.DeepEqual(in, out) {
			return 0, true
		}
		if out != contract.RedactedValue || in == nil || in == "" {
			return 0, false
		}
		return 1, true
	}
}

// FuzzScreen pins the unscreened-field report against any document shape.
//
// screen never redacts and never mutates, so the document is byte-identical afterwards; and
// the count it reports equals an independent count of the leaves the rules describe - a
// non-empty string under a key that looks like a credential, not already on the redaction
// list - so the report cannot drift from its own definition.
func FuzzScreen(f *testing.F) {
	for _, seed := range documentSeeds {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		row, ok := decodeDocument(data)
		if !ok {
			return
		}
		before, err := json.Marshal(row)
		if err != nil {
			return
		}

		// Screen the way translateRow does: against the raw row, with the paths redaction took.
		_, redactions, err := redactedDocument(row)
		if err != nil {
			t.Fatalf("a decoded row failed to re-encode: %v", err)
		}
		resource := contract.Resource{ID: "/subscriptions/sub-1/resourcegroups/rg/providers/ns/t/n"}
		gap := screen(resource, row, redactions)

		if after, _ := json.Marshal(row); !bytes.Equal(before, after) {
			t.Errorf("screen mutated the document it was screening:\n before: %s\n after:  %s", before, after)
		}

		already := make(map[string]struct{}, len(redactions))
		for _, r := range redactions {
			already[r.Path] = struct{}{}
		}
		var found []string
		collectCandidates(map[string]any(row), "", already, &found)
		want := countCredentialLeaves(map[string]any(row), "", already)
		if len(found) != want {
			t.Errorf("screen found %d candidate paths %v, an independent count says %d", len(found), found, want)
		}

		if gap == nil {
			if want != 0 {
				t.Errorf("screen said nothing about %d unscreened fields", want)
			}
			return
		}
		if want == 0 {
			t.Errorf("screen raised a gap with nothing to report: %+v", gap)
		}
		if gap.Reason != contract.GapUnscreened || gap.Target != resource.ID {
			t.Errorf("gap = %+v, want %s on %s", gap, contract.GapUnscreened, resource.ID)
		}
	})
}

// countCredentialLeaves is the oracle FuzzScreen checks collectCandidates against: the same
// rule stated as a count rather than a walk.
func countCredentialLeaves(node any, path string, already map[string]struct{}) int {
	total := 0
	switch typed := node.(type) {
	case map[string]any:
		for key, value := range typed {
			at := key
			if path != "" {
				at = path + "." + key
			}
			if _, skip := already[at]; skip {
				continue
			}
			if looksLikeCredential(key) && isSecretShapedValue(value) {
				total++
				continue
			}
			total += countCredentialLeaves(value, at, already)
		}
	case []any:
		for i, value := range typed {
			total += countCredentialLeaves(value, path+"["+strconv.Itoa(i)+"]", already)
		}
	}
	return total
}
