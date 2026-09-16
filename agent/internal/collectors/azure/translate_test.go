package azure

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/manukyanv07/parity-scanner/contract"
)

// testSubscription is the boundary these rows were read from.
const testSubscription = "sub-1"

// row builds one ARG row. Named differently from discover_test.go's rows() because that
// one only ever sets an id.
func row(fields map[string]any) armResource { return armResource(fields) }

// only translates a single row and fails if it was dropped.
func only(t *testing.T, r armResource) contract.Resource {
	t.Helper()
	got, _ := translate(testSubscription, []armResource{r})
	if len(got) != 1 {
		t.Fatalf("translate dropped the row: got %d resources, want 1", len(got))
	}
	return got[0]
}

// document decodes a translated resource's document back into a tree.
func document(t *testing.T, r contract.Resource) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(r.Document, &out); err != nil {
		t.Fatalf("document is not valid JSON: %v", err)
	}
	return out
}

// dig walks a decoded document by dotted path, understanding `key[n]` array steps so that
// array paths go through the same assertions as scalar ones. It returns the value, the
// object that holds the leaf, the leaf key, and whether the walk reached it.
func dig(tree any, path string) (value any, holder map[string]any, leaf string, ok bool) {
	node := tree
	for _, segment := range strings.Split(path, ".") {
		key, index, hasIndex := segment, 0, false
		if open := strings.IndexByte(segment, '['); open >= 0 {
			n, err := strconv.Atoi(strings.TrimSuffix(segment[open+1:], "]"))
			if err != nil {
				return nil, nil, "", false
			}
			key, index, hasIndex = segment[:open], n, true
		}

		object, isObject := node.(map[string]any)
		if !isObject {
			return nil, nil, "", false
		}
		next, present := object[key]
		if !present {
			return nil, object, key, false
		}
		holder, leaf = object, key

		if hasIndex {
			list, isList := next.([]any)
			if !isList || index >= len(list) {
				return nil, nil, "", false
			}
			next = list[index]
			holder, leaf = nil, ""
		}
		node = next
	}
	return node, holder, leaf, true
}

func at(t *testing.T, tree any, path string) any {
	t.Helper()
	v, _, _, _ := dig(tree, path)
	return v
}

// contract.md §2.5 specifies this parsing exactly, and its three worked examples are the
// first three cases. Ambiguity here "produces a graph that looks right and matches
// nothing", so every id shape the scanner can meet is pinned.
func TestTranslateParsesIDsPerSpec(t *testing.T) {
	tests := []struct {
		name         string
		id           string
		argType      string // ARG's own columns, consulted only as a fallback
		argName      string
		wantAccount  string
		wantGroup    string
		wantType     string
		wantName     string
		wantParentID string
	}{
		{
			name:        "top level has no parent",
			id:          "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1",
			wantAccount: "sub-1",
			wantGroup:   "rg",
			wantType:    "microsoft.keyvault/vaults",
			wantName:    "kv1",
		},
		{
			name:         "child names its parent",
			id:           "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet1/subnets/db",
			wantAccount:  "sub-1",
			wantGroup:    "rg",
			wantType:     "microsoft.network/virtualnetworks/subnets",
			wantName:     "db",
			wantParentID: "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.network/virtualnetworks/vnet1",
		},
		{
			name:         "config child names the site, not the config collection",
			id:           "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Web/sites/web/config/appsettings",
			wantAccount:  "sub-1",
			wantGroup:    "rg",
			wantType:     "microsoft.web/sites/config",
			wantName:     "appsettings",
			wantParentID: "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.web/sites/web",
		},
		{
			name:         "grandchild parents to the child, not the root",
			id:           "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa/blobServices/default/containers/c1",
			wantAccount:  "sub-1",
			wantGroup:    "rg",
			wantType:     "microsoft.storage/storageaccounts/blobservices/containers",
			wantName:     "c1",
			wantParentID: "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.storage/storageaccounts/sa/blobservices/default",
		},
		{
			// ARM nests a SECOND /providers/ for an extension resource. Splitting on the
			// first types this microsoft.containerservice/managedclusters/providers/extensions
			// — a phantom type with no resource-type row, hence no recovery strategy — and
			// parents it to a path that is not a resource.
			name:         "extension resource types from the LAST providers and parents to its scope",
			id:           "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/aks1/providers/Microsoft.KubernetesConfiguration/extensions/flux",
			wantAccount:  "sub-1",
			wantGroup:    "rg",
			wantType:     "microsoft.kubernetesconfiguration/extensions",
			wantName:     "flux",
			wantParentID: "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.containerservice/managedclusters/aks1",
		},
		{
			// Every role assignment on a resource scope has the extension shape, and
			// unreadGaps() already promises the authorizationresources table. Getting this
			// wrong is the measured failure in scanner-engine.md §12: a recovered app with
			// no role assignments and every dashboard green.
			name:         "role assignment on a resource scope",
			id:           "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa/providers/Microsoft.Authorization/roleAssignments/11111111-2222-3333-4444-555555555555",
			wantAccount:  "sub-1",
			wantGroup:    "rg",
			wantType:     "microsoft.authorization/roleassignments",
			wantName:     "11111111-2222-3333-4444-555555555555",
			wantParentID: "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.storage/storageaccounts/sa",
		},
		{
			name:        "subscription-level resource has no group",
			id:          "/subscriptions/sub-1/providers/Microsoft.Authorization/policyAssignments/pa1",
			wantAccount: "sub-1",
			wantType:    "microsoft.authorization/policyassignments",
			wantName:    "pa1",
		},
		{
			name:        "resource group has no providers section, so ARG's columns answer",
			id:          "/subscriptions/sub-1/resourceGroups/MyRG",
			argType:     "Microsoft.Resources/subscriptions/resourceGroups",
			argName:     "MyRG",
			wantAccount: "sub-1",
			wantGroup:   "MyRG",
			wantType:    "microsoft.resources/subscriptions/resourcegroups",
			wantName:    "MyRG",
		},
		{
			name:        "management group has no subscription, so the scanned one answers",
			id:          "/providers/Microsoft.Management/managementGroups/mg1",
			wantAccount: testSubscription,
			wantType:    "microsoft.management/managementgroups",
			wantName:    "mg1",
		},
		{
			// A namespace with no type/name pair after it is not a resource id. ARG's
			// columns answer rather than the parser inventing a type.
			name:        "namespace with no pair falls back to ARG",
			id:          "/subscriptions/sub-1/providers/Microsoft.Foo",
			argType:     "Microsoft.Foo/things",
			argName:     "thing",
			wantAccount: "sub-1",
			wantType:    "microsoft.foo/things",
			wantName:    "thing",
		},
		{
			// An unpaired trailing segment cannot be split into type/name. Flooring the
			// count would confidently report type=microsoft.web/sites name=web, so the
			// estate would hold two resources both claiming to be that site, one of them
			// asserting it has no parent.
			name:        "malformed odd id defers to ARG instead of guessing",
			id:          "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Web/sites/web/config",
			argType:     "Microsoft.Web/sites/config",
			argName:     "web/config",
			wantAccount: "sub-1",
			wantGroup:   "rg",
			wantType:    "microsoft.web/sites/config",
			wantName:    "web/config",
		},
		{
			name:        "a trailing slash does not change identity",
			id:          "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1/",
			wantAccount: "sub-1",
			wantGroup:   "rg",
			wantType:    "microsoft.keyvault/vaults",
			wantName:    "kv1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := only(t, row(map[string]any{"id": tc.id, "type": tc.argType, "name": tc.argName}))

			wantID := strings.ToLower(strings.TrimRight(tc.id, "/"))
			if got.ID != wantID {
				t.Errorf("ID  = %q, want %q", got.ID, wantID)
			}
			if got.Account != tc.wantAccount {
				t.Errorf("Account = %q, want %q", got.Account, tc.wantAccount)
			}
			if got.Group != tc.wantGroup {
				t.Errorf("Group = %q, want %q", got.Group, tc.wantGroup)
			}
			if got.Type != tc.wantType {
				t.Errorf("Type = %q, want %q", got.Type, tc.wantType)
			}
			if got.Name != tc.wantName {
				t.Errorf("Name = %q, want %q", got.Name, tc.wantName)
			}
			if got.ParentID != tc.wantParentID {
				t.Errorf("ParentID = %q, want %q", got.ParentID, tc.wantParentID)
			}
		})
	}
}

// contract.md §2.5 mandates lowercasing exactly two things: the whole id, because it is
// the equality key, and type, because it is the resource-type table's lookup key. Its own
// justification is "normalizing the KEY does not lose it" — so name, the display value a
// restore recreates the resource under, must keep its casing.
func TestTranslateLowercasesOnlyTheKeys(t *testing.T) {
	got := only(t, row(map[string]any{
		"id":   "/subscriptions/SUB-1/resourceGroups/MyRG/providers/Microsoft.Web/sites/MyWebApp",
		"type": "Microsoft.Web/sites",
		"name": "MyWebApp",
	}))

	if got.ID != strings.ToLower(got.ID) {
		t.Errorf("ID is not lowercased: %q", got.ID)
	}
	if got.Type != "microsoft.web/sites" {
		t.Errorf("Type = %q, want microsoft.web/sites", got.Type)
	}
	if got.Name != "MyWebApp" {
		t.Errorf("Name = %q, want MyWebApp — name is a display value, not a key", got.Name)
	}
	if got.Group != "MyRG" {
		t.Errorf("Group = %q, want MyRG — the container the customer selects by", got.Group)
	}
	// A subscription GUID is a key, and ScanMeta.Account is lowercased at the entrypoint,
	// so these must agree or the estate cannot join to itself.
	if got.Account != "sub-1" {
		t.Errorf("Account = %q, want sub-1", got.Account)
	}
}

// Account is the isolation boundary and has no omitempty. A resource attributed to no
// account is unrecoverable and unfilterable, so an id that names none inherits the
// subscription actually being scanned.
func TestTranslateFallsBackToTheScannedSubscription(t *testing.T) {
	got := only(t, row(map[string]any{"id": "/tenants/t1/providers/Microsoft.Billing/billingAccounts/ba1"}))
	if got.Account != testSubscription {
		t.Errorf("Account = %q, want the scanned subscription %q", got.Account, testSubscription)
	}
	if strings.ToLower(only(t, row(map[string]any{
		"id": "/providers/Microsoft.Management/managementGroups/mg",
	})).Account) == "" {
		t.Error("Account is empty; nothing downstream can attribute this resource")
	}
}

// Normalizing the key must not lose the cloud's own spelling — the document is the source
// material for every later derivation, and it has to say what Azure said.
func TestTranslateDocumentKeepsTheCloudsOwnSpelling(t *testing.T) {
	const original = "/subscriptions/Sub-1/resourceGroups/RG/providers/Microsoft.KeyVault/vaults/KV1"
	got := only(t, row(map[string]any{
		"id":            original,
		"type":          "Microsoft.KeyVault/vaults",
		"name":          "KV1",
		"location":      "eastus",
		"resourceGroup": "RG",
		"properties":    map[string]any{"enableSoftDelete": true},
		"sku":           map[string]any{"name": "standard"},
	}))

	doc := document(t, got)
	if doc["id"] != original {
		t.Errorf("document id = %v, want the original casing %q", doc["id"], original)
	}
	if doc["type"] != "Microsoft.KeyVault/vaults" {
		t.Errorf("document type = %v, want the original casing", doc["type"])
	}
	for _, key := range []string{"id", "type", "name", "location", "resourceGroup", "properties", "sku"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("document lost key %q", key)
		}
	}
	if at(t, doc, "properties.enableSoftDelete") != true {
		t.Error("document lost properties.enableSoftDelete")
	}
}

// The contract says a global resource has no region; ARM says location "global". Region is
// also a lookup key for DR-region pairing, so "East US" and "eastus" must not become two
// places — the same defect that inflated the type count from 87 to 93, in another column.
func TestTranslateNormalizesRegion(t *testing.T) {
	tests := map[string]string{
		"global":    "",
		"Global":    "",
		"GLOBAL":    "",
		"eastus":    "eastus",
		"East US":   "eastus",
		"EastUS":    "eastus",
		"West US 2": "westus2",
		"":          "",
	}
	for location, want := range tests {
		got := only(t, row(map[string]any{
			"id":       "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv",
			"location": location,
		}))
		if got.Region != want {
			t.Errorf("location %q gave Region %q, want %q", location, got.Region, want)
		}
	}
}

// Tags are a selection key the customer typed. Lowercasing them would stop their own
// selector matching, so unlike an id they keep their casing.
func TestTranslateCarriesTagsWithCasingIntact(t *testing.T) {
	got := only(t, row(map[string]any{
		"id":   "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv",
		"tags": map[string]any{"CostCentre": "R&D", "dr-tier": "gold", "count": float64(3)},
	}))

	want := map[string]string{"CostCentre": "R&D", "dr-tier": "gold", "count": "3"}
	if !reflect.DeepEqual(got.Tags, want) {
		t.Errorf("Tags = %#v, want %#v", got.Tags, want)
	}
}

// A null tag value must not become the string "<nil>": that fabricates a value the cloud
// never returned, and a selector on the tag would then match it.
func TestTranslateDoesNotInventTagValues(t *testing.T) {
	got := only(t, row(map[string]any{
		"id":   "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv",
		"tags": map[string]any{"env": nil},
	}))
	if _, present := got.Tags["env"]; present {
		t.Errorf("Tags = %#v, want the null tag skipped rather than stringified", got.Tags)
	}
}

// An absent tag object must stay absent rather than becoming an empty one, so `omitempty`
// keeps it off the wire.
func TestTranslateOmitsMissingTags(t *testing.T) {
	for _, value := range []any{nil, map[string]any{}, "not an object"} {
		got := only(t, row(map[string]any{
			"id":   "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv",
			"tags": value,
		}))
		if got.Tags != nil {
			t.Errorf("tags %#v gave Tags %#v, want nil", value, got.Tags)
		}
	}
}

// webAppRow carries both the values §2.4 says to withhold and the join keys it says must
// survive.
func webAppRow() armResource {
	return row(map[string]any{
		"id":   "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Web/sites/web",
		"type": "Microsoft.Web/sites",
		"name": "web",
		"properties": map[string]any{
			"siteConfig": map[string]any{
				"appSettings": []any{
					map[string]any{"name": "DB_PASSWORD", "value": "hunter2"},
					map[string]any{"name": "KEYVAULT_REF", "value": "@Microsoft.KeyVault(SecretUri=https://kv.vault.azure.net/secrets/db)"},
				},
				"connectionStrings": []any{
					map[string]any{"name": "sql", "connectionValue": "Server=db;Password=hunter2"},
				},
			},
			"administratorLoginPassword": "hunter2",
			"keys": map[string]any{
				"primaryKey":   "pk",
				"secondaryKey": "sk",
				"accessKey":    "ak",
			},
			// The join keys a regex sweep would destroy.
			"keyVaultUri":                 "https://kv.vault.azure.net/",
			"sshPublicKey":                "ssh-rsa AAAA",
			"privateDnsZoneArmResourceId": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/privateDnsZones/z",
		},
	})
}

// §2.4's central rule: the value is replaced, the KEY survives. A deleted key is
// indistinguishable from one that was never set, which is exactly the ambiguity Gap
// exists to prevent — so every path is checked for key presence, not just for value.
func TestTranslateRedactsEverySeedListedValue(t *testing.T) {
	got := only(t, webAppRow())
	doc := document(t, got)

	want := []string{
		"properties.siteConfig.appSettings[0].value",
		"properties.siteConfig.appSettings[1].value",
		"properties.siteConfig.connectionStrings[0].connectionValue",
		"properties.administratorLoginPassword",
		"properties.keys.primaryKey",
		"properties.keys.secondaryKey",
		"properties.keys.accessKey",
	}

	recorded := map[string]string{}
	for _, r := range got.Redactions {
		recorded[r.Path] = r.Reason
	}
	if len(got.Redactions) != len(want) {
		t.Errorf("got %d redactions, want %d: %+v", len(got.Redactions), len(want), got.Redactions)
	}

	for _, path := range want {
		if reason, ok := recorded[path]; !ok {
			t.Errorf("no redaction recorded at %s", path)
		} else if reason == "" {
			t.Errorf("redaction at %s has no reason", path)
		}

		value, holder, leaf, reached := dig(doc, path)
		if !reached {
			t.Errorf("%s is missing from the document — the KEY must survive with the marker in place", path)
			continue
		}
		if holder != nil {
			if _, present := holder[leaf]; !present {
				t.Errorf("%s: the key was deleted rather than the value replaced", path)
			}
		}
		if value != contract.RedactedValue {
			t.Errorf("%s = %v, want %q", path, value, contract.RedactedValue)
		}
	}

	// The neighbouring name must not be touched: only the value is a secret.
	for i := range 2 {
		if v := at(t, doc, fmt.Sprintf("properties.siteConfig.appSettings[%d].name", i)); v == contract.RedactedValue {
			t.Errorf("appSettings[%d].name was redacted; only the value should be", i)
		}
	}
}

// The most important test in this file. contract.md §2.4 names these three fields as what
// a `key|secret|token` sweep would wrongly redact, and warns that over-redaction "breaks
// the dependency graph in a way no test notices". Each is presented to the rules ALONE, so
// this asserts something the value checks above cannot: that no rule can reach it.
func TestTranslateNeverRedactsJoinKeys(t *testing.T) {
	joinKeys := map[string]string{ //gosec:disable G101 -- the join keys are URLs and ids; the test is that they are NOT secrets
		"keyVaultUri":                 "https://kv.vault.azure.net/",
		"sshPublicKey":                "ssh-rsa AAAA",
		"privateDnsZoneArmResourceId": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/privateDnsZones/z",
		"secretUri":                   "https://kv.vault.azure.net/secrets/db",
		"tokenEndpoint":               "https://login.microsoftonline.com/t/oauth2/token",
		"primaryKeyVaultId":           "/subscriptions/sub-1/providers/Microsoft.KeyVault/vaults/kv",
	}
	for field, value := range joinKeys {
		t.Run(field, func(t *testing.T) {
			// Presented at depth 1 and depth 2, since the seed list has a `*` wildcard at
			// depth 2 that a naive rule could widen into.
			for _, r := range []armResource{
				row(map[string]any{"id": "/subscriptions/sub-1/providers/Microsoft.Web/sites/w",
					"properties": map[string]any{field: value}}),
				row(map[string]any{"id": "/subscriptions/sub-1/providers/Microsoft.Web/sites/w",
					"properties": map[string]any{"nested": map[string]any{field: value}}}),
			} {
				got := only(t, r)
				if len(got.Redactions) != 0 {
					t.Errorf("%s was redacted (%+v) — this silently breaks the dependency graph", field, got.Redactions)
				}
			}
		})
	}
}

// A secret is a scalar. A `*` wildcard can reach an object, and replacing it would
// collapse a whole subtree into one marker — hiding an ARM resource id and a Key Vault URI
// inside what looks like a single withheld key. That is over-redaction arriving through a
// wildcard rather than a regex.
func TestTranslateDoesNotRedactWholeSubtrees(t *testing.T) {
	const vaultID = "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv"
	got := only(t, row(map[string]any{
		"id": "/subscriptions/sub-1/providers/Microsoft.Storage/storageAccounts/sa",
		"properties": map[string]any{"encryption": map[string]any{
			"accessKey": map[string]any{"keyVaultUri": "https://kv/", "id": vaultID},
		}},
	}))

	if len(got.Redactions) != 0 {
		t.Errorf("Redactions = %+v, want none: the matched value is an object, not a secret", got.Redactions)
	}
	doc := document(t, got)
	if v := at(t, doc, "properties.encryption.accessKey.id"); v != vaultID {
		t.Errorf("the resource id inside the subtree was lost: %v", v)
	}
	if v := at(t, doc, "properties.encryption.accessKey.keyVaultUri"); v != "https://kv/" {
		t.Errorf("the key vault URI inside the subtree was lost: %v", v)
	}
}

// The recorded path has to be the concrete location, not the rule pattern, or a reviewer
// cannot tell which of fifty app settings was withheld.
func TestTranslateRecordsConcretePathsNotPatterns(t *testing.T) {
	got := only(t, webAppRow())
	if len(got.Redactions) == 0 {
		t.Fatal("no redactions to inspect")
	}
	for _, r := range got.Redactions {
		if strings.Contains(r.Path, "*") || strings.Contains(r.Path, arrayStep) {
			t.Errorf("redaction path %q is a pattern, not a location", r.Path)
		}
	}
}

// Map iteration order is random in Go. Without the sort in redactedDocument, a rule with a
// `*` segment would emit its redactions in a different order on every run, so the payload
// — and any golden test over it — would be unstable.
func TestTranslateIsDeterministic(t *testing.T) {
	first := only(t, webAppRow())
	for i := range 20 {
		again := only(t, webAppRow())
		if !reflect.DeepEqual(first.Redactions, again.Redactions) {
			t.Fatalf("redaction order changed on run %d:\n%v\n%v", i, first.Redactions, again.Redactions)
		}
		if string(first.Document) != string(again.Document) {
			t.Fatalf("document bytes changed on run %d", i)
		}
	}
}

// discover's rows belong to discover. A collector that redacts its own input is a bug
// waiting for a second reader of the same row.
func TestTranslateDoesNotMutateItsInput(t *testing.T) {
	input := webAppRow()
	before, err := json.Marshal(map[string]any(input))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	translate(testSubscription, []armResource{input})

	after, err := json.Marshal(map[string]any(input))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(before) != string(after) {
		t.Errorf("translate mutated the caller's row:\nbefore %s\nafter  %s", before, after)
	}
}

// A row with no id cannot be referenced or recovered. It is dropped, and Collect's count
// comparison turns the difference into a not-attempted Gap, so it is never silently absent.
func TestTranslateDropsRowsWithNoUsableID(t *testing.T) {
	got, _ := translate(testSubscription, []armResource{
		row(map[string]any{"name": "no id at all"}),
		row(map[string]any{"id": ""}),
		row(map[string]any{"id": 42}), // not a string
		row(map[string]any{"id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv"}),
	})
	if len(got) != 1 {
		t.Fatalf("got %d resources, want only the one with a usable id", len(got))
	}
	if got[0].Name != "kv" {
		t.Errorf("kept the wrong row: %+v", got[0])
	}
}

func TestTranslateHandlesEmptyInput(t *testing.T) {
	if got, _ := translate(testSubscription, nil); len(got) != 0 {
		t.Errorf("translate(nil) = %v, want empty", got)
	}
	if got, _ := translate(testSubscription, []armResource{}); len(got) != 0 {
		t.Errorf("translate(empty) = %v, want empty", got)
	}
}

// Redaction walks whatever shape the cloud returned. Missing sections, wrong types and
// nulls must be no-ops rather than panics — a collector that crashes on one odd resource
// loses the whole subscription — and each shape's redaction outcome is asserted, not just
// that it survived.
func TestTranslateSurvivesUnexpectedShapes(t *testing.T) {
	tests := []struct {
		name           string
		properties     any
		wantRedactions int
	}{
		{"no properties at all", nil, 0},
		{"properties is a string", "not an object", 0},
		{"siteConfig is an array", map[string]any{"siteConfig": []any{1, 2}}, 0},
		{"appSettings is a string", map[string]any{"siteConfig": map[string]any{"appSettings": "nope"}}, 0},
		{"appSettings holds scalars and nulls", map[string]any{"siteConfig": map[string]any{"appSettings": []any{"scalar", nil}}}, 0},
		{"password is null", map[string]any{"administratorLoginPassword": nil}, 0},
		{"password is empty", map[string]any{"administratorLoginPassword": ""}, 0},
		{"password is set", map[string]any{"administratorLoginPassword": "x"}, 1},
		{"password is a number", map[string]any{"administratorLoginPassword": float64(1)}, 1},
		{"wildcard key holds an array", map[string]any{"a": map[string]any{"primaryKey": []any{"x"}}}, 0},
		{"two wildcard matches", map[string]any{
			"a": map[string]any{"primaryKey": "x"},
			"b": map[string]any{"primaryKey": "y"},
		}, 2},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := only(t, row(map[string]any{
				"id":         "/subscriptions/sub-1/providers/Microsoft.Web/sites/w",
				"properties": tc.properties,
			}))
			if len(got.Redactions) != tc.wantRedactions {
				t.Errorf("got %d redactions, want %d: %+v", len(got.Redactions), tc.wantRedactions, got.Redactions)
			}
			if !json.Valid(got.Document) {
				t.Error("produced invalid document JSON")
			}
		})
	}
}

// ARM has changed a property's casing between API versions before. Matching keys
// case-insensitively cannot widen which field is meant — it is the same field — but it
// does survive that drift.
func TestTranslateRedactsRegardlessOfARMKeyCasing(t *testing.T) {
	got := only(t, row(map[string]any{
		"id": "/subscriptions/sub-1/providers/Microsoft.Web/sites/web",
		"properties": map[string]any{
			"SiteConfig": map[string]any{
				"AppSettings": []any{map[string]any{"Name": "X", "Value": "secret"}},
			},
		},
	}))
	if len(got.Redactions) != 1 {
		t.Fatalf("Redactions = %v, want 1 despite the changed casing", got.Redactions)
	}
	if at(t, document(t, got), "properties.SiteConfig.AppSettings[0].Name") != "X" {
		t.Error("the neighbouring key vanished instead of only the value being redacted")
	}
}

// Every resource the scanner emits must declare which cloud it came from.
func TestTranslateStampsTheProvider(t *testing.T) {
	got := only(t, row(map[string]any{"id": "/subscriptions/sub-1/providers/Microsoft.Web/sites/web"}))
	if got.Provider != contract.ProviderAzure {
		t.Errorf("Provider = %q, want %q", got.Provider, contract.ProviderAzure)
	}
}

// The seed list reads `properties.*.primaryKey` — one level of nesting, which is where
// Azure actually puts account keys. A key sitting directly on properties is therefore NOT
// covered. Pinned deliberately: §2.4 says extend the list one entry at a time with a
// reason, so widening it is a decision for the contract, not something a collector does
// quietly. See the follow-up issue on the unlisted-field heuristic.
func TestTranslateFollowsTheSeedListLiterally(t *testing.T) {
	got := only(t, row(map[string]any{
		"id":         "/subscriptions/sub-1/providers/Microsoft.Storage/storageAccounts/sa",
		"properties": map[string]any{"primaryKey": "pk"},
	}))
	if len(got.Redactions) != 0 {
		t.Errorf("Redactions = %v; properties.primaryKey is outside the seed list", got.Redactions)
	}
}
