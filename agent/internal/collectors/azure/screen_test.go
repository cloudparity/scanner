package azure

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/manukyanv07/parity-scanner/contract"
)

// appInsightsRow is the measured real case: microsoft.insights/components exists in
// essentially every subscription and returns both of these directly in ARG's document.
// Before screening they shipped verbatim next to `redactions: []`.
func appInsightsRow() armResource {
	return row(map[string]any{
		"id":   "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Insights/components/ai",
		"type": "Microsoft.Insights/components",
		"name": "ai",
		"properties": map[string]any{
			"InstrumentationKey": "00000000-1111-2222-3333-444444444444",
			"ConnectionString":   "InstrumentationKey=00000000-1111;IngestionEndpoint=https://eastus-1.in.applicationinsights.azure.com/",
			"ApplicationId":      "aaaabbbb-cccc",
			"RetentionInDays":    float64(90),
		},
	})
}

func onlyWithGap(t *testing.T, r armResource) (contract.Resource, []contract.Gap) {
	t.Helper()
	got, gaps := translate(testSubscription, []armResource{r})
	if len(got) != 1 {
		t.Fatalf("translate dropped the row: got %d resources", len(got))
	}
	return got[0], gaps
}

func TestScreenFlagsUnlistedCredentialFields(t *testing.T) {
	resource, gaps := onlyWithGap(t, appInsightsRow())

	if len(gaps) != 1 {
		t.Fatalf("got %d gaps, want exactly 1 per resource: %+v", len(gaps), gaps)
	}
	g := gaps[0]
	if g.Reason != contract.GapUnscreened {
		t.Errorf("reason = %q, want %q", g.Reason, contract.GapUnscreened)
	}
	if g.Target != resource.ID {
		t.Errorf("target = %q, want the resource id %q", g.Target, resource.ID)
	}
	for _, want := range []string{"properties.InstrumentationKey", "properties.ConnectionString"} {
		if !strings.Contains(g.Detail, want) {
			t.Errorf("detail does not name %s:\n%s", want, g.Detail)
		}
	}
	// ApplicationId ends in a pointer suffix and RetentionInDays is a number.
	for _, unwanted := range []string{"ApplicationId", "RetentionInDays"} {
		if strings.Contains(g.Detail, unwanted) {
			t.Errorf("detail wrongly names %s:\n%s", unwanted, g.Detail)
		}
	}
}

// The whole point: flagging must not become redacting. §2.4 says a suspected field is
// reported, never withheld, because over-redaction breaks the dependency graph silently.
func TestScreenNeverRedacts(t *testing.T) {
	resource, gaps := onlyWithGap(t, appInsightsRow())

	if len(resource.Redactions) != 0 {
		t.Errorf("Redactions = %+v, want none — screening reports, it does not withhold", resource.Redactions)
	}
	if len(gaps) != 1 {
		t.Fatalf("expected the gap that says so")
	}

	var doc map[string]any
	if err := json.Unmarshal(resource.Document, &doc); err != nil {
		t.Fatalf("document: %v", err)
	}
	properties := doc["properties"].(map[string]any)
	if properties["InstrumentationKey"] != "00000000-1111-2222-3333-444444444444" {
		t.Errorf("the value was altered: %v", properties["InstrumentationKey"])
	}
	if properties["InstrumentationKey"] == contract.RedactedValue {
		t.Error("screening redacted on suspicion, which §2.4 forbids")
	}
}

// The three fields contract.md §2.4 names as what a `key|secret|token` sweep destroys. The
// heuristic exists precisely to not be that sweep, so this is its most important test.
func TestScreenNeverFlagsJoinKeys(t *testing.T) {
	joinKeys := map[string]string{
		"keyVaultUri":                 "https://kv.vault.azure.net/",
		"sshPublicKey":                "ssh-rsa AAAAB3Nza",
		"privateDnsZoneArmResourceId": "/subscriptions/sub-1/providers/Microsoft.Network/privateDnsZones/z",
		"secretIdentifier":            "https://kv.vault.azure.net/secrets/db",
		"secretUri":                   "https://kv.vault.azure.net/secrets/db",
		"tokenEndpoint":               "https://login.microsoftonline.com/t/oauth2/token",
		"credentialName":              "my-cred",
		"passwordVersion":             "3",
		"certificateThumbprint":       "AB12CD34",
		"secretsEnabled":              "true",
	}
	for field, value := range joinKeys {
		t.Run(field, func(t *testing.T) {
			_, gaps := onlyWithGap(t, row(map[string]any{
				"id":         "/subscriptions/sub-1/providers/Microsoft.Web/sites/w",
				"properties": map[string]any{field: value},
			}))
			if len(gaps) != 0 {
				t.Errorf("%s was flagged (%+v) — it is an address, not a payload, and the graph is built from it", field, gaps)
			}
		})
	}
}

// A field the seed list already redacted must not also be reported as unscreened: it WAS
// screened, and double-reporting would make the list look worse than it is.
func TestScreenSkipsWhatTheSeedListAlreadyCovered(t *testing.T) {
	resource, gaps := onlyWithGap(t, row(map[string]any{
		"id": "/subscriptions/sub-1/providers/Microsoft.Sql/servers/sql",
		"properties": map[string]any{
			"administratorLoginPassword": "hunter2",
		},
	}))

	if len(resource.Redactions) != 1 {
		t.Fatalf("expected the seed rule to redact it: %+v", resource.Redactions)
	}
	if len(gaps) != 0 {
		t.Errorf("a redacted field was also reported as unscreened: %+v", gaps)
	}
}

// One gap per RESOURCE. App Insights is near-universal, so per-field would emit hundreds on
// a real estate and drown the signal.
func TestScreenEmitsOneGapPerResource(t *testing.T) {
	_, gaps := translate(testSubscription, []armResource{
		appInsightsRow(),
		row(map[string]any{
			"id": "/subscriptions/sub-1/providers/Microsoft.NotificationHubs/namespaces/ns/notificationHubs/h",
			"properties": map[string]any{
				"gcmCredential":  map[string]any{"googleApiKey": "AIza-fake"},
				"apnsCredential": map[string]any{"token": "fake-token"},
			},
		}),
	})
	if len(gaps) != 2 {
		t.Fatalf("got %d gaps for 2 resources, want 1 each: %+v", len(gaps), gaps)
	}
	// The nested paths must be reported with their full location.
	joined := gaps[0].Detail + gaps[1].Detail
	for _, want := range []string{"properties.gcmCredential.googleApiKey", "properties.apnsCredential.token"} {
		if !strings.Contains(joined, want) {
			t.Errorf("nested path %s not reported:\n%s", want, joined)
		}
	}
}

// A clean resource must carry no gap, or the honesty surface becomes noise and gets ignored.
func TestScreenSaysNothingWhenThereIsNothingToSay(t *testing.T) {
	_, gaps := onlyWithGap(t, row(map[string]any{
		"id":   "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet",
		"type": "Microsoft.Network/virtualNetworks",
		"properties": map[string]any{
			"addressSpace": map[string]any{"addressPrefixes": []any{"10.0.0.0/16"}},
			"subnets":      []any{map[string]any{"name": "db", "properties": map[string]any{"addressPrefix": "10.0.1.0/24"}}},
		},
	}))
	if len(gaps) != 0 {
		t.Errorf("a vnet was flagged: %+v", gaps)
	}
}

// Array elements must be reachable, since appSettings-style lists are exactly where
// credentials hide.
func TestScreenReportsPathsInsideArrays(t *testing.T) {
	_, gaps := onlyWithGap(t, row(map[string]any{
		"id": "/subscriptions/sub-1/providers/Microsoft.DataFactory/factories/df",
		"properties": map[string]any{
			"linkedServices": []any{
				map[string]any{"name": "sql", "connectionString": "Server=x;Password=y"},
			},
		},
	}))
	if len(gaps) != 1 {
		t.Fatalf("got %d gaps: %+v", len(gaps), gaps)
	}
	if !strings.Contains(gaps[0].Detail, "properties.linkedServices[0].connectionString") {
		t.Errorf("array path not reported:\n%s", gaps[0].Detail)
	}
}

// Only values that could carry a credential. A bool or a number named "secret..." is a
// setting, and flagging it trains a human to stop reading the list.
func TestScreenIgnoresNonStringAndEmptyValues(t *testing.T) {
	for name, value := range map[string]any{
		"bool":   true,
		"number": float64(1),
		"null":   nil,
		"empty":  "",
		"object": map[string]any{"nested": "x"},
	} {
		t.Run(name, func(t *testing.T) {
			_, gaps := onlyWithGap(t, row(map[string]any{
				"id":         "/subscriptions/sub-1/providers/Microsoft.Web/sites/w",
				"properties": map[string]any{"adminPassword": value},
			}))
			if len(gaps) != 0 {
				t.Errorf("%s value flagged: %+v", name, gaps)
			}
		})
	}
}

// Map iteration is random, so the reported path list must be sorted or the payload is
// unstable and a golden test over it would flake.
func TestScreenIsDeterministic(t *testing.T) {
	first := ""
	for i := range 20 {
		_, gaps := onlyWithGap(t, appInsightsRow())
		if len(gaps) != 1 {
			t.Fatalf("run %d: got %d gaps", i, len(gaps))
		}
		if i == 0 {
			first = gaps[0].Detail
			continue
		}
		if gaps[0].Detail != first {
			t.Fatalf("path order changed on run %d:\n%s\n%s", i, first, gaps[0].Detail)
		}
	}
}

// A pathological resource must not produce an unreadable gap.
func TestScreenCapsTheReportedPaths(t *testing.T) {
	properties := map[string]any{}
	for i := range 50 {
		properties[fmt.Sprintf("password%02d", i)] = "x"
	}
	_, gaps := onlyWithGap(t, row(map[string]any{
		"id":         "/subscriptions/sub-1/providers/Microsoft.Web/sites/w",
		"properties": properties,
	}))
	if len(gaps) != 1 {
		t.Fatalf("got %d gaps", len(gaps))
	}
	if !strings.Contains(gaps[0].Detail, "shipped 50 field(s)") {
		t.Errorf("the gap does not state the true count:\n%s", gaps[0].Detail)
	}
	if !strings.Contains(gaps[0].Detail, fmt.Sprintf("and %d more", 50-maxReportedPaths)) {
		t.Errorf("the gap does not say it truncated the list:\n%s", gaps[0].Detail)
	}
}

// The discriminator on its own: payload versus address. This is the line that decides
// whether the dependency graph survives.
func TestLooksLikeCredential(t *testing.T) {
	payload := []string{
		"adminPassword", "administratorLoginPassword", "clientSecret", "InstrumentationKey",
		"ConnectionString", "primaryKey", "secondaryKey", "accessKey", "accountKey",
		"sharedAccessKey", "googleApiKey", "privateKey", "sasToken", "pwd", "passwd",
	}
	address := []string{
		"keyVaultUri", "sshPublicKey", "privateDnsZoneArmResourceId", "secretIdentifier",
		"secretUri", "secretUrl", "tokenEndpoint", "credentialName", "passwordVersion",
		"certificateThumbprint", "secretsEnabled", "keyType", "publicKeys",
		"virtualNetworkSubnetId", "provisioningState", "location",
	}
	for _, k := range payload {
		if !looksLikeCredential(k) {
			t.Errorf("%q should be flagged as a possible credential", k)
		}
	}
	for _, k := range address {
		if looksLikeCredential(k) {
			t.Errorf("%q is an address or a setting and must NOT be flagged", k)
		}
	}
}

// The gap must survive the wire, since the honesty screen renders it from JSON.
func TestScreenGapRoundTrips(t *testing.T) {
	_, gaps := onlyWithGap(t, appInsightsRow())
	encoded, err := json.Marshal(gaps[0])
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back contract.Gap
	if err := json.Unmarshal(encoded, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !reflect.DeepEqual(back, gaps[0]) {
		t.Errorf("round trip changed the gap:\n%+v\n%+v", gaps[0], back)
	}
	if !strings.Contains(string(encoded), `"reason":"unscreened"`) {
		t.Errorf("the wire form does not carry the new reason: %s", encoded)
	}
}
