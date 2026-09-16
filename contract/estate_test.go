package contract

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// update rewrites the golden file instead of comparing against it.
var update = flag.Bool("update", false, "rewrite golden files")

// sampleEstate is the fixture every test in this file works from: one Key Vault,
// one reference, one gap, one redaction.
func sampleEstate() Estate {
	return Estate{
		ContractVersion: ContractVersion,
		Scan: ScanMeta{
			Provider:      ProviderAzure,
			Account:       "sub-1",
			ScannedAt:     "2026-08-11T12:00:00Z",
			Collector:     "azure/0.1.0",
			ResourceCount: 1,
			Gaps: []Gap{{
				Reason: GapDataPlane,
				Target: "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.keyvault/vaults/kv1",
				Detail: "secret values are data-plane; names are visible, values are not",
			}},
		},
		Resources: []Resource{{
			Provider: ProviderAzure,
			ID:       "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.keyvault/vaults/kv1",
			ParentID: "",
			Type:     "microsoft.keyvault/vaults",
			Name:     "kv1",
			Account:  "sub-1",
			Group:    "rg",
			Region:   "eastus",
			Tags:     map[string]string{"tier": "prod"},
			Document: json.RawMessage(`{"properties":{"enableSoftDelete":true},"sku":{"name":"standard"}}`),
			Redactions: []Redaction{{
				Path:   "properties.connectionString",
				Reason: "credential-bearing value",
			}},
		}},
		Dependencies: []Dependency{{
			From:       "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.keyvault/vaults/kv1",
			To:         "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.network/virtualnetworks/vnet1/subnets/db",
			Via:        "properties.networkAcls.virtualNetworkRules[0].id",
			Resolution: ResolutionChildOfScanned,
		}},
	}
}

// The payload must survive a JSON round trip unchanged — it is simultaneously the wire
// format, the DB shape, and the API response. If this breaks, both sides break silently.
func TestEstateJSONRoundTrip(t *testing.T) {
	in := sampleEstate()

	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out Estate
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.ContractVersion != ContractVersion {
		t.Errorf("contractVersion: got %d want %d", out.ContractVersion, ContractVersion)
	}
	if got, want := out.Scan.Account, in.Scan.Account; got != want {
		t.Errorf("account: got %q want %q", got, want)
	}
	if len(out.Resources) != 1 || len(out.Dependencies) != 1 {
		t.Fatalf("counts: got %d resources, %d references", len(out.Resources), len(out.Dependencies))
	}

	r := out.Resources[0]
	if r.Group != "rg" || r.Region != "eastus" || r.Account != "sub-1" {
		t.Errorf("translated identity lost: %+v", r)
	}
	if r.Tags["tier"] != "prod" {
		t.Errorf("tags lost: %+v", r.Tags)
	}
	if len(r.Redactions) != 1 || r.Redactions[0].Path == "" {
		t.Errorf("redactions lost: %+v", r.Redactions)
	}
	if len(out.Scan.Gaps) != 1 || out.Scan.Gaps[0].Reason != GapDataPlane {
		t.Errorf("gaps lost: %+v", out.Scan.Gaps)
	}
	if out.Dependencies[0].Resolution != ResolutionChildOfScanned {
		t.Errorf("resolution lost: %+v", out.Dependencies[0])
	}
}

// The raw document is the source material every later derivation reads. It must arrive
// byte-for-byte as the collector read it — no re-ordering, no re-encoding, no loss.
func TestDocumentSurvivesVerbatim(t *testing.T) {
	// Deliberately awkward: unsorted keys, a null, a nested array, a unicode string.
	raw := `{"zeta":1,"alpha":{"b":[1,2,{"c":null}]},"name":"café"}`
	in := Estate{
		ContractVersion: ContractVersion,
		Resources:       []Resource{{ID: "r1", Document: json.RawMessage(raw)}},
	}

	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out Estate
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if got := string(out.Resources[0].Document); got != raw {
		t.Errorf("document altered in transit:\n got %s\nwant %s", got, raw)
	}
}

// The scanner is dumb: it reports what it saw and never what it means. These field names
// are engine-side judgments (docs/specs/contract.md §3) and must never appear on the wire.
// This test is the executable form of the observe/judge boundary.
func TestScanPayloadCarriesNoJudgment(t *testing.T) {
	forbidden := []string{"buckets", "drStrategy", "strength", "configHash", "ruleSetVersion", "verdict"}

	b, err := json.Marshal(sampleEstate())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Check the objects we define. The raw document is excluded on purpose: it is the
	// cloud's own JSON and we make no claims about the keys inside it.
	objects := []map[string]any{generic, generic["scan"].(map[string]any)}
	for _, key := range []string{"resources", "dependencies"} {
		for _, item := range generic[key].([]any) {
			objects = append(objects, item.(map[string]any))
		}
	}

	for _, obj := range objects {
		for _, f := range forbidden {
			if _, found := obj[f]; found {
				t.Errorf("judgment field %q leaked into the scan payload — it belongs to the engine", f)
			}
		}
	}
}

// The wire format is pinned by a golden file so an accidental field rename shows up as a
// diff in review rather than as a silent break in the control plane.
// Regenerate deliberately with: go test ./contract -update
func TestEstateGolden(t *testing.T) {
	got, err := json.MarshalIndent(sampleEstate(), "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got = append(got, '\n')

	path := filepath.Join("testdata", "estate.golden.json")
	if *update {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		t.Logf("updated %s", path)
		return
	}

	want, err := os.ReadFile(path) //gosec:disable G304 -- a golden file under testdata/
	if err != nil {
		t.Fatalf("read golden (run with -update to create): %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("wire format changed.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}
