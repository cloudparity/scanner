package contract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sampleManifest is the fixture every test here works from: one base copy of one Postgres
// database, one thing deliberately not backed up, and the FOUR PARTS Azure's restore-as-files
// actually writes (AD-033) — one PGDMP archive beside three plain-SQL files.
//
// Four rather than one on purpose: a one-part fixture is what let a single Artifact.Format
// look sufficient for a whole artifact (AD-037).
func sampleManifest() Manifest {
	return Manifest{
		ContractVersion: BackupContractVersion,
		Kind:            BackupBase,
		Source: BackupSource{
			Provider:      ProviderAzure,
			ResourceID:    "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.dbforpostgresql/flexibleservers/pg1",
			Account:       "/subscriptions/sub-1",
			Database:      "orders",
			Engine:        "postgres",
			EngineVersion: "16",
		},
		ReadPoint: ReadPoint{
			At:       "2026-08-14T09:14:00Z",
			Position: "0/1A2B3C8",
		},
		Schema: "9f2c4b1e7a03d568",
		Artifact: Artifact{
			Format: FormatPGDumpCustom,
			// The total across the four parts, and no whole-artifact hash: the cloud moved
			// these bytes into four objects (RouteProviderCopy) and there was no single
			// upload stream to hash. Part.SHA256 is what vouches for anything here.
			Bytes:  1048576 + 793 + 4096 + 360,
			SHA256: "",
			Parts: []Part{
				{
					Path:   "pg1/orders/2026-08-14T09-14-00Z/database.sql",
					Bytes:  1048576,
					SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
					Format: FormatPGDumpCustom,
					Role:   PartDatabase,
				},
				{
					Path:   "pg1/orders/2026-08-14T09-14-00Z/roles.sql",
					Bytes:  793,
					SHA256: "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03",
					Format: FormatPlainSQL,
					Role:   PartRoles,
				},
				{
					Path:   "pg1/orders/2026-08-14T09-14-00Z/schema.sql",
					Bytes:  4096,
					SHA256: "6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b",
					Format: FormatPlainSQL,
					Role:   PartSchema,
				},
				{
					Path:   "pg1/orders/2026-08-14T09-14-00Z/tablespaces.sql",
					Bytes:  360,
					SHA256: "d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35",
					Format: FormatPlainSQL,
					Role:   PartTablespaces,
				},
			},
		},
		Producer: Producer{
			Agent: "azure/0.1.0",
			Tool:  "pg_dump 16.4",
			Args:  []string{"--format=custom", "--no-owner"},
		},
		Transfer: RouteProviderCopy,
		Skipped: []Gap{{
			Reason: GapPermissionDenied,
			Target: "reporting",
			Detail: "no connect privilege on database reporting; it is not in this backup",
		}},
	}
}

// sampleChain is a base and two change files over it, and the SECOND CHANGE FILE OVERLAPS THE
// FIRST on purpose: replay is at-least-once (AD-039 measured a stream that confirmed nothing
// being redelivered every transaction at the same LSNs), so a chain whose ranges overlap is the
// healthy shape and not a corrupt one. A fixture of neatly adjacent ranges would let a verifier
// that demands adjacency look correct.
func sampleChain() Chain {
	base := sampleManifest()
	base.ReadPoint.At = "2026-08-14T09:14:00Z"
	base.ReadPoint.Position = "0/1A2B000"

	return Chain{
		ContractVersion: BackupContractVersion,
		Segments:        []Manifest{base, sampleChange("0/1A2B000", "0/1A2B3C8"), sampleChange("0/1A2B300", "0/1A2B9F0")},
		Confirmed:       "0/1A2B9F0",
	}
}

// sampleChange is one change file: the range it covers, and the schema fingerprint that was
// current while it was captured.
func sampleChange(from, to string) Manifest {
	return Manifest{
		ContractVersion: BackupContractVersion,
		Kind:            BackupChange,
		Source:          sampleManifest().Source,
		ReadPoint:       ReadPoint{At: "2026-08-14T09:19:00Z", Position: to, From: from},
		Schema:          "9f2c4b1e7a03d568",
		Artifact: Artifact{
			Format: FormatPlainSQL,
			Bytes:  2048,
			Parts: []Part{{
				// A position carries a "/" and a path is not the place to put one: the golden
				// file is what a reader learns the format from, so it must not model an object
				// layout no producer could write.
				Path:   "pg1/orders/" + strings.ReplaceAll(from, "/", "-") + "/changes.0000",
				Bytes:  2048,
				SHA256: "4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce",
				Format: FormatPlainSQL,
				Role:   PartDatabase,
			}},
		},
		Producer: Producer{Agent: "azure/0.1.0", Tool: "pglogrepl 0.0.0"},
		Transfer: RouteAgentStream,
	}
}

// The manifest is the interface between the agent that writes a backup and whatever
// later reads it — the control plane, and eventually the agent that restores it. Like
// Estate it is simultaneously the wire format, the DB shape and the API response, so a
// round trip that loses a field breaks both sides silently.
func TestManifestJSONRoundTrip(t *testing.T) {
	in := sampleManifest()

	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out Manifest
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if out.ContractVersion != BackupContractVersion {
		t.Errorf("contractVersion: got %d want %d", out.ContractVersion, BackupContractVersion)
	}
	if out.Kind != BackupBase {
		t.Errorf("kind: got %q want %q", out.Kind, BackupBase)
	}
	if out.Source.Database != "orders" || out.Source.EngineVersion != "16" {
		t.Errorf("source lost: %+v", out.Source)
	}
	if out.ReadPoint.Position != "0/1A2B3C8" || out.ReadPoint.At == "" {
		t.Errorf("read point lost: %+v", out.ReadPoint)
	}
	if out.Artifact.SHA256 != in.Artifact.SHA256 || out.Artifact.Bytes != in.Artifact.Bytes {
		t.Errorf("artifact lost: %+v", out.Artifact)
	}
	if len(out.Artifact.Parts) != 4 || out.Artifact.Parts[0].Path == "" {
		t.Errorf("parts lost: %+v", out.Artifact.Parts)
	}
	if out.Schema != in.Schema {
		t.Errorf("schema fingerprint lost: got %q want %q", out.Schema, in.Schema)
	}
	if out.Producer.Tool != "pg_dump 16.4" || len(out.Producer.Args) != 2 {
		t.Errorf("producer lost: %+v", out.Producer)
	}
	if len(out.Skipped) != 1 || out.Skipped[0].Reason != GapPermissionDenied {
		t.Errorf("skipped lost: %+v", out.Skipped)
	}
}

// Which route carried the bytes has to survive, because losing it makes a real failure
// undetectable: the provider's own cross-region copy stops being available, the agent
// quietly starts streaming the bytes itself, and cost and latency both jump with nothing
// to compare against. The field exists so ingest can flag the change.
func TestManifestRecordsWhichRouteCarriedTheBytes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		route TransferRoute
	}{
		{"the provider copied it server-side", RouteProviderCopy},
		{"our agent streamed it", RouteAgentStream},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := sampleManifest()
			in.Transfer = tc.route

			b, err := json.Marshal(in)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var out Manifest
			if err := json.Unmarshal(b, &out); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if out.Transfer != tc.route {
				t.Errorf("transfer route: got %q want %q", out.Transfer, tc.route)
			}
		})
	}
}

// A part's format and its role have to survive the wire: they are what a restorer refuses and
// selects on, and losing either puts it back to guessing which of four objects is the archive
// (AD-037).
func TestManifestPartsCarryTheirOwnFormatAndRole(t *testing.T) {
	for _, tc := range []struct {
		name   string
		path   string
		format string
		role   PartRole
	}{
		{"the archive, and the only part pg_restore can read", "database.sql", FormatPGDumpCustom, PartDatabase},
		{"the roles and their grants", "roles.sql", FormatPlainSQL, PartRoles},
		{"the DDL on its own", "schema.sql", FormatPlainSQL, PartSchema},
		{"the tablespaces, which name paths on the source host", "tablespaces.sql", FormatPlainSQL, PartTablespaces},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := sampleManifest()
			in.Artifact.Parts = []Part{{
				Path: tc.path, Bytes: 1, SHA256: "00", Format: tc.format, Role: tc.role,
			}}

			b, err := json.Marshal(in)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var out Manifest
			if err := json.Unmarshal(b, &out); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			got := out.Artifact.Parts[0]
			if got.Format != tc.format {
				t.Errorf("format: got %q want %q — a restorer cannot tell what this part is", got.Format, tc.format)
			}
			if got.Role != tc.role {
				t.Errorf("role: got %q want %q — a restorer cannot tell which part is the archive", got.Role, tc.role)
			}
		})
	}
}

// The two new Part fields and Manifest.Schema were added WITHOUT a version bump, and that is
// only honest if a producer that does not set them writes exactly the bytes it wrote before.
// An empty role encoded as "" would be a claim — and specifically a claim that this part is
// not the archive, made by a producer that never heard the question.
func TestManifestOmitsTheAdditiveFieldsWhenUnset(t *testing.T) {
	in := sampleManifest()
	in.Schema = ""
	in.Source.Account = ""
	in.Artifact.Parts = []Part{{Path: "base.0000", Bytes: 1, SHA256: "00"}}

	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := generic["schema"]; present {
		t.Errorf("an unset schema fingerprint must be omitted, not encoded: %s", b)
	}

	if _, present := generic["source"].(map[string]any)["account"]; present {
		t.Errorf("an unset account must be omitted, not encoded as \"\": %s", b)
	}

	part := generic["artifact"].(map[string]any)["parts"].([]any)[0].(map[string]any)
	for _, field := range []string{"format", "role"} {
		if _, present := part[field]; present {
			t.Errorf("an unset part %q must be omitted, not encoded as \"\": %s", field, b)
		}
	}

	// A base begins after nothing, so it writes no range start. sampleManifest IS a base, which
	// is why this belongs here rather than in a test of its own.
	if _, present := generic["readPoint"].(map[string]any)["from"]; present {
		t.Errorf("a base begins after nothing and must write no \"from\": %s", b)
	}
}

// The chain is what a restore actually reads, and losing a segment or the order of them on the
// wire is the same data loss as losing the file itself.
func TestChainJSONRoundTrip(t *testing.T) {
	in := sampleChain()

	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out Chain
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if len(out.Segments) != len(in.Segments) {
		t.Fatalf("segments lost: got %d want %d", len(out.Segments), len(in.Segments))
	}
	if out.Segments[0].Kind != BackupBase {
		t.Errorf("the chain no longer begins with a base: %q", out.Segments[0].Kind)
	}
	for i, seg := range out.Segments {
		want := in.Segments[i]
		if seg.ReadPoint.From != want.ReadPoint.From || seg.ReadPoint.Position != want.ReadPoint.Position {
			t.Errorf("segment %d lost its range: got %+v want %+v", i, seg.ReadPoint, want.ReadPoint)
		}
		if seg.Schema != want.Schema {
			t.Errorf("segment %d lost its schema fingerprint: got %q want %q", i, seg.Schema, want.Schema)
		}
	}
	if out.Confirmed != in.Confirmed {
		t.Errorf("the confirmed position was lost: got %q want %q — nothing would notice a file "+
			"missing from the end of the chain", out.Confirmed, in.Confirmed)
	}
}

// An absent Skipped list is a claim that everything asked for was backed up. It must
// therefore be absent only when that is true — never as an artefact of encoding. This
// pins the same discipline Estate applies to Gaps (contract.md §4).
func TestManifestSkippedIsAClaimNotADefault(t *testing.T) {
	in := sampleManifest()
	in.Skipped = nil

	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := generic["skipped"]; present {
		t.Errorf("an empty skipped list must be omitted, not encoded as null or []: %s", b)
	}
}

// sampleReBase is the object that says a chain stops here: the schema moved under a running
// change stream, so nothing more may be laid over that base (C5).
func sampleReBase() ReBase {
	return ReBase{
		ContractVersion: BackupContractVersion,
		At:              "2026-08-14T09:31:07Z",
		Reason:          ReBaseSchemaChanged,
		Recoverable:     "0/1A2B3C8",
		Detail: "the chain's base was captured against schema 9f2c4b1e7a03d568 and this cycle " +
			"against 4d1e88ba90c3f712",
	}
}

// A re-base marker with no recoverable position is the failure it exists to prevent, arrived at
// from the other side: whoever reads it learns the chain is dead and not how far it still
// restores, which is the only thing anyone can act on at 3am.
func TestReBaseCarriesTheLastRecoverablePosition(t *testing.T) {
	b, err := json.Marshal(sampleReBase())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out ReBase
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Recoverable != sampleReBase().Recoverable {
		t.Errorf("the last recoverable position was lost: got %q want %q",
			out.Recoverable, sampleReBase().Recoverable)
	}
	if out.Reason != ReBaseSchemaChanged {
		t.Errorf("the reason was lost: got %q", out.Reason)
	}
}

// EVERY REASON IS ITS OWN INCIDENT, AND ITS SPELLING IS THE WIRE. A migration the customer
// deployed and a replication slot nobody can reach any more need different answers from whoever
// reads this object, so the values are pinned here: renaming one is a control plane that stops
// recognising a dead chain, silently, which is the failure the whole re-base marker exists for.
func TestEachReBaseReasonKeepsItsOwnSpelling(t *testing.T) {
	for _, tc := range []struct {
		reason ReBaseReason
		want   string
	}{
		{ReBaseSchemaChanged, "schema-changed"},
		{ReBaseSlotLost, "slot-lost"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			if string(tc.reason) != tc.want {
				t.Errorf("reason = %q, want %q", tc.reason, tc.want)
			}
		})
	}
}

// The golden file pins this the way the manifest's does, and for a sharper reason: this object
// is read by whoever schedules the next base copy, and a renamed field there is a chain that
// stays dead while everything reports healthy.
func TestReBaseGolden(t *testing.T) {
	got, err := json.MarshalIndent(sampleReBase(), "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got = append(got, '\n')

	path := filepath.Join("testdata", "rebase.golden.json")
	if *update {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}

	want, err := os.ReadFile(path) //gosec:disable G304 -- a golden file under testdata/
	if err != nil {
		t.Fatalf("read golden (run: go test ./contract -update): %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("re-base wire format changed.\n got:\n%s\nwant:\n%s", got, want)
	}
}

// The golden file pins the wire format. A field renamed or dropped shows up here as a
// reviewable diff rather than as a silent break in whatever reads it next.
func TestManifestGolden(t *testing.T) {
	got, err := json.MarshalIndent(sampleManifest(), "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got = append(got, '\n')

	path := filepath.Join("testdata", "manifest.golden.json")
	if *update {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}

	want, err := os.ReadFile(path) //gosec:disable G304 -- a golden file under testdata/
	if err != nil {
		t.Fatalf("read golden (run: go test ./contract -update): %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("manifest wire format changed.\n got:\n%s\nwant:\n%s", got, want)
	}
}

// The chain has its own golden file for the reason the manifest has one: it is simultaneously
// the wire format, the DB shape and the API response, and a field renamed here is a restore
// that cannot tell whether it is holding every file.
func TestChainGolden(t *testing.T) {
	got, err := json.MarshalIndent(sampleChain(), "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got = append(got, '\n')

	path := filepath.Join("testdata", "chain.golden.json")
	if *update {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}

	want, err := os.ReadFile(path) //gosec:disable G304 -- a golden file under testdata/
	if err != nil {
		t.Fatalf("read golden (run: go test ./contract -update): %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("chain wire format changed.\n got:\n%s\nwant:\n%s", got, want)
	}
}

// A manifest read on its own has to be placeable in an account. ResourceID is opaque by
// construction — nothing may parse an account out of it — so without this field what the scanner
// OBSERVED about a database and what the agent DID to it sit in two piles nothing joins.
func TestManifestCarriesTheAccountItJoinsToAScan(t *testing.T) {
	b, err := json.Marshal(sampleManifest())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out Manifest
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// The same spelling ScanMeta.Account and Resource.Account use, because that is what it joins to.
	if out.Source.Account != "/subscriptions/sub-1" {
		t.Errorf("account: got %q want %q — this manifest cannot be joined to a scan",
			out.Source.Account, "/subscriptions/sub-1")
	}
}

// sampleReport is the ordinary cycle: a backup was stored, and the slot was read on the way past.
func sampleReport() CycleReport {
	m := sampleManifest()
	return CycleReport{
		ContractVersion: BackupContractVersion,
		Chain:           "install-7/pg1/orders",
		Account:         "/subscriptions/sub-1",
		At:              "2026-08-14T09:14:02Z",
		Manifest:        &m,
		Slot: &SlotReading{
			RetainedBytes:  16 * 1024 * 1024,
			DiskFreeBytes:  91268055040,
			DiskTotalBytes: 137438953472,
		},
	}
}

// sampleFailedReport is the cycle that errored and stored nothing: no manifest, because nothing
// was written, and no re-base, because the chain is not over — the agent simply could not reach
// the server this hour.
func sampleFailedReport() CycleReport {
	return CycleReport{
		ContractVersion: BackupContractVersion,
		Chain:           "install-7/pg1/orders",
		Account:         "/subscriptions/sub-1",
		At:              "2026-08-14T10:14:02Z",
		Failure: &CycleFailure{
			Detail: "connect to pg1.postgres.database.azure.com:5432: dial tcp: i/o timeout",
		},
	}
}

// Every outcome a cycle can have must survive the wire in the same envelope. Two shapes for one
// event is two ingest paths, and the second one is the one nobody keeps working.
func TestCycleReportCarriesEveryOutcome(t *testing.T) {
	rb := sampleReBase()
	for _, tc := range []struct {
		name string
		in   CycleReport
	}{
		{"a backup was stored", sampleReport()},
		{"the chain was declared over", CycleReport{
			ContractVersion: BackupContractVersion,
			Chain:           "install-7/pg1/orders",
			Account:         "/subscriptions/sub-1",
			At:              "2026-08-14T09:31:07Z",
			ReBase:          &rb,
		}},
		{"the cycle failed and stored nothing", sampleFailedReport()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, err := json.Marshal(tc.in)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			var out CycleReport
			if err := json.Unmarshal(b, &out); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}

			// The envelope carries what neither a manifest nor a re-base does. Losing either is a
			// report nobody can attribute to a chain or a customer.
			if out.Chain != tc.in.Chain || out.Account != tc.in.Account || out.At != tc.in.At {
				t.Errorf("the envelope lost its identity: got %+v want chain=%q account=%q at=%q",
					out, tc.in.Chain, tc.in.Account, tc.in.At)
			}
			if out.ContractVersion != BackupContractVersion {
				t.Errorf("contractVersion: got %d want %d", out.ContractVersion, BackupContractVersion)
			}
			switch {
			case tc.in.Manifest != nil:
				if out.Manifest == nil || out.Manifest.ReadPoint.Position != tc.in.Manifest.ReadPoint.Position {
					t.Errorf("the manifest was lost: %+v", out.Manifest)
				}
			case tc.in.ReBase != nil:
				if out.ReBase == nil || out.ReBase.Recoverable != tc.in.ReBase.Recoverable {
					t.Errorf("the re-base was lost: %+v", out.ReBase)
				}
			case tc.in.Failure != nil:
				if out.Failure == nil || out.Failure.Detail != tc.in.Failure.Detail {
					t.Errorf("the failure was lost: %+v — \"the last attempt failed\" is unrepresentable again",
						out.Failure)
				}
			}
		})
	}
}

// A cycle that errors writes neither a manifest nor a re-base, so before this field the engine
// could not tell an agent that had been failing every hour for a week from an agent that was
// never scheduled. The two must not encode the same.
func TestAFailedCycleIsDistinguishableFromNoCycleAtAll(t *testing.T) {
	b, err := json.Marshal(sampleFailedReport())
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	failure, ok := generic["failure"].(map[string]any)
	if !ok {
		t.Fatalf("a failed cycle encoded no failure: %s", b)
	}
	if failure["detail"] == "" {
		t.Errorf("the failure carries no sentence anybody can read: %s", b)
	}
	// It is a failure and NOT a dead chain. A re-base here would send whoever reads it to take a
	// new base copy over a chain that is perfectly alive.
	for _, absent := range []string{"manifest", "rebase"} {
		if _, present := generic[absent]; present {
			t.Errorf("a failed cycle must not encode %q: %s", absent, b)
		}
	}
}

// AD-021, on the payload it was written for: the agent brings facts, the engine judges. This test
// is the executable form of that line for the backup path, and the list is what a well-meaning
// change would add.
//
// achievedRpo is named explicitly because it is the one everybody reaches for. It is
// now − ReadPoint.At, it is meaningless without the customer's target, and the engine derives it
// from what is already here — an agent that computed it would be doing arithmetic on its own
// clock and calling the answer authoritative.
func TestCycleReportCarriesNoVerdict(t *testing.T) {
	forbidden := []string{
		"verdict", "decision", "healthy", "stale", "severity", "alert", "status", "ok",
		"achievedRpo", "rpo", "rpoSeconds", "lagSeconds", "pressure", "degraded",
	}

	for _, report := range []CycleReport{sampleReport(), sampleFailedReport()} {
		b, err := json.Marshal(report)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var generic map[string]any
		if err := json.Unmarshal(b, &generic); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}

		objects := []map[string]any{generic}
		for _, key := range []string{"manifest", "rebase", "failure", "slot"} {
			if obj, ok := generic[key].(map[string]any); ok {
				objects = append(objects, obj)
			}
		}
		if m, ok := generic["manifest"].(map[string]any); ok {
			for _, key := range []string{"source", "readPoint", "artifact", "producer"} {
				if obj, ok := m[key].(map[string]any); ok {
					objects = append(objects, obj)
				}
			}
		}

		for _, obj := range objects {
			for _, f := range forbidden {
				if _, found := obj[f]; found {
					t.Errorf("judgment field %q leaked into the cycle report — it belongs to the engine", f)
				}
			}
		}
	}
}

// The slot reading is the brake's NUMBERS and nothing else. Its Verdict and its Decision stay in
// the agent: whether retention is dangerous depends on the customer's disk, their tolerance and
// their history, and that is the engine's call. Pinning the exact key set is what stops a later
// change carrying the assessment across with the measurement.
func TestSlotReadingIsNumbersOnly(t *testing.T) {
	b, err := json.Marshal(SlotReading{RetainedBytes: 1, DiskFreeBytes: 2, DiskTotalBytes: 3})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	want := map[string]bool{"retainedBytes": true, "diskFreeBytes": true, "diskTotalBytes": true}
	for k := range generic {
		if !want[k] {
			t.Errorf("the slot reading grew a field the engine did not ask for: %q", k)
		}
	}
	for k := range want {
		if _, present := generic[k]; !present {
			t.Errorf("the slot reading lost %q — retention with no disk beside it is unactionable", k)
		}
	}
}

// Absent is "not measured", never zero. A slot reading of three zeroes would read as a full disk
// holding nothing, which is a fact, and the agent did not observe it.
func TestCycleReportOmitsWhatTheCycleDidNotProduce(t *testing.T) {
	in := sampleReport()
	in.Slot = nil

	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, absent := range []string{"slot", "rebase", "failure"} {
		if _, present := generic[absent]; present {
			t.Errorf("an unproduced %q must be omitted, not encoded as null: %s", absent, b)
		}
	}
}

// The golden file pins the envelope the way the manifest's pins the manifest. This is what the
// control plane parses, so a renamed field here is DR status that silently stops arriving.
func TestCycleReportGolden(t *testing.T) {
	for _, tc := range []struct {
		file string
		in   CycleReport
	}{
		{"cyclereport.golden.json", sampleReport()},
		{"cyclereport-failed.golden.json", sampleFailedReport()},
	} {
		t.Run(tc.file, func(t *testing.T) {
			got, err := json.MarshalIndent(tc.in, "", "  ")
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			got = append(got, '\n')

			path := filepath.Join("testdata", tc.file)
			if *update {
				if err := os.WriteFile(path, got, 0o600); err != nil {
					t.Fatalf("write golden: %v", err)
				}
				return
			}

			want, err := os.ReadFile(path) //gosec:disable G304 -- a golden file under testdata/
			if err != nil {
				t.Fatalf("read golden (run: go test ./contract -update): %v", err)
			}
			if string(got) != string(want) {
				t.Errorf("cycle report wire format changed.\n got:\n%s\nwant:\n%s", got, want)
			}
		})
	}
}
