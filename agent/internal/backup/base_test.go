package backup

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/manukyanv07/parity-scanner/chain"
	chainpg "github.com/manukyanv07/parity-scanner/chain/postgres"
	"github.com/manukyanv07/parity-scanner/contract"
)

// THE CLAIM THIS FILE EXISTS TO TEST: a chain's SEGMENT 0 is a real object somebody wrote, and it
// is never written over a base copy nobody checked. Until B5 there was no writer for it at all, so
// chain.Verify — which refuses a chain whose first segment is not a base — could not accept any
// chain this repo produced end to end.
//
// The part fakes are fake_test.go's and the store fake is run_test.go's memStore. Nothing here
// writes a second stream fake: `labelled` only dresses one of theirs with the path and the two
// labels an object the CLOUD wrote already carries.

// labelled is one of fake_test.go's parts, told where it already sits in the container and what it
// is. A base copy's parts are not alike — database.sql is a PGDMP archive and the other three are
// plain SQL (AD-033) — so every one of them says so for itself.
func labelled(part Part, path, format string, role contract.PartRole) Part {
	part.Path, part.Format, part.Role = path, format, role
	return part
}

// azureWrote is the four files Azure's restore-as-files leaves in our container, as a Source. The
// paths are Azure's own: it named them, and this manifest describes objects where they are rather
// than objects the agent produced.
func azureWrote(position Position, schema string, parts ...Part) *fakeSource {
	return &fakeSource{base: Batch{Position: position, Schema: schema, Parts: parts}}
}

// theFourFiles is a healthy base copy: the archive plus the three plain-SQL files beside it.
func theFourFiles() []Part {
	const rp = "parity-rp-1"
	return []Part{
		labelled(wholePart("database.sql", "PGDMP-and-then-the-data"), rp+"/database.sql",
			contract.FormatPGDumpCustom, contract.PartDatabase),
		labelled(wholePart("roles.sql", "CREATE ROLE orders_rw;"), rp+"/roles.sql",
			contract.FormatPlainSQL, contract.PartRoles),
		labelled(wholePart("schema.sql", "CREATE TABLE orders ();"), rp+"/schema.sql",
			contract.FormatPlainSQL, contract.PartSchema),
		labelled(wholePart("tablespaces.sql", "CREATE TABLESPACE fast;"), rp+"/tablespaces.sql",
			contract.FormatPlainSQL, contract.PartTablespaces),
	}
}

// THE DELIVERABLE. The base manifest describes exactly the four objects the cloud left, says it is
// a base, says the cloud moved the bytes, and carries the position the slot was at BEFORE the copy
// was asked for so the chain's first segment has a range at all.
func TestTheBaseManifestDescribesWhatTheCloudWroteAndGoesLast(t *testing.T) {
	store := newMemStore()
	c := testCycle(&Pipeline{Store: store})

	got, err := c.Base(context.Background(), azureWrote("0/1A2B000", "sha256:abc", theFourFiles()...))
	if err != nil {
		t.Fatalf("a clean base copy failed: %v", err)
	}

	// EXACTLY ONE OBJECT WAS WRITTEN, AND IT IS THE MANIFEST. Azure put the bytes in the container;
	// an agent that also stored them would have copied four files onto themselves and described a
	// copy it did not make.
	if len(landed(store)) != 1 {
		t.Fatalf("the base cycle wrote %v; it moves no bytes and writes only the manifest", landed(store))
	}
	found := manifestsIn(store)
	if len(found) != 1 {
		t.Fatalf("manifests in the store: %v, want exactly one", found)
	}
	if !strings.HasPrefix(found[0], "install-7/pg1/orders/") {
		t.Errorf("the base manifest landed at %q, outside the scope it was given", found[0])
	}

	stored, _ := object(store, found[0])
	var wire contract.Manifest
	if err := json.Unmarshal([]byte(stored), &wire); err != nil {
		t.Fatalf("the base manifest that was stored is not a manifest: %v", err)
	}

	if wire.ContractVersion != contract.BackupContractVersion || wire.Kind != contract.BackupBase {
		t.Errorf("manifest header %+v: chain.Verify requires segment 0 to be a %q",
			wire, contract.BackupBase)
	}
	if wire.Transfer != contract.RouteProviderCopy {
		t.Errorf("transfer %q: Azure wrote these bytes into our container and the agent did not "+
			"stream them", wire.Transfer)
	}
	// THE SLOT'S POSITION, TAKEN BEFORE THE COPY WAS REQUESTED (AD-033). The seam's promise is that
	// it is at or before the state of the bytes, and it is what the first change file resumes from.
	if wire.ReadPoint.Position != "0/1A2B000" {
		t.Errorf("readPoint.position is %q, want the slot's own 0/1A2B000", wire.ReadPoint.Position)
	}
	if wire.ReadPoint.From != "" {
		t.Errorf("readPoint.from is %q; a base begins after nothing", wire.ReadPoint.From)
	}
	if _, err := time.Parse(time.RFC3339, wire.ReadPoint.At); err != nil {
		t.Errorf("readPoint.at %q is not RFC3339: %v", wire.ReadPoint.At, err)
	}
	// C5 compares every later cycle against this. Without it there is nothing to compare to, and a
	// migration under the chain reaches a restore months later as a shape mismatch.
	if wire.Schema != "sha256:abc" {
		t.Errorf("schema %q: C5's DDL detection has nothing to hold a later cycle against", wire.Schema)
	}
	if wire.Source.Database != "orders" || wire.Producer.Agent != "azure/0.1.0" {
		t.Errorf("the cycle's own facts did not reach the base manifest: %+v", wire)
	}
	if wire.Artifact.SHA256 != "" {
		t.Errorf("artifact.sha256 is %q, and no such single stream was ever hashed", wire.Artifact.SHA256)
	}

	// EVERY HASH IS ONE THIS CODE COMPUTED BY READING THE OBJECT BACK, and every part carries the
	// two labels a restorer selects on — an unlabelled part is what AD-037 measured the cost of.
	want := map[contract.PartRole]struct{ path, format, body string }{
		contract.PartDatabase:    {"parity-rp-1/database.sql", contract.FormatPGDumpCustom, "PGDMP-and-then-the-data"},
		contract.PartRoles:       {"parity-rp-1/roles.sql", contract.FormatPlainSQL, "CREATE ROLE orders_rw;"},
		contract.PartSchema:      {"parity-rp-1/schema.sql", contract.FormatPlainSQL, "CREATE TABLE orders ();"},
		contract.PartTablespaces: {"parity-rp-1/tablespaces.sql", contract.FormatPlainSQL, "CREATE TABLESPACE fast;"},
	}
	if len(wire.Artifact.Parts) != len(want) {
		t.Fatalf("%d parts, want the four files a restore-as-files writes: %+v",
			len(wire.Artifact.Parts), wire.Artifact.Parts)
	}
	var total int64
	for _, part := range wire.Artifact.Parts {
		expected, known := want[part.Role]
		if !known {
			t.Fatalf("the manifest carries a part labelled %q, which is none of the four", part.Role)
		}
		if part.Path != expected.path {
			t.Errorf("%s sits at %q, want the path Azure wrote it to, %q", part.Role, part.Path, expected.path)
		}
		if part.Format != expected.format {
			t.Errorf("%s is labelled %q, want %q", part.Role, part.Format, expected.format)
		}
		if part.SHA256 != digest(expected.body) {
			t.Errorf("%s: the manifest says %q and the object hashes to %q",
				part.Role, part.SHA256, digest(expected.body))
		}
		if part.Bytes != int64(len(expected.body)) {
			t.Errorf("%s: the manifest says %d bytes and the object is %d",
				part.Role, part.Bytes, len(expected.body))
		}
		total += part.Bytes
	}
	if wire.Artifact.Bytes != total {
		t.Errorf("artifact.bytes is %d and its parts total %d", wire.Artifact.Bytes, total)
	}

	// What Base returns is what is in the store, so a caller reads the chain's base schema and
	// position from the same object a restorer will.
	if got.Schema != wire.Schema || got.ReadPoint.Position != wire.ReadPoint.Position {
		t.Errorf("Base returned %+v and the store holds %+v", got, wire)
	}
}

// KILLED WHILE THE COPY WAS STILL BEING CHECKED. Three of the four objects checked out and the
// fourth died, which is the shape B4 already refuses for a change cycle: a manifest here would be
// believed, and it would vouch for four objects nobody finished reading.
func TestABaseCopyKilledPartWayThroughLeavesNoManifest(t *testing.T) {
	store := newMemStore()
	c := testCycle(&Pipeline{Store: store})

	parts := theFourFiles()
	parts[3] = labelled(truncatedPart("tablespaces.sql", "CREATE TABLE", errStreamDied),
		"parity-rp-1/tablespaces.sql", contract.FormatPlainSQL, contract.PartTablespaces)

	_, err := c.Base(context.Background(), azureWrote("0/1A2B000", "sha256:abc", parts...))
	if err == nil {
		t.Fatal("a base copy that could not be read through reported success")
	}
	if !errors.Is(err, errStreamDied) {
		t.Errorf("error %v does not carry %v", err, errStreamDied)
	}
	if tried := manifestsAttemptedIn(store); len(tried) != 0 {
		t.Fatalf("a base manifest at %v was offered for a copy that was never checked through", tried)
	}
	if got := landed(store); len(got) != 0 {
		t.Fatalf("the base cycle wrote %v after failing", got)
	}
}

// The other two ways the check ends without vouching for the copy. The middle row is the one that
// matters most: every byte was read and the verdict arrived at Close, so the artifact looks whole
// from the container's side and a manifest is easiest to write and worst to have.
func TestABaseCopyThatDoesNotCheckOutGetsNoManifest(t *testing.T) {
	tests := []struct {
		name    string
		part    Part
		wantErr error
	}{
		{
			name:    "nothing would open, so nothing was ever read",
			part:    unopenablePart("database.sql", errRefused),
			wantErr: errRefused,
		},
		{
			// THE COMPLETE UPLOAD THAT DOES NOT CHECK OUT. Azure wrote every byte, the read side saw
			// a clean EOF, and the verdict came at Close.
			name:    "every byte was read back and the check at close refused it",
			part:    flushFailsPart("database.sql", "PGDMP-and-then-the-data", errFlushFailed),
			wantErr: errFlushFailed,
		},
		{
			name:    "the read back died part way through the archive",
			part:    truncatedPart("database.sql", "PGDMP", errStreamDied),
			wantErr: errStreamDied,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := newMemStore()
			c := testCycle(&Pipeline{Store: store})

			part := labelled(tc.part, "parity-rp-1/database.sql",
				contract.FormatPGDumpCustom, contract.PartDatabase)

			_, err := c.Base(context.Background(), azureWrote("0/1A2B000", "sha256:abc", part))
			if err == nil {
				t.Fatal("a base copy that could not be checked reported success")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("error %v does not carry %v", err, tc.wantErr)
			}
			if tried := manifestsAttemptedIn(store); len(tried) != 0 {
				t.Fatalf("a base manifest at %v claims a copy that failed with %v", tried, err)
			}
		})
	}
}

// AN UNLABELLED PART IS REFUSED, NOT DEFAULTED. The measured cost of guessing was a restore
// reporting success with the roles, the grants and the tablespaces silently missing (AD-037), so
// "nobody said" and "this is the archive" must not be able to reach a manifest as the same thing.
//
// Every row here is knowable from the batch alone, which is why it is refused BEFORE the copy is
// read: none of these facts gets cheaper to discover after a hundred gigabytes have gone past.
func TestABaseCopyIsRefusedOnWhatTheSourceSaidBeforeItIsRead(t *testing.T) {
	const prefix = "install-7/base-1"
	whole := func() Batch {
		return Batch{Position: "0/1A2B000", Schema: "sha256:abc", Parts: []Part{
			labelled(wholePart("database.sql", "PGDMP"), "parity-rp-1/database.sql",
				contract.FormatPGDumpCustom, contract.PartDatabase),
		}}
	}

	tests := []struct {
		name string
		bend func(*Batch)
		says string
	}{
		{
			name: "no parts at all, which is a manifest over nothing",
			bend: func(b *Batch) { b.Parts = nil },
			says: "no objects",
		},
		{
			// THE RULE THIS TICKET TURNS ON. A part nobody labelled is one a restorer refuses, and
			// it must be refused HERE — before a manifest carries it — rather than at a restore.
			name: "a part nobody said the role of",
			bend: func(b *Batch) { b.Parts[0].Role = "" },
			says: "nobody labelled",
		},
		{
			name: "a part nobody said the format of",
			bend: func(b *Batch) { b.Parts[0].Format = "" },
			says: "nobody labelled",
		},
		{
			// The manifest is the only record of where these objects are: the agent did not choose
			// their paths, so a part that does not carry one is unreachable forever. It is also
			// what a batch meant for the pipeline looks like when it arrives here by mistake.
			name: "a part that does not say where it is",
			bend: func(b *Batch) { b.Parts[0].Path = "" },
			says: "where it is",
		},
		{
			name: "a part with nothing to read it through",
			bend: func(b *Batch) { b.Parts[0].Open = nil },
			says: "no Open",
		},
		{
			name: "no position, so the change stream could not resume from the base",
			bend: func(b *Batch) { b.Position = "" },
			says: "resume",
		},
		{
			// A base begins after nothing (contract.ReadPoint). One that claims a range start is
			// claiming to continue a chain that does not exist.
			name: "a base that claims to begin somewhere",
			bend: func(b *Batch) { b.From = "0/1" },
			says: "begins after nothing",
		},
		{
			name: "two objects at one path, where the second overwrote the first",
			bend: func(b *Batch) { b.Parts = append(b.Parts, b.Parts[0]) },
			says: "twice",
		},
		{
			name: "an object sitting where the manifest goes",
			bend: func(b *Batch) { b.Parts[0].Path = prefix + "/" + manifestName },
			says: manifestName,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			batch := whole()
			tc.bend(&batch)

			err := checkCopy(batch, prefix)
			if err == nil {
				t.Fatal("the check vouched for it")
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("error %q does not say %q", err, tc.says)
			}
		})
	}

	if err := checkCopy(whole(), prefix); err != nil {
		t.Errorf("the check refused a base copy that is fine: %v", err)
	}
}

// The two facts only a read-back can establish. Neither is reachable today — readBackOne computes
// the hash and counts the bytes itself — and that is the point: the guarantee is "never", not
// "never so far", so the day something else builds these parts it fails loudly.
func TestTheBaseAuditRefusesWhatItCannotVouchFor(t *testing.T) {
	whole := func() []contract.Part {
		return []contract.Part{{
			Path: "parity-rp-1/database.sql", Bytes: 5, SHA256: digest("PGDMP"),
			Format: contract.FormatPGDumpCustom, Role: contract.PartDatabase,
		}}
	}

	tests := []struct {
		name string
		bend func([]contract.Part)
		says string
	}{
		{
			name: "a hash that is not one this code computed",
			bend: func(p []contract.Part) { p[0].SHA256 = "deadbeef" },
			says: "not a sha256",
		},
		{
			name: "a hash in a second spelling, which compares unequal to the one a restorer computes",
			bend: func(p []contract.Part) { p[0].SHA256 = strings.ToUpper(digest("PGDMP")) },
			says: "not a sha256",
		},
		{
			name: "a zero-byte object, which no restore can use",
			bend: func(p []contract.Part) { p[0].Bytes = 0 },
			says: "no bytes",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			parts := whole()
			tc.bend(parts)

			err := auditBase(parts)
			if err == nil {
				t.Fatal("the audit vouched for it")
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("error %q does not say %q", err, tc.says)
			}
		})
	}

	if err := auditBase(whole()); err != nil {
		t.Errorf("the audit refused a base copy that is fine: %v", err)
	}
}

// A base copy the source could not produce is not a backup and must not read as one. It is the
// first caller of Source.Base in the repo, so this path had never been exercised.
func TestABaseCopyTheSourceCouldNotProduceWritesNothing(t *testing.T) {
	store := newMemStore()
	c := testCycle(&Pipeline{Store: store})

	_, err := c.Base(context.Background(), &fakeSource{baseFails: errRefused})
	if !errors.Is(err, errRefused) {
		t.Fatalf("a source that could not take a base copy gave %v", err)
	}
	if got := landed(store); len(got) != 0 {
		t.Errorf("it wrote %v for a copy that never happened", got)
	}
}

// A store that refuses the base manifest FAILS the cycle. It does not hand back a manifest nobody
// can find: a caller that took the chain's base position from one would start a change stream over
// a base no restore will ever locate.
func TestAStoreThatRefusesTheBaseManifestFailsTheCycle(t *testing.T) {
	errRefusedManifest := errors.New("HTTP 403 from the container: AuthorizationPermissionMismatch")
	store := newMemStore()
	refusing := &flakyManifest{inner: store, err: errRefusedManifest, refusals: 99}
	c := testCycle(&Pipeline{Store: refusing})

	_, err := c.Base(context.Background(), azureWrote("0/1A2B000", "sha256:abc", theFourFiles()...))
	if !errors.Is(err, errRefusedManifest) {
		t.Fatalf("a refused base manifest gave %v", err)
	}
	if refusing.tries != defaultAttempts {
		t.Errorf("the base manifest was offered %d times, want %d", refusing.tries, defaultAttempts)
	}
	if found := manifestsIn(store); len(found) != 0 {
		t.Fatalf("the base manifest at %v was refused and is somehow present", found)
	}
}

// The audit is only worth anything if Base consults it, and an unlabelled part is a shape a real
// source can produce: contract.Part treats an empty Role as "nobody said", and a producer that
// never heard the question writes exactly that.
func TestABaseCopyWithAnUnlabelledPartWritesNoManifest(t *testing.T) {
	store := newMemStore()
	c := testCycle(&Pipeline{Store: store})

	parts := theFourFiles()
	parts[1].Role = "" // roles.sql, unlabelled

	_, err := c.Base(context.Background(), azureWrote("0/1A2B000", "sha256:abc", parts...))
	if err == nil {
		t.Fatal("a base copy carrying an unlabelled part was written up as a backup")
	}
	if !strings.Contains(err.Error(), "nobody labelled") {
		t.Errorf("error %q does not say why the copy could not be claimed", err)
	}
	if tried := manifestsAttemptedIn(store); len(tried) != 0 {
		t.Fatalf("a base manifest at %v was offered for a copy the audit refused", tried)
	}
}

// A cycle that could not describe a base copy refuses before it reads a byte of one, the same way
// a change cycle refuses before it stores one.
func TestABaseCycleThatCouldNotDescribeItselfRefusesFirst(t *testing.T) {
	store := newMemStore()
	c := testCycle(&Pipeline{Store: store})
	c.Subject.EngineVersion = ""

	if _, err := c.Base(context.Background(), azureWrote("0/1A2B000", "sha256:abc", theFourFiles()...)); err == nil {
		t.Fatal("a cycle that cannot describe itself took a base copy anyway")
	}
	if got := landed(store); len(got) != 0 {
		t.Errorf("it wrote %v before finding out", got)
	}
}

// THE POINT OF THE WHOLE TICKET: a chain whose segment 0 is a base manifest THIS CODE WROTE, with
// change segments over it, verifies end to end — and the same chain with a file missing out of the
// middle of it still fails loudly.
func TestAChainOfARealBaseAndItsChangesVerifies(t *testing.T) {
	store := newMemStore()
	ctx := context.Background()

	// One installation, two phases. The base cycle's artifact is principally a PGDMP archive; the
	// change cycles' artifacts are decoded change files, and their BaseSchema is what the base established.
	base := testCycle(&Pipeline{Store: store})
	base.BaseSchema = ""
	base.Format = contract.FormatPGDumpCustom

	segment0, err := base.Base(ctx, azureWrote("0/1000", "sha256:abc", theFourFiles()...))
	if err != nil {
		t.Fatalf("the base copy failed: %v", err)
	}

	changes := testCycle(&Pipeline{Store: store})
	changes.Format = contract.FormatChangeJSONL
	changes.BaseSchema = segment0.Schema

	first, err := changes.Run(ctx, changing("0/2000", "sha256:abc",
		labelled(wholePart("changes.0001", "one"), "", contract.FormatChangeJSONL, contract.PartChanges)),
		Position(segment0.ReadPoint.Position))
	if err != nil {
		t.Fatalf("the first change cycle failed: %v", err)
	}
	second, err := changes.Run(ctx, changing("0/3000", "sha256:abc",
		labelled(wholePart("changes.0002", "two"), "", contract.FormatChangeJSONL, contract.PartChanges)),
		Position(first.ReadPoint.Position))
	if err != nil {
		t.Fatalf("the second change cycle failed: %v", err)
	}

	whole := contract.Chain{
		ContractVersion: contract.BackupContractVersion,
		Segments:        []contract.Manifest{segment0, first, second},
		Confirmed:       second.ReadPoint.Position,
	}
	checked, err := chain.Verify(whole, chainpg.WAL{})
	if err != nil {
		t.Fatalf("a chain of a real base and its changes did not verify: %v", err)
	}
	if checked != chain.CheckedWhole {
		t.Errorf("the chain was checked %q, want %q", checked, chain.CheckedWhole)
	}

	// AND IT STILL FAILS LOUDLY ON A FILE MISSING OUT OF THE MIDDLE. Everything left is internally
	// perfect — the objects hash, the manifests parse, both segments are correct about themselves —
	// and what happened between 0/1000 and 0/2000 is carried by nothing.
	holed := whole
	holed.Segments = []contract.Manifest{segment0, second}
	if _, err := chain.Verify(holed, chainpg.WAL{}); err == nil {
		t.Fatal("a chain with its middle file missing verified")
	} else if !strings.Contains(err.Error(), "0/1000") || !strings.Contains(err.Error(), "0/2000") {
		t.Errorf("the error %q does not name the two ends of the hole", err)
	}
}
