package contract

// The backup manifest — everything one backup cycle produced, and nothing else.
//
// WHY IT LIVES IN THIS PACKAGE. Estate is what the scanner OBSERVED; a manifest is what
// the backup agent DID. AD-021 separates those two ideas deliberately, so a sibling
// package was the obvious alternative. It is the wrong call: both are wire formats
// shared between an agent in a customer's cloud and our control plane, both are
// simultaneously the wire shape, the DB shape and the API response, and both need the
// same versioning discipline. Splitting them would duplicate that discipline and invite
// the two halves to drift. They share a package and keep separate version constants,
// because they version independently (E6.3).
//
// WHAT A MANIFEST MEANS. It is the signal that a backup is real. It is written LAST, and
// only after the artifact it describes has been written whole and checked. A manifest
// beside an incomplete artifact is worse than no backup at all, because it will be
// trusted (E6.10).

// BackupContractVersion is the wire-format version of a manifest. It moves independently
// of ContractVersion: the scanner's payload and the agent's payload are produced by
// different code on different schedules, and tying them together would force a version
// bump on one every time the other changed.
const BackupContractVersion = 1

// BackupKind distinguishes the one full copy from the changes laid on top of it.
//
// Both exist from the start because the seam is Base and Since
// (docs/specs/backup-shape.md §4). A manifest that could only describe a base would have
// to change shape the day the change stream lands, and that is a wire break.
type BackupKind string

const (
	// BackupBase is the one full copy a chain is built on. It happens once, and again
	// only when something forces a re-base — a schema change or a dropped slot.
	BackupBase BackupKind = "base"

	// BackupChange is one batch of changes since a previous position.
	BackupChange BackupKind = "change"
)

// TransferRoute records who actually moved the bytes.
//
// It is not bookkeeping. When a provider's own cross-region copy stops being available —
// a broken snapshot chain, a schema change, a reset feed — the agent will quietly fall
// back to streaming the bytes itself, and cost and latency both jump. Nothing else in
// the system can see that happen, so it is recorded on every cycle and compared on
// ingest.
type TransferRoute string

const (
	// RouteProviderCopy means the cloud moved it server-side and our code was never in
	// the byte path. Preferred wherever it exists.
	RouteProviderCopy TransferRoute = "provider-copy"

	// RouteAgentStream means our agent read the bytes and wrote them. The fallback,
	// and always the more expensive one.
	RouteAgentStream TransferRoute = "agent-stream"
)

// Manifest is one backup cycle: what was copied, from where, as of when, into what, by
// whom, and what was deliberately left out.
type Manifest struct {
	ContractVersion int        `json:"contractVersion"`
	Kind            BackupKind `json:"kind"`

	Source    BackupSource `json:"source"`
	ReadPoint ReadPoint    `json:"readPoint"`

	// Schema is backup.Batch.Schema on the wire: the source's fingerprint at capture time,
	// empty where the idea is meaningless — a disk snapshot has no schema — and validated
	// by nothing, since a required field here would force every future source to invent a
	// value it does not have.
	//
	// IT EXISTS SO A LATER CYCLE CAN BE COMPARED AGAINST THE BASE'S. A schema change forces
	// a re-base, and the agent that notices has a fresh fingerprint in hand and nothing to
	// hold it against unless the base wrote its own down.
	//
	// THE WIRE FORM IS ONE DIGEST PER FINGERPRINTING ALGORITHM the agent that wrote it knew:
	// space-separated, oldest first, each `[v<n>:]<hash>:<hex>`. The oldest carries NO TAG and
	// never will — every fingerprint already written into a manifest is a bare `sha256:…`, and
	// tagging it retrospectively would move all of them, which is the exact churn the versioning
	// exists to prevent. So the untagged spelling is permanently the first algorithm's name.
	//
	// TWO OF THESE, FROM TWO AGENTS, ARE COMPARED BY chain.SchemaMoved AND BY NOTHING ELSE.
	// Widening what a fingerprint reads — the LOGGED/UNLOGGED fix did, E9.7 will again — moves
	// every digest there is, so a string comparison would read a release of OURS as every
	// customer's schema moving and re-base the whole fleet at once. Two ends are comparable
	// where they share an algorithm, which is the only question that function asks.
	//
	// (An agent comparing two fingerprints IT took, in one window, over one algorithm list may
	// of course use !=; that is postgres.baseCopyOnce's H0/H1 and it is strictly stricter. The
	// rule above is about values that could have come from two different agent versions.)
	Schema string `json:"schema,omitempty"`

	Artifact Artifact      `json:"artifact"`
	Producer Producer      `json:"producer"`
	Transfer TransferRoute `json:"transfer"`

	// Skipped is everything asked for and not backed up, and why. An absent list is a
	// claim that nothing was skipped; it is not a default — the same rule Estate applies
	// to Gaps (contract.md §4).
	//
	// It reuses Gap rather than inventing a parallel vocabulary: a database we could not
	// read for lack of permission is the same kind of fact whether a scanner or an agent
	// found it, and one vocabulary is one thing for the engine to understand.
	Skipped []Gap `json:"skipped,omitempty"`
}

// BackupSource identifies what was copied, in the contract's vocabulary.
type BackupSource struct {
	Provider Provider `json:"provider"`

	// ResourceID is the server, in the cloud's own spelling. OPAQUE, exactly as
	// Resource.ID is: compare it, index it, join on it, never parse it.
	ResourceID string `json:"resourceId"`

	// Account is the isolation boundary the server lives in — Azure subscription, AWS account,
	// GCP project — spelled exactly as Resource.Account is, BECAUSE THAT IS WHAT IT JOINS TO.
	//
	// Without it a manifest cannot be put beside the scan of the same estate: ResourceID alone is
	// opaque by construction, so nothing may parse an account out of it, and the two halves of
	// what we know about one database — what the scanner OBSERVED and what the agent DID — stay
	// in separate piles. Additive: a producer that does not set it writes the bytes it wrote
	// before.
	Account string `json:"account,omitempty"`

	// Database is the unit a logical backup actually covers. A server hosts many, and
	// backing up "the server" is a category error that loses half the data.
	Database string `json:"database,omitempty"`

	Engine string `json:"engine"` // "postgres", "mysql"

	// EngineVersion is the major version, and it is load-bearing at restore rather than
	// at backup: a dump taken from 16 fails against a 14 target at the very end of a
	// long restore, in the middle of an incident. Recording it lets the target be
	// checked before anything starts.
	EngineVersion string `json:"engineVersion"`
}

// ReadPoint is the instant this backup is consistent as of.
//
// It exists so that resources which must be restored together can be checked for
// agreement. Without it there is nothing to compare a database against a disk snapshot
// with, and "everything backed up fine, they just disagree about when" is a corruption
// that passes every green check.
type ReadPoint struct {
	At string `json:"at"` // RFC3339, for humans and for ordering across sources

	// Position is the source's own marker: a WAL LSN for Postgres, file and offset for
	// MySQL, a snapshot id for a disk, a cursor for a change feed. OPAQUE — store it,
	// hand it back, compare it for equality. Only the source that issued it can order
	// two of them, because only Postgres knows 0/1A2B3C8 follows 0/1A2B000.
	Position string `json:"position"`

	// From is where this backup BEGINS and Position is where it REACHES. Together they are the
	// range it covers, and THE RANGE IS WHAT MAKES A HOLE BETWEEN TWO BACKUPS VISIBLE: with one
	// end alone, two consecutive files can miss everything in between while each one is
	// perfectly correct about itself. Opaque exactly as Position is.
	//
	// IT IS THE SOURCE'S ACCOUNT OF WHAT IT DELIVERED, NEVER THE POSITION WE ASKED FROM, and the
	// difference is the point. An agent that lost its replication slot and made a new one
	// resumes LATER than it was asked to; a From copied from the request would claim the file
	// begins where the previous one ended, and the chain would verify with a hole in the middle
	// of it — the exact failure C4 exists to catch.
	//
	// Empty on a base, which begins after nothing.
	From string `json:"from,omitempty"`
}

// Chain is a base and every change file laid over it, in order. It is what a restore reads, and
// it is the only place a hole BETWEEN two backups can be seen.
//
// ONE MANIFEST CANNOT SHOW A GAP. A manifest describes what one cycle stored and is correct
// about it; the failure that loses a customer's data lives between two cycles, where what
// happened after one file's end never reached the next file's start. Every object hashes, every
// manifest parses, and the rows are found missing at restore. Nothing downstream re-derives
// this, so it is checked here or nowhere.
//
// SEGMENTS ARE WHOLE MANIFESTS RATHER THAN A SUMMARY OF THEM. A lighter per-segment record would
// repeat the range, the schema fingerprint and the parts, and the copy is what a verifier would
// read — so a chain could disagree with the manifests it is made of and still pass.
type Chain struct {
	ContractVersion int `json:"contractVersion"`

	// Segments are the base at [0] and the change files after it, IN THE ORDER THEY REPLAY.
	// That order is a claim made by whoever assembled the chain, and nothing re-sorts it:
	// sorting means ordering two positions, which only the source can do (backup-shape.md §5).
	// A verifier therefore checks the order it was given rather than repairing it.
	Segments []Manifest `json:"segments"`

	// Confirmed is the last position the source was told is durable, and it is what makes a file
	// missing from the END of the chain detectable. Checked against the last segment it is the
	// one thing that is always true — the chain reaches as far as the chain reaches — so without
	// an independent record of how far it SHOULD reach, files lost off the end are invisible.
	Confirmed string `json:"confirmed"`
}

// ReBaseReason is why a chain stopped. Small, and it grows one value per thing that can kill a
// chain — because whoever reads this has to act differently: a schema change means the customer
// deployed a migration, a lost slot means WAL we can no longer reach.
type ReBaseReason string

const (
	// ReBaseSchemaChanged is the silent one, and it is why this object exists at all. LOGICAL
	// DECODING DOES NOT CARRY DDL: an ordinary ALTER TABLE reaches a change file as nothing
	// whatsoever — the transaction that ran it decodes as an empty BEGIN/COMMIT pair — so every
	// change captured afterwards describes columns that are no longer the ones it names, and
	// nothing in the stream, the manifest or the chain says so. It is found at restore, months
	// later, by a customer.
	ReBaseSchemaChanged ReBaseReason = "schema-changed"

	// ReBaseSlotLost is the replication slot the change stream reads through no longer being on
	// the server. THREE THINGS DO IT AND ALL THREE ARE SILENT: an HA failover on PostgreSQL 16 or
	// below, where the slot is simply not carried to the standby because `failover` does not exist
	// before 17 (AD-034); the provider removing it to stop WAL filling the primary's disk; and our
	// own safety brake dropping it for the same reason (C6).
	//
	// WHAT MAKES IT WORTH ITS OWN VALUE rather than a note on the one above: an agent that merely
	// reconnects gets a NEW slot starting from a LATER position, and every file it writes after
	// that sits on the far side of a hole in a chain that verifies, hashes and reads as healthy.
	// A migration is the customer's doing and a lost slot is WAL nobody can reach any more, so the
	// two send whoever reads this to two different places.
	ReBaseSlotLost ReBaseReason = "slot-lost"
)

// ReBase is the agent's record that A CHAIN STOPS HERE AND A NEW BASE COPY IS OWED.
//
// It is written into the cycle's own prefix, in the place that cycle's manifest would have gone,
// and the two are alternatives: a prefix holds a manifest (the chain continues) or a ReBase (the
// chain does not), never both. That is what makes it un-missable to whoever assembles the chain
// by listing the container, and it is why it needs no clearing — the next base copy writes under
// a new prefix and this object stays true about the chain it ended.
//
// IT IS NOT AN ERROR REPORT. The cycle that writes it also returns a sentinel to whoever is
// scheduling, so a live agent re-bases immediately; this object is for the agent that was
// restarted, and for the control plane, neither of which saw the error.
type ReBase struct {
	ContractVersion int    `json:"contractVersion"`
	At              string `json:"at"` // RFC3339

	Reason ReBaseReason `json:"reason"`

	// Recoverable is the last position this chain can still be restored to — the point the
	// cycle before this one reached. IT IS THE ONE FIELD ANYBODY ACTS ON: a chain that is dead
	// and a chain that is dead as of an hour ago are different incidents, and "healthy" is what
	// a marker without it reads as.
	Recoverable string `json:"recoverable"`

	// Detail is the sentence a human reads at 3am — which fingerprints differed, which slot
	// went. Never parsed.
	Detail string `json:"detail,omitempty"`
}

// The formats an artifact or one of its parts is written in, spelled once because two
// packages compare them for exact equality. A restorer refuses a part whose format is not
// the one it can load, so a second spelling of the same format does not read as a variant —
// it reads as a broken artifact.
const (
	// FormatPGDumpCustom is a PGDMP archive: what pg_dump -Fc writes and the only thing
	// pg_restore can read.
	FormatPGDumpCustom = "pg_dump/custom"

	// FormatPlainSQL is a file of statements, which psql reads and pg_restore does not.
	FormatPlainSQL = "sql/plain"

	// A change file is FormatChangeJSONL, spelled in change.go beside the record it is made of.
	// There is deliberately no format here for the raw logical-replication stream: a pgoutput
	// payload names its table by a relation id whose meaning lives in the session that produced
	// it, so a file of them is unreadable at restore by construction. The agent decodes on the
	// way past (agent/internal/backup/postgres/change.go) and stores records, and a constant
	// naming a format nothing can read back is a constant somebody eventually labels a part with.
)

// PartRole is what one object in an artifact is FOR.
//
// Small on purpose, and it names what Azure's restore-as-files actually writes (AD-033). An
// empty role is NOT PartDatabase: "nobody said" and "this is the archive" must not be the
// same value, because the reason the field exists is so a restorer can refuse to guess.
type PartRole string

const (
	// PartDatabase is the one object that carries the data — database.sql, in
	// FormatPGDumpCustom. The only part pg_restore can be fed.
	PartDatabase PartRole = "database"

	// PartRoles is roles.sql: the roles and their grants, plain SQL. It is applied with
	// psql, and BEFORE the database part, because the objects that part creates refer to
	// the roles by name.
	PartRoles PartRole = "roles"

	// PartSchema is schema.sql: the DDL alone, plain SQL. Redundant with what the database
	// part already carries, and kept because it is what answers "what shape was this"
	// without a server to restore into.
	PartSchema PartRole = "schema"

	// PartTablespaces is tablespaces.sql: CREATE TABLESPACE, plain SQL. It names paths on
	// the source host, so it restores nowhere without being edited first.
	PartTablespaces PartRole = "tablespaces"

	// PartChanges is one file of decoded changes, in FormatChangeJSONL. It is what a change
	// segment of a chain is made of, and it is replayed OVER a restored base rather than
	// restored — a different verb, which is why it is a different role.
	PartChanges PartRole = "changes"
)

// Artifact is what landed in the store.
type Artifact struct {
	// Format names how to read it back — "pg_dump/custom", not "binary". A restore
	// months later must not have to guess.
	//
	// It describes the artifact AS A WHOLE. Where the parts are not alike — an Azure base
	// copy is one PGDMP archive beside three plain-SQL files (AD-033) — this says what the
	// artifact principally is, and Part.Format is what a restorer actually reads.
	Format string `json:"format"`

	// Bytes is the total across every part, so it answers "how much did this cycle store"
	// and nothing finer. Where an artifact has several parts, only Part.Bytes says how big
	// any one object is.
	Bytes int64 `json:"bytes"`

	// SHA256 is computed from the stream as it was uploaded, never by re-reading the
	// object afterwards. Re-reading proves the object is intact; it does not prove the
	// object matches what the database gave us.
	//
	// IT IS THE SINGLE-STREAM CASE ONLY. Where the cloud moved the bytes into several
	// objects there is no such stream to hash — a base copy from Azure is four files we
	// read back rather than one we wrote (AD-033) — and it is Part.SHA256, per object, that
	// vouches for anything. A restorer checks the part it is loading and never this.
	SHA256 string `json:"sha256"`

	// Parts is every object written, in order. Large copies are chunked and a cloud-side
	// copy arrives already split, and an object missing from this list is one nobody will
	// notice is missing.
	Parts []Part `json:"parts"`
}

// Part is one object in the store.
//
// FORMAT AND ROLE ARE PER-PART BECAUSE THE PARTS ARE NOT ALWAYS ALIKE. Azure's
// restore-as-files writes database.sql in PGDMP format beside roles.sql, schema.sql and
// tablespaces.sql in plain SQL (AD-033); with only Artifact.Format, nothing on the wire says
// which one is the archive, and the measured cost of that was a restore reporting success
// with the roles, grants and tablespaces silently missing (AD-037).
type Part struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`

	// Format is how to read back THIS object, in Artifact.Format's vocabulary.
	//
	// EMPTY IS NOT INHERITANCE. It says nobody labelled this object, and a restorer refuses
	// it rather than assuming Artifact.Format applies — the same rule Role follows. That is
	// still additive: a producer that never heard the question writes exactly the bytes it
	// wrote before, and the manifest it writes parses; this repo simply declines to restore
	// from it until E6.9 wires the fields through.
	Format string `json:"format,omitempty"`

	// Role is what this object is for, and it is what a restorer will SELECT on. Nothing
	// reads it yet: the psql step that applies roles.sql before the archive does not exist,
	// and E6.9 owns it. Empty where an artifact has one part and the question never arises.
	Role PartRole `json:"role,omitempty"`
}

// SlotReading is what the replication slot was holding when the cycle ended. NUMBERS ONLY.
//
// The agent's safety brake already measures all three every tick (agent/internal/backup/postgres,
// brake.Reading) and today they die in that process. They are the difference between "a chain
// stopped" and "a chain stopped because WAL was about to fill the customer's primary", and nobody
// outside the agent can see either number.
//
// WHAT IS DELIBERATELY NOT HERE is the brake's own Verdict and Decision. Whether retention is
// dangerous depends on the customer's disk, their tolerance and their history — it is a judgment,
// and AD-021 puts every judgment on the engine's side of the wire. The agent brings the facts it
// alone can see; the engine decides what they mean.
type SlotReading struct {
	// RetainedBytes is the WAL the server is holding because of our slot: the distance from the
	// slot's restart_lsn to the server's current write position. Zero is a slot holding nothing,
	// which is the healthy resting state and not an absence.
	RetainedBytes int64 `json:"retainedBytes"`

	// DiskFreeBytes and DiskTotalBytes are the primary's disk. Both zero means the agent could
	// not read it — a permission the customer did not grant, or a managed service that does not
	// expose it — and a reader must treat that as unknown rather than as a full disk. Retention
	// on its own is unactionable, which is why the two travel together.
	DiskFreeBytes  int64 `json:"diskFreeBytes"`
	DiskTotalBytes int64 `json:"diskTotalBytes"`
}

// CycleFailure is a cycle that ended in an error and stored nothing.
//
// IT EXISTS BECAUSE "THE LAST ATTEMPT FAILED" WAS UNREPRESENTABLE. A cycle writes a Manifest when
// it succeeds and a ReBase when it declares the chain over, and a cycle that simply errors — the
// server unreachable, the store refusing a write, credentials expired — writes neither. Nothing
// downstream can distinguish that from an agent that was never scheduled, so a backup that has
// been failing every hour for a week looks exactly like a backup that is merely quiet.
//
// It is a struct rather than a string so it can grow additively; the contract is additive-only
// within a version, and a bare string could never gain a second fact.
type CycleFailure struct {
	// Detail is the error as the agent saw it, in a sentence a human reads at 3am. NEVER PARSED,
	// and never an assessment: that a cycle failed is a fact the agent alone holds, and whether a
	// failed cycle is an incident is the engine's to decide.
	Detail string `json:"detail"`
}

// CycleReport is what the agent tells the control plane about one backup cycle.
//
// WHY AN ENVELOPE RATHER THAN POSTING THE MANIFEST. A Manifest and a ReBase are alternatives —
// one prefix holds one or the other — so a client that posted "whichever happened" would need two
// endpoints and the engine two ingest paths for one event. Worse, NEITHER OBJECT CARRIES CHAIN
// IDENTITY OR TENANCY: a ReBase is a reason, a position and a timestamp, and there is nothing in
// it that says whose chain stopped. The envelope is where those live, so every cycle reports the
// same shape whatever happened inside it.
//
// EXACTLY ONE OF Manifest, ReBase AND Failure DESCRIBES THE OUTCOME. All three nil is a report
// that says nothing happened, which is not a thing a cycle can mean. Nothing in this package
// enforces that: the contract is types, and rejecting a malformed payload is the ingest's job —
// the same division Estate already lives under, where validation is the API's and not the wire's.
//
// NO VERDICT CROSSES THIS WIRE (AD-021). In particular there is no achieved-RPO field: it is
// now − ReadPoint.At, it needs the customer's target to mean anything, and it is derived
// engine-side from what is already here. A field for it would be the agent doing arithmetic on
// its own clock and calling the answer a number the engine could not check.
type CycleReport struct {
	ContractVersion int `json:"contractVersion"`

	// Chain is the stable root this source's cycles write under (backup.Cycle.Scope, e.g.
	// "install-7/pg1/orders"). It is what makes consecutive reports the same chain, and it is on
	// the envelope because a ReBase carries no identity of its own. OPAQUE — compare it, join on
	// it, never parse it.
	Chain string `json:"chain"`

	// Account is the isolation boundary, spelled as Resource.Account is. Tenancy, and the join to
	// the scan of the same estate.
	//
	// IT IS ON THE ENVELOPE BECAUSE A RE-BASE AND A FAILURE HAVE NOWHERE ELSE TO PUT IT. On a
	// report that carries a manifest the same string appears twice, at Manifest.Source.Account
	// too, and that one is there so a manifest read out of the store on its own can still be
	// placed. THIS ONE IS AUTHORITATIVE: a reader routes on the envelope and never has to open
	// the payload to know whose report it is holding. They must agree, and a producer that lets
	// them disagree has a bug — nothing here checks it, because the check belongs where the
	// payload is validated.
	Account string `json:"account"`

	// At is when the cycle ended, RFC3339. The agent's clock, and the engine's clock is what any
	// staleness is measured against — which is the whole reason this is a fact and not a verdict.
	At string `json:"at"`

	// Manifest is the cycle that stored a backup. Nil otherwise.
	Manifest *Manifest `json:"manifest,omitempty"`

	// ReBase is the cycle that declared the chain over. Nil otherwise.
	ReBase *ReBase `json:"rebase,omitempty"`

	// Failure is the cycle that errored and stored nothing. Nil otherwise.
	Failure *CycleFailure `json:"failure,omitempty"`

	// Slot is what the replication slot was holding, where the source has one. Nil where the
	// source has no such thing, or where the reading could not be taken — absent is "not
	// measured", never zero.
	Slot *SlotReading `json:"slot,omitempty"`
}

// Producer records what made this, so a bad backup can be traced to the build that
// wrote it rather than guessed at.
type Producer struct {
	Agent string `json:"agent"` // agent name and version, e.g. "azure/0.1.0"

	// Tool is the external program and its version — "pg_dump 16.4". The client's major
	// version has to be the server's or newer, so a restore failure that traces back to
	// a mismatched client is answerable from the manifest alone.
	Tool string `json:"tool"`

	// Args are the flags it ran with. A dump taken with different flags restores
	// differently, and "which flags did we use in March" is otherwise unanswerable.
	Args []string `json:"args,omitempty"`
}
