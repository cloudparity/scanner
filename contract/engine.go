package contract

// Engine-side vocabulary — NOT part of the scan payload.
//
// Everything in this file is produced by the disaster-recovery engine from a stored
// Estate plus the Knowledge Base. A scanner never emits any of it. It lives here
// because contract/ is also the shape the API returns to the dashboard.
//
// These types predate the scanner/engine split and are carried forward unchanged. They
// are redesigned when the engine is designed, not before. The scan payload
// (estate.go) is the piece settled now.

// RecoveryVerb is how a resource comes back in the secondary region. The type zoo lives
// in data: adding a database is a row in the resource-type table, not a branch in code
// (scanner-engine.md §11).
type RecoveryVerb string

const (
	VerbCreateStandby     RecoveryVerb = "create-standby"
	VerbAddRegion         RecoveryVerb = "add-region"
	VerbToggleRedundancy  RecoveryVerb = "toggle-redundancy"
	VerbEstablishBinding  RecoveryVerb = "establish-binding"
	VerbTrafficCutover    RecoveryVerb = "traffic-cutover"
	VerbRedeploy          RecoveryVerb = "redeploy"
	VerbRewriteReferences RecoveryVerb = "rewrite-references"
)

// Selection is how a customer chooses a recovery scope. Tags are a convenience, not a
// foundation: selection must work by explicit ids, by resource type, or by group even
// when a customer tags nothing.
type Selection struct {
	By    string `json:"by"` // "ids" | "type" | "group" | "tag"
	Value string `json:"value"`
}

// Closure is the selection plus everything a successful recovery drags in. Computed on
// demand, never stored.
type Closure struct {
	Selection Selection        `json:"selection"`
	Required  []string         `json:"required"`
	Optional  []string         `json:"optional"`
	Manifest  CoverageManifest `json:"manifest"`
}

// CoverageManifest is the honesty surface: metadata-green is not recovered. It is built
// from the engine's own analysis plus the scanner's Gap and Redaction reports.
type CoverageManifest struct {
	Ready       []string         `json:"ready"`
	NeedsManual []ManifestReason `json:"needsManual"`
	CantSee     []ManifestReason `json:"cantSee"`
	Unknown     []ManifestReason `json:"unknown"`
}

// ManifestReason pairs a resource with why it needs attention.
type ManifestReason struct {
	ResourceID string `json:"resourceId"`
	Reason     string `json:"reason"`
}
