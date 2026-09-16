// Package contract defines the canonical Estate — everything a scanner sends to the
// disaster-recovery engine, and nothing else.
//
// The scanner is deliberately dumb. It reads a cloud exhaustively, restates the
// identifying facts in this package's vocabulary, and ships the untouched source
// document alongside. It makes no judgments: no property bucketing, no recovery
// strategy, no hard-vs-soft dependency call. Every one of those needs the Knowledge
// Base, the Knowledge Base is the moat, and the moat stays server-side
// (docs/architecture.md §7, AD-007).
//
// The translation boundary: collectors are the only cloud-aware code in the system.
// Past this package nothing speaks a cloud's vocabulary. Two strings — Resource.ID and
// Resource.Type — keep the cloud's own spelling because no universal vocabulary for
// them exists. They are OPAQUE KEYS: downstream may compare, index, and look them up,
// and may never parse them. Everything worth parsing out of them is already a field.
//
// See docs/specs/contract.md (normative) and docs/specs/contract-derivation.md (why).
package contract

import "encoding/json"

// ContractVersion is the wire-format version of the scan payload. Changes are
// additive-only within a version; a breaking change bumps it (contract.md §6).
const ContractVersion = 1

// RedactedValue replaces any value the collector removed at the translation boundary.
// The value is replaced, never the key: a deleted key is indistinguishable from a key
// that was never set, and that ambiguity is the bug Gap exists to prevent.
const RedactedValue = "[REDACTED]"

// Provider names the cloud a collector reads. It is a label to look up by, never a
// value any engine-side code branches on.
type Provider string

// The providers a collector can claim to have read.
const (
	ProviderAzure Provider = "azure"
	ProviderAWS   Provider = "aws"
	ProviderGCP   Provider = "gcp"
	ProviderK8s   Provider = "k8s"
)

// Estate is one complete scan of one account.
type Estate struct {
	ContractVersion int          `json:"contractVersion"`
	Scan            ScanMeta     `json:"scan"`
	Resources       []Resource   `json:"resources"`
	Dependencies    []Dependency `json:"dependencies"`
}

// ScanMeta describes the run: who scanned what, when, and what they could not reach.
type ScanMeta struct {
	Provider  Provider `json:"provider"`
	Account   string   `json:"account"`   // the scanned boundary — see Resource.Account
	ScannedAt string   `json:"scannedAt"` // RFC3339
	Collector string   `json:"collector"` // collector name and version, e.g. "azure/0.1.0"

	ResourceCount int `json:"resourceCount"`

	// Gaps is everything the scan could not read, and why. An empty list is a claim
	// that the scan was complete; it is not a default (contract.md §4).
	Gaps []Gap `json:"gaps,omitempty"`
}

// Resource is one thing found in a customer's cloud: its identity in our words, plus
// the cloud's own document untouched.
type Resource struct {
	Provider Provider `json:"provider"`

	// ID is the cloud's own identifier (ARM resourceId, ARN, GCP full resource name,
	// K8s apiVersion/kind/namespace/name), normalized by the collector so that string
	// equality is the correct identity test for that cloud: Azure ids are lowercased
	// because ARM's own casing is inconsistent; AWS/GCP/K8s are verbatim because their
	// identifiers are case-sensitive. The original spelling survives in Document.
	// OPAQUE downstream — compare it, index it, never parse it. See contract.md §2.5.
	ID string `json:"id"`

	// ParentID is the ID of the resource this one hangs off, if any. The collector
	// resolves it, so no engine-side code ever has to parse an ID to find ancestry.
	ParentID string `json:"parentId,omitempty"`

	// Type is the cloud's own type string, verbatim and case-folded
	// ("microsoft.keyvault/vaults"). OPAQUE downstream: it is the lookup key into the
	// resource-type table, where every fact about this kind of thing is stated in our
	// vocabulary. Case-folding matters — mixed casing inflated a real scan's type count
	// from 87 to 93 (scanner-engine.md §12).
	Type string `json:"type"`

	Name string `json:"name"`

	// Account is the isolation boundary the resource lives in: Azure subscription,
	// AWS account, GCP project, Kubernetes cluster.
	Account string `json:"account"`

	// Group is the container the customer selects by: Azure resource group,
	// Kubernetes namespace. Empty where the cloud has no equivalent (AWS, GCP).
	Group string `json:"group,omitempty"`

	// Region is empty for genuinely global resources.
	Region string `json:"region,omitempty"`

	// Tags are a selection key and nothing else — never hashed, regenerated on the
	// standby (scanner-engine.md §3). Selection must still work without them.
	Tags map[string]string `json:"tags,omitempty"`

	// Document is the resource's full configuration exactly as the cloud returned it,
	// stored as JSONB. It is the source material for every derivation the engine makes
	// later, which is what lets a Knowledge Base improvement re-derive every stored
	// estate with no re-scan.
	Document json.RawMessage `json:"document"`

	// Redactions lists values removed from Document before it left the customer's
	// cloud, and why. The key survives with RedactedValue in place of the value.
	Redactions []Redaction `json:"redactions,omitempty"`
}

// Redaction records one value withheld at the translation boundary.
type Redaction struct {
	Path   string `json:"path"` // dotted path into Document
	Reason string `json:"reason"`
}

// Dependency is a pointer the collector found from one resource to another: resource From
// names To at property path Via.
//
// Named for the customer, who is shown these and asked what to protect. "This resource has
// five dependencies" needs no explanation; "five references" invites "references to what?".
//
// But the older name carried a distinction worth keeping, so read this before treating the
// name literally: a Dependency records only that A POINTER EXISTS. It is an observation -
// this string appeared in this field - and NOT a claim that the target is required. Whether
// a dependency is fatal or optional is a judgment the engine makes from the resource-type
// table plus customer policy, because the same pointer can be optional in general and
// mandatory under a compliance mandate (scanner-engine.md §4). The collector assigns no
// strength here and must never start: that is the whole of AD-021.
//
// It is also not called an edge. Edge is graph vocabulary; dependency is what a customer
// deciding whether to back something up actually needs to read.
//
// Only a collector can produce these: recognizing that a string is an ARM resourceId (or an
// ARN, or a GCP resource name) is cloud-specific parsing, and cloud-specific parsing lives
// on the collector side of the boundary. Dependencies whose discovery needs per-type
// knowledge - an app's connection string naming a database by its FQDN - are derived
// engine-side from Document via the resource-type table.
type Dependency struct {
	From string `json:"from"`
	To   string `json:"to"`
	Via  string `json:"via"` // property path in From's Document
	// ResolvedTo is the scanned resource a ChildOfScanned dependency actually landed on, and
	// is empty for every other resolution.
	//
	// Without it the engine has to split To on "/" to learn that a dependency to
	// …/virtualnetworks/vnet1/subnets/db means "recovering this needs vnet1" — and §2.5 is
	// explicit that if engine code ever needs to split an id, the boundary has been
	// violated, because everything worth parsing out of an id is already a field. The
	// collector computes this ancestor anyway while resolving; discarding it just moved the
	// parsing downstream.
	//
	// It also lets the engine judge something the collector must not. A subnet comes back
	// WITH its vnet; a role assignment or a diagnostic setting scoped to a storage account
	// does NOT come back when that account is recreated. Both are ChildOfScanned, and only
	// the resource-type table knows which is which (AD-021). Naming the ancestor is the
	// observation; deciding whether it means "already covered" is the judgment.
	ResolvedTo string     `json:"resolvedTo,omitempty"`
	Resolution Resolution `json:"resolution"`
}

// Resolution says whether a reference's target was actually scanned. It is stated
// relative to THIS scan, which is what makes it actionable: "we did not scan it" is
// fixable by onboarding the account (AD-013); "it does not exist" is not.
type Resolution string

const (
	// ResolutionInScan — the target is a resource in this estate.
	ResolutionInScan Resolution = "in-scan"
	// ResolutionChildOfScanned — the target hangs off a resource in this estate
	// (a subnet, an ipConfiguration, a private-endpoint connection). 64% of references
	// in a real subscription landed here (scanner-engine.md §12).
	ResolutionChildOfScanned Resolution = "child-of-scanned"
	// ResolutionOutOfScan — neither. Cross-account, cross-tenant, global, or deleted.
	ResolutionOutOfScan Resolution = "out-of-scan"
)

// Gap is one thing the scan could not read, or read without screening. Silence is never a
// verdict: a resource with
// no app settings and a resource whose app settings were never fetched look identical
// on the wire unless the second one carries a Gap (scanner-engine.md §10.1, §10.6).
type Gap struct {
	Reason GapReason `json:"reason"`
	Target string    `json:"target"`           // resource ID, or a description of what went unread
	Detail string    `json:"detail,omitempty"` // free text for a human
}

// GapReason enumerates why something went unread. The list is short on purpose: each
// reason has a different owner and a different fix.
type GapReason string

const (
	// GapNotAttempted — the collector simply did not fetch it. This is a bug, not a
	// limit. On a complete scan the count should be zero.
	GapNotAttempted GapReason = "not-attempted"

	// GapPermissionDenied — the credential lacks the permission. Fixable by granting a
	// narrower-than-owner role; a product decision, not a code one.
	GapPermissionDenied GapReason = "permission-denied"

	// GapDataPlane — the value lives behind the resource's own data plane and we
	// deliberately never read it: secret values, database logins, certificate private
	// keys, queue contents, volume data. Permanent and intentional.
	GapDataPlane GapReason = "data-plane"

	// GapNoCollector — it needs a collector that does not exist yet, e.g. objects
	// inside a Kubernetes cluster (AD-012).
	GapNoCollector GapReason = "no-collector"

	// GapOutOfScope — it belongs to an account this scan was not invited into.
	// Subscriptions are onboarded, never auto-adopted (AD-013).
	GapOutOfScope GapReason = "out-of-scope"

	// GapExcluded — the collector CAN read it and deliberately does not, because collecting it
	// would be wrong rather than merely unnecessary. Kubernetes Pods and ReplicaSets are the
	// case this exists for: a controller creates them from a spec that IS collected, so
	// restoring them would fight the controller that owns them.
	//
	// Permanent and intentional, like GapDataPlane, but for redundancy rather than sensitivity.
	// It was previously reported as not-attempted, which says "this is a bug, should be zero" -
	// so a correct scan could never reach the zero its own contract asked for, and a real
	// collector bug was indistinguishable from a deliberate exclusion.
	GapExcluded GapReason = "excluded"

	// GapUnresolved — a reference WAS read, and cannot be expressed as a resource id from the
	// plane that read it. The join is the engine's to make, not a hole in the scan.
	//
	// Both cases so far are the Kubernetes plane pointing at Azure. A pod's image says
	// "myregistry.azurecr.io/app:1.0", which carries a login server and no subscription or
	// resource group; a service account's workload-identity annotation carries a managed
	// identity's client id, which is a GUID that appears in no ARM id. The infra plane collected
	// both targets, so the estate holds everything needed - but only the engine, which sees both
	// planes, can put them together.
	//
	// Distinct from not-attempted (nobody looked), from no-collector (nothing can read it) and
	// from out-of-scope (we were not invited): the data is present and the id is not derivable.
	GapUnresolved GapReason = "unresolved"

	// GapUnscreened — the collector shipped fields it did not check against the redaction
	// list (§2.4). This is the one reason that is not about absence: the value WAS read and
	// WAS sent. It is not a claim that a secret leaked, and deliberately not a judgment
	// about the value — the scanner makes none (AD-021). It is a claim that nobody has
	// looked.
	//
	// The fix is a human adding the path to the seed list, which §2.4 says eventually
	// becomes a fact on the resource-type row rather than code inside a collector. Until
	// then, an empty Redactions list on a resource that carries one of these is honest
	// rather than reassuring.
	GapUnscreened GapReason = "unscreened"
)
