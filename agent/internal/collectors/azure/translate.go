package azure

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/manukyanv07/parity-scanner/contract"
)

// translate restates each resource's identity in the contract's vocabulary and carries
// the untouched document alongside (infra-scanner §4, contract.md §2.5). Nothing is
// dropped: ARM's resourceId becomes ID, location becomes Region, subscription becomes
// Account, and the cloud's own spelling survives inside Document.
//
// subscription is the boundary being scanned. It is the fallback Account for an id that
// names none — Account is the isolation boundary and has no omitempty, so a resource
// attributed to nothing is unrecoverable and unfilterable.
//
// Pure function: rows in, resources out, no I/O, which is what makes the id parsing
// testable without a subscription.
func translate(subscription string, raw []armResource) ([]contract.Resource, []contract.Gap) {
	out := make([]contract.Resource, 0, len(raw))
	var gaps []contract.Gap
	for _, row := range raw {
		r, unscreened, ok := translateRow(subscription, row)
		if !ok {
			continue
		}
		out = append(out, r)
		if unscreened != nil {
			gaps = append(gaps, *unscreened)
		}
	}
	return out, gaps
}

// translateRow converts one ARG row, and reports any field it shipped without screening
// against the redaction list (§2.4). It returns false only when the row cannot be identified
// or serialized at all; Collect compares the counts and reports the difference as a
// not-attempted Gap, so a dropped row is never silently absent.
func translateRow(subscription string, row armResource) (contract.Resource, *contract.Gap, bool) {
	original := str(row["id"])

	// A trailing slash would stop the id string-equalling a reference to the same
	// resource written without one, and id equality *is* the identity test.
	id := strings.ToLower(strings.TrimRight(original, "/"))
	if id == "" {
		// Without an id nothing can reference it and nothing can be recovered by it. Tested
		// AFTER trimming: FuzzTranslateRow found that an id of "/" passed the empty check and
		// shipped a resource whose ID was "", which every reference to nothing would match.
		return contract.Resource{}, nil, false
	}

	// Parse the ORIGINAL spelling. contract.md §2.5 mandates lowercasing exactly two
	// things — the whole id (it is the key every Reference matches against, and ARM's own
	// casing is inconsistent) and type (a lookup key into the resource-type table).
	// Parsing the lowercased string instead would leak normalization into name and group,
	// which are display values the customer selects by, not keys.
	parsed := parseARMID(original)

	// The id is the normative source (contract.md §2.5) and parsing from one place keeps
	// type, name and parentId mutually consistent. ARG's own columns answer for ids the
	// id grammar does not cover — a resource group, a management group — and for a
	// malformed id, where a floored pair count would otherwise invent a confident wrong
	// answer.
	resourceType, name := parsed.resourceType, parsed.name
	parentID := parsed.parentID
	if parsed.malformed || resourceType == "" {
		resourceType = strings.ToLower(str(row["type"]))
		name = str(row["name"])
		if parsed.malformed {
			parentID = ""
		}
	}

	account := parsed.account
	if account == "" {
		account = strings.ToLower(subscription)
	}

	document, redactions, err := redactedDocument(row)
	if err != nil {
		// Unreachable in practice: the row was produced by decoding JSON, so it
		// re-marshals. The error text is deliberately discarded rather than logged — it
		// could quote a value fragment, and this package never logs. Shipping a resource
		// with no document would hand the engine something it can derive nothing from, so
		// drop it and let Collect's count guard say so.
		return contract.Resource{}, nil, false
	}

	resource := contract.Resource{
		Provider:   contract.ProviderAzure,
		ID:         id,
		ParentID:   parentID,
		Type:       resourceType,
		Name:       name,
		Account:    account,
		Group:      parsed.group,
		Region:     region(str(row["location"])),
		Tags:       stringMap(row["tags"]),
		Document:   document,
		Redactions: redactions,
	}

	// Screened against the row itself rather than the re-decoded document: same tree, one
	// less allocation, and the redacted paths are already known here.
	return resource, screen(resource, row, redactions), true
}

// region translates Azure's spelling of global-ness into ours — ARM says
// `location: "global"`, the contract says a global resource has no region.
//
// Spaces are stripped as well as case folded. ARM returns both the display form
// ("East US") and the canonical form ("eastus") depending on the API, and region is the
// lookup key for DR-region pairing: lowercasing alone yields "east us", which is a
// SECOND region for the same place. That is the 87-vs-93 type-count defect in another
// column, and it was shipped here until an adversarial review caught it.
func region(location string) string {
	if strings.EqualFold(location, "global") {
		return ""
	}
	return strings.ToLower(strings.ReplaceAll(location, " ", ""))
}

// stringMap converts ARG's tag object. Tag keys keep their casing: unlike an id, a tag is
// a selection key the customer typed, and lowercasing it would stop their own selector
// matching.
func stringMap(v any) map[string]string {
	m, ok := v.(map[string]any)
	if !ok || len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, val := range m {
		switch typed := val.(type) {
		case string:
			out[k] = typed
		case nil:
			// Skip rather than formatting: fmt.Sprint(nil) yields "<nil>", which
			// fabricates a value the cloud never returned, and a selector on this tag
			// would then match that string.
			continue
		default:
			out[k] = fmt.Sprint(typed)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// armID holds the facts contract.md §2.5 says to parse out of an ARM resourceId, so no
// engine-side code ever has to parse an id to find ancestry.
type armID struct {
	account      string // lowercased: a subscription GUID is a key
	group        string // original casing: a selection key the customer typed
	resourceType string // lowercased: the resource-type table's lookup key
	name         string // original casing: the display value a restore recreates
	parentID     string // lowercased: it is an id, matched by equality

	// malformed marks an id with an unpaired trailing type segment, or an empty segment.
	// Flooring the pair count would silently produce a confident wrong type, name and
	// parent — the "graph that looks right and matches nothing" §2.5 opens by warning
	// about. An empty segment ("//" inside the id) is the same failure from the other
	// side: FuzzParseARMID found that "/providers/ns//x" parsed to the type "ns/" with a
	// parent ending in a slash, keys that no table row and no reference could ever match.
	malformed bool
}

// parseARMID splits an ARM resourceId, preserving casing; the caller decides what to
// lowercase.
//
//	{scope}/providers/{ns}/{type1}/{name1}[/{type2}/{name2}]…
//
// The scope is usually /subscriptions/{sub}/resourceGroups/{rg}, but an EXTENSION
// resource nests a second /providers/ and its scope is another resource:
//
//	/subscriptions/s/resourceGroups/rg/providers/Microsoft.ContainerService/managedClusters/aks1
//	  /providers/Microsoft.KubernetesConfiguration/extensions/flux
//
// So the split is on the LAST /providers/, not the first. Splitting on the first types
// that resource as `microsoft.containerservice/managedclusters/providers/extensions` — a
// phantom type with no resource-type row, hence no recovery strategy — and parents it to
// a path that is not a resource, which dead-ends the parentId walk §2.5 step 2 depends
// on. Every role assignment on a resource scope has this exact shape, so the
// authorizationresources table promised in unreadGaps() is all extension ids.
//
// Absent segments are left empty rather than guessed: a management-group id has no
// subscription, a subscription-level resource has no resource group, and a resource group
// has no /providers/ section at all.
func parseARMID(id string) armID {
	var out armID

	segments := strings.Split(strings.TrimPrefix(strings.TrimRight(id, "/"), "/"), "/")

	last := -1
	for i, segment := range segments {
		if segment == "" {
			// ARM never emits an empty segment, so this id is not one of ARM's. Type,
			// name and parent are left unset rather than assembled from the pieces that
			// happen to be there; translate falls back to ARG's own columns for the first
			// two and refuses to parent the resource at all.
			out.malformed = true
		}
		if strings.EqualFold(segment, "providers") {
			last = i
		}
	}

	// account and group come from the leading scope, whatever the id nests afterwards.
	scope := segments
	if last >= 0 {
		scope = segments[:last]
	}
	for i := 0; i+1 < len(scope); i += 2 {
		switch strings.ToLower(scope[i]) {
		case "subscriptions":
			out.account = strings.ToLower(scope[i+1])
		case "resourcegroups":
			out.group = scope[i+1]
		}
	}

	// Need a namespace and at least one type/name pair after it.
	if out.malformed || last < 0 || len(segments) < last+4 {
		return out
	}

	namespace := segments[last+1]
	rest := segments[last+2:]
	out.malformed = len(rest)%2 == 1
	pairs := len(rest) / 2

	types := make([]string, 0, pairs+1)
	types = append(types, namespace)
	for p := 0; p < pairs; p++ {
		types = append(types, rest[2*p])
	}
	out.resourceType = strings.ToLower(strings.Join(types, "/"))
	out.name = rest[2*pairs-1]

	switch {
	case pairs > 1:
		// The id minus its trailing type/name pair. Rebuilt from segments rather than
		// trimmed off the string, so a trailing unpaired segment cannot yield the id
		// itself as its own parent.
		parent := make([]string, 0, len(segments))
		parent = append(parent, segments[:last+2]...)
		for p := 0; p < pairs-1; p++ {
			parent = append(parent, rest[2*p], rest[2*p+1])
		}
		out.parentID = strings.ToLower("/" + strings.Join(parent, "/"))
	case scopeIsResource(segments[:last]):
		// An extension resource hangs off the resource it is scoped to.
		out.parentID = strings.ToLower("/" + strings.Join(segments[:last], "/"))
	}
	return out
}

// scopeIsResource reports whether a scope is itself a resource — i.e. it has its own
// /providers/ section — rather than a subscription or resource group, which are not
// resources in this estate.
func scopeIsResource(scope []string) bool {
	for _, segment := range scope {
		if strings.EqualFold(segment, "providers") {
			return true
		}
	}
	return false
}

// redactionRule names one path whose value must not leave the customer's cloud. The path
// is pre-split: the rules are constants, so parsing them per resource would be six
// identical allocations for every row in the estate.
type redactionRule struct {
	path   []string
	reason string
}

// arrayStep marks "every element of this array" in a rule path.
const arrayStep = "[*]"

// redactionRules is the curated seed list from contract.md §2.4, and it is curated on
// purpose: nothing is redacted on suspicion. Extend one entry at a time, each with a
// reason. §2.4 explains why a regex sweep is worse than no sweep, and
// TestTranslateNeverRedactsJoinKeys is the executable version of that warning.
var redactionRules = []redactionRule{
	{[]string{"properties", "siteConfig", "appSettings", arrayStep, "value"}, "App Service app settings may hold connection strings"},
	{[]string{"properties", "siteConfig", "connectionStrings", arrayStep, "connectionValue"}, "App Service connection strings"},
	{[]string{"properties", "administratorLoginPassword"}, "database administrator password"},
	{[]string{"properties", "*", "primaryKey"}, "account key"},
	{[]string{"properties", "*", "secondaryKey"}, "account key"},
	{[]string{"properties", "*", "accessKey"}, "account key"},
}

// redactedDocument returns the row as JSON with every seed-listed value replaced, plus a
// record of each replacement.
//
// The row is deep-copied first: discover's rows belong to discover, and a collector that
// mutates its own input is a bug waiting for a second reader.
func redactedDocument(row armResource) (json.RawMessage, []contract.Redaction, error) {
	document := deepCopyMap(row)

	var found []contract.Redaction
	for _, rule := range redactionRules {
		applyRedaction(document, rule.path, "", rule.reason, &found)
	}

	// Map iteration order is random, so a `*` rule matching several keys would otherwise
	// emit redactions in a different order on every run and make the payload unstable.
	// Stable because §2.4 says this list grows, and the first overlapping entry would give
	// two records with the same path and different reasons.
	sort.SliceStable(found, func(a, b int) bool { return found[a].Path < found[b].Path })

	encoded, err := json.Marshal(document)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal document for %s: %w", str(row["id"]), err)
	}
	return encoded, found, nil
}

// applyRedaction walks one rule against the document, replacing values in place and
// recording the concrete path of each — `properties.siteConfig.appSettings[0].value`, not
// the pattern — so a reviewer can see exactly what was withheld.
//
// Key matching is case-insensitive: it cannot widen which field is meant, and it survives
// ARM returning appSettings in one API version and appsettings in another.
func applyRedaction(node any, pattern []string, path, reason string, found *[]contract.Redaction) {
	segment, rest := pattern[0], pattern[1:]

	if segment == arrayStep {
		list, ok := node.([]any)
		if !ok {
			return
		}
		for i := range list {
			applyRedaction(list[i], rest, fmt.Sprintf("%s[%d]", path, i), reason, found)
		}
		return
	}

	object, ok := node.(map[string]any)
	if !ok {
		return
	}
	for key, value := range object {
		if segment != "*" && !strings.EqualFold(key, segment) {
			continue
		}
		at := key
		if path != "" {
			at = path + "." + key
		}
		if len(rest) > 0 {
			applyRedaction(value, rest, at, reason, found)
			continue
		}
		if held, redacted := redactValue(value); redacted {
			object[key] = held
			*found = append(*found, contract.Redaction{Path: at, Reason: reason})
		}
	}
}

// redactValue decides whether one matched value is withheld.
//
// A secret is a scalar. Replacing a map or a slice would collapse a whole subtree into
// one marker — and a `*` wildcard can reach an object, so a rule aimed at an account key
// could swallow the keyVaultUri and resource id beside it. That is the over-redaction
// §2.4 warns "breaks the dependency graph in a way no test notices", so leave the subtree
// alone rather than hiding the graph inside it.
//
// nil and "" are left alone too: there is nothing to withhold, and recording a redaction
// that hid nothing is a false report. Azure returns "" for an unset password on some
// types.
func redactValue(value any) (any, bool) {
	switch typed := value.(type) {
	case nil:
		return value, false
	case string:
		if typed == "" {
			return value, false
		}
	case map[string]any, []any:
		return value, false
	}
	return contract.RedactedValue, true
}

// deepCopyMap clones a decoded JSON object so redaction never touches the caller's rows.
func deepCopyMap(source map[string]any) map[string]any {
	out := make(map[string]any, len(source))
	for k, v := range source {
		out[k] = deepCopy(v)
	}
	return out
}

func deepCopy(v any) any {
	switch typed := v.(type) {
	case map[string]any:
		return deepCopyMap(typed)
	case []any:
		out := make([]any, len(typed))
		for i, val := range typed {
			out[i] = deepCopy(val)
		}
		return out
	default:
		// Scalars decoded from JSON are immutable values, so sharing them is safe.
		return v
	}
}

// str reads a string field from an ARG row, yielding "" for a missing or non-string value
// rather than panicking on a shape we did not expect.
func str(v any) string {
	s, _ := v.(string)
	return s
}
