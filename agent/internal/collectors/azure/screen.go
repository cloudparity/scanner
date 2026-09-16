package azure

import (
	"fmt"
	"sort"
	"strings"

	"github.com/manukyanv07/parity-scanner/contract"
)

// Screening is the second half of contract.md §2.4, and the half that was missing:
//
//	"Anything a heuristic flags but the list does not cover is recorded as a Gap for human
//	 review — it is NOT redacted on suspicion."
//
// Without it there is no way to discover what the curated seed list is missing, and it IS
// missing things. Measured: microsoft.insights/components exists in essentially every
// subscription and returns properties.InstrumentationKey and properties.ConnectionString
// directly in ARG's document. Both shipped verbatim next to `redactions: []`, which is a
// positive claim that nothing was withheld.
//
// Two rules make this safe:
//
//  1. It NEVER redacts. §2.4 is explicit that over-redaction is worse than none, because a
//     `key|secret|token` sweep would blank keyVaultUri, sshPublicKey and
//     privateDnsZoneArmResourceId — the join keys the dependency graph is built from — and
//     break it in a way no test notices.
//  2. It states a fact about the COLLECTOR, not a verdict on the value. The gap says "I did
//     not screen these paths", not "this is a secret". The scanner makes no judgments
//     (AD-021), and a runtime inference that something looks like a credential would be one.

// credentialTokens name a leaf whose VALUE is plausibly a credential. Deliberately
// compound: bare "key" is absent, because it would match keyVaultUri and sshPublicKey and
// re-create the exact failure §2.4 warns about.
var credentialTokens = []string{
	"password", "passwd", "pwd",
	"secret",
	"token",
	"credential",
	"apikey",
	"accesskey", "accountkey", "primarykey", "secondarykey", "sharedkey", "sharedaccesskey",
	"instrumentationkey",
	"connectionstring", "connstring",
	"privatekey",
	"sastoken", "signature",
}

// pointerSuffixes mark a name whose value is an ADDRESS rather than a payload. Matched as a
// suffix, not a substring: substring matching on "id" would exclude anything containing
// those two letters anywhere, which is most of ARM.
var pointerSuffixes = []string{
	"uri", "url", "endpoint",
	"id", "ids", "identifier",
	"name", "names",
	"path", "reference", "ref",
	"thumbprint", "version", "type",
	"enabled", "disabled",
	"expiry", "expires", "expiration",
}

// maxReportedPaths caps how many paths one gap names. One gap per RESOURCE, not per field:
// App Insights is near-universal, so per-field would emit hundreds of gaps on a
// large estate and drown the signal it exists to raise.
const maxReportedPaths = 20

// screen reports fields the collector shipped without checking them against the redaction
// list. It returns nil when there is nothing to say, so a clean resource carries no gap.
func screen(resource contract.Resource, document map[string]any, redacted []contract.Redaction) *contract.Gap {
	already := make(map[string]struct{}, len(redacted))
	for _, r := range redacted {
		already[r.Path] = struct{}{}
	}

	var found []string
	collectCandidates(document, "", already, &found)
	if len(found) == 0 {
		return nil
	}
	sort.Strings(found)

	shown := found
	suffix := ""
	if len(shown) > maxReportedPaths {
		shown = shown[:maxReportedPaths]
		suffix = fmt.Sprintf(" and %d more", len(found)-maxReportedPaths)
	}

	return &contract.Gap{
		Reason: contract.GapUnscreened,
		Target: resource.ID,
		Detail: fmt.Sprintf(
			"shipped %d field(s) not covered by the redaction list whose names suggest a credential: %s%s. The values were sent as read; nobody has decided whether they should have been withheld (contract.md §2.4)",
			len(found), strings.Join(shown, ", "), suffix),
	}
}

// collectCandidates walks the document and records the path of every non-empty string leaf
// whose key looks like a credential and which the seed list did not already cover.
func collectCandidates(node any, path string, already map[string]struct{}, found *[]string) {
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
				*found = append(*found, at)
				continue
			}
			collectCandidates(value, at, already, found)
		}
	case []any:
		for i, value := range typed {
			collectCandidates(value, fmt.Sprintf("%s[%d]", path, i), already, found)
		}
	}
}

// looksLikeCredential matches on the leaf key alone. Case-insensitive, because ARM's casing
// is inconsistent across API versions.
func looksLikeCredential(key string) bool {
	lower := strings.ToLower(key)

	// A public key is public by definition, and sshPublicKey is one of the three fields
	// §2.4 names as what a naive sweep destroys.
	if strings.Contains(lower, "publickey") {
		return false
	}
	for _, suffix := range pointerSuffixes {
		if strings.HasSuffix(lower, suffix) {
			return false
		}
	}
	for _, token := range credentialTokens {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

// isSecretShapedValue keeps the report to values that could actually carry one. A bool
// `secretsEnabled` or a count is a setting, not a credential, and flagging it is noise that
// makes a human stop reading the list.
func isSecretShapedValue(value any) bool {
	text, ok := value.(string)
	return ok && text != "" && text != contract.RedactedValue
}
