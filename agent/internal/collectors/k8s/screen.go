package k8s

import (
	"fmt"
	"sort"
	"strings"

	"github.com/manukyanv07/parity-scanner/contract"
)

// Screening: contract.md §2.4's other half, and the half this collector was missing.
//
//	"Anything a heuristic flags but the list does not cover is recorded as a Gap for human
//	 review — it is NOT redacted on suspicion."
//
// Why it matters more here than on Azure. An adversarial review of the first version found that
// scrubbing Secret.data was necessary but nowhere near sufficient, because the most common way a
// credential reaches a Kubernetes cluster is not a Secret at all:
//
//	spec.template.spec.containers[0].env[0].value          "DD_API_KEY: 8f2c..."
//	spec.template.spec.initContainers[0].args[0]           "--dsn=postgres://admin:pw@db/app"
//	data.<key> on a ConfigMap                              fluent-bit Http_Passwd, Helm 2 releases
//	parameters.<key> on a StorageClass                     legacy provisioner inline keys
//	spec.rules annotations on an Ingress                   auth-url with userinfo, snippet headers
//	spec.template.spec.volumes[].gitRepo.repository        https://x:ghp_token@github.com/...
//
// Every one of those shipped verbatim next to `redactions: []`, and §2.3 makes an empty gaps list a
// positive claim that nothing was withheld. So the leak was not merely unfixed, it was ASSERTED
// clean. That is what this closes: the values still ship, and the estate now says nobody screened them.
//
// Two rules, taken from the Azure screener and equally load-bearing here:
//
//  1. It NEVER redacts. A `password|token|key` sweep over a pod spec would blank
//     serviceAccountName, secretKeyRef.name, configMapRef.name and storageClassName - the join keys
//     the entire dependency graph is built from - and break it in a way no test would notice.
//  2. It states a fact about the COLLECTOR, not a verdict on the value. The gap says "these paths
//     were not screened", never "this is a secret". Judgment belongs to the engine (AD-021).

// maxScreenedPaths bounds one gap. The actionable fact is that unscreened fields exist and roughly
// where, not an unbounded list.
const maxScreenedPaths = 20

// The locations whose CONTENT is free-form and routinely holds a literal credential, regardless of
// what the field is called.
//
// This is the important difference from the Azure screener. On ARM a credential lands in a field
// NAMED for it - connectionString, primaryKey - so matching the leaf name works. In Kubernetes it
// lands in a field named `value`, `args` or `data`, whose name says nothing at all. So the match is
// STRUCTURAL: a path shape, not a leaf name.
//
// Nested locations, matched anywhere in the path because a pod spec appears at several depths -
// directly on a Pod, under spec.template on a Deployment, under spec.jobTemplate.spec.template on a
// CronJob.
var valueBearingFragments = []string{
	// A container's literal env values and its command line. ".env[" does not match ".envFrom[",
	// which holds only references.
	".env[", ".command[", ".args[",
	// Free-form volume sources that take a literal instead of a secret reference.
	".gitRepo.repository", ".flexVolume.options", ".csi.volumeAttributes",
}

// TOP-LEVEL payload fields, matched as a PREFIX rather than a substring.
//
// Substring matching was wrong here and a test caught it: "data." is contained in "metadata.name",
// so every object in the cluster - including a bare Namespace with nothing but a name - was flagged
// as carrying an unscreened credential. A screener that fires on everything is exactly as useless as
// one that fires on nothing, and it would have buried the real findings it exists to surface.
var valueBearingPrefixes = []string{
	// ConfigMap and Secret payloads. Configuration by definition, but a customer who puts a password
	// in one should be told we shipped it rather than left to assume we did not.
	"data.", "binaryData.", "stringData.",
	// StorageClass driver parameters. Cluster-scoped, so one leak is global.
	"parameters.",
}

// screen reports fields shipped without being checked against the redaction list.
func screen(resource contract.Resource, document map[string]any, redacted []contract.Redaction) *contract.Gap {
	already := make(map[string]struct{}, len(redacted))
	for _, r := range redacted {
		already[r.Path] = struct{}{}
	}

	var found []string
	screenNode(document, "", already, &found)
	if len(found) == 0 {
		return nil
	}
	sort.Strings(found)

	shown := found
	suffix := ""
	if len(shown) > maxScreenedPaths {
		shown = shown[:maxScreenedPaths]
		suffix = fmt.Sprintf(" and %d more", len(found)-maxScreenedPaths)
	}

	return &contract.Gap{
		Reason: contract.GapUnscreened,
		Target: resource.ID,
		Detail: fmt.Sprintf("shipped %d field(s) whose contents are free-form and could hold a "+
			"credential, none of them covered by the redaction list: %s%s. The values were sent as "+
			"read - nobody has decided whether they should have been withheld (contract.md §2.4). "+
			"A literal password in a container's env value or command line is the most common way a "+
			"credential leaves a cluster, and it is indistinguishable from ordinary configuration "+
			"without per-application knowledge",
			len(found), strings.Join(shown, ", "), suffix),
	}
}

// screenNode walks the document recording paths that are free-form and not already redacted.
func screenNode(node any, path string, already map[string]struct{}, found *[]string) {
	switch typed := node.(type) {
	case map[string]any:
		for key, value := range typed {
			at := key
			if path != "" {
				at = path + "." + key
			}
			if _, redacted := already[at]; redacted {
				// Already withheld and declared. Reporting it again would say a field was
				// unscreened when it was in fact removed.
				continue
			}
			if isValueBearing(at) && isScalar(value) {
				*found = append(*found, at)
				continue
			}
			screenNode(value, at, already, found)
		}
	case []any:
		for i, value := range typed {
			at := fmt.Sprintf("%s[%d]", path, i)
			if isValueBearing(at) && isScalar(value) {
				*found = append(*found, at)
				continue
			}
			screenNode(value, at, already, found)
		}
	}
}

// isValueBearing reports whether a path sits in a free-form location.
func isValueBearing(path string) bool {
	for _, prefix := range valueBearingPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	for _, fragment := range valueBearingFragments {
		if strings.Contains(path, fragment) {
			return true
		}
	}
	return false
}

// isScalar keeps the report on leaves. Flagging a whole subtree would name a container rather than
// the field that actually carries a value, which is not actionable.
func isScalar(v any) bool {
	switch v.(type) {
	case map[string]any, []any, nil:
		return false
	}
	return true
}
