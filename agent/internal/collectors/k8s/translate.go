package k8s

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/manukyanv07/parity-scanner/contract"
)

// Translating a Kubernetes object into the contract.
//
// The identity scheme, which is what lets one estate hold both planes:
//
//	ID       apps/v1/Deployment/cloud-parity/cloud-parity-api   verbatim, case-sensitive
//	Account  the CLUSTER's ARM resource id
//	Group    the namespace
//	ParentID the owning object, or the namespace, or the cluster
//
// Account is the join. contract.Resource defines it as "the isolation boundary the resource lives
// in: Azure subscription, AWS account, GCP project, Kubernetes cluster" - so setting it to the
// cluster's ARM id is not a reinterpretation, it is the field working as specified. A Deployment and
// the AKS cluster it runs on therefore sit in one estate and the dependency graph spans both
// (AD-025).
//
// IDs are verbatim rather than lowercased, unlike Azure. contract.md is explicit: Azure ids are
// lowercased because ARM's own casing is inconsistent, while "AWS/GCP/K8s are verbatim because their
// identifiers are case-sensitive". A Deployment named "API" and one named "api" are two objects.

// translate converts one LIST response into contract resources.
func translate(clusterID string, spec kindSpec, items []map[string]any) ([]contract.Resource, []contract.Gap) {
	out := make([]contract.Resource, 0, len(items))
	var gaps []contract.Gap

	for _, item := range items {
		meta, _ := item["metadata"].(map[string]any)
		name := str(meta["name"])
		if name == "" {
			// Without a name nothing can reference it and nothing can be recreated from it. Counted
			// rather than dropped silently, for the same reason translateRow does on the Azure side.
			gaps = append(gaps, contract.Gap{
				Reason: contract.GapNotAttempted,
				Target: clusterID + "/" + spec.apiVersion + "/" + spec.kind,
				Detail: "an object of this kind came back with no metadata.name, so it is absent from the estate",
			})
			continue
		}
		namespace := str(meta["namespace"])
		if spec.clusterScoped {
			namespace = ""
		}

		// Secret VALUES never leave the cluster. Stripped here, at the boundary, so no later code
		// path can reintroduce them.
		clean, redactions := scrub(spec.kind, item)
		clean = normalise(spec, clean)

		document, err := json.Marshal(clean)
		if err != nil {
			gaps = append(gaps, contract.Gap{
				Reason: contract.GapNotAttempted,
				Target: objectID(spec, namespace, name),
				Detail: fmt.Sprintf("this object could not be encoded, so it is absent from the estate: %v", err),
			})
			continue
		}

		resource := contract.Resource{
			Provider:   contract.ProviderK8s,
			ID:         objectID(spec, namespace, name),
			ParentID:   parentID(clusterID, spec, meta, namespace),
			Type:       resourceType(spec),
			Name:       name,
			Account:    clusterID,
			Group:      namespace,
			Tags:       labels(meta),
			Document:   document,
			Redactions: redactions,
		}
		out = append(out, resource)

		// §2.4's flagging half. Values still ship; the estate now says nobody screened them.
		if gap := screen(resource, clean, redactions); gap != nil {
			gaps = append(gaps, *gap)
		}
	}

	// Sorted so a scan of an unchanged cluster produces identical bytes. The API returns objects in
	// its own order, which is not stable across calls.
	sort.Slice(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	return out, gaps
}

// objectID is apiVersion/Kind/namespace/name, or apiVersion/Kind/name when cluster-scoped.
func objectID(spec kindSpec, namespace, name string) string {
	if namespace == "" {
		return spec.apiVersion + "/" + spec.kind + "/" + name
	}
	return spec.apiVersion + "/" + spec.kind + "/" + namespace + "/" + name
}

// resourceType is the lookup key into the resource-type table, so it must be stable and lowercase
// like every other Type in the contract: "apps/v1/deployment".
func resourceType(spec kindSpec) string {
	return strings.ToLower(spec.apiVersion + "/" + spec.kind)
}

// parentID walks up: an owner if one exists, else the namespace, else the cluster.
//
// ownerReferences first, because that is the real hierarchy - a ReplicaSet belongs to its Deployment,
// not merely to its namespace - and contract.Resource says the collector resolves ParentID so no
// engine code has to parse an id to find ancestry.
func parentID(clusterID string, spec kindSpec, meta map[string]any, namespace string) string {
	// The CONTROLLER owner, not the first entry. Kubernetes convention is that the single reference
	// with controller:true is the real parent; list order is arbitrary and any apply can reorder it.
	// Taking the first meant ParentID could point at a non-controller owner AND could change between
	// scans of an unchanged object, which is a second source of false churn.
	if id := ownerRefID(meta, namespace, true); id != "" {
		return id
	}
	if id := ownerRefID(meta, namespace, false); id != "" {
		return id
	}
	if namespace != "" {
		return objectID(kindSpec{apiVersion: "v1", kind: "Namespace"}, "", namespace)
	}
	// A cluster-scoped object with no owner hangs off the cluster itself, which is what ties the
	// application plane to the Azure estate.
	return clusterID
}

// ownerRefID returns the id of an ownerReference, preferring the controller when asked.
//
// KNOWN LIMIT, stated rather than pretended away: an ownerReference carries apiVersion/kind/name/uid
// and NO scope, while Kubernetes permits a namespaced dependent to have a cluster-scoped owner. The
// dependent's namespace is assumed, which is right in the overwhelming majority. When it is wrong the
// id has one segment too many and matches nothing, so the failure is a MISSING edge rather than a
// wrong one - which is the right way round, but it is still a gap the engine cannot see.
func ownerRefID(meta map[string]any, namespace string, controllerOnly bool) string {
	owners, ok := meta["ownerReferences"].([]any)
	if !ok {
		return ""
	}
	for _, o := range owners {
		owner, ok := o.(map[string]any)
		if !ok {
			continue
		}
		if controllerOnly {
			if isController, _ := owner["controller"].(bool); !isController {
				continue
			}
		}
		api, kind, name := str(owner["apiVersion"]), str(owner["kind"]), str(owner["name"])
		if api == "" || kind == "" || name == "" {
			continue
		}
		return objectID(kindSpec{apiVersion: api, kind: kind}, namespace, name)
	}
	return ""
}

// labels become Tags. contract.Resource is explicit that tags are a SELECTION key and nothing else,
// which is exactly what a Kubernetes label is.
func labels(meta map[string]any) map[string]string {
	raw, ok := meta["labels"].(map[string]any)
	if !ok || len(raw) == 0 {
		return nil
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		out[k] = str(v)
	}
	return out
}

// volatileMetadata changes without the object changing, so storing it makes every scan differ.
//
// MEASURED: a Deployment's stored document carried status.conditions[].lastUpdateTime, plus
// resourceVersion, uid, generation and creationTimestamp. resourceVersion is bumped by ANY write
// anywhere in the cluster, and an HPA rewrites status every 15 seconds - so the claim that a scan of
// an unchanged cluster is byte-identical was simply false, and drift detection would have reported
// 100% churn on a cluster where nothing happened.
//
// uid and resourceVersion must also never reach a restore: they identify THIS cluster's instance of
// the object, and applying them fails or resurrects a stale generation.
var volatileMetadata = []string{
	"resourceVersion", "uid", "generation", "creationTimestamp", "selfLink",
	"deletionTimestamp", "deletionGracePeriodSeconds", "finalizers",
}

// normalise makes the stored document a stable, restorable object.
//
// Two changes, both about what the Document is FOR - it is the source material a restore is derived
// from, so it should be applyable and it should not churn:
//
//  1. status and the volatile metadata above are dropped. status is observed state, never desired
//     state; nothing recreates an object from it.
//  2. apiVersion and kind are INJECTED. A collection LIST returns items with empty TypeMeta - the
//     API server sets those on the List wrapper (DeploymentList), not on each item - so every stored
//     document was a Kubernetes object that could not be applied or schema-validated as-is, and the
//     real kind was only recoverable by parsing the id.
func normalise(spec kindSpec, item map[string]any) map[string]any {
	clone := shallowCopy(item)
	delete(clone, "status")
	clone["apiVersion"] = spec.apiVersion
	clone["kind"] = spec.kind

	if meta, ok := clone["metadata"].(map[string]any); ok {
		metaClone := shallowCopy(meta)
		for _, key := range volatileMetadata {
			delete(metaClone, key)
		}
		clone["metadata"] = metaClone
	}
	return clone
}

// lastAppliedAnnotation is kubectl's copy of the manifest that created an object - and a direct
// plaintext secret leak.
//
// MEASURED, not theoretical. Applying a Secret with `kubectl apply` and stringData put the entire
// original manifest into this annotation, plaintext value included:
//
//	metadata.annotations["kubectl.kubernetes.io/last-applied-configuration"] =
//	  {"kind":"Secret",...,"stringData":{"db-password":"not-a-real-password"},...}
//
// So scrubbing data and stringData is NOT sufficient. The first version of this collector stripped
// both correctly and shipped the value anyway, in an annotation nobody thought to look at. Anyone
// who ever created a Secret with kubectl apply has its plaintext sitting in that annotation.
//
// Stripped from EVERY kind, not only Secrets: it is a redundant duplicate of the object for
// everything else, so removing it costs nothing and closes the leak wherever it appears - including
// on a ConfigMap or a Deployment whose applied manifest happened to embed a credential.
// appliedManifestAnnotations are annotations that hold a COPY OF THE WHOLE OBJECT, including its
// data. kubectl's is the famous one; it is not the only one, and an adversarial review found four
// more that are just as systematic for anyone using the tool in question:
//
//	kubectl.kubernetes.io/last-applied-configuration   kubectl apply, on everything it touches
//	objectset.rio.cattle.io/applied                    Rancher / Fleet, gzip+base64 for large objects
//	kopf.zalando.org/last-handled-configuration        any kopf-based operator
//	kapp.k14s.io/original                              Carvel kapp
//	openshift.io/token-secret.value                    ARO/OpenShift: the PLAINTEXT token itself
//
// The last one is not a manifest copy at all - it is a bare credential in an annotation - and it is
// included here because the effect is identical.
//
// Stripped from EVERY kind, since an applied manifest can embed a credential on a ConfigMap or a
// Deployment just as easily as on a Secret. An arbitrary annotation from tooling nobody has heard of
// is still a residual risk, which is what screen.go exists to surface rather than silently accept.
var appliedManifestAnnotations = []string{
	"kubectl.kubernetes.io/last-applied-configuration",
	"objectset.rio.cattle.io/applied",
	"kopf.zalando.org/last-handled-configuration",
	"kapp.k14s.io/original",
	"openshift.io/token-secret.value",
}

// managedFieldsKey is field-ownership bookkeeping. No values, but it can be several times the size
// of the object it describes, and nothing downstream reads it.
const managedFieldsKey = "managedFields"

// scrub removes what must never leave the cluster, and records each removal.
//
// A Secret's data and stringData hold the values. The KEYS are kept, because a restore needs to know
// which secrets must exist and what fields they carry - the same promise as Key Vault, where names
// come back and values never do. Every removal is recorded in Redactions, so the estate states that
// something was taken out rather than looking like the object simply had no data.
//
// Residual risk worth naming: an ARBITRARY annotation on a Secret could also carry a value, and no
// rule can detect that. What is handled here is the systematic path - the one kubectl creates for
// everyone by default.
func scrub(kind string, item map[string]any) (map[string]any, []contract.Redaction) {
	clone := shallowCopy(item)
	var redactions []contract.Redaction

	// Applies to every kind.
	if meta, ok := clone["metadata"].(map[string]any); ok {
		metaClone := shallowCopy(meta)
		if ann, ok := metaClone["annotations"].(map[string]any); ok {
			var annClone map[string]any
			for _, key := range appliedManifestAnnotations {
				if _, present := ann[key]; !present {
					continue
				}
				if annClone == nil {
					annClone = shallowCopy(ann)
				}
				delete(annClone, key)
				redactions = append(redactions, contract.Redaction{
					Path: "metadata.annotations." + key,
					Reason: "an annotation carrying a copy of the whole object, or a bare token. These " +
						"hold plaintext values for any Secret created from a manifest, and for every other " +
						"kind they are a redundant duplicate of the object",
				})
			}
			if annClone != nil {
				metaClone["annotations"] = annClone
			}
		}
		if _, present := metaClone[managedFieldsKey]; present {
			delete(metaClone, managedFieldsKey)
			redactions = append(redactions, contract.Redaction{
				Path:   "metadata." + managedFieldsKey,
				Reason: "field-ownership bookkeeping; no values, and often larger than the object itself",
			})
		}
		clone["metadata"] = metaClone
	}

	if kind != "Secret" {
		// Only Secret is treated as value-bearing beyond the above. A ConfigMap is configuration by
		// definition - the same position the Azure collector takes on App Configuration key-values -
		// and a customer who puts a password in one has a problem the scanner cannot detect.
		return clone, redactions
	}

	for _, field := range []string{"data", "stringData"} {
		values, ok := clone[field].(map[string]any)
		if !ok || len(values) == 0 {
			continue
		}
		keys := make([]string, 0, len(values))
		for k := range values {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		// Key -> contract.RedactedValue, keeping the field an OBJECT.
		//
		// The first version replaced the whole map with a JSON array of keys. That reads more
		// plainly, but it changes the field's TYPE, and contract/estate.go is explicit that "the key
		// survives with RedactedValue in place of the value" - so engine-side code expecting
		// document.data to be an object would mis-handle every k8s Secret, and contract.RedactedValue
		// went unused by this collector. Conformance beats readability here.
		masked := make(map[string]any, len(keys))
		for _, k := range keys {
			masked[k] = contract.RedactedValue
		}
		clone[field] = masked
		for _, k := range keys {
			redactions = append(redactions, contract.Redaction{
				Path:   field + "." + k,
				Reason: "a Secret value never leaves the cluster; the key is kept so a restore knows what must exist",
			})
		}
	}
	return clone, redactions
}

// shallowCopy avoids mutating the caller's decoded object, which the lister may reuse.
func shallowCopy(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func str(v any) string {
	s, _ := v.(string)
	return s
}
