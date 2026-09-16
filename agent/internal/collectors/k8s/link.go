package k8s

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/manukyanv07/parity-scanner/contract"
)

// Dependencies between Kubernetes objects, and out to Azure.
//
// Same discipline as the Azure collector: this records that A POINTER EXISTS and never that the
// target is required. Whether a dependency is fatal is a resource-type judgment the engine makes
// (AD-021), so nothing here assigns strength.
//
// Unlike ARM, a Kubernetes reference is almost never a full identifier - it is a bare name, resolved
// against the referrer's own namespace. So this cannot be a generic "walk every string and match a
// shape" pass like link.go on the Azure side. Each reference is read from the field that holds it,
// which means per-kind knowledge, which means this list is explicit and grows deliberately.

// WHAT HOLDS NO EDGE, and why - so absence is a decision rather than an oversight:
//
//	v1/Service        A Service selects pods by LABEL, never by name, so no reference exists to
//	                  follow. The edge runs the other way and only a label match produces it, and
//	                  that match is the engine's (AD-021). Its Azure load balancer annotations
//	                  (azure-load-balancer-resource-group, azure-pip-name, internal-subnet) name ARM
//	                  resources rather than cluster objects; they are stored verbatim in the
//	                  document, which is what a restore reads them from.
//	NetworkPolicy     Also pure label selectors, plus CIDR blocks.
//
// link records every pointer the collected objects hold.
func link(clusterID string, resources []contract.Resource) ([]contract.Dependency, []contract.Gap) {
	known := make(map[string]struct{}, len(resources))
	for _, r := range resources {
		known[r.ID] = struct{}{}
	}

	var deps []contract.Dependency
	var gaps []contract.Gap
	workloadIdentities := map[string]string{}
	registries := map[string]struct{}{}

	for _, r := range resources {
		var obj map[string]any
		if err := json.Unmarshal(r.Document, &obj); err != nil {
			gaps = append(gaps, contract.Gap{
				Reason: contract.GapNotAttempted,
				Target: r.ID,
				Detail: "the stored document could not be read back, so this object's dependencies were never scanned",
			})
			continue
		}
		add := func(via, targetID string) {
			if targetID == "" || targetID == r.ID {
				return
			}
			resolution, ancestor := resolve(targetID, known)
			deps = append(deps, contract.Dependency{
				From: r.ID, To: targetID, Via: via,
				ResolvedTo: ancestor, Resolution: resolution,
			})
		}

		// The owner chain. ParentID already carries it, but a dependency makes it traversable in the
		// same structure as everything else.
		if meta, ok := obj["metadata"].(map[string]any); ok {
			if owners, ok := meta["ownerReferences"].([]any); ok {
				for i, o := range owners {
					owner, ok := o.(map[string]any)
					if !ok {
						continue
					}
					// Validated the same way translate does. The two consumers of ownerReferences
					// previously disagreed: translate skipped an owner missing apiVersion/kind/name
					// while this emitted an edge to a fabricated id like "v1//prod/name".
					add(pathf("metadata.ownerReferences[%d]", i),
						ownerID(owner, r.Group))
				}
			}
			// Workload identity: the annotation tying a ServiceAccount to an Azure managed identity's
			// CLIENT id. Counted here and declared ONCE below, not once per ServiceAccount - a gap per
			// object is unbounded on a real cluster and repeats on every scan forever, which is the
			// noise problem the Azure collector fixed by making its analogous limit a single static
			// declaration.
			if ann, ok := meta["annotations"].(map[string]any); ok {
				if v := str(ann["azure.workload.identity/client-id"]); v != "" {
					workloadIdentities[r.ID] = v
				}
			}
		}

		spec, _ := obj["spec"].(map[string]any)
		note := func(image string) {
			if host := registryHost(image); host != "" {
				registries[host] = struct{}{}
			}
		}
		switch r.Type {
		case "apps/v1/deployment", "apps/v1/daemonset", "apps/v1/replicaset":
			linkPodSpec(spec, "spec.template.spec", r.Group, add, note)
		case "apps/v1/statefulset":
			linkPodSpec(spec, "spec.template.spec", r.Group, add, note)
			// The governing Service. Unlike a Deployment's, this is NOT optional decoration: every pod's
			// stable DNS name is <pod>.<serviceName>.<ns>.svc, so a StatefulSet restored without it has
			// pods that cannot find each other. Clustered databases - the exact workloads a StatefulSet
			// exists for - do not form a quorum, and the failure looks like an application bug.
			if svc := str(spec["serviceName"]); svc != "" {
				add("spec.serviceName", validID("v1", "Service", r.Group, svc))
			}
			// volumeClaimTemplates. The PVCs themselves are named <template>-<sts>-<ordinal> and do not
			// exist until a pod does, so THEY are not resolvable - but the StorageClass they name does
			// exist now, and it is what decides whether the restored StatefulSet gets storage at all.
			for i, t := range asList(spec["volumeClaimTemplates"]) {
				tmpl, ok := t.(map[string]any)
				if !ok {
					continue
				}
				if sc := str(mapOf(tmpl["spec"])["storageClassName"]); sc != "" {
					add(pathf("spec.volumeClaimTemplates[%d].spec.storageClassName", i),
						validID("storage.k8s.io/v1", "StorageClass", "", sc))
				}
			}
		case "batch/v1/cronjob":
			if jt, ok := spec["jobTemplate"].(map[string]any); ok {
				if js, ok := jt["spec"].(map[string]any); ok {
					linkPodSpec(js, "spec.jobTemplate.spec.template.spec", r.Group, add, note)
				}
			}
		case "batch/v1/job":
			linkPodSpec(spec, "spec.template.spec", r.Group, add, note)
		case "v1/pod":
			// A Pod's spec IS the pod spec - there is no template to reach through.
			linkPod(spec, "spec", r.Group, add, note)
		case "networking.k8s.io/v1/ingress":
			linkIngress(spec, r.Group, add)
		case "v1/persistentvolumeclaim":
			if sc := str(spec["storageClassName"]); sc != "" {
				add("spec.storageClassName", validID("storage.k8s.io/v1", "StorageClass", "", sc))
			}
			if vn := str(spec["volumeName"]); vn != "" {
				add("spec.volumeName", validID("v1", "PersistentVolume", "", vn))
			}
		case "v1/persistentvolume":
			// Cluster-scoped, so its claimRef carries its own namespace.
			if sc := str(spec["storageClassName"]); sc != "" {
				add("spec.storageClassName", validID("storage.k8s.io/v1", "StorageClass", "", sc))
			}
			if ref, ok := spec["claimRef"].(map[string]any); ok {
				add("spec.claimRef", validID("v1", "PersistentVolumeClaim",
					str(ref["namespace"]), str(ref["name"])))
			}
		case "autoscaling/v2/horizontalpodautoscaler":
			if ref, ok := spec["scaleTargetRef"].(map[string]any); ok {
				// apiVersion is OPTIONAL in CrossVersionObjectReference and the API server does not
				// default it, so an omitted one previously produced "/Deployment/prod/api" - a
				// non-empty id that can never equal the real one, silently turning the HPA edge into
				// a dangling reference. Defaulted to apps/v1, which is where every scalable built-in
				// workload lives.
				api := str(ref["apiVersion"])
				if api == "" {
					api = "apps/v1"
				}
				add("spec.scaleTargetRef", validID(api, str(ref["kind"]), r.Group, str(ref["name"])))
			}
		case "rbac.authorization.k8s.io/v1/rolebinding", "rbac.authorization.k8s.io/v1/clusterrolebinding":
			linkBinding(obj, r.Group, add)
		}

		// priorityClassName and runtimeClassName, on every kind that carries a pod template. Both are
		// ADMISSION-time requirements: a workload naming a class the target cluster lacks is rejected
		// outright ("no PriorityClass with name X was found") rather than degrading, so a restore that
		// misses them succeeds at apply and then produces zero pods.
		linkPodClasses(r.Type, spec, add)
	}

	// Map iteration and API ordering are both unstable; the estate must not be.
	sort.Slice(deps, func(a, b int) bool {
		if deps[a].From != deps[b].From {
			return deps[a].From < deps[b].From
		}
		if deps[a].Via != deps[b].Via {
			return deps[a].Via < deps[b].Via
		}
		return deps[a].To < deps[b].To
	})
	gaps = append(gaps, workloadIdentityGap(workloadIdentities)...)
	gaps = append(gaps, registryGap(registries)...)
	return dedupe(deps), gaps
}

// workloadIdentityGap declares, once, that ServiceAccount-to-Azure-identity bindings are carried but
// not resolved.
//
// The annotation holds a managed identity's CLIENT id, which is a GUID and appears in no ARM resource
// id, so this collector cannot turn it into a dependency. The infra plane DID collect that identity,
// so the engine can join them - which makes this a limit to state rather than a bug to fix here.
func workloadIdentityGap(bindings map[string]string) []contract.Gap {
	if len(bindings) == 0 {
		return nil
	}
	accounts := make([]string, 0, len(bindings))
	for id := range bindings {
		accounts = append(accounts, id)
	}
	sort.Strings(accounts)
	shown := accounts
	if len(shown) > 5 {
		shown = shown[:5]
	}
	examples := make([]string, 0, len(shown))
	for _, id := range shown {
		examples = append(examples, id+" -> "+bindings[id])
	}
	return []contract.Gap{{
		Reason: contract.GapUnresolved,
		Target: "azure-workload-identity-bindings",
		Detail: fmt.Sprintf("%d service account(s) are bound to an Azure managed identity by CLIENT id, "+
			"which is a GUID and appears in no ARM resource id, so this collector cannot emit the "+
			"dependency. The infra plane collected those identities, so the engine can join them on the "+
			"client id once the resource-type table says where each type keeps it. Examples: %s",
			len(bindings), strings.Join(examples, ", ")),
	}}
}

// registryHost returns the registry a container image is pulled from, or "" for a Docker Hub short
// name that names no host at all.
//
// The rule that matters: the first path segment is a HOST only if it contains a dot or a colon, or is
// exactly "localhost". Without that, "library/nginx" reads as host "library" and "nginx:1.25" as host
// "nginx", which would invent registries that do not exist.
func registryHost(image string) string {
	image = strings.TrimSpace(image)
	if image == "" {
		return ""
	}
	first, rest, found := strings.Cut(image, "/")
	if !found {
		return ""
	}
	_ = rest
	if first == "localhost" || strings.ContainsAny(first, ".:") {
		return first
	}
	return ""
}

// registryGap declares the container registries the workloads pull from, once.
//
// Why a gap and not a dependency: an ACR's ARM id is
// /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.ContainerRegistry/registries/<name>,
// and an image reference carries only "<name>.azurecr.io". The registry NAME is recoverable, the
// subscription and resource group are not, so this collector cannot build the id - and emitting a
// fabricated one would be worse than saying so. The infra plane did collect every ACR in the
// subscription, so the engine can join on the name; this states the join it has to make.
func registryGap(registries map[string]struct{}) []contract.Gap {
	if len(registries) == 0 {
		return nil
	}
	hosts := make([]string, 0, len(registries))
	for h := range registries {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	return []contract.Gap{{
		Reason: contract.GapUnresolved,
		Target: "container-image-registries",
		Detail: fmt.Sprintf("workloads pull images from %d registry host(s) that could not be turned "+
			"into a dependency, because an image reference carries a login server and not an ARM id: %s. "+
			"For *.azurecr.io the registry name is the first label, so the engine can join it to the "+
			"registries the infra plane collected. This edge decides a restore: a private registry that "+
			"region B cannot reach leaves every pod in ImagePullBackOff",
			len(hosts), strings.Join(hosts, ", ")),
	}}
}

// linkPodSpec reaches through .template.spec to the pod spec, which is where Deployments,
// StatefulSets, DaemonSets, Jobs and CronJobs all keep theirs.
func linkPodSpec(spec map[string]any, base, namespace string, add func(via, id string), note func(image string)) {
	template, ok := spec["template"].(map[string]any)
	if !ok {
		return
	}
	pod, ok := template["spec"].(map[string]any)
	if !ok {
		return
	}
	linkPod(pod, base, namespace, add, note)
}

// podSpecOf returns the pod spec inside whichever kind carries one, and the path to it.
func podSpecOf(resourceType string, spec map[string]any) (map[string]any, string) {
	switch resourceType {
	case "apps/v1/deployment", "apps/v1/statefulset", "apps/v1/daemonset", "apps/v1/replicaset",
		"batch/v1/job":
		return mapOf(mapOf(spec["template"])["spec"]), "spec.template.spec"
	case "batch/v1/cronjob":
		inner := mapOf(mapOf(spec["jobTemplate"])["spec"])
		return mapOf(mapOf(inner["template"])["spec"]), "spec.jobTemplate.spec.template.spec"
	case "v1/pod":
		return spec, "spec"
	}
	return nil, ""
}

// linkPodClasses records the two cluster-scoped classes a pod spec names.
func linkPodClasses(resourceType string, spec map[string]any, add func(via, id string)) {
	pod, base := podSpecOf(resourceType, spec)
	if pod == nil {
		return
	}
	if pc := str(pod["priorityClassName"]); pc != "" {
		add(base+".priorityClassName",
			validID("scheduling.k8s.io/v1", "PriorityClass", "", pc))
	}
	if rc := str(pod["runtimeClassName"]); rc != "" {
		add(base+".runtimeClassName", validID("node.k8s.io/v1", "RuntimeClass", "", rc))
	}
}

// linkPod reads the references inside one pod spec: ConfigMaps, Secrets, PVCs and the
// ServiceAccount. These decide whether a restored workload starts at all.
func linkPod(pod map[string]any, base, namespace string, add func(via, id string), note func(image string)) {
	cm := func(name, via string) { add(via, validID("v1", "ConfigMap", namespace, name)) }
	sec := func(name, via string) { add(via, validID("v1", "Secret", namespace, name)) }

	if sa := str(pod["serviceAccountName"]); sa != "" {
		add(base+".serviceAccountName", validID("v1", "ServiceAccount", namespace, sa))
	}
	for i, p := range asList(pod["imagePullSecrets"]) {
		if m, ok := p.(map[string]any); ok {
			sec(str(m["name"]), pathf("%s.imagePullSecrets[%d]", base, i))
		}
	}
	for _, group := range []string{"containers", "initContainers", "ephemeralContainers"} {
		for ci, c := range asList(pod[group]) {
			container, ok := c.(map[string]any)
			if !ok {
				continue
			}
			for ei, e := range asList(container["envFrom"]) {
				src, ok := e.(map[string]any)
				if !ok {
					continue
				}
				if ref, ok := src["configMapRef"].(map[string]any); ok {
					cm(str(ref["name"]), pathf("%s.%s[%d].envFrom[%d].configMapRef", base, group, ci, ei))
				}
				if ref, ok := src["secretRef"].(map[string]any); ok {
					sec(str(ref["name"]), pathf("%s.%s[%d].envFrom[%d].secretRef", base, group, ci, ei))
				}
			}
			// The IMAGE. Nothing else in the estate records what a workload actually runs, so a
			// restore had the full desired state of every Deployment except the one field that says
			// which container to start. It is also the cross-plane edge to Azure Container Registry:
			// a private ACR that is not reachable from region B leaves every pod in ImagePullBackOff,
			// which is the single most common way a cluster restore fails.
			note(str(container["image"]))
			for vi, e := range asList(container["env"]) {
				entry, ok := e.(map[string]any)
				if !ok {
					continue
				}
				from, ok := entry["valueFrom"].(map[string]any)
				if !ok {
					continue
				}
				if ref, ok := from["configMapKeyRef"].(map[string]any); ok {
					cm(str(ref["name"]), pathf("%s.%s[%d].env[%d].valueFrom.configMapKeyRef", base, group, ci, vi))
				}
				if ref, ok := from["secretKeyRef"].(map[string]any); ok {
					sec(str(ref["name"]), pathf("%s.%s[%d].env[%d].valueFrom.secretKeyRef", base, group, ci, vi))
				}
			}
		}
	}
	for vi, v := range asList(pod["volumes"]) {
		vol, ok := v.(map[string]any)
		if !ok {
			continue
		}
		if ref, ok := vol["configMap"].(map[string]any); ok {
			cm(str(ref["name"]), pathf("%s.volumes[%d].configMap", base, vi))
		}
		if ref, ok := vol["secret"].(map[string]any); ok {
			// A secret volume uses secretName, not name.
			sec(str(ref["secretName"]), pathf("%s.volumes[%d].secret", base, vi))
		}
		if ref, ok := vol["persistentVolumeClaim"].(map[string]any); ok {
			add(pathf("%s.volumes[%d].persistentVolumeClaim", base, vi),
				validID("v1", "PersistentVolumeClaim", namespace, str(ref["claimName"])))
		}
		// CSI volumes. On AKS this is how the Key Vault provider mounts secrets: the driver is
		// secrets-store.csi.k8s.io and volumeAttributes.secretProviderClass names a CUSTOM resource
		// this collector does not read, so the edge is emitted and resolve() reports it as
		// child-of-scanned rather than pretending the mount has no dependency.
		if csi, ok := vol["csi"].(map[string]any); ok {
			if spc := str(mapOf(csi["volumeAttributes"])["secretProviderClass"]); spc != "" {
				add(pathf("%s.volumes[%d].csi.volumeAttributes.secretProviderClass", base, vi),
					validID("secrets-store.csi.x-k8s.io/v1", "SecretProviderClass", namespace, spc))
			}
			if ref, ok := csi["nodePublishSecretRef"].(map[string]any); ok {
				sec(str(ref["name"]), pathf("%s.volumes[%d].csi.nodePublishSecretRef", base, vi))
			}
		}
		// azureFile mounts name the Secret holding the storage account key, and azureDisk names the
		// managed disk directly. Both are legacy in-tree drivers still present on real AKS clusters.
		if af, ok := vol["azureFile"].(map[string]any); ok {
			sec(str(af["secretName"]), pathf("%s.volumes[%d].azureFile.secretName", base, vi))
		}
		for pi, p := range asList(mapOf(vol["projected"])["sources"]) {
			src, ok := p.(map[string]any)
			if !ok {
				continue
			}
			if ref, ok := src["configMap"].(map[string]any); ok {
				cm(str(ref["name"]), pathf("%s.volumes[%d].projected.sources[%d].configMap", base, vi, pi))
			}
			if ref, ok := src["secret"].(map[string]any); ok {
				sec(str(ref["name"]), pathf("%s.volumes[%d].projected.sources[%d].secret", base, vi, pi))
			}
		}
	}
}

// linkIngress records the Services an Ingress routes to and the Secrets holding its TLS certificates.
// These two are what a DNS cutover depends on: the hostname is in the Ingress, and the certificate
// has to exist in the target cluster or the flip serves errors.
func linkIngress(spec map[string]any, namespace string, add func(via, id string)) {
	svc := func(name, via string) { add(via, validID("v1", "Service", namespace, name)) }
	if cls := str(spec["ingressClassName"]); cls != "" {
		add("spec.ingressClassName", validID("networking.k8s.io/v1", "IngressClass", "", cls))
	}
	if def, ok := spec["defaultBackend"].(map[string]any); ok {
		if s, ok := def["service"].(map[string]any); ok {
			svc(str(s["name"]), "spec.defaultBackend.service")
		}
	}
	for ti, t := range asList(spec["tls"]) {
		if entry, ok := t.(map[string]any); ok {
			if sn := str(entry["secretName"]); sn != "" {
				add(pathf("spec.tls[%d].secretName", ti), validID("v1", "Secret", namespace, sn))
			}
		}
	}
	for ri, r := range asList(spec["rules"]) {
		rule, ok := r.(map[string]any)
		if !ok {
			continue
		}
		for pi, p := range asList(mapOf(rule["http"])["paths"]) {
			pathEntry, ok := p.(map[string]any)
			if !ok {
				continue
			}
			if b, ok := pathEntry["backend"].(map[string]any); ok {
				if s, ok := b["service"].(map[string]any); ok {
					svc(str(s["name"]), pathf("spec.rules[%d].http.paths[%d].backend.service", ri, pi))
				}
			}
		}
	}
}

// linkBinding records which role a binding grants and to which subjects.
func linkBinding(obj map[string]any, namespace string, add func(via, id string)) {
	if ref, ok := obj["roleRef"].(map[string]any); ok {
		kind := str(ref["kind"])
		ns := namespace
		if kind == "ClusterRole" {
			ns = ""
		}
		add("roleRef", validID("rbac.authorization.k8s.io/v1", kind, ns, str(ref["name"])))
	}
	for i, s := range asList(obj["subjects"]) {
		subject, ok := s.(map[string]any)
		if !ok || str(subject["kind"]) != "ServiceAccount" {
			// Users and Groups are directory principals, not cluster objects, so there is nothing
			// in the estate for them to point at.
			continue
		}
		ns := str(subject["namespace"])
		if ns == "" {
			ns = namespace
		}
		add(pathf("subjects[%d]", i), validID("v1", "ServiceAccount", ns, str(subject["name"])))
	}
}

// resolve states the target's status RELATIVE TO THIS SCAN, mirroring azure/link.go's resolve.
//
// The middle case was missing entirely, and it is the common one. Every namespaced object's parent
// chain terminates at a Namespace this scan read, so a reference to a kind we skipped - a Flux
// HelmRelease owner, an Argo Application, a ReplicaSet while derived kinds are off - is NOT
// out-of-scan. contract/estate.go reserves out-of-scan for "cross-account, cross-tenant, global, or
// deleted", none of which describes an object sitting in a namespace we just listed. Reporting it as
// out-of-scan loses the only distinction that matters: "in a namespace we scanned but a kind we
// skipped" versus "does not exist".
func resolve(target string, known map[string]struct{}) (contract.Resolution, string) {
	if _, ok := known[target]; ok {
		return contract.ResolutionInScan, ""
	}
	// A namespaced id is apiVersion/Kind/namespace/name, so its ancestor is that Namespace. Naming it
	// keeps id parsing on this side of the boundary, exactly as ResolvedTo requires.
	if parts := strings.Split(target, "/"); len(parts) >= 2 {
		namespace := parts[len(parts)-2]
		// A cluster-scoped id is apiVersion/Kind/name, so the segment before the name is the KIND, not
		// a namespace - "storage.k8s.io/v1/StorageClass/managed-csi" would have claimed an ancestor
		// namespace called "StorageClass". Segment counting cannot tell the two apart, because a
		// grouped apiVersion contains a slash of its own. Kubernetes' own naming rules can: a kind is
		// always PascalCase, and a namespace must be a DNS-1123 label, which forbids uppercase. So
		// rejecting anything that is not a valid label is exact rather than a heuristic.
		ancestor := "v1/Namespace/" + namespace
		if _, ok := known[ancestor]; ok && ancestor != target && isDNSLabel(namespace) {
			return contract.ResolutionChildOfScanned, ancestor
		}
	}
	return contract.ResolutionOutOfScan, ""
}

// isDNSLabel reports whether s could be a namespace name: RFC 1123, so lowercase alphanumerics and
// dashes only. Every Kubernetes kind fails this on its first character.
func isDNSLabel(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
			return false
		}
	}
	return true
}

// validID builds a target id only when every part needed to identify it is present.
//
// Without this a reference missing a field produced a non-empty but unmatchable id -
// "v1/ConfigMap/prod/" for a missing name, "rbac.../v1//prod/name" for a missing kind - which `add`
// accepted and emitted as a dangling dependency. Two different malformed references could even
// collapse to the same id. azure/link.go's referenceTarget rejects malformed shapes for the same
// reason: an edge to a resource that cannot exist is worse than no edge.
func validID(apiVersion, kind, namespace, name string) string {
	if apiVersion == "" || kind == "" || name == "" {
		return ""
	}
	return objectID(kindSpec{apiVersion: apiVersion, kind: kind}, namespace, name)
}

// ownerID builds the id of an ownerReference.
//
// KNOWN LIMIT, stated because it cannot be fixed from here: an ownerReference carries
// apiVersion/kind/name/uid and NO scope, while Kubernetes permits a namespaced dependent to have a
// cluster-scoped owner. The dependent's namespace is assumed, which is right in the overwhelming
// majority and wrong for a cluster-scoped custom resource owning namespaced objects. The result is
// then an id that resolves to nothing rather than a wrong match, because a cluster-scoped owner's
// real id has one fewer segment - so the failure is a missing edge, not a false one.
func ownerID(owner map[string]any, namespace string) string {
	return validID(str(owner["apiVersion"]), str(owner["kind"]), namespace, str(owner["name"]))
}

func dedupe(sorted []contract.Dependency) []contract.Dependency {
	if len(sorted) < 2 {
		return sorted
	}
	kept := sorted[:1]
	for _, d := range sorted[1:] {
		last := kept[len(kept)-1]
		if d.From == last.From && d.Via == last.Via && d.To == last.To {
			continue
		}
		kept = append(kept, d)
	}
	return kept
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

func mapOf(v any) map[string]any {
	m, _ := v.(map[string]any)
	if m == nil {
		return map[string]any{}
	}
	return m
}

func pathf(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}
