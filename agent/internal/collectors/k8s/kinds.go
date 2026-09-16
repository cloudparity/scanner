package k8s

import "strings"

// The kinds this collector reads, listed explicitly rather than discovered.
//
// Explicit for the same reason the Azure collector lists its ARG tables: infra-scanner §3 allows no
// third option between READ and REPORTED, and a curated list can be checked against the gap list by
// a test. API discovery would read whatever a cluster happens to expose, which means a new CRD
// silently changes what a scan claims to cover.
//
// WHAT IS DELIBERATELY NOT HERE, and why - because "we did not read it" has to be a decision:
//
//	Pods, ReplicaSets      DERIVED. A Deployment creates its ReplicaSet and a ReplicaSet creates its
//	                       Pods, so restoring them is not just unnecessary, it is wrong - the
//	                       controller would fight the restore. They are read only when
//	                       PARITY_K8S_INCLUDE_DERIVED is set, because on a real cluster they are
//	                       thousands of rows of churn that no recovery plan acts on.
//	Events, Endpoints,     Ephemeral. Regenerated within seconds of a restore.
//	EndpointSlices
//	Nodes                  Infrastructure, and AKS recreates them with the node pool. The infra
//	                       collector already has the node pool's size, count and image.
//	Metrics, Leases        Runtime state, not configuration.

// kindSpec is one Kubernetes collection to read.
type kindSpec struct {
	// apiVersion as it appears in an object: "v1", "apps/v1", "networking.k8s.io/v1".
	apiVersion string
	// kind is the singular object kind: "Deployment".
	kind string
	// path is the cluster-wide collection URL, which returns objects from EVERY namespace in one
	// call. Reading per-namespace would multiply the call count by the namespace count for no gain.
	path string
	// clusterScoped marks a kind with no namespace, so Group is left empty rather than fabricated.
	clusterScoped bool
	// derived marks state a controller regenerates. Off by default - see the note above.
	derived bool
}

// resource returns the RBAC resource name - the plural the API server uses.
//
// Taken from the PATH, never pluralised from the kind. The first version did
// strings.ToLower(kind)+"s", which produces "ingresss", "ingressclasss", "storageclasss" and
// "networkpolicys" - four invalid names out of the curated list. RBAC does not validate resource
// names, so a customer pasted the rule from the gap, the ClusterRole applied cleanly, and the next
// scan was denied again. That defeated the entire reason the gap prints a rule.
func (k kindSpec) resource() string {
	if i := strings.LastIndex(k.path, "/"); i >= 0 {
		return k.path[i+1:]
	}
	return strings.ToLower(k.kind)
}

// group returns the RBAC apiGroup. The core group is written as "" in a ClusterRole, not as "v1".
func (k kindSpec) group() string {
	if i := strings.Index(k.apiVersion, "/"); i >= 0 {
		return k.apiVersion[:i]
	}
	return ""
}

// kinds is the curated list.
//
// Order is stable, which is one of the two halves of a stable scan; normalise() in translate.go is the
// other. MEASURED on the live testbed: two consecutive scans of an unchanged cluster produced 305
// resources with 0 differing documents. Only ScanMeta.scannedAt differs between them, by design.
func kinds() []kindSpec {
	return []kindSpec{
		// --- the boundaries a customer selects by ---
		{apiVersion: "v1", kind: "Namespace", path: "/api/v1/namespaces", clusterScoped: true},

		// --- workloads: the desired state a restore recreates ---
		{apiVersion: "apps/v1", kind: "Deployment", path: "/apis/apps/v1/deployments"},
		{apiVersion: "apps/v1", kind: "StatefulSet", path: "/apis/apps/v1/statefulsets"},
		{apiVersion: "apps/v1", kind: "DaemonSet", path: "/apis/apps/v1/daemonsets"},
		{apiVersion: "batch/v1", kind: "CronJob", path: "/apis/batch/v1/cronjobs"},
		{apiVersion: "batch/v1", kind: "Job", path: "/apis/batch/v1/jobs"},

		// --- how traffic reaches them, which is what a DNS cutover repoints ---
		{apiVersion: "v1", kind: "Service", path: "/api/v1/services"},
		{apiVersion: "networking.k8s.io/v1", kind: "Ingress", path: "/apis/networking.k8s.io/v1/ingresses"},
		{apiVersion: "networking.k8s.io/v1", kind: "IngressClass", path: "/apis/networking.k8s.io/v1/ingressclasses", clusterScoped: true},
		{apiVersion: "networking.k8s.io/v1", kind: "NetworkPolicy", path: "/apis/networking.k8s.io/v1/networkpolicies"},

		// --- configuration. Secret VALUES are stripped in translate; only keys survive. ---
		{apiVersion: "v1", kind: "ConfigMap", path: "/api/v1/configmaps"},
		{apiVersion: "v1", kind: "Secret", path: "/api/v1/secrets"},

		// --- storage. The PVC is the request; the data itself is a replication problem. ---
		{apiVersion: "v1", kind: "PersistentVolumeClaim", path: "/api/v1/persistentvolumeclaims"},
		// The PV is where the AZURE DISK lives: spec.csi.volumeHandle on disk.csi.azure.com is the
		// full ARM id of the managed disk, and spec.nodeAffinity is the zone it is pinned to. Without
		// it the estate can say a claim wants 8Gi of managed-csi but cannot say WHICH disk holds the
		// data - so nothing downstream can snapshot or replicate it, and DR fails for every stateful
		// app. It was previously absent AND unmentioned, which is the one thing kinds() forbids.
		{apiVersion: "v1", kind: "PersistentVolume", path: "/api/v1/persistentvolumes", clusterScoped: true},
		{apiVersion: "storage.k8s.io/v1", kind: "StorageClass", path: "/apis/storage.k8s.io/v1/storageclasses", clusterScoped: true},

		// --- scaling and availability, both of which change behaviour after a restore ---
		{apiVersion: "autoscaling/v2", kind: "HorizontalPodAutoscaler", path: "/apis/autoscaling/v2/horizontalpodautoscalers"},
		{apiVersion: "policy/v1", kind: "PodDisruptionBudget", path: "/apis/policy/v1/poddisruptionbudgets"},

		// --- admission. Both of these REJECT pod creation when absent, rather than degrading: a
		// Deployment naming a PriorityClass the new cluster lacks restores cleanly and then never
		// produces a single pod ("no PriorityClass with name X was found"). Same for RuntimeClass.
		{apiVersion: "scheduling.k8s.io/v1", kind: "PriorityClass", path: "/apis/scheduling.k8s.io/v1/priorityclasses", clusterScoped: true},
		{apiVersion: "node.k8s.io/v1", kind: "RuntimeClass", path: "/apis/node.k8s.io/v1/runtimeclasses", clusterScoped: true},

		// --- identity. A ServiceAccount annotation is where workload identity ties a pod to an
		// Azure managed identity, which is a cross-plane dependency the engine needs.
		{apiVersion: "v1", kind: "ServiceAccount", path: "/api/v1/serviceaccounts"},
		{apiVersion: "rbac.authorization.k8s.io/v1", kind: "Role", path: "/apis/rbac.authorization.k8s.io/v1/roles"},
		{apiVersion: "rbac.authorization.k8s.io/v1", kind: "RoleBinding", path: "/apis/rbac.authorization.k8s.io/v1/rolebindings"},
		{apiVersion: "rbac.authorization.k8s.io/v1", kind: "ClusterRole", path: "/apis/rbac.authorization.k8s.io/v1/clusterroles", clusterScoped: true},
		{apiVersion: "rbac.authorization.k8s.io/v1", kind: "ClusterRoleBinding", path: "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", clusterScoped: true},

		// --- derived, off unless asked for ---
		{apiVersion: "apps/v1", kind: "ReplicaSet", path: "/apis/apps/v1/replicasets", derived: true},
		{apiVersion: "v1", kind: "Pod", path: "/api/v1/pods", derived: true},
	}
}
