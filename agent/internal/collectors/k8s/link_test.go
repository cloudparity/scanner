package k8s

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/manukyanv07/parity-scanner/contract"
)

// resourceFrom builds the resource shape link() consumes: a stored document plus the type and
// namespace translate() would have derived from it.
func resourceFrom(t *testing.T, resourceType, id, namespace string, doc map[string]any) contract.Resource {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal document: %v", err)
	}
	return contract.Resource{ID: id, Type: resourceType, Group: namespace, Document: raw}
}

func hasDep(deps []contract.Dependency, to string) bool {
	for _, d := range deps {
		if d.To == to {
			return true
		}
	}
	return false
}

func TestRegistryHost(t *testing.T) {
	// The first path segment is a HOST only if it has a dot or a colon, or is exactly localhost.
	// Without that rule "library/nginx" reads as a registry called "library".
	for image, want := range map[string]string{
		"myregistry.azurecr.io/app:1.0":      "myregistry.azurecr.io",
		"mcr.microsoft.com/oss/kubernetes/x": "mcr.microsoft.com",
		"localhost:5000/app":                 "localhost:5000",
		"library/nginx:1.25":                 "",
		"nginx":                              "",
		"":                                   "",
	} {
		if got := registryHost(image); got != want {
			t.Errorf("registryHost(%q) = %q, want %q", image, got, want)
		}
	}
}

// The image is the one field that says what a workload actually runs, and on AKS it is the edge to
// Azure Container Registry: a private registry region B cannot reach leaves every pod in
// ImagePullBackOff, which is the most common way a cluster restore fails.
func TestLinkReportsImageRegistriesAndPodDependencies(t *testing.T) {
	deployment := resourceFrom(t, "apps/v1/deployment", "apps/v1/Deployment/prod/api", "prod", map[string]any{
		"spec": map[string]any{"template": map[string]any{"spec": map[string]any{
			"priorityClassName": "high",
			"runtimeClassName":  "kata",
			"containers": []any{map[string]any{
				"name": "api", "image": "myregistry.azurecr.io/api:2.1",
			}},
			"volumes": []any{map[string]any{
				"name": "secrets",
				"csi": map[string]any{
					"driver":           "secrets-store.csi.k8s.io",
					"volumeAttributes": map[string]any{"secretProviderClass": "azure-kv"},
				},
			}},
		}}},
	})

	deps, gaps := link([]contract.Resource{deployment})

	for _, want := range []string{
		"scheduling.k8s.io/v1/PriorityClass/high",
		"node.k8s.io/v1/RuntimeClass/kata",
		"secrets-store.csi.x-k8s.io/v1/SecretProviderClass/prod/azure-kv",
	} {
		if !hasDep(deps, want) {
			t.Errorf("missing dependency to %s; deps: %v", want, deps)
		}
	}

	var registry *contract.Gap
	for i := range gaps {
		if gaps[i].Target == "container-image-registries" {
			registry = &gaps[i]
		}
	}
	if registry == nil {
		t.Fatalf("no registry gap, so nothing records what the workload runs; gaps: %v", gaps)
	}
	if registry.Reason != contract.GapUnresolved {
		t.Errorf("reason = %q, want unresolved: the image was READ, it just cannot be turned into an "+
			"ARM id from inside the cluster", registry.Reason)
	}
	if !strings.Contains(registry.Detail, "myregistry.azurecr.io") {
		t.Errorf("gap does not name the registry the engine must join on: %s", registry.Detail)
	}
}

// A StatefulSet without its governing Service has pods that cannot resolve each other, so a restored
// clustered database never forms a quorum - and the failure looks like an application bug.
func TestLinkStatefulSetServiceAndStorage(t *testing.T) {
	sts := resourceFrom(t, "apps/v1/statefulset", "apps/v1/StatefulSet/prod/pg", "prod", map[string]any{
		"spec": map[string]any{
			"serviceName": "pg-headless",
			"volumeClaimTemplates": []any{map[string]any{
				"spec": map[string]any{"storageClassName": "managed-csi"},
			}},
			"template": map[string]any{"spec": map[string]any{}},
		},
	})
	deps, _ := link([]contract.Resource{sts})
	for _, want := range []string{
		"v1/Service/prod/pg-headless",
		"storage.k8s.io/v1/StorageClass/managed-csi",
	} {
		if !hasDep(deps, want) {
			t.Errorf("missing dependency to %s; deps: %v", want, deps)
		}
	}
}

// A cluster-scoped id is apiVersion/Kind/name, so the segment before the name is the KIND. Parsing a
// namespace out of it would claim an ancestor namespace called "StorageClass". A kind is always
// PascalCase and a namespace must be a lowercase DNS-1123 label, which settles it exactly.
func TestResolveDoesNotInventAnAncestorForClusterScopedTargets(t *testing.T) {
	known := map[string]struct{}{
		"v1/Namespace/prod":         {},
		"v1/Namespace/StorageClass": {},
	}
	if res, _ := resolve("storage.k8s.io/v1/StorageClass/managed-csi", known); res != contract.ResolutionOutOfScan {
		t.Errorf("cluster-scoped target resolved as %q; the kind was mistaken for a namespace", res)
	}
	res, ancestor := resolve("v1/ConfigMap/prod/app-config", known)
	if res != contract.ResolutionChildOfScanned || ancestor != "v1/Namespace/prod" {
		t.Errorf("namespaced target resolved as %q via %q, want child-of-scanned via the namespace",
			res, ancestor)
	}

	for label, want := range map[string]bool{
		"prod": true, "kube-system": true, "team-1": true,
		"StorageClass": false, "Prod": false, "": false, "ns_1": false,
		strings.Repeat("a", 64): false,
	} {
		if got := isDNSLabel(label); got != want {
			t.Errorf("isDNSLabel(%q) = %v, want %v", label, got, want)
		}
	}
}

// A PersistentVolume is where the AZURE DISK id lives, and its claimRef carries its own namespace
// because the PV itself is cluster-scoped.
func TestLinkPersistentVolumeUsesTheClaimNamespace(t *testing.T) {
	pv := resourceFrom(t, "v1/persistentvolume", "v1/PersistentVolume/pvc-9f2", "", map[string]any{
		"spec": map[string]any{
			"storageClassName": "managed-csi",
			"claimRef":         map[string]any{"namespace": "prod", "name": "data-pg-0"},
		},
	})
	deps, _ := link([]contract.Resource{pv})
	if !hasDep(deps, "v1/PersistentVolumeClaim/prod/data-pg-0") {
		t.Errorf("the PV was not linked to the claim it is bound to: %v", deps)
	}
	if !hasDep(deps, "storage.k8s.io/v1/StorageClass/managed-csi") {
		t.Errorf("the PV was not linked to its storage class: %v", deps)
	}
}
