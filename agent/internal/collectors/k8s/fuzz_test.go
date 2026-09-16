package k8s

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/manukyanv07/parity-scanner/contract"
)

// Fuzz targets for what this collector parses out of an API server's answer.
//
// The Azure fuzzers pin id parsing; here the id is built rather than parsed, so what is
// fuzzed is the object itself - the one place an arbitrary document meets code that promises
// to have stripped every Secret value out of it before it left the cluster.

// objectSeeds are the object shapes the unit tests drive translate with.
var objectSeeds = []string{
	`{}`,
	`null`,
	`"not an object"`,
	`{"metadata":{"name":"app-secret","namespace":"prod","annotations":{"kubectl.kubernetes.io/last-applied-configuration":"{\"kind\":\"Secret\",\"stringData\":{\"db-password\":\"hunter2\"}}","meta.helm.sh/release-name":"app"},"managedFields":[{"manager":"kubectl"}]},"type":"Opaque","data":{"db-password":"aHVudGVyMg=="},"stringData":{"api-key":"hunter2"}}`,
	`{"metadata":{"name":"api","namespace":"prod","resourceVersion":"1000","uid":"1f2e","generation":2,"creationTimestamp":"2026-08-13T17:00:00Z","labels":{"app":"api","n":1},"ownerReferences":[{"apiVersion":"apps/v1","kind":"ReplicaSet","name":"api-abc","controller":true},{"apiVersion":"v1","kind":"Other","name":"o"}]},"spec":{"replicas":2,"template":{"spec":{"containers":[{"image":"myregistry.azurecr.io/app:1.0","env":[{"name":"DD_API_KEY","value":"8f2c"}],"args":["--dsn=postgres://admin:pw@db/app"]}],"serviceAccountName":"api","volumes":[{"gitRepo":{"repository":"https://x:tok@github.com/x"}}]}}},"status":{"availableReplicas":2}}`,
	`{"metadata":{"name":"","namespace":"prod"}}`,
	`{"metadata":{"name":"cm","namespace":"prod"},"data":{"Http_Passwd":"pw","plain":"value","nested":{"not":"scalar"},"nothing":null}}`,
	`{"metadata":"flat","data":"flat","stringData":["list"],"spec":7}`,
	`{"metadata":{"name":"managed-csi"},"parameters":{"skuName":"Premium_LRS","key":"k"},"provisioner":"disk.csi.azure.com"}`,
	`{"metadata":{"name":"s","namespace":"prod","annotations":"flat"},"data":{"a":1,"b":true,"c":[],"d":{}}}`,
}

// FuzzTranslateObject drives one object of one kind through scrub, normalise and screen.
//
// What it pins for any object: nothing panics; the object handed in is never mutated; the
// same object translates the same way twice; the document ships as valid JSON and carries
// neither status, the volatile metadata, managedFields nor any applied-manifest
// annotation; and on a Secret every data and stringData value is RedactedValue with a
// redaction recorded per key - the one promise this collector exists to keep.
func FuzzTranslateObject(f *testing.F) {
	specs := kinds()
	for i, seed := range objectSeeds {
		f.Add(i%len(specs), []byte(seed))
		f.Add(indexOfKind(specs, "Secret"), []byte(seed))
	}
	f.Fuzz(func(t *testing.T, which int, data []byte) {
		var decoded any
		if err := json.Unmarshal(data, &decoded); err != nil {
			return
		}
		item, ok := decoded.(map[string]any)
		if !ok {
			return
		}
		index := which % len(specs)
		if index < 0 {
			index += len(specs)
		}
		spec := specs[index]
		before, err := json.Marshal(item)
		if err != nil {
			return
		}

		const cluster = "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.containerservice/managedclusters/aks"
		resources, gaps := translate(cluster, spec, []map[string]any{item})
		again, gapsAgain := translate(cluster, spec, []map[string]any{item})
		if !reflect.DeepEqual(resources, again) || !reflect.DeepEqual(gaps, gapsAgain) {
			t.Errorf("translate is not deterministic on %s", before)
		}
		if after, _ := json.Marshal(item); !bytes.Equal(before, after) {
			t.Errorf("translate mutated its input:\n before: %s\n after:  %s", before, after)
		}

		if len(resources) > 1 {
			t.Fatalf("one object produced %d resources", len(resources))
		}
		if len(resources) == 0 {
			if len(gaps) != 1 || gaps[0].Reason != contract.GapNotAttempted {
				t.Errorf("a dropped object must be declared as not-attempted, got %+v", gaps)
			}
			return
		}
		r := resources[0]

		if r.Provider != contract.ProviderK8s || r.Account != cluster {
			t.Errorf("identity not stamped: provider %q account %q", r.Provider, r.Account)
		}
		if !strings.HasPrefix(r.ID, spec.apiVersion+"/"+spec.kind+"/") || !strings.HasSuffix(r.ID, "/"+r.Name) {
			t.Errorf("ID %q is not apiVersion/Kind/[namespace/]name for %s", r.ID, r.Name)
		}
		if r.Type != strings.ToLower(r.Type) {
			t.Errorf("Type %q is not lowercased", r.Type)
		}
		if spec.clusterScoped && r.Group != "" {
			t.Errorf("cluster-scoped %s carries namespace %q", spec.kind, r.Group)
		}
		if r.ParentID == "" {
			t.Errorf("ParentID is empty; every object hangs off an owner, a namespace or the cluster")
		}

		var document map[string]any
		if err := json.Unmarshal(r.Document, &document); err != nil {
			t.Fatalf("Document is not a JSON object: %v", err)
		}
		if _, present := document["status"]; present {
			t.Error("status shipped; it is observed state and churns every scan")
		}
		if document["apiVersion"] != spec.apiVersion || document["kind"] != spec.kind {
			t.Errorf("apiVersion/kind not injected: %v/%v", document["apiVersion"], document["kind"])
		}
		if meta, ok := document["metadata"].(map[string]any); ok {
			for _, key := range volatileMetadata {
				if _, present := meta[key]; present {
					t.Errorf("metadata.%s shipped; it is volatile", key)
				}
			}
			if _, present := meta[managedFieldsKey]; present {
				t.Errorf("metadata.%s shipped", managedFieldsKey)
			}
			if annotations, ok := meta["annotations"].(map[string]any); ok {
				for _, key := range appliedManifestAnnotations {
					if _, present := annotations[key]; present {
						t.Errorf("metadata.annotations[%s] shipped; it carries a copy of the whole object", key)
					}
				}
			}
		}

		recorded := make(map[string]struct{}, len(r.Redactions))
		for _, red := range r.Redactions {
			if red.Path == "" || red.Reason == "" {
				t.Errorf("redaction with an empty path or reason: %+v", red)
			}
			recorded[red.Path] = struct{}{}
		}
		if spec.kind == "Secret" {
			for _, field := range []string{"data", "stringData"} {
				values, ok := document[field].(map[string]any)
				if !ok {
					continue
				}
				for key, value := range values {
					if value != contract.RedactedValue {
						t.Errorf("Secret %s.%s shipped as %v, want %s", field, key, value, contract.RedactedValue)
					}
					if _, ok := recorded[field+"."+key]; !ok {
						t.Errorf("Secret %s.%s was replaced but no redaction records it", field, key)
					}
				}
			}
		}

		for _, g := range gaps {
			if g.Target != r.ID || g.Reason != contract.GapUnscreened {
				t.Errorf("translate raised a gap that is not this resource's screening gap: %+v", g)
			}
		}

		// The translated resource is what link reads, so it must link without incident and
		// never point at itself.
		dependencies, _ := link([]contract.Resource{r})
		for _, d := range dependencies {
			if d.From != r.ID || d.To == r.ID || d.To == "" {
				t.Errorf("malformed dependency %+v on %q", d, r.ID)
			}
		}
	})
}

func indexOfKind(specs []kindSpec, kind string) int {
	for i, spec := range specs {
		if spec.kind == kind {
			return i
		}
	}
	return 0
}

// FuzzResolve pins the id resolution link.go performs against any target string.
//
// A child-of-scanned answer must name an ancestor the scan actually holds, and that
// ancestor must be a Namespace whose name obeys the DNS-label rule that keeps a kind from
// being mistaken for one.
func FuzzResolve(f *testing.F) {
	for _, seed := range []string{
		"", "/", "v1/Namespace/prod", "v1/ConfigMap/prod/app-config",
		"storage.k8s.io/v1/StorageClass/managed-csi", "v1/Namespace/StorageClass",
		"apps/v1/Deployment/prod/api", "v1/ConfigMap//x", "rbac.authorization.k8s.io/v1//prod/name",
		"v1/Namespace/" + strings.Repeat("a", 63), "v1/Namespace/" + strings.Repeat("a", 64),
	} {
		f.Add(seed)
	}
	known := map[string]struct{}{
		"v1/Namespace/prod":         {},
		"v1/Namespace/StorageClass": {},
		"v1/Namespace/":             {},
		"v1/ConfigMap/prod/x":       {},
	}
	f.Fuzz(func(t *testing.T, target string) {
		resolution, ancestor := resolve(target, known)
		switch resolution {
		case contract.ResolutionInScan:
			if _, ok := known[target]; !ok || ancestor != "" {
				t.Errorf("resolve(%q) = in-scan via %q, but it is not a known id", target, ancestor)
			}
		case contract.ResolutionChildOfScanned:
			if _, ok := known[ancestor]; !ok {
				t.Errorf("resolve(%q) named ancestor %q, which the scan does not hold", target, ancestor)
			}
			namespace := strings.TrimPrefix(ancestor, "v1/Namespace/")
			if namespace == ancestor || !isDNSLabel(namespace) || ancestor == target {
				t.Errorf("resolve(%q) named ancestor %q, which is not a Namespace with a DNS-label name", target, ancestor)
			}
			if parts := strings.Split(target, "/"); len(parts) < 2 || parts[len(parts)-2] != namespace {
				t.Errorf("resolve(%q) named namespace %q, which is not the id's namespace segment", target, namespace)
			}
		case contract.ResolutionOutOfScan:
			if ancestor != "" {
				t.Errorf("resolve(%q) = out-of-scan but named %q", target, ancestor)
			}
		default:
			t.Errorf("resolve(%q) = %q, which is not a Resolution", target, resolution)
		}
	})
}

// FuzzRegistryHost pins the image-reference parser: a host is returned only when the first
// path segment can be one, and it is always exactly that segment.
func FuzzRegistryHost(f *testing.F) {
	for _, seed := range []string{
		"", "nginx", "library/nginx:1.25", "myregistry.azurecr.io/app:1.0",
		"mcr.microsoft.com/oss/kubernetes/x", "localhost:5000/app", "localhost/app",
		"  spaced.io/app  ", "/leading/slash", "a:b/c", "a.b", "a:b",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, image string) {
		host := registryHost(image)
		if host == "" {
			return
		}
		if strings.Contains(host, "/") {
			t.Errorf("registryHost(%q) = %q contains a slash", image, host)
		}
		if !strings.HasPrefix(strings.TrimSpace(image), host+"/") {
			t.Errorf("registryHost(%q) = %q is not the first path segment", image, host)
		}
		if host != "localhost" && !strings.ContainsAny(host, ".:") {
			t.Errorf("registryHost(%q) = %q can only be a Docker Hub namespace", image, host)
		}
	})
}
