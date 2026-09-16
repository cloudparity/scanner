package k8s

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/manukyanv07/parity-scanner/contract"
)

const testCluster = "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.containerservice/managedclusters/aks1"

// fakeLister answers by path and records what it was asked.
type fakeLister struct {
	items map[string][]map[string]any
	errs  map[string]error
	asked []string
}

func (f *fakeLister) List(_ context.Context, path string) ([]map[string]any, error) {
	f.asked = append(f.asked, path)
	if err, ok := f.errs[path]; ok {
		return nil, err
	}
	return f.items[path], nil
}

func obj(raw string) map[string]any {
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		panic(err)
	}
	return m
}

// THE test. A Secret's value must never reach the estate, and the path that broke this in practice
// was not data or stringData - it was kubectl's own annotation.
//
// Measured against a real cluster: `kubectl apply` on a Secret with stringData writes the ENTIRE
// manifest, plaintext included, into metadata.annotations. The first version of this collector
// stripped data and stringData correctly and shipped the value anyway.
func TestSecretValueNeverReachesTheEstate(t *testing.T) {
	const plaintext = "not-a-real-password"
	secret := obj(`{
      "metadata": {
        "name": "app-secret", "namespace": "prod",
        "annotations": {
          "kubectl.kubernetes.io/last-applied-configuration":
            "{\"kind\":\"Secret\",\"stringData\":{\"db-password\":\"` + plaintext + `\"}}",
          "meta.helm.sh/release-name": "app"
        },
        "managedFields": [{"manager":"kubectl","operation":"Apply"}]
      },
      "type": "Opaque",
      "data": {"db-password": "` + base64.StdEncoding.EncodeToString([]byte(plaintext)) + `"},
      "stringData": {"api-key": "` + plaintext + `"}
    }`)

	got, gaps := translate(testCluster, kindSpec{apiVersion: "v1", kind: "Secret", path: "/api/v1/secrets"},
		[]map[string]any{secret})
	if len(got) != 1 {
		t.Fatalf("got %d resources, want 1", len(got))
	}
	// Screening may flag remaining free-form paths; what must NOT happen is a leak, asserted below.
	for _, g := range gaps {
		if g.Reason != contract.GapUnscreened {
			t.Errorf("unexpected gap: [%s] %s", g.Reason, g.Detail)
		}
	}
	body := string(got[0].Document)

	if strings.Contains(body, plaintext) {
		t.Fatalf("the plaintext secret value reached the estate: %s", body)
	}
	if strings.Contains(body, base64.StdEncoding.EncodeToString([]byte(plaintext))) {
		t.Fatal("the base64 secret value reached the estate")
	}
	if strings.Contains(body, "last-applied-configuration") {
		t.Error("kubectl's applied-manifest annotation survived, and it carries plaintext values")
	}
	if strings.Contains(body, "managedFields") {
		t.Error("managedFields survived; it is bulky bookkeeping nothing reads")
	}

	// The KEYS must survive, or a restore cannot say what has to exist.
	var d map[string]any
	if err := json.Unmarshal(got[0].Document, &d); err != nil {
		t.Fatal(err)
	}
	// An OBJECT with the key preserved and contract.RedactedValue in place of the value, because
	// contract/estate.go specifies that shape. An array of keys would change the field's type.
	masked, ok := d["data"].(map[string]any)
	if !ok {
		t.Fatalf("data = %v (%T), want an object", d["data"], d["data"])
	}
	if masked["db-password"] != contract.RedactedValue {
		t.Errorf("data.db-password = %v, want %q", masked["db-password"], contract.RedactedValue)
	}
	// An unrelated annotation must NOT be collateral damage.
	ann, _ := (d["metadata"].(map[string]any))["annotations"].(map[string]any)
	if _, ok := ann["meta.helm.sh/release-name"]; !ok {
		t.Error("an unrelated annotation was removed along with the leaking one")
	}
	// Every removal has to be declared by PATH, or the object just looks empty. Counting is not
	// enough - the fixture has a value in data AND in stringData, so there are four.
	paths := map[string]bool{}
	for _, r := range got[0].Redactions {
		paths[r.Path] = true
		if r.Reason == "" {
			t.Errorf("redaction %q carries no reason", r.Path)
		}
	}
	for _, want := range []string{
		"metadata.annotations.kubectl.kubernetes.io/last-applied-configuration",
		"metadata.managedFields",
		"data.db-password",
		"stringData.api-key",
	} {
		if !paths[want] {
			t.Errorf("removal of %q was not declared; declared: %v", want, paths)
		}
	}
}

// The leak is not Secret-specific: an applied manifest can embed a credential on any kind.
func TestAppliedManifestAnnotationIsStrippedFromEveryKind(t *testing.T) {
	cm := obj(`{"metadata":{"name":"c","namespace":"prod","annotations":{
	  "kubectl.kubernetes.io/last-applied-configuration":"{\"data\":{\"pw\":\"leaked-here\"}}"}},
	  "data":{"k":"v"}}`)
	got, _ := translate(testCluster, kindSpec{apiVersion: "v1", kind: "ConfigMap"}, []map[string]any{cm})
	if strings.Contains(string(got[0].Document), "leaked-here") {
		t.Fatal("an applied-manifest annotation leaked through a non-Secret kind")
	}
}

// Account is the join to the infra estate. Without it a Deployment cannot be tied to its cluster and
// the graph breaks at the plane boundary (AD-025).
func TestIdentitySchemeJoinsToTheInfraEstate(t *testing.T) {
	dep := obj(`{"metadata":{"name":"api","namespace":"prod","labels":{"app":"api"}},
	  "spec":{"template":{"spec":{"containers":[{"name":"c"}]}}}}`)
	got, _ := translate(testCluster, kindSpec{apiVersion: "apps/v1", kind: "Deployment"},
		[]map[string]any{dep})
	r := got[0]
	if r.ID != "apps/v1/Deployment/prod/api" {
		t.Errorf("id = %q", r.ID)
	}
	if r.Type != "apps/v1/deployment" {
		t.Errorf("type = %q, want it lowercased for the type table", r.Type)
	}
	if r.Account != testCluster {
		t.Errorf("account = %q, want the cluster's ARM id", r.Account)
	}
	if r.Group != "prod" {
		t.Errorf("group = %q, want the namespace", r.Group)
	}
	if r.ParentID != "v1/Namespace/prod" {
		t.Errorf("parentId = %q, want the namespace", r.ParentID)
	}
	if r.Provider != contract.ProviderK8s {
		t.Errorf("provider = %q", r.Provider)
	}
	if r.Tags["app"] != "api" {
		t.Errorf("labels did not become tags: %v", r.Tags)
	}
}

// IDs are case-sensitive, unlike Azure: two objects differing only in case are two objects.
func TestIDsAreVerbatimNotLowercased(t *testing.T) {
	got, _ := translate(testCluster, kindSpec{apiVersion: "apps/v1", kind: "Deployment"},
		[]map[string]any{obj(`{"metadata":{"name":"API","namespace":"Prod"}}`)})
	if got[0].ID != "apps/v1/Deployment/Prod/API" {
		t.Errorf("id = %q, want it verbatim", got[0].ID)
	}
}

// An owned object parents to its OWNER, not merely to its namespace.
func TestOwnedObjectParentsToItsOwner(t *testing.T) {
	rs := obj(`{"metadata":{"name":"api-abc","namespace":"prod","ownerReferences":[
	  {"apiVersion":"apps/v1","kind":"Deployment","name":"api"}]}}`)
	got, _ := translate(testCluster, kindSpec{apiVersion: "apps/v1", kind: "ReplicaSet"},
		[]map[string]any{rs})
	if got[0].ParentID != "apps/v1/Deployment/prod/api" {
		t.Errorf("parentId = %q, want the owning Deployment", got[0].ParentID)
	}
}

// A cluster-scoped object hangs off the CLUSTER, which is what anchors the plane.
func TestClusterScopedObjectParentsToTheCluster(t *testing.T) {
	got, _ := translate(testCluster,
		kindSpec{apiVersion: "v1", kind: "Namespace", clusterScoped: true},
		[]map[string]any{obj(`{"metadata":{"name":"prod"}}`)})
	if got[0].ParentID != testCluster {
		t.Errorf("parentId = %q, want the cluster", got[0].ParentID)
	}
	if got[0].Group != "" {
		t.Errorf("group = %q, want empty for a cluster-scoped object", got[0].Group)
	}
}

// The dependencies that decide whether a restored workload starts at all.
func TestWorkloadDependenciesAreFound(t *testing.T) {
	resources, _ := translate(testCluster, kindSpec{apiVersion: "apps/v1", kind: "Deployment"},
		[]map[string]any{obj(`{"metadata":{"name":"api","namespace":"prod"},"spec":{"template":{"spec":{
		  "serviceAccountName":"api-sa",
		  "imagePullSecrets":[{"name":"registry-cred"}],
		  "containers":[{"name":"c",
		    "envFrom":[{"configMapRef":{"name":"api-config"}},{"secretRef":{"name":"api-env"}}],
		    "env":[{"name":"P","valueFrom":{"secretKeyRef":{"name":"db-creds","key":"pw"}}}]}],
		  "volumes":[
		    {"name":"v1","configMap":{"name":"vol-config"}},
		    {"name":"v2","secret":{"secretName":"vol-secret"}},
		    {"name":"v3","persistentVolumeClaim":{"claimName":"data"}}]}}}}`)})
	deps, _ := link(testCluster, resources)

	want := map[string]string{
		"spec.template.spec.serviceAccountName":                          "v1/ServiceAccount/prod/api-sa",
		"spec.template.spec.imagePullSecrets[0]":                         "v1/Secret/prod/registry-cred",
		"spec.template.spec.containers[0].envFrom[0].configMapRef":       "v1/ConfigMap/prod/api-config",
		"spec.template.spec.containers[0].envFrom[1].secretRef":          "v1/Secret/prod/api-env",
		"spec.template.spec.containers[0].env[0].valueFrom.secretKeyRef": "v1/Secret/prod/db-creds",
		"spec.template.spec.volumes[0].configMap":                        "v1/ConfigMap/prod/vol-config",
		"spec.template.spec.volumes[1].secret":                           "v1/Secret/prod/vol-secret",
		"spec.template.spec.volumes[2].persistentVolumeClaim":            "v1/PersistentVolumeClaim/prod/data",
	}
	found := map[string]string{}
	for _, d := range deps {
		found[d.Via] = d.To
	}
	for via, to := range want {
		if found[via] != to {
			t.Errorf("via %q = %q, want %q", via, found[via], to)
		}
	}
}

// An Ingress is what a DNS cutover repoints, so its Service and its TLS Secret both matter: without
// the certificate in the target cluster the flip serves errors.
func TestIngressLinksToItsServiceAndTLSSecret(t *testing.T) {
	resources, _ := translate(testCluster, kindSpec{apiVersion: "networking.k8s.io/v1", kind: "Ingress"},
		[]map[string]any{obj(`{"metadata":{"name":"web","namespace":"prod"},"spec":{
		  "ingressClassName":"nginx",
		  "tls":[{"hosts":["app.example.com"],"secretName":"app-tls"}],
		  "rules":[{"host":"app.example.com","http":{"paths":[
		    {"path":"/","backend":{"service":{"name":"api","port":{"number":80}}}}]}}]}}`)})
	deps, _ := link(testCluster, resources)
	found := map[string]string{}
	for _, d := range deps {
		found[d.Via] = d.To
	}
	for via, to := range map[string]string{
		"spec.tls[0].secretName":                      "v1/Secret/prod/app-tls",
		"spec.rules[0].http.paths[0].backend.service": "v1/Service/prod/api",
		"spec.ingressClassName":                       "networking.k8s.io/v1/IngressClass/nginx",
	} {
		if found[via] != to {
			t.Errorf("via %q = %q, want %q", via, found[via], to)
		}
	}
}

// Pods and ReplicaSets are DERIVED - a controller recreates them - so restoring them is wrong. Off
// by default, and the omission is declared rather than silent.
func TestDerivedKindsAreSkippedAndDeclared(t *testing.T) {
	f := &fakeLister{items: map[string][]map[string]any{}}
	c := &Collector{clusterID: testCluster, lister: f}
	_, _, gaps, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range f.asked {
		if strings.HasSuffix(path, "/pods") || strings.HasSuffix(path, "/replicasets") {
			t.Errorf("a derived kind was listed by default: %s", path)
		}
	}
	var declared bool
	for _, g := range gaps {
		if strings.HasSuffix(g.Target, "/derived-objects") {
			declared = true
			if !strings.Contains(g.Detail, "PARITY_K8S_INCLUDE_DERIVED") {
				t.Error("the gap does not say how to include them")
			}
		}
	}
	if !declared {
		t.Error("skipping derived kinds was not declared as a gap")
	}
}

func TestDerivedKindsAreReadWhenAsked(t *testing.T) {
	f := &fakeLister{items: map[string][]map[string]any{}}
	c := &Collector{clusterID: testCluster, lister: f, includeDerived: true}
	if _, _, _, err := c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	var pods bool
	for _, p := range f.asked {
		if strings.HasSuffix(p, "/pods") {
			pods = true
		}
	}
	if !pods {
		t.Error("pods were not listed even though derived kinds were requested")
	}
}

// A denial must name the exact ClusterRole rule to add. Telling a customer to "widen RBAC" is not
// actionable; naming the apiGroup, resource and verb is.
func TestDeniedKindNamesTheClusterRoleRule(t *testing.T) {
	f := &fakeLister{
		items: map[string][]map[string]any{},
		errs: map[string]error{
			"/apis/apps/v1/deployments": &apiError{status: 403,
				body: `{"kind":"Status","reason":"Forbidden","message":"deployments.apps is forbidden"}`},
		},
	}
	c := &Collector{clusterID: testCluster, lister: f}
	_, _, gaps, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, g := range gaps {
		if !strings.HasSuffix(g.Target, "apps/v1/Deployment") {
			continue
		}
		found = true
		if g.Reason != contract.GapPermissionDenied {
			t.Errorf("reason = %q, want permission-denied", g.Reason)
		}
		for _, want := range []string{`apiGroups: ["apps"]`, `resources: ["deployments"]`, "verbs: [list]"} {
			if !strings.Contains(g.Detail, want) {
				t.Errorf("the gap does not contain %q: %s", want, g.Detail)
			}
		}
	}
	if !found {
		t.Error("a denied kind produced no gap")
	}
}

// A kind this cluster does not serve is a FACT, not a permission problem - and saying so wrongly
// would send a customer to change RBAC that is already correct.
func TestUnservedKindIsNotAPermissionProblem(t *testing.T) {
	f := &fakeLister{
		items: map[string][]map[string]any{},
		errs:  map[string]error{"/apis/autoscaling/v2/horizontalpodautoscalers": &apiError{status: 404, body: "404 page not found"}},
	}
	c := &Collector{clusterID: testCluster, lister: f}
	_, _, gaps, _ := c.Collect(context.Background())
	for _, g := range gaps {
		if strings.HasSuffix(g.Target, "HorizontalPodAutoscaler") && g.Reason == contract.GapPermissionDenied {
			t.Error("a kind the cluster does not serve was reported as a permission problem")
		}
	}
}

// Without the cluster id nothing has an account, so the estate could never join the infra plane.
func TestClusterIDIsRequired(t *testing.T) {
	c := &Collector{lister: &fakeLister{}}
	if _, _, _, err := c.Collect(context.Background()); err == nil {
		t.Fatal("Collect succeeded with no cluster id")
	}
}

// Same cluster in, same bytes out - the API returns objects in an unstable order.
func TestOutputIsDeterministic(t *testing.T) {
	items := []map[string]any{
		obj(`{"metadata":{"name":"zebra","namespace":"prod"}}`),
		obj(`{"metadata":{"name":"alpha","namespace":"prod"}}`),
		obj(`{"metadata":{"name":"middle","namespace":"prod"}}`),
	}
	first, _ := translate(testCluster, kindSpec{apiVersion: "v1", kind: "ConfigMap"}, items)
	for i := 0; i < 20; i++ {
		again, _ := translate(testCluster, kindSpec{apiVersion: "v1", kind: "ConfigMap"}, items)
		for j := range first {
			if again[j].ID != first[j].ID {
				t.Fatalf("run %d differs at %d: %s vs %s", i, j, again[j].ID, first[j].ID)
			}
		}
	}
	if first[0].Name != "alpha" {
		t.Errorf("not sorted: first is %q", first[0].Name)
	}
}

// An object with no name cannot be referenced or recreated, so it is reported rather than dropped.
func TestUnnamedObjectIsReported(t *testing.T) {
	_, gaps := translate(testCluster, kindSpec{apiVersion: "v1", kind: "ConfigMap"},
		[]map[string]any{obj(`{"metadata":{"namespace":"prod"}}`)})
	if len(gaps) != 1 || gaps[0].Reason != contract.GapNotAttempted {
		t.Fatalf("gaps = %+v, want one not-attempted", gaps)
	}
}

// Every kind in the list must be reachable, or the list is lying about coverage.
func TestEveryKindHasAPath(t *testing.T) {
	seen := map[string]bool{}
	for _, k := range kinds() {
		if k.path == "" || !strings.HasPrefix(k.path, "/") {
			t.Errorf("%s/%s has no usable path: %q", k.apiVersion, k.kind, k.path)
		}
		id := k.apiVersion + "/" + k.kind
		if seen[id] {
			t.Errorf("%s is listed twice", id)
		}
		seen[id] = true
	}
	if len(kinds()) < 15 {
		t.Errorf("only %d kinds listed; the curated set should be broader", len(kinds()))
	}
}

// A RoleBinding is how a workload gets its in-cluster permissions. Restore the workload without it
// and the pods start and then fail every API call they make.
func TestBindingLinksToItsRoleAndSubjects(t *testing.T) {
	resources, _ := translate(testCluster,
		kindSpec{apiVersion: "rbac.authorization.k8s.io/v1", kind: "RoleBinding"},
		[]map[string]any{obj(`{"metadata":{"name":"api-rb","namespace":"prod"},
		  "roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"api-role"},
		  "subjects":[
		    {"kind":"ServiceAccount","name":"api-sa"},
		    {"kind":"ServiceAccount","name":"other-sa","namespace":"staging"},
		    {"kind":"User","name":"someone@example.com"}]}`)})
	deps, _ := link(testCluster, resources)
	found := map[string]string{}
	for _, d := range deps {
		found[d.Via] = d.To
	}
	for via, to := range map[string]string{
		"roleRef":     "rbac.authorization.k8s.io/v1/Role/prod/api-role",
		"subjects[0]": "v1/ServiceAccount/prod/api-sa",
		// An explicit namespace on a subject wins over the binding's own.
		"subjects[1]": "v1/ServiceAccount/staging/other-sa",
	} {
		if found[via] != to {
			t.Errorf("via %q = %q, want %q", via, found[via], to)
		}
	}
	// A User is a directory principal, not a cluster object, so there is nothing to point at.
	if _, ok := found["subjects[2]"]; ok {
		t.Error("a User subject produced a dependency, but no such object exists in the estate")
	}
}

// A ClusterRoleBinding's roleRef is cluster-scoped, so it must NOT be namespaced.
func TestClusterRoleBindingRoleRefIsNotNamespaced(t *testing.T) {
	resources, _ := translate(testCluster,
		kindSpec{apiVersion: "rbac.authorization.k8s.io/v1", kind: "ClusterRoleBinding", clusterScoped: true},
		[]map[string]any{obj(`{"metadata":{"name":"crb"},
		  "roleRef":{"kind":"ClusterRole","name":"view"},
		  "subjects":[{"kind":"ServiceAccount","name":"sa","namespace":"prod"}]}`)})
	deps, _ := link(testCluster, resources)
	for _, d := range deps {
		if d.Via == "roleRef" && d.To != "rbac.authorization.k8s.io/v1/ClusterRole/view" {
			t.Errorf("roleRef = %q, want an unnamespaced ClusterRole id", d.To)
		}
	}
}

// A CronJob keeps its pod spec two levels deeper than everything else.
func TestCronJobPodSpecIsReached(t *testing.T) {
	resources, _ := translate(testCluster, kindSpec{apiVersion: "batch/v1", kind: "CronJob"},
		[]map[string]any{obj(`{"metadata":{"name":"nightly","namespace":"prod"},"spec":{"jobTemplate":{
		  "spec":{"template":{"spec":{"containers":[{"name":"c",
		    "envFrom":[{"secretRef":{"name":"job-creds"}}]}]}}}}}}`)})
	deps, _ := link(testCluster, resources)
	var found bool
	for _, d := range deps {
		if d.To == "v1/Secret/prod/job-creds" {
			found = true
			if !strings.HasPrefix(d.Via, "spec.jobTemplate.spec.template.spec") {
				t.Errorf("via = %q, want the jobTemplate path", d.Via)
			}
		}
	}
	if !found {
		t.Error("a CronJob's secret reference was not found")
	}
}

// A bare Pod has no template to reach through: spec IS the pod spec.
func TestBarePodSpecIsReadDirectly(t *testing.T) {
	resources, _ := translate(testCluster, kindSpec{apiVersion: "v1", kind: "Pod"},
		[]map[string]any{obj(`{"metadata":{"name":"p","namespace":"prod"},
		  "spec":{"serviceAccountName":"pod-sa","containers":[{"name":"c"}]}}`)})
	deps, _ := link(testCluster, resources)
	var found bool
	for _, d := range deps {
		if d.To == "v1/ServiceAccount/prod/pod-sa" && d.Via == "spec.serviceAccountName" {
			found = true
		}
	}
	if !found {
		t.Errorf("a bare Pod's serviceAccountName was not linked: %+v", deps)
	}
}

// A PVC's StorageClass decides what disk a restore provisions - and a class that does not exist in
// the target region leaves the workload pending forever.
func TestPVCLinksToItsStorageClass(t *testing.T) {
	resources, _ := translate(testCluster, kindSpec{apiVersion: "v1", kind: "PersistentVolumeClaim"},
		[]map[string]any{obj(`{"metadata":{"name":"data","namespace":"prod"},
		  "spec":{"storageClassName":"managed-csi","resources":{"requests":{"storage":"8Gi"}}}}`)})
	deps, _ := link(testCluster, resources)
	if len(deps) != 1 || deps[0].To != "storage.k8s.io/v1/StorageClass/managed-csi" {
		t.Errorf("deps = %+v, want one link to the StorageClass", deps)
	}
}

func TestHPALinksToWhatItScales(t *testing.T) {
	resources, _ := translate(testCluster,
		kindSpec{apiVersion: "autoscaling/v2", kind: "HorizontalPodAutoscaler"},
		[]map[string]any{obj(`{"metadata":{"name":"api-hpa","namespace":"prod"},
		  "spec":{"scaleTargetRef":{"apiVersion":"apps/v1","kind":"Deployment","name":"api"},
		  "minReplicas":2,"maxReplicas":10}}`)})
	deps, _ := link(testCluster, resources)
	if len(deps) != 1 || deps[0].To != "apps/v1/Deployment/prod/api" {
		t.Errorf("deps = %+v, want one link to the scaled Deployment", deps)
	}
}

// Workload identity ties a ServiceAccount to an Azure managed identity by CLIENT id, which is a GUID
// and not a resource id - so this collector cannot resolve it, and says so rather than dropping it.
func TestWorkloadIdentityAnnotationIsReported(t *testing.T) {
	resources, _ := translate(testCluster, kindSpec{apiVersion: "v1", kind: "ServiceAccount"},
		[]map[string]any{obj(`{"metadata":{"name":"api-sa","namespace":"prod","annotations":{
		  "azure.workload.identity/client-id":"3d1310f7-0ca3-4f69-acb9-da82ec15cea7"}}}`)})
	_, gaps := link(testCluster, resources)
	var found bool
	for _, g := range gaps {
		if strings.Contains(g.Detail, "3d1310f7-0ca3-4f69-acb9-da82ec15cea7") {
			found = true
			if !strings.Contains(g.Detail, "infra plane") {
				t.Errorf("the gap does not say the engine can join it: %q", g.Detail)
			}
		}
	}
	if !found {
		t.Errorf("the workload identity binding was not reported: %+v", gaps)
	}
}

// A reference to something outside the scan must be marked, not silently treated as present.
func TestUnresolvedReferenceIsOutOfScan(t *testing.T) {
	resources, _ := translate(testCluster, kindSpec{apiVersion: "apps/v1", kind: "Deployment"},
		[]map[string]any{obj(`{"metadata":{"name":"api","namespace":"prod"},"spec":{"template":{"spec":{
		  "containers":[{"name":"c","envFrom":[{"configMapRef":{"name":"never-collected"}}]}]}}}}`)})
	deps, _ := link(testCluster, resources)
	if len(deps) != 1 {
		t.Fatalf("deps = %+v", deps)
	}
	if deps[0].Resolution != contract.ResolutionOutOfScan {
		t.Errorf("resolution = %q, want out-of-scan", deps[0].Resolution)
	}
}

// One string can name the same target twice; that is one dependency, not two.
func TestDuplicateDependenciesCollapse(t *testing.T) {
	resources, _ := translate(testCluster, kindSpec{apiVersion: "apps/v1", kind: "Deployment"},
		[]map[string]any{obj(`{"metadata":{"name":"api","namespace":"prod"},"spec":{"template":{"spec":{
		  "containers":[
		    {"name":"a","envFrom":[{"configMapRef":{"name":"cfg"}}]},
		    {"name":"b","envFrom":[{"configMapRef":{"name":"cfg"}}]}]}}}}`)})
	deps, _ := link(testCluster, resources)
	// Two containers, same ConfigMap, DIFFERENT paths - so two dependencies is correct here. What must
	// never happen is the identical triple appearing twice.
	seen := map[string]int{}
	for _, d := range deps {
		seen[d.From+"|"+d.Via+"|"+d.To]++
	}
	for k, n := range seen {
		if n > 1 {
			t.Errorf("%s appears %d times", k, n)
		}
	}
}

// An unreadable stored document must be reported, not skipped.
func TestUnreadableDocumentIsReported(t *testing.T) {
	_, gaps := link(testCluster, []contract.Resource{{
		ID: "apps/v1/Deployment/prod/api", Type: "apps/v1/deployment",
		Document: []byte("{not json"),
	}})
	if len(gaps) != 1 || gaps[0].Reason != contract.GapNotAttempted {
		t.Fatalf("gaps = %+v, want one not-attempted", gaps)
	}
}

// The scrub is triggered by kindSpec.kind being exactly "Secret". Nothing tied that string to the
// entry in kinds(), so renaming or lowercasing it there would ship every secret value in the cluster
// with the whole suite still green. An adversarial review called this out as one typo deep.
func TestTheSecretKindSpecStillMatchesWhatScrubLooksFor(t *testing.T) {
	var found bool
	for _, k := range kinds() {
		if k.apiVersion == "v1" && k.kind == "Secret" {
			found = true
			if k.path != "/api/v1/secrets" {
				t.Errorf("Secret path = %q", k.path)
			}
		}
	}
	if !found {
		t.Fatal("kinds() has no entry with kind exactly \"Secret\" - scrub() keys off that string, " +
			"so secret VALUES would ship in plaintext")
	}
	// And prove the coupling end to end: a Secret fetched through the real kinds() entry is scrubbed.
	var spec kindSpec
	for _, k := range kinds() {
		if k.kind == "Secret" {
			spec = k
		}
	}
	got, _ := translate(testCluster, spec, []map[string]any{
		obj(`{"metadata":{"name":"s","namespace":"prod"},"data":{"pw":"c2VjcmV0"}}`)})
	if strings.Contains(string(got[0].Document), "c2VjcmV0") {
		t.Fatal("a Secret routed through the real kinds() entry was NOT scrubbed")
	}
}

// A literal credential in a pod spec is the most common way one leaves a cluster, and it cannot be
// redacted without breaking the graph. So it must be FLAGGED - values ship, and the estate says
// nobody screened them.
func TestLiteralValuesInPodSpecsAreFlaggedNotSilentlyShipped(t *testing.T) {
	resources, gaps := translate(testCluster, kindSpec{apiVersion: "apps/v1", kind: "Deployment"},
		[]map[string]any{obj(`{"metadata":{"name":"api","namespace":"prod"},"spec":{"template":{"spec":{
		  "initContainers":[{"name":"m","args":["--dsn=postgres://admin:Sup3rS3cret@db/app"]}],
		  "containers":[{"name":"c","env":[{"name":"DD_API_KEY","value":"8f2c-real-key"}]}]}}}}`)})

	// NOT redacted: blanking these would also blank serviceAccountName and every *Ref name the
	// dependency graph is built from.
	if !strings.Contains(string(resources[0].Document), "Sup3rS3cret") {
		t.Error("the value was redacted; §2.4 is explicit that over-redaction is worse than none")
	}
	var flagged *contract.Gap
	for i, g := range gaps {
		if g.Reason == contract.GapUnscreened {
			flagged = &gaps[i]
		}
	}
	if flagged == nil {
		t.Fatalf("a pod spec with literal env values and args produced no unscreened gap: %+v", gaps)
	}
	for _, want := range []string{"env[0].value", "args[0]"} {
		if !strings.Contains(flagged.Detail, want) {
			t.Errorf("the gap does not name %q: %s", want, flagged.Detail)
		}
	}
}

// ConfigMaps are shipped whole by design, so they must be flagged - otherwise one full of passwords
// is indistinguishable from an empty one.
func TestConfigMapDataIsFlagged(t *testing.T) {
	_, gaps := translate(testCluster, kindSpec{apiVersion: "v1", kind: "ConfigMap"},
		[]map[string]any{obj(`{"metadata":{"name":"c","namespace":"prod"},
		  "data":{"Http_Passwd":"hunter2","log_level":"info"}}`)})
	var flagged bool
	for _, g := range gaps {
		if g.Reason == contract.GapUnscreened && strings.Contains(g.Detail, "data.Http_Passwd") {
			flagged = true
		}
	}
	if !flagged {
		t.Errorf("ConfigMap data was shipped with no unscreened gap: %+v", gaps)
	}
}

// A StorageClass is cluster-scoped, so one unscreened parameter is a global leak.
func TestStorageClassParametersAreFlagged(t *testing.T) {
	_, gaps := translate(testCluster,
		kindSpec{apiVersion: "storage.k8s.io/v1", kind: "StorageClass", clusterScoped: true},
		[]map[string]any{obj(`{"metadata":{"name":"legacy"},"parameters":{"restuserkey":"abc123"}}`)})
	var flagged bool
	for _, g := range gaps {
		if g.Reason == contract.GapUnscreened && strings.Contains(g.Detail, "parameters.restuserkey") {
			flagged = true
		}
	}
	if !flagged {
		t.Errorf("StorageClass parameters were shipped with no unscreened gap: %+v", gaps)
	}
}

// A path that WAS redacted must not also be reported as unscreened - that would claim a field was
// shipped unchecked when it was in fact removed.
func TestRedactedPathsAreNotAlsoReportedAsUnscreened(t *testing.T) {
	_, gaps := translate(testCluster, kindSpec{apiVersion: "v1", kind: "Secret"},
		[]map[string]any{obj(`{"metadata":{"name":"s","namespace":"prod"},"data":{"pw":"c2VjcmV0"}}`)})
	for _, g := range gaps {
		if g.Reason == contract.GapUnscreened && strings.Contains(g.Detail, "data.pw") {
			t.Errorf("a redacted path was also reported unscreened: %s", g.Detail)
		}
	}
}

// The other whole-object annotations, one per tool that writes them.
func TestEveryAppliedManifestAnnotationIsStripped(t *testing.T) {
	for _, key := range appliedManifestAnnotations {
		raw := `{"metadata":{"name":"s","namespace":"prod","annotations":{` +
			`"` + key + `":"leaked-` + "value" + `"}},"data":{"k":"dg=="}}`
		got, _ := translate(testCluster, kindSpec{apiVersion: "v1", kind: "Secret"},
			[]map[string]any{obj(raw)})
		if strings.Contains(string(got[0].Document), "leaked-value") {
			t.Errorf("%s was not stripped", key)
		}
		var declared bool
		for _, r := range got[0].Redactions {
			if strings.HasSuffix(r.Path, key) {
				declared = true
			}
		}
		if !declared {
			t.Errorf("stripping %s was not declared as a redaction", key)
		}
	}
}

// The screener must not fire on ordinary objects, or it buries the findings it exists to surface.
// "data." is a substring of "metadata.name", so substring matching flagged EVERY object in the
// cluster - including a Namespace with nothing but a name.
func TestScreenerDoesNotFireOnOrdinaryObjects(t *testing.T) {
	for _, fixture := range []struct {
		kind kindSpec
		raw  string
	}{
		{kindSpec{apiVersion: "v1", kind: "Namespace", clusterScoped: true},
			`{"metadata":{"name":"prod","labels":{"env":"prod"}}}`},
		{kindSpec{apiVersion: "v1", kind: "Service"},
			`{"metadata":{"name":"api","namespace":"prod"},"spec":{"selector":{"app":"api"},"ports":[{"port":80}]}}`},
		{kindSpec{apiVersion: "apps/v1", kind: "Deployment"},
			// envFrom holds only REFERENCES, so it must not be mistaken for env.
			`{"metadata":{"name":"api","namespace":"prod"},"spec":{"template":{"spec":{"containers":[
			  {"name":"c","envFrom":[{"configMapRef":{"name":"cfg"}}]}]}}}}`},
	} {
		_, gaps := translate(testCluster, fixture.kind, []map[string]any{obj(fixture.raw)})
		for _, g := range gaps {
			if g.Reason == contract.GapUnscreened {
				t.Errorf("%s was flagged unscreened with nothing free-form in it: %s",
					fixture.kind.kind, g.Detail)
			}
		}
	}
}

// The gap prints an RBAC rule a customer pastes. Four kinds pluralised wrongly by
// strings.ToLower(kind)+"s" - ingresss, ingressclasss, storageclasss, networkpolicys - and RBAC does
// not validate resource names, so the ClusterRole applied cleanly and the next scan was denied again.
func TestTheRBACRuleInAGapIsActuallyValid(t *testing.T) {
	for _, k := range kinds() {
		// The path's last segment IS the plural the API server serves, by construction.
		if got, want := k.resource(), k.path[strings.LastIndex(k.path, "/")+1:]; got != want {
			t.Errorf("%s resource() = %q, want %q", k.kind, got, want)
		}
		if naive := strings.ToLower(k.kind) + "s"; naive != k.resource() {
			t.Logf("  %s: naive pluralisation %q would have been wrong (correct %q)",
				k.kind, naive, k.resource())
		}
		if k.group() == "v1" {
			t.Errorf("%s group() = %q; the core group is \"\" in RBAC, never \"v1\"", k.kind, k.group())
		}
	}
	// And end to end through the gap text.
	f := &fakeLister{items: map[string][]map[string]any{}, errs: map[string]error{
		"/apis/networking.k8s.io/v1/ingresses": &apiError{status: 403, body: "forbidden"},
	}}
	c := &Collector{clusterID: testCluster, lister: f}
	_, _, gaps, _ := c.Collect(context.Background())
	for _, g := range gaps {
		if g.Reason != contract.GapPermissionDenied {
			continue
		}
		if !strings.Contains(g.Detail, `resources: ["ingresses"]`) {
			t.Errorf("the gap prints an invalid resource name: %s", g.Detail)
		}
		if strings.Contains(g.Detail, "ingresss") {
			t.Error("the gap still prints the triple-s plural")
		}
	}
}

// A reference to a kind we skipped is NOT out-of-scan: its namespace was scanned. The contract
// reserves out-of-scan for cross-account, global or deleted, and losing that distinction loses the
// only thing worth knowing here.
func TestUnscannedKindInAScannedNamespaceIsChildOfScanned(t *testing.T) {
	resources, _ := translate(testCluster,
		kindSpec{apiVersion: "v1", kind: "Namespace", clusterScoped: true},
		[]map[string]any{obj(`{"metadata":{"name":"prod"}}`)})
	owned, _ := translate(testCluster, kindSpec{apiVersion: "v1", kind: "Secret"},
		[]map[string]any{obj(`{"metadata":{"name":"s","namespace":"prod","ownerReferences":[
		  {"apiVersion":"helm.toolkit.fluxcd.io/v2","kind":"HelmRelease","name":"app"}]}}`)})
	deps, _ := link(testCluster, append(resources, owned...))

	if len(deps) != 1 {
		t.Fatalf("deps = %+v, want one owner edge", deps)
	}
	if deps[0].Resolution != contract.ResolutionChildOfScanned {
		t.Errorf("resolution = %q, want child-of-scanned (the HelmRelease's namespace WAS scanned)",
			deps[0].Resolution)
	}
	// The contract requires child-of-scanned to name the ancestor.
	if deps[0].ResolvedTo != "v1/Namespace/prod" {
		t.Errorf("resolvedTo = %q, want the scanned namespace", deps[0].ResolvedTo)
	}
}

func TestOutOfScanCarriesNoResolvedTo(t *testing.T) {
	resources, _ := translate(testCluster, kindSpec{apiVersion: "v1", kind: "Secret"},
		[]map[string]any{obj(`{"metadata":{"name":"s","namespace":"unscanned-ns","ownerReferences":[
		  {"apiVersion":"g/v1","kind":"Thing","name":"t"}]}}`)})
	deps, _ := link(testCluster, resources)
	for _, d := range deps {
		if d.Resolution == contract.ResolutionOutOfScan && d.ResolvedTo != "" {
			t.Errorf("out-of-scan carries resolvedTo %q", d.ResolvedTo)
		}
	}
}

// A reference missing a field produced a non-empty but unmatchable id, emitted as a dangling edge -
// and two different malformed references could collapse to the same id.
func TestMalformedReferencesProduceNoEdge(t *testing.T) {
	for name, raw := range map[string]string{
		"envFrom configMapRef with no name": `{"metadata":{"name":"a","namespace":"prod"},"spec":{"template":{"spec":{
		  "containers":[{"name":"c","envFrom":[{"configMapRef":{}}]}]}}}}`,
		"owner with no kind": `{"metadata":{"name":"b","namespace":"prod","ownerReferences":[
		  {"apiVersion":"apps/v1","name":"x"}]}}`,
		"owner with no apiVersion": `{"metadata":{"name":"c","namespace":"prod","ownerReferences":[
		  {"kind":"Deployment","name":"x"}]}}`,
	} {
		resources, _ := translate(testCluster, kindSpec{apiVersion: "apps/v1", kind: "Deployment"},
			[]map[string]any{obj(raw)})
		deps, _ := link(testCluster, resources)
		for _, d := range deps {
			// A well-formed k8s id has no empty segment.
			for _, seg := range strings.Split(d.To, "/") {
				if seg == "" {
					t.Errorf("%s produced a malformed target %q via %q", name, d.To, d.Via)
				}
			}
		}
	}
}

// apiVersion is OPTIONAL in CrossVersionObjectReference, and omitting it produced "/Deployment/..."
// which can never match - silently turning the HPA edge into a dangling reference.
func TestHPAWithNoAPIVersionStillResolves(t *testing.T) {
	target, _ := translate(testCluster, kindSpec{apiVersion: "apps/v1", kind: "Deployment"},
		[]map[string]any{obj(`{"metadata":{"name":"api","namespace":"prod"}}`)})
	hpa, _ := translate(testCluster, kindSpec{apiVersion: "autoscaling/v2", kind: "HorizontalPodAutoscaler"},
		[]map[string]any{obj(`{"metadata":{"name":"h","namespace":"prod"},
		  "spec":{"scaleTargetRef":{"kind":"Deployment","name":"api"}}}`)})
	deps, _ := link(testCluster, append(target, hpa...))
	var found bool
	for _, d := range deps {
		if d.To == "apps/v1/Deployment/prod/api" && d.Resolution == contract.ResolutionInScan {
			found = true
		}
	}
	if !found {
		t.Errorf("an HPA with no apiVersion did not resolve to its Deployment: %+v", deps)
	}
}

// One gap per ServiceAccount is unbounded on a real cluster and repeats forever.
func TestWorkloadIdentityIsDeclaredOnceNotPerServiceAccount(t *testing.T) {
	var items []map[string]any
	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		items = append(items, obj(`{"metadata":{"name":"sa-`+n+`","namespace":"prod","annotations":{
		  "azure.workload.identity/client-id":"guid-`+n+`"}}}`))
	}
	resources, _ := translate(testCluster, kindSpec{apiVersion: "v1", kind: "ServiceAccount"}, items)
	_, gaps := link(testCluster, resources)
	var n int
	for _, g := range gaps {
		if g.Target == "azure-workload-identity-bindings" {
			n++
			if !strings.Contains(g.Detail, "7 service account(s)") {
				t.Errorf("the gap does not count them: %s", g.Detail)
			}
		}
	}
	if n != 1 {
		t.Errorf("got %d workload-identity gaps for 7 service accounts, want 1", n)
	}
}

// An empty cluster must emit [] not null, or the payload shape differs between planes.
func TestEmptyClusterEmitsAnEmptyArrayNotNull(t *testing.T) {
	c := &Collector{clusterID: testCluster, lister: &fakeLister{items: map[string][]map[string]any{}}}
	res, _, _, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res == nil {
		t.Fatal("resources is nil, so the payload marshals to null")
	}
	encoded, _ := json.Marshal(map[string]any{"resources": res})
	if strings.Contains(string(encoded), "null") {
		t.Errorf("empty cluster marshalled to %s", encoded)
	}
}

// ScanMeta must agree with Resource.Account or the estate cannot join to itself. A trailing slash on
// the flag was enough to break it, because main.go normalised separately from the collector.
func TestAccountNormalisationCannotDiverge(t *testing.T) {
	for _, raw := range []string{
		"/subscriptions/SUB-1/resourceGroups/RG/providers/Microsoft.ContainerService/managedClusters/AKS1",
		"/subscriptions/SUB-1/resourceGroups/RG/providers/Microsoft.ContainerService/managedClusters/AKS1/",
	} {
		c := New(raw)
		got, _ := translate(c.Account(), kindSpec{apiVersion: "v1", kind: "Namespace", clusterScoped: true},
			[]map[string]any{obj(`{"metadata":{"name":"prod"}}`)})
		if got[0].Account != c.Account() {
			t.Errorf("resource account %q != scan account %q", got[0].Account, c.Account())
		}
		if strings.HasSuffix(c.Account(), "/") {
			t.Errorf("account %q keeps a trailing slash", c.Account())
		}
	}
}

// 401 is authentication, 403 is authorisation. Grouping them told a customer to widen a ClusterRole
// that was already correct, and it hid the projected-token rotation bug: a token expiring mid-scan
// read as "your RBAC is too narrow".
func TestListGapSeparatesAuthenticationFromAuthorisation(t *testing.T) {
	spec := kindSpec{apiVersion: "networking.k8s.io/v1", kind: "Ingress",
		path: "/apis/networking.k8s.io/v1/ingresses"}

	denied := listGap("/subscriptions/s/aks", spec, &apiError{status: 403, body: `forbidden`})
	if denied.Reason != contract.GapPermissionDenied {
		t.Errorf("403 reason = %q, want permission-denied", denied.Reason)
	}
	// The rule must be pasteable: the plural comes from the request path, never from the kind, or it
	// reads "ingresss" and RBAC accepts it silently.
	if !strings.Contains(denied.Detail, `resources: ["ingresses"]`) {
		t.Errorf("403 detail does not carry a valid RBAC rule: %s", denied.Detail)
	}

	rejected := listGap("/subscriptions/s/aks", spec, &apiError{status: 401, body: `Unauthorized`})
	if rejected.Reason == contract.GapPermissionDenied {
		t.Error("401 reported as permission-denied, which sends the customer to edit correct RBAC")
	}
	if !strings.Contains(rejected.Detail, "not authorisation") {
		t.Errorf("401 detail does not say the ClusterRole is not the problem: %s", rejected.Detail)
	}
}

// Absence has to be a declaration. A curated kind list means every cert-manager Certificate and every
// SecretProviderClass is missing, and silence about that makes an incomplete estate look complete.
func TestCollectDeclaresExclusionsAndCustomResources(t *testing.T) {
	c := New("/subscriptions/s/aks")
	c.lister = &fakeLister{}
	_, _, gaps, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	byTarget := map[string]contract.Gap{}
	for _, g := range gaps {
		byTarget[g.Target] = g
	}

	derived, ok := byTarget["/subscriptions/s/aks/derived-objects"]
	if !ok {
		t.Fatal("Pods and ReplicaSets are skipped without saying so")
	}
	if derived.Reason != contract.GapExcluded {
		t.Errorf("derived reason = %q, want excluded: not-attempted means \"this is a bug, should be "+
			"zero\", so a correct scan could never reach the zero its own contract asks for",
			derived.Reason)
	}

	custom, ok := byTarget["/subscriptions/s/aks/custom-resources"]
	if !ok {
		t.Fatal("custom resources are not collected AND not declared")
	}
	if custom.Reason != contract.GapNoCollector {
		t.Errorf("custom resource reason = %q, want no-collector", custom.Reason)
	}
}

func TestVersionIsStamped(t *testing.T) {
	// ScanMeta records which build produced an estate; an empty version makes a stored scan
	// unattributable when a collector bug is found later.
	if New(testCluster).Version() != collectorVersion {
		t.Errorf("Version() = %q, want %q", New(testCluster).Version(), collectorVersion)
	}
}

// The RBAC plural comes from the request path. Pluralising the kind produced "ingresss",
// "networkpolicys", "storageclasss" and "ingressclasss" - names RBAC accepts silently, so a customer
// pasted the rule, it applied cleanly, and the next scan was denied again.
func TestEveryKindPrintsAPasteableRBACRule(t *testing.T) {
	for _, spec := range kinds() {
		if strings.HasSuffix(spec.resource(), "ss") && !strings.HasSuffix(spec.resource(), "sses") &&
			!strings.HasSuffix(spec.resource(), "class") {
			t.Errorf("%s: resource %q looks like a bad plural", spec.kind, spec.resource())
		}
		if !strings.HasSuffix(spec.path, "/"+spec.resource()) {
			t.Errorf("%s: resource %q does not match its path %s", spec.kind, spec.resource(), spec.path)
		}
		if spec.group() != "" && !strings.HasPrefix(spec.apiVersion, spec.group()+"/") {
			t.Errorf("%s: group %q does not match apiVersion %q", spec.kind, spec.group(), spec.apiVersion)
		}
		// The core group is "" in a ClusterRole, never "v1".
		if !strings.Contains(spec.apiVersion, "/") && spec.group() != "" {
			t.Errorf("%s: core group reported as %q, want empty", spec.kind, spec.group())
		}
	}
	// The fallback for a spec whose path holds no slash is unreachable for every curated kind - the
	// loop above asserts each path ends in "/" + resource. It lowercases and deliberately does NOT
	// guess a plural, because guessing is what produced "ingresss" in the first place.
	fallback := kindSpec{apiVersion: "v1", kind: "Widget", path: "widgets"}
	if fallback.resource() != "widget" {
		t.Errorf("resource() = %q for a pathless spec, want the un-pluralised kind",
			fallback.resource())
	}
}
