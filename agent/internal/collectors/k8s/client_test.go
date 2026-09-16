package k8s

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/manukyanv07/parity-scanner/agent/internal/collectors"
	"github.com/manukyanv07/parity-scanner/contract"
)

// withFakeAPI stands up an API server and points the collector's config at it.
//
// Plain HTTP rather than TLS: http.Transport ignores TLSClientConfig for an http:// URL, so this
// exercises newInClusterClient, get and List end to end without certificate machinery that would
// test the standard library rather than this code.
func withFakeAPI(t *testing.T, handler http.HandlerFunc) *apiClient {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("  fake-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PARITY_K8S_API_SERVER", server.URL+"/")
	t.Setenv("PARITY_K8S_TOKEN_FILE", tokenFile)
	t.Setenv("PARITY_K8S_CA_FILE", "")
	t.Setenv("PARITY_K8S_NAMESPACE_FILE", filepath.Join(dir, "missing-namespace"))

	client, _, err := newInClusterClient()
	if err != nil {
		t.Fatalf("newInClusterClient: %v", err)
	}
	return client
}

func TestListWalksEveryPage(t *testing.T) {
	var seen []string
	client := withFakeAPI(t, func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.Query().Get("continue"))
		switch r.URL.Query().Get("continue") {
		case "":
			fmt.Fprint(w, `{"items":[{"metadata":{"name":"a"}}],"metadata":{"continue":"tok-1"}}`)
		case "tok-1":
			fmt.Fprint(w, `{"items":[{"metadata":{"name":"b"}}],"metadata":{"continue":"tok-2"}}`)
		default:
			fmt.Fprint(w, `{"items":[{"metadata":{"name":"c"}}],"metadata":{"continue":""}}`)
		}
	})

	items, err := client.List(context.Background(), "/api/v1/configmaps")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 {
		t.Fatalf("got %d items across pages, want 3", len(items))
	}
	// A short read here would silently under-report the estate, which is the failure this guards.
	if len(seen) != 3 {
		t.Errorf("made %d requests, want 3: %v", len(seen), seen)
	}
	if seen[1] != "tok-1" || seen[2] != "tok-2" {
		t.Errorf("continue tokens were not threaded through: %v", seen)
	}
}

func TestListSendsTheBearerTokenAndAsksForJSON(t *testing.T) {
	var auth, accept string
	var limit string
	client := withFakeAPI(t, func(w http.ResponseWriter, r *http.Request) {
		auth, accept = r.Header.Get("Authorization"), r.Header.Get("Accept")
		limit = r.URL.Query().Get("limit")
		fmt.Fprint(w, `{"items":[]}`)
	})
	if _, err := client.List(context.Background(), "/api/v1/pods"); err != nil {
		t.Fatal(err)
	}
	// Trimmed: the projected token file ends with a newline, and a newline in a header is invalid.
	if auth != "Bearer fake-token" {
		t.Errorf("Authorization = %q, want the trimmed token", auth)
	}
	if accept != "application/json" {
		t.Errorf("Accept = %q", accept)
	}
	if limit != fmt.Sprint(listPageSize) {
		t.Errorf("limit = %q, want %d", limit, listPageSize)
	}
}

// A server that keeps handing back a continue token must not turn a scan into an unbounded loop.
func TestListStopsAtThePageBudget(t *testing.T) {
	client := withFakeAPI(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"items":[{"metadata":{"name":"x"}}],"metadata":{"continue":"never-ends"}}`)
	})
	_, err := client.List(context.Background(), "/api/v1/configmaps")
	if err == nil {
		t.Fatal("List returned no error against a server that never stops paging")
	}
	if !strings.Contains(err.Error(), "page budget") {
		t.Errorf("error = %v, want it to name the page budget", err)
	}
}

// The API server's own message names the missing RBAC verb, which is what makes a gap actionable, so
// the body must survive the error path.
func TestNon200KeepsTheServerMessage(t *testing.T) {
	client := withFakeAPI(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"kind":"Status","reason":"Forbidden","message":"deployments.apps is forbidden"}`)
	})
	_, err := client.List(context.Background(), "/apis/apps/v1/deployments")
	if err == nil {
		t.Fatal("a 403 produced no error")
	}
	var apiErr *apiError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error is %T, want *apiError so listGap can classify it", err)
	}
	if apiErr.status != http.StatusForbidden {
		t.Errorf("status = %d", apiErr.status)
	}
	if !strings.Contains(apiErr.body, "deployments.apps is forbidden") {
		t.Errorf("the server message was discarded: %q", apiErr.body)
	}
	if !strings.Contains(apiErr.Error(), "403") {
		t.Errorf("Error() = %q, want the status in it", apiErr.Error())
	}
}

func TestListRejectsAMalformedBody(t *testing.T) {
	client := withFakeAPI(t, func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `{"items": not json`)
	})
	if _, err := client.List(context.Background(), "/api/v1/configmaps"); err == nil {
		t.Fatal("a malformed body produced no error")
	}
}

// A cancelled scan must stop asking, not keep walking pages.
func TestListHonoursContextCancellation(t *testing.T) {
	calls := 0
	client := withFakeAPI(t, func(w http.ResponseWriter, _ *http.Request) {
		calls++
		fmt.Fprint(w, `{"items":[],"metadata":{"continue":"more"}}`)
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.List(ctx, "/api/v1/configmaps"); err == nil {
		t.Fatal("List ignored a cancelled context")
	}
	if calls != 0 {
		t.Errorf("made %d requests on a cancelled context, want 0", calls)
	}
}

// Running outside a cluster with nothing configured must fail with an explanation, not a nil panic
// somewhere later.
func TestNewInClusterClientExplainsWhenNotInACluster(t *testing.T) {
	t.Setenv("PARITY_K8S_API_SERVER", "")
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	_, _, err := newInClusterClient()
	if err == nil {
		t.Fatal("newInClusterClient succeeded outside a cluster")
	}
	if !strings.Contains(err.Error(), "not running in a cluster") {
		t.Errorf("error = %v, want it to say it is not in a cluster", err)
	}
}

// In a real pod the API address comes from the injected service env vars.
func TestNewInClusterClientUsesTheInjectedServiceAddress(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("t"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PARITY_K8S_API_SERVER", "")
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	t.Setenv("KUBERNETES_SERVICE_PORT", "443")
	t.Setenv("PARITY_K8S_TOKEN_FILE", tokenFile)
	t.Setenv("PARITY_K8S_CA_FILE", "")

	client, _, err := newInClusterClient()
	if err != nil {
		t.Fatal(err)
	}
	if client.server != "https://10.0.0.1:443" {
		t.Errorf("server = %q", client.server)
	}
}

// No token means no auth, and continuing would produce a scan of nothing that looked like an empty
// cluster.
func TestNewInClusterClientFailsWithoutAToken(t *testing.T) {
	t.Setenv("PARITY_K8S_API_SERVER", "https://example.invalid")
	t.Setenv("PARITY_K8S_TOKEN_FILE", filepath.Join(t.TempDir(), "absent"))
	if _, _, err := newInClusterClient(); err == nil {
		t.Fatal("newInClusterClient succeeded with no service account token")
	}
}

// An explicitly named CA that cannot be read is an error, not something to quietly proceed without -
// proceeding would mean trusting whatever certificate the connection presented.
func TestNewInClusterClientFailsOnAnUnreadableNamedCA(t *testing.T) {
	dir := t.TempDir()
	tokenFile := filepath.Join(dir, "token")
	if err := os.WriteFile(tokenFile, []byte("t"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PARITY_K8S_API_SERVER", "https://example.invalid")
	t.Setenv("PARITY_K8S_TOKEN_FILE", tokenFile)
	t.Setenv("PARITY_K8S_CA_FILE", filepath.Join(dir, "absent-ca.crt"))
	if _, _, err := newInClusterClient(); err == nil {
		t.Fatal("newInClusterClient succeeded with a named CA it could not read")
	}
}

func TestEnvOrFallsBack(t *testing.T) {
	t.Setenv("PARITY_TEST_KEY", "")
	if got := envOr("PARITY_TEST_KEY", "fallback"); got != "fallback" {
		t.Errorf("got %q, want the fallback", got)
	}
	t.Setenv("PARITY_TEST_KEY", "set")
	if got := envOr("PARITY_TEST_KEY", "fallback"); got != "set" {
		t.Errorf("got %q, want the set value", got)
	}
}

// The whole collector, driven through the real client against a fake API - so Collect, the client and
// translate are exercised together rather than only through an injected fake.
func TestCollectEndToEndThroughTheRealClient(t *testing.T) {
	client := withFakeAPI(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/namespaces":
			fmt.Fprint(w, `{"items":[{"metadata":{"name":"prod"}}]}`)
		case "/apis/apps/v1/deployments":
			fmt.Fprint(w, `{"items":[{"metadata":{"name":"api","namespace":"prod"},
			  "spec":{"template":{"spec":{"containers":[{"name":"c",
			  "envFrom":[{"configMapRef":{"name":"cfg"}}]}]}}}}]}`)
		case "/api/v1/configmaps":
			fmt.Fprint(w, `{"items":[{"metadata":{"name":"cfg","namespace":"prod"},"data":{"k":"v"}}]}`)
		default:
			fmt.Fprint(w, `{"items":[]}`)
		}
	})

	c := &Collector{clusterID: testCluster, lister: client}
	res, deps, gaps, err := c.Collect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 3 {
		t.Fatalf("got %d resources, want 3 (namespace, deployment, configmap): %+v", len(res), res)
	}
	var linked bool
	for _, d := range deps {
		if d.From == "apps/v1/Deployment/prod/api" && d.To == "v1/ConfigMap/prod/cfg" {
			linked = true
		}
	}
	if !linked {
		t.Errorf("the deployment was not linked to its configmap: %+v", deps)
	}
	// Only the derived-objects declaration, plus any §2.4 screening flags. Nothing FAILED here, so
	// no permission-denied or not-attempted gap should appear for a kind.
	for _, g := range gaps {
		if strings.HasSuffix(g.Target, "/derived-objects") ||
			strings.HasSuffix(g.Target, "/custom-resources") ||
			g.Reason == contract.GapUnscreened {
			continue
		}
		t.Errorf("unexpected gap: [%s] %s", g.Reason, g.Target)
	}
}

func TestNewLowercasesTheClusterIDAndReportsThePlane(t *testing.T) {
	c := New("/subscriptions/SUB-1/resourceGroups/RG/providers/Microsoft.ContainerService/managedClusters/AKS1/")
	if c.Plane() != collectors.PlaneK8s {
		t.Errorf("plane = %q", c.Plane())
	}
	// Lowercased and trimmed, so it equals the Account the Azure collector emits for the same cluster
	// - which is the whole point of the join.
	want := "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.containerservice/managedclusters/aks1"
	if c.clusterID != want {
		t.Errorf("clusterID = %q, want %q", c.clusterID, want)
	}
}

func TestTruncateKeepsMessagesReadable(t *testing.T) {
	if got := truncate("  a\n\tb   c  ", 100); got != "a b c" {
		t.Errorf("got %q, want whitespace collapsed", got)
	}
	long := strings.Repeat("x", 300)
	got := truncate(long, 10)
	if len(got) != 13 || !strings.HasSuffix(got, "...") {
		t.Errorf("got %q (len %d), want 10 chars plus an ellipsis", got, len(got))
	}
}

// Guards the invariant that every listed kind is actually requested, so a kind cannot be added to the
// curated list and silently never read.
func TestCollectAsksForEveryNonDerivedKind(t *testing.T) {
	f := &fakeLister{items: map[string][]map[string]any{}}
	c := &Collector{clusterID: testCluster, lister: f}
	if _, _, _, err := c.Collect(context.Background()); err != nil {
		t.Fatal(err)
	}
	asked := map[string]bool{}
	for _, p := range f.asked {
		asked[p] = true
	}
	for _, k := range kinds() {
		if k.derived {
			continue
		}
		if !asked[k.path] {
			t.Errorf("%s/%s is in the curated list but was never requested (%s)", k.apiVersion, k.kind, k.path)
		}
	}
}

func TestJSONEncodingOfAnEstateHoldsBothPlanesIdentity(t *testing.T) {
	got, _ := translate(testCluster, kindSpec{apiVersion: "apps/v1", kind: "Deployment"},
		[]map[string]any{obj(`{"metadata":{"name":"api","namespace":"prod"}}`)})
	encoded, err := json.Marshal(got[0])
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(encoded, &back); err != nil {
		t.Fatal(err)
	}
	if back["provider"] != "k8s" {
		t.Errorf("provider = %v", back["provider"])
	}
	if back["account"] != testCluster {
		t.Errorf("account = %v, want the cluster id so the estate joins", back["account"])
	}
}

// The projected token EXPIRES and kubelet rewrites the file in place. Reading it once at startup
// meant a scan that outlived the rotation started collecting 401s, and because a failed LIST becomes
// a gap, the second half of a large cluster's estate turned into permission gaps telling the customer
// to widen a ClusterRole that was already correct.
func TestBearerFollowsTokenRotation(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "token")
	if err := os.WriteFile(file, []byte("first-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &fileTokenSource{path: file, last: "first-token"}
	bearer := func() string {
		got, err := c.token(context.Background())
		if err != nil {
			return ""
		}
		return got
	}
	if got := bearer(); got != "first-token" {
		t.Fatalf("token() = %q", got)
	}

	if err := os.WriteFile(file, []byte("  rotated-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := bearer(); got != "rotated-token" {
		t.Errorf("token() = %q after rotation, want the new token; a stale token means 401 mid-scan", got)
	}

	// A read failure must reuse the last good token rather than send an empty bearer, which the API
	// server answers with 401 - the same misleading outcome by a different route.
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if got := bearer(); got != "rotated-token" {
		t.Errorf("token() = %q after the file vanished, want the last good token", got)
	}
	// An empty file is not a token either.
	if err := os.WriteFile(file, []byte("\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := bearer(); got != "rotated-token" {
		t.Errorf("token() = %q for an empty token file, want the last good token", got)
	}
}
