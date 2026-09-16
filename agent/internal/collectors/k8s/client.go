// Package k8s reads the application plane: the objects inside a Kubernetes cluster.
//
// Where it runs, and why that decides everything else. Per AD-024 this collector runs as a Job
// INSIDE the cluster, not as something reaching in from outside:
//
//   - a private cluster's API server has no public address, and an authorized-IP-range cluster
//     blocks an outside caller even when public. From a pod the API is always reachable.
//   - it never holds cluster credentials. The pod's own service-account token is the auth, so
//     listClusterUserCredential is never requested and no kubeconfig is ever handled.
//   - the permission ask becomes one read-only ClusterRole, which a customer can read in seconds.
//
// NO client-go. The Kubernetes API is JSON over HTTPS and this collector only ever LISTs, so
// client-go would add an enormous dependency tree to an agent that is meant to be open source and
// auditable, in exchange for conveniences a read-only lister does not need. The Azure collector
// reads ARM the same way.
package k8s

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Standard in-cluster projected service-account paths. Present in every pod unless a customer
// deliberately disables the projection.
const (
	tokenPath     = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	caPath        = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	namespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

// listPageSize bounds one LIST response. The API server also enforces its own limits; this keeps
// memory predictable on a large cluster rather than pulling every object of a kind at once.
const listPageSize = 500

// lister performs one paged LIST against the API. An interface so every layer above it is testable
// without a cluster, matching graphClient and armFetcher on the Azure side.
type lister interface {
	List(ctx context.Context, path string) ([]map[string]any, error)
}

// apiClient talks to one cluster.
type apiClient struct {
	server string
	// tokens yields the bearer token per request. Two implementations, chosen at construction: the
	// pod's projected service-account file, or an Entra token for the AKS audience. See token.go.
	tokens tokenSource
	http   *http.Client
}

// newInClusterClient builds a client from the pod's own projected credentials.
//
// The three env overrides exist so the collector can be exercised against a real cluster from
// outside during development, using a short-lived token from `kubectl create token`. They are NOT
// how it runs in production - a customer install mounts nothing and sets nothing.
func newInClusterClient() (*apiClient, string, error) {
	server := os.Getenv("PARITY_K8S_API_SERVER")
	if server == "" {
		host, port := os.Getenv("KUBERNETES_SERVICE_HOST"), os.Getenv("KUBERNETES_SERVICE_PORT")
		if host == "" || port == "" {
			return nil, "", fmt.Errorf("not running in a cluster: KUBERNETES_SERVICE_HOST/PORT are unset " +
				"and PARITY_K8S_API_SERVER was not provided")
		}
		server = "https://" + net.JoinHostPort(host, port)
	}
	server = strings.TrimRight(server, "/")

	// WHICH IDENTITY. Explicit rather than sniffed, because the two modes fail in ways that look
	// nothing like each other and a wrong guess is very hard to read from the error.
	var tokens tokenSource
	if strings.EqualFold(os.Getenv("PARITY_K8S_AUTH"), "entra") {
		// The central model: outside the cluster, authorised by an Azure role assignment.
		var err error
		if tokens, err = newEntraTokenSource(); err != nil {
			return nil, "", err
		}
	} else {
		// The in-cluster default (AD-024).
		tokenFile := envOr("PARITY_K8S_TOKEN_FILE", tokenPath)
		if _, err := os.ReadFile(tokenFile); err != nil {
			return nil, "", fmt.Errorf("read service account token %s: %w. If this is meant to run "+
				"OUTSIDE the cluster against an Azure-RBAC cluster, set PARITY_K8S_AUTH=entra to "+
				"authenticate with a managed identity instead", tokenFile, err)
		}
		tokens = &fileTokenSource{path: tokenFile}
	}

	// An EMPTY pool is the trap. Setting RootCAs to a pool with no certificates does not fall back to
	// the system roots - it trusts nothing, so every request fails the handshake. Combined with a
	// failed LIST becoming a gap rather than an error, the outcome was a scan that read NOTHING and
	// still exited 0 with resourceCount 0, which is indistinguishable from an empty cluster. So an
	// unusable pool is left nil (system roots) rather than empty.
	// WHERE THE CA COMES FROM, in each mode. In-cluster it is projected into the pod. In the central
	// mode there is no pod, and the CA is NOT in the cluster's ARM representation - the API server
	// presents a certificate issued by the cluster's own private CA (measured: issuer=CN=ca,
	// subject=CN=apiserver), so the system trust store fails the handshake outright. The only Azure
	// API that returns it is listClusterUserCredential, so the central model needs that action too,
	// for the CA and nothing else.
	var pool *x509.CertPool
	caFile := envOr("PARITY_K8S_CA_FILE", caPath)
	if pem, err := os.ReadFile(caFile); err == nil {
		pool = x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, "", fmt.Errorf("cluster CA %s contains no usable certificate; every request "+
				"would fail the TLS handshake and the scan would look like an empty cluster", caFile)
		}
	} else if os.Getenv("PARITY_K8S_CA_FILE") != "" {
		// An explicitly named CA that cannot be read is an error, not something to fall back from.
		return nil, "", fmt.Errorf("read cluster CA %s: %w", caFile, err)
	}

	// The pod's namespace is not needed for reading, only for reporting where the scan ran from.
	own := ""
	if b, err := os.ReadFile(envOr("PARITY_K8S_NAMESPACE_FILE", namespacePath)); err == nil {
		own = strings.TrimSpace(string(b))
	}

	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		MaxIdleConnsPerHost: 4,
	}
	return &apiClient{
		server: server,
		tokens: tokens,
		http:   &http.Client{Transport: transport, Timeout: 60 * time.Second},
	}, own, nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// List walks every page of one collection and returns the items.
//
// Kubernetes pages with metadata.continue rather than a link, and a continue token expires, so a
// slow walk over a large collection can fail mid-way with 410 Gone. That surfaces as an error
// rather than a short read, because a truncated list would silently under-report the estate.
func (c *apiClient) List(ctx context.Context, path string) ([]map[string]any, error) {
	var items []map[string]any
	cont := ""

	// Bounded for the same reason the Resource Graph pager is: a server that keeps returning a
	// continue token must not turn a scan into an unbounded loop.
	for attempt := 0; attempt < 200; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		q := url.Values{}
		q.Set("limit", fmt.Sprint(listPageSize))
		if cont != "" {
			q.Set("continue", cont)
		}
		body, err := c.get(ctx, path+"?"+q.Encode())
		if err != nil {
			return nil, err
		}
		var decoded struct {
			Items    []map[string]any `json:"items"`
			Metadata struct {
				Continue string `json:"continue"`
			} `json:"metadata"`
		}
		if err := json.Unmarshal(body, &decoded); err != nil {
			return nil, fmt.Errorf("decode %s: %w", path, err)
		}
		items = append(items, decoded.Items...)
		if decoded.Metadata.Continue == "" {
			return items, nil
		}
		cont = decoded.Metadata.Continue
	}
	return nil, fmt.Errorf("%s: exceeded the page budget, which means the API kept returning a continue token", path)
}

func (c *apiClient) get(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.server+path, nil)
	if err != nil {
		return nil, err
	}
	bearer, err := c.tokens.token(ctx)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Bounded: an API server returning an unbounded stream must not exhaust the job's 1 GiB.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		// The body is kept: a Kubernetes error carries the reason (Forbidden vs NotFound) and the
		// message names the missing RBAC verb, which is exactly what a permission gap must say.
		return nil, &apiError{status: resp.StatusCode, body: strings.TrimSpace(string(body))}
	}
	return body, nil
}

// apiError carries the status and the server's own message, so a gap can name the RBAC rule to add.
type apiError struct {
	status int
	body   string
}

func (e *apiError) Error() string { return fmt.Sprintf("HTTP %d: %s", e.status, e.body) }
