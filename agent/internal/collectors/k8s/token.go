package k8s

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// How the collector proves who it is, and why there are two completely different answers.
//
// AD-024 put this collector inside the cluster, where the pod's own projected service-account token
// is the credential and nothing has to be configured. That is still the fallback, and it is the only
// option on a cluster whose authorization is Kubernetes RBAC.
//
// MEASURED 2026-08-14 on the testbed: on a cluster with Entra integration and Azure RBAC, a principal
// holding one custom role of 24 read-only data actions read all 19 kinds present, 300 resources, with
// zero permission-denied gaps, and was refused every write. It ran OUTSIDE the cluster. That is the
// central model, and it needs an Entra token rather than a service-account token - which is what this
// file adds.
//
// WHAT STILL REQUIRES listClusterUserCredential, because it was briefly claimed otherwise: the
// cluster's CA CERTIFICATE. The API server presents a certificate issued by the cluster's own private
// CA - measured, `issuer=CN=ca, subject=CN=apiserver` - so the system trust store cannot verify it and
// a plain HTTPS call fails the handshake outright. That CA is not in the ARM representation of the
// cluster; the only Azure API that hands it over is the one behind
// Microsoft.ContainerService/managedClusters/listClusterUserCredential/action.
//
// Taking that action is nevertheless SAFE on this kind of cluster, and that is the whole point of
// AD-027's cluster shape. Measured on the same cluster: the kubeconfig it returns carries the CA and
// NO credential - no client certificate, no client key, no static token, just an exec plugin that
// fetches an Entra token. On an old-style cluster the identical call returns a two-year
// `O=system:masters` certificate. Same action, completely different blast radius, decided entirely by
// whether the customer disabled local accounts.

// aksScope is the Entra audience for the AKS API server. Fixed and public - the same value in every
// tenant. A wrong audience is rejected as a bare 401 that mentions nothing about audiences.
const aksScope = "6dae42f8-4368-4678-94ff-3960e28e3630/.default"

// tokenRefreshWindow renews early. A token that expires mid-scan turns the rest of the estate into
// permission gaps advising the customer to widen a role that was never the problem, which is the
// failure the projected-token bug already taught us once.
const tokenRefreshWindow = 5 * time.Minute

// tokenSource yields the bearer token for one request.
type tokenSource interface {
	token(ctx context.Context) (string, error)
}

// fileTokenSource reads a token from disk on EVERY call.
//
// Not a micro-optimisation to remove: a projected service-account token expires, and kubelet rewrites
// the file in place at around 80% of its lifetime. Reading once at startup meant a long scan began
// collecting 401s part-way through.
type fileTokenSource struct {
	path string
	mu   sync.RWMutex
	last string
}

func (f *fileTokenSource) token(context.Context) (string, error) {
	if raw, err := os.ReadFile(f.path); err == nil {
		if t := strings.TrimSpace(string(raw)); t != "" {
			f.mu.Lock()
			f.last = t
			f.mu.Unlock()
			return t, nil
		}
	}
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.last == "" {
		return "", fmt.Errorf("service account token %s is unreadable or empty", f.path)
	}
	// A transient read failure reuses the last good value rather than sending an empty bearer token,
	// which the API server answers with 401 - the same misleading outcome by another route.
	return f.last, nil
}

// credential is the part of an Azure credential this file uses. An interface so the caching and
// expiry logic is testable without a network or a real identity.
type credential interface {
	GetToken(ctx context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error)
}

// entraTokenSource fetches an Entra token for the AKS audience and caches it until it is nearly due.
//
// azidentity's DefaultAzureCredential is deliberately reused from the Azure collector rather than
// hand-rolling a call to the instance metadata endpoint: it already resolves a Container App's
// user-assigned identity, a workload identity, and a developer's az CLI session, and those are
// exactly the three places this runs.
type entraTokenSource struct {
	cred credential
	mu   sync.Mutex
	tok  azcore.AccessToken
}

func (e *entraTokenSource) token(ctx context.Context) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.tok.Token != "" && time.Until(e.tok.ExpiresOn) > tokenRefreshWindow {
		return e.tok.Token, nil
	}
	tok, err := e.cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{aksScope}})
	if err != nil {
		return "", fmt.Errorf("acquire an Entra token for the AKS API (%s): %w", aksScope, err)
	}
	if tok.Token == "" {
		return "", fmt.Errorf("entra returned an empty token for %s", aksScope)
	}
	e.tok = tok
	return tok.Token, nil
}

// newEntraTokenSource builds the production Entra source.
func newEntraTokenSource() (tokenSource, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("no Azure identity available for Entra authentication. In a Container "+
			"App this means no managed identity is assigned; locally it means `az login` has not run: %w", err)
	}
	return &entraTokenSource{cred: cred}, nil
}
