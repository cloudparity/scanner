package k8s

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/manukyanv07/parity-scanner/agent/internal/collectors"
	"github.com/manukyanv07/parity-scanner/contract"
)

// collectorVersion is stamped into ScanMeta so a stored estate says which build produced it.
const collectorVersion = "0.1.0"

// Collector reads one cluster's application plane.
type Collector struct {
	// clusterID is the cluster's ARM resource id, and it is REQUIRED.
	//
	// A pod cannot discover which AKS cluster it is running in - nothing in the Kubernetes API says
	// so - and without it every resource this collector emits would have no Account, so it could
	// never join the infra estate and the dependency graph would break exactly at the boundary that
	// matters. The install passes it in, the same way the infra job is told its own resource group.
	// AD-025 rejects deriving it from node labels or IMDS: best-effort detection would make the join
	// silently WRONG rather than absent, and a wrong parent is a confident wrong graph.
	clusterID string

	// lister is nil in production and built on first Collect. Tests inject a fake so the suite
	// exercises this method rather than a hand-copy of it.
	lister lister

	// includeDerived keeps Pods and ReplicaSets. Off by default: a controller recreates them, so
	// restoring them is wrong, and on a real cluster they are thousands of rows of churn.
	includeDerived bool
}

// New builds a collector for the cluster with the given ARM resource id.
func New(clusterID string) *Collector {
	return &Collector{
		clusterID:      strings.ToLower(strings.TrimRight(clusterID, "/")),
		includeDerived: os.Getenv("PARITY_K8S_INCLUDE_DERIVED") != "",
	}
}

// Plane reports which plane this collector reads.
func (c *Collector) Plane() collectors.Plane { return collectors.PlaneK8s }

// Version is the collector build stamped into ScanMeta.
func (c *Collector) Version() string { return collectorVersion }

// Account is the normalised cluster id, exposed so ScanMeta cannot disagree with Resource.Account.
//
// main.go was lowercasing the raw flag itself while New() also trimmed a trailing slash, so
// `--cluster-id .../aks1/` produced scans.account != resources.account and an estate that could not
// join to itself. That is the exact failure the Azure branch documents guarding against, reintroduced
// by a copy-paste. One source of truth removes the possibility.
func (c *Collector) Account() string { return c.clusterID }

// interface conformance, checked at compile time. The Azure collector asserts this; without it a
// signature drift is only caught wherever the concrete type happens to be used.
var _ collectors.Collector = (*Collector)(nil)

// Collect lists every configured kind, translates it, and links what points at what.
//
// A failed LIST of one kind does NOT fail the scan. The distinction matches the Azure collector: a
// dropped page makes the resource list itself wrong, while one unreadable kind loses one known
// category and saying so precisely beats discarding an otherwise-good estate. That matters more here
// than on Azure, because a customer's ClusterRole may deliberately omit a kind.
func (c *Collector) Collect(ctx context.Context) ([]contract.Resource, []contract.Dependency, []contract.Gap, error) {
	if c.clusterID == "" {
		return nil, nil, nil, fmt.Errorf("the cluster's ARM resource id is required: without it no " +
			"resource has an account and the estate cannot join the infra plane (AD-025)")
	}

	list := c.lister
	if list == nil {
		client, _, err := newInClusterClient()
		if err != nil {
			return nil, nil, nil, err
		}
		list = client
	}

	// Non-nil so an empty cluster emits "resources": [] rather than null. The Azure path does the
	// same, and a payload whose shape changes between planes is a problem for every non-Go consumer.
	resources := make([]contract.Resource, 0, 64)
	var gaps []contract.Gap

	for _, spec := range kinds() {
		if spec.derived && !c.includeDerived {
			continue
		}
		items, err := list.List(ctx, spec.path)
		if err != nil {
			gaps = append(gaps, listGap(c.clusterID, spec, err))
			continue
		}
		translated, translateGaps := translate(c.clusterID, spec, items)
		resources = append(resources, translated...)
		gaps = append(gaps, translateGaps...)
	}

	if !c.includeDerived {
		gaps = append(gaps, contract.Gap{
			Reason: contract.GapExcluded,
			Target: c.clusterID + "/derived-objects",
			Detail: "Pods and ReplicaSets were not read. They are DERIVED - a Deployment creates its " +
				"ReplicaSet and a ReplicaSet creates its Pods - so recreating them is not merely " +
				"unnecessary but wrong, since the controller would fight the restore. The desired state " +
				"they come from IS collected. Set PARITY_K8S_INCLUDE_DERIVED to read them anyway",
		})
	}

	gaps = append(gaps, customResourceGap(c.clusterID))

	dependencies, linkGaps := link(c.clusterID, resources)
	return resources, dependencies, append(gaps, linkGaps...), nil
}

// customResourceGap declares that custom resources are not read.
//
// kinds() is a CURATED list, which means anything a cluster serves beyond it is absent - and on a real
// AKS cluster that is never nothing: cert-manager Certificates, an ingress controller's
// IngressRoute/Gateway, a Crossplane or ASO resource, and on AKS specifically the
// SecretProviderClass that mounts Key Vault secrets into pods. Several of those are load-bearing for a
// restore.
//
// Read cluster-wide discovery to enumerate them and this becomes a real gap per CRD. Until then the
// honest statement is one declaration that the estate covers built-in kinds only - because the
// alternative, silence, makes an estate that omits every cert-manager Certificate look complete.
// infra-scanner §3 allows no third option between READ and REPORTED.
//
// THIS IS BLOCKING, not a completeness nicety (AD-027). A restore does not replay secret values, it
// repoints secret REFERENCES at the DR vault - and the field it has to patch,
// SecretProviderClass.spec.parameters.keyvaultName, lives in a custom resource. Same for External
// Secrets Operator's SecretStore. So the object holding the one field that decides whether a restored
// pod can reach its password is precisely the object this collector does not read.
func customResourceGap(clusterID string) contract.Gap {
	return contract.Gap{
		Reason: contract.GapNoCollector,
		Target: clusterID + "/custom-resources",
		Detail: "only the built-in kinds this collector curates were read. Custom resources - " +
			"cert-manager Certificates, SecretProviderClasses that mount Key Vault secrets on AKS, " +
			"ingress controller CRs, Crossplane or Azure Service Operator resources - were not " +
			"enumerated at all, so an object graph that depends on one is incomplete in a way the " +
			"resource list alone does not reveal. Reading /apis to discover served CRDs is the fix. " +
			"This blocks RESTORE and not merely completeness: a SecretProviderClass names the Key " +
			"Vault a pod's secrets come from, and repointing that name at the DR vault is how a " +
			"restored pod reaches its password at all (AD-027)",
	}
}

// listGap turns a failed LIST into the gap that names who can fix it.
//
// A 403 here is the common and actionable case: it means the ClusterRole is missing a rule, and the
// API server's own message names the group and resource, so the gap can state the exact rule to add
// rather than telling a customer to widen their RBAC and hope.
func listGap(clusterID string, spec kindSpec, err error) contract.Gap {
	target := clusterID + "/" + spec.apiVersion + "/" + spec.kind

	var apiErr *apiError
	if errors.As(err, &apiErr) {
		switch apiErr.status {
		case http.StatusUnauthorized:
			// 401 is NOT a missing ClusterRole rule, and reporting it as one sends a customer to edit
			// RBAC that is already correct. It means the bearer token was rejected: expired, or the
			// service account was deleted. Grouping it with 403 also hid the projected-token rotation
			// bug this collector had, because a mid-scan expiry read as "your RBAC is too narrow".
			return contract.Gap{
				Reason: contract.GapNotAttempted,
				Target: target,
				Detail: fmt.Sprintf("the API server rejected the service account TOKEN when listing %s "+
					"(HTTP 401), which is authentication and not authorisation - the ClusterRole is not "+
					"the problem. Usually an expired projected token or a deleted service account. The "+
					"API server said: %s", spec.kind, truncate(apiErr.body, 240)),
			}
		case http.StatusForbidden:
			return contract.Gap{
				Reason: contract.GapPermissionDenied,
				Target: target,
				Detail: fmt.Sprintf("the service account was denied list on %s, so every object of that "+
					"kind is absent from the estate. Add this to the ClusterRole: apiGroups: [%q], "+
					"resources: [%q], verbs: [list]. The API server said: %s",
					spec.kind, spec.group(), spec.resource(), truncate(apiErr.body, 240)),
			}
		case http.StatusNotFound:
			// The kind is not served by this cluster - an older API version, or a CRD that is not
			// installed. A fact rather than a hole, but still worth stating: a reader must be able to
			// tell "no Ingresses exist" from "Ingresses were never asked for".
			return contract.Gap{
				Reason: contract.GapNotAttempted,
				Target: target,
				Detail: fmt.Sprintf("this cluster does not serve %s at %s, so the kind was skipped. "+
					"Usually an API version this cluster predates, or an optional component that is "+
					"not installed", spec.kind, spec.apiVersion),
			}
		}
	}
	return contract.Gap{
		Reason: contract.GapNotAttempted,
		Target: target,
		Detail: fmt.Sprintf("listing %s failed, so every object of that kind is absent from the estate: %v",
			spec.kind, err),
	}
}

func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
