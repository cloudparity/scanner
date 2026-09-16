package k8s

import (
	"encoding/json"
	"testing"
)

// Two scans of an object that only differs in status and resourceVersion must produce the SAME
// document. Measured on the live cluster before this was fixed: the stored document carried
// status.conditions[].lastUpdateTime and resourceVersion/uid/generation/creationTimestamp, so every
// object differed on every scan and drift detection would have reported 100% churn on a cluster where
// nothing had happened.
func TestTranslateIsStableAcrossScans(t *testing.T) {
	spec := kindSpec{apiVersion: "apps/v1", kind: "Deployment", path: "/apis/apps/v1/deployments"}
	at := func(rv, ts string, replicas int) map[string]any {
		return map[string]any{
			"metadata": map[string]any{
				"name": "api", "namespace": "prod",
				"resourceVersion": rv, "uid": "1f2e-" + rv, "generation": float64(replicas),
				"creationTimestamp": "2026-08-13T17:00:00Z",
			},
			"spec": map[string]any{"replicas": float64(2)},
			"status": map[string]any{
				"availableReplicas": float64(replicas),
				"conditions":        []any{map[string]any{"lastUpdateTime": ts}},
			},
		}
	}

	first, _ := translate("/subscriptions/s/aks", spec, []map[string]any{at("1000", "17:55:42Z", 2)})
	second, _ := translate("/subscriptions/s/aks", spec, []map[string]any{at("94213", "18:29:26Z", 1)})
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("want one resource from each scan, got %d and %d", len(first), len(second))
	}
	if string(first[0].Document) != string(second[0].Document) {
		t.Errorf("document changed between scans of an unchanged spec:\n first: %s\nsecond: %s",
			first[0].Document, second[0].Document)
	}

	var doc map[string]any
	if err := json.Unmarshal(first[0].Document, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := doc["status"]; present {
		t.Error("status is observed state and must not be stored: nothing restores an object from it")
	}
	// A LIST returns items with EMPTY TypeMeta - the API server sets kind on the List wrapper, not on
	// each item - so without injection every stored document was an object that could not be applied.
	if doc["apiVersion"] != "apps/v1" || doc["kind"] != "Deployment" {
		t.Errorf("apiVersion/kind not injected, so the document is not applyable: %v/%v",
			doc["apiVersion"], doc["kind"])
	}
	meta := doc["metadata"].(map[string]any)
	for _, key := range []string{"resourceVersion", "uid", "generation", "creationTimestamp"} {
		if _, present := meta[key]; present {
			t.Errorf("metadata.%s is volatile and identifies THIS cluster's instance; it must not "+
				"be stored or carried into a restore", key)
		}
	}
	if meta["name"] != "api" {
		t.Errorf("stripping volatile metadata removed the name too: %v", meta)
	}
}

// The CONTROLLER owner is the parent, not whichever reference happens to be first. List order is
// arbitrary, so taking the first both picked a non-controller owner and made ParentID change between
// scans of an unchanged object - a second source of false churn.
func TestParentPrefersControllerOwner(t *testing.T) {
	spec := kindSpec{apiVersion: "v1", kind: "Pod", path: "/api/v1/pods"}
	got, _ := translate("/subscriptions/s/aks", spec, []map[string]any{{
		"metadata": map[string]any{
			"name": "api-abc", "namespace": "prod",
			"ownerReferences": []any{
				map[string]any{"apiVersion": "v1", "kind": "ConfigMap", "name": "sidecar-config"},
				map[string]any{"apiVersion": "apps/v1", "kind": "ReplicaSet", "name": "api-7d9", "controller": true},
			},
		},
	}})
	if len(got) != 1 {
		t.Fatalf("want one resource, got %d", len(got))
	}
	if want := "apps/v1/ReplicaSet/prod/api-7d9"; got[0].ParentID != want {
		t.Errorf("ParentID = %q, want the controller %q", got[0].ParentID, want)
	}
}
