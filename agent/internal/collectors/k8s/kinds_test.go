package k8s

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The manifest a customer applies must cover every kind the collector reads.
//
// Without this the two drift in the one direction that is invisible: a kind added in code, the
// ClusterRole left alone, and the next scan reports a permission gap on a cluster where the customer
// did exactly what we asked. It fails silently for THEM, not for us.
//
// Read as text rather than parsed as YAML on purpose - the agent stays dependency-clean, and a
// substring check catches the drift that actually happens.
func TestReaderManifestCoversEveryKind(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "deploy", "kubernetes", "reader.yaml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	manifest := string(raw)

	for _, spec := range kinds() {
		if spec.derived {
			// Off by default, so the customer's role is deliberately NOT widened for it. Granting a
			// permission the collector does not exercise is the opposite of least privilege.
			if strings.Contains(manifest, "- "+spec.resource()+"\n") {
				t.Errorf("%s is derived and off by default, but the manifest still asks for %q",
					spec.kind, spec.resource())
			}
			continue
		}
		if !strings.Contains(manifest, "- "+spec.resource()+"\n") {
			t.Errorf("%s: the collector lists %q but the ClusterRole does not grant it, so a customer "+
				"who applied reader.yaml gets a permission gap for doing everything right",
				spec.kind, spec.resource())
		}
		group := spec.group()
		if group == "" {
			group = `""`
		} else {
			group = `"` + group + `"`
		}
		if !strings.Contains(manifest, "apiGroups: ["+group+"]") {
			t.Errorf("%s: apiGroup %s is missing from the manifest", spec.kind, group)
		}
	}

	// A write verb in this file would be a serious regression: the scanner never mutates a customer's
	// cloud, and the manifest is the artifact a customer's security review reads.
	for _, forbidden := range []string{
		"create", "update", "patch", "delete", "deletecollection",
		"watch", "impersonate", "escalate", "bind", "exec", "*",
	} {
		if strings.Contains(manifest, `"`+forbidden+`"`) {
			t.Errorf("reader.yaml grants %q; the application collector only ever lists", forbidden)
		}
	}
}
