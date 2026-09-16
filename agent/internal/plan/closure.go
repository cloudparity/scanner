// Package plan computes recovery closures over the dependency graph (infra-scanner spec §6).
package plan

import "github.com/manukyanv07/parity-scanner/contract"

// Closure computes the transitive closure over hard edges for a selection, plus the
// optional soft edges and the coverage manifest.
//
// Not implemented: the graph walk over hard edges from the selected resources, the soft
// edges, and the CoverageManifest (ready / needs-manual / cant-see / unknown) are
// https://github.com/cloudparity/scanner/issues/8. Until then the estate is not read.
func Closure(_ contract.Estate, sel contract.Selection) contract.Closure {
	return contract.Closure{Selection: sel}
}
