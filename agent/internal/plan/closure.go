// Package plan computes recovery closures over the dependency graph (infra-scanner spec §6).
package plan

import "github.com/manukyanv07/parity-scanner/contract"

// Closure computes the transitive closure over hard edges for a selection, plus the
// optional soft edges and the coverage manifest.
//
// TODO(wed): graph walk over hard edges from the selected resources; offer soft edges;
// build the CoverageManifest (ready / needs-manual / cant-see / unknown).
func Closure(estate contract.Estate, sel contract.Selection) contract.Closure {
	return contract.Closure{Selection: sel}
}
