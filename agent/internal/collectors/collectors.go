// Package collectors defines the interface every scanner collector implements, and hosts
// the per-cloud implementations (azure today; aws, gcp, k8s later).
//
// Many collectors, one contract, one reconciler (docs/engineering.md). Naming this seam from
// the very first collector is what makes adding clouds additive, not a rewrite.
package collectors

import (
	"context"

	"github.com/manukyanv07/parity-scanner/contract"
)

// Plane identifies which cloud a collector reads.
type Plane string

// The planes a collector can read. Every collector names exactly one.
const (
	PlaneAzure Plane = "azure"
	PlaneAWS   Plane = "aws"
	PlaneGCP   Plane = "gcp"
	PlaneK8s   Plane = "k8s" // cloud-agnostic in-cluster app plane
)

// Collector reads one cloud exhaustively and translates what it finds into the canonical
// contract. Every collector's output reaches the reconciler through this one interface.
//
// A collector is dumb by design: it reports what it saw, what it could not reach, and
// which resources point at which. It never decides what any of that means — that needs
// the Knowledge Base, and the Knowledge Base is server-side (contract/estate.go).
//
// The MVP is one-shot (Collect). The cursor/watch form (poll/read) arrives with the
// reconciler; when it does it extends this interface — it never changes the contract.
type Collector interface {
	Plane() Plane
	Collect(ctx context.Context) ([]contract.Resource, []contract.Dependency, []contract.Gap, error)
}
