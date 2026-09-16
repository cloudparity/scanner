package main

// prune.go is `scanner prune`: the caller pruning never had.
//
// backup.Prune was written, tested and reachable from NOTHING, because nothing turned a container
// into the []backup.Stored it consumes. assemble.go is that, and this file is where an operator
// reaches it — a separate subcommand on the same binary rather than a step inside `scanner backup`,
// for three reasons that are all the same reason.
//
//  1. IT DELETES, AND `scanner backup` DOES NOT. The backup loop holds a store whose interface has
//     one method and it writes (run.go's Store); the destructive interface is a different one
//     (prune.go's Container), so no path through a backup cycle can reach a Delete. Calling a prune
//     from inside that loop would put the two back in the same process on the same schedule, and
//     the property would become a matter of review rather than of shape.
//
//  2. RETENTION IS A DECISION SOMEBODY MAKES. Policy's zero value retires no chain at all; a prune
//     that ran on the RPO clock would need a policy configured on every install, and an install
//     that got it wrong would discover it as missing recovery points.
//
//  3. DRY RUN IS THE DEFAULT AND THE PLAN IS PRINTED. Without --apply this command reads the
//     container, prints exactly what it would delete and why, and exits. That is only useful if a
//     human can run it on its own.
//
// THE ORDERER IS POSTGRES'S, and it is passed rather than assumed: chain.Verify checks the ranges
// only when it is given something that can order the source's own positions, and prune.go refuses to
// retire anything at all when it is not (nothing could then be shown whole). Today the one source is
// Postgres; the day there is another, this is where the second orderer is chosen.

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/manukyanv07/parity-scanner/agent/internal/backup"
	"github.com/manukyanv07/parity-scanner/agent/internal/backup/store"
	"github.com/manukyanv07/parity-scanner/chain/postgres"
)

// pruneConfig is the whole of what an operator chooses.
type pruneConfig struct {
	containerURL string
	scope        string
	keep         time.Duration
	superseded   bool
	apply        bool
}

// pruneFlags registers everything the command takes, with the same environment fallbacks `scanner
// backup` uses — in a container the environment is the normal route, and these are the same two
// values that command already reads.
func pruneFlags(fs *flag.FlagSet) *pruneConfig {
	c := &pruneConfig{}
	fs.StringVar(&c.containerURL, "container-url", os.Getenv("PARITY_BACKUP_CONTAINER"),
		"https://<account>.blob.core.windows.net/<container> — the container to prune (required)")
	fs.StringVar(&c.scope, "scope", os.Getenv("PARITY_BACKUP_SCOPE"),
		"the stable root every cycle for this source writes under; it bounds what may be deleted (required)")
	// NO DEFAULT, and it is the flag this whole command is about: a default retention window is a
	// decision nobody made, applied to every install, that deletes backups.
	fs.DurationVar(&c.keep, "keep", 0,
		"retire a chain whose newest recovery point is older than this (e.g. 720h). Unset, no chain is retired")
	fs.BoolVar(&c.superseded, "superseded", false,
		"also retire chains a re-base ended. OFF by default: such a chain is still the only thing "+
			"that restores to any point before the new base")
	fs.BoolVar(&c.apply, "apply", false,
		"actually delete. Without it this prints the plan and touches nothing")
	return c
}

// refuse returns nil only when the command can safely open something.
//
// THE TRIM IS THE SAME ONE backupConfig.normalise DOES AND FOR THE SAME REASON. A scope with a
// stray space passes every emptiness test and backup.checkPrefix alike, and addresses a tree
// nothing was ever written to — which this command would read as an empty container and this one's
// answer to an empty container is to delete nothing, so the failure is silent both ways.
func (c *pruneConfig) refuse() error {
	c.containerURL, c.scope = strings.TrimSpace(c.containerURL), strings.TrimSpace(c.scope)
	if c.containerURL == "" || c.scope == "" {
		return errors.New("prune: refusing to start without --container-url and --scope. The scope " +
			"is what bounds every deletion, and a listing with no prefix is the whole container — " +
			"every other source's backups in it would read as this one's debris")
	}
	// A WINDOW THAT OPENS IN THE FUTURE RETIRES EVERY CHAIN IN THE CONTAINER. It is a typo with a
	// minus sign in it, and it is the one value of this flag that is never what anybody meant.
	if c.keep < 0 {
		return fmt.Errorf("prune: --keep is %s, so the retention window would open in the future "+
			"and every chain in %s would be older than it", c.keep, c.scope)
	}
	return nil
}

// policy is what this configuration is willing to lose. THE ZERO CONFIGURATION RETIRES NOTHING: it
// sweeps a killed cycle's debris and leaves every chain alone.
func (c pruneConfig) policy(now time.Time) backup.Policy {
	policy := backup.Policy{Superseded: c.superseded}
	if c.keep > 0 {
		policy.Before = now.Add(-c.keep)
	}
	return policy
}

// pruneCommand is `scanner prune` with a return value, so the one exit path is here.
//
//	0  the plan was produced, and applied if it was asked for
//	1  the container, or what is in it, stopped the prune
//	2  it was misconfigured, and nothing was opened
func pruneCommand(args []string) int {
	fs := flag.NewFlagSet("prune", flag.ExitOnError)
	cfg := pruneFlags(fs)
	_ = fs.Parse(args) // ExitOnError: Parse exits itself, it never returns an error

	if err := cfg.refuse(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	ctx := context.Background()
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "prune: resolve an Azure credential:", err)
		return 2
	}
	blobs, err := store.NewBlob(cred, cfg.containerURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "prune:", err)
		return 2
	}

	now := time.Now().UTC()
	policy := cfg.policy(now)

	// READ, THEN DECIDE, THEN — SEPARATELY — DELETE. Assemble makes no decision and Prune reaches
	// no container, so everything up to the plan below is a read of the customer's container and
	// nothing else.
	assembled, err := backup.Assemble(ctx, blobs, cfg.scope)
	if err != nil {
		fmt.Fprintln(os.Stderr, "prune:", err)
		return 1
	}
	plan, err := backup.Prune(assembled.Scope, now, assembled.Chains, assembled.Listed,
		policy, postgres.WAL{})
	if err != nil {
		fmt.Fprintln(os.Stderr, "prune:", err)
		return 1
	}

	// THE PLAN IS PRINTED WHETHER OR NOT IT WILL RUN, and it is printed BEFORE it runs. It is the
	// only thing between a policy and a customer's last backup, and a plan nobody can read is a
	// plan nobody will check.
	fmt.Printf("prune: %d chains under %s\n", len(assembled.Chains), assembled.Scope)
	fmt.Print(plan)

	if !cfg.apply {
		fmt.Println("prune: nothing was deleted — pass --apply to run this plan")
		return 0
	}
	if err := backup.Apply(ctx, blobs, plan, postgres.WAL{}); err != nil {
		// Apply stops at the first failure, and what has already gone is a retired chain's
		// manifests — objects under no manifest, which the next prune sweeps as debris.
		fmt.Fprintln(os.Stderr, "prune:", err)
		return 1
	}
	fmt.Printf("prune: %d objects deleted\n", len(plan.Delete))
	return 0
}
