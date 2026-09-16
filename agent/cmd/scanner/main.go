// Command scanner is the Cloud Parity infrastructure scanner (MVP).
// See docs/specs/infra-scanner.md. Read-only, metadata-only, single static binary.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/manukyanv07/parity-scanner/agent/internal/collectors/azure"
	"github.com/manukyanv07/parity-scanner/agent/internal/collectors/k8s"
	"github.com/manukyanv07/parity-scanner/agent/internal/plan"
	"github.com/manukyanv07/parity-scanner/agent/internal/upload"
	"github.com/manukyanv07/parity-scanner/contract"
)

// collectorVersion identifies which build produced an estate, so a payload can be traced
// back to the code that wrote it (contract.md ScanMeta.Collector).
const collectorVersion = "0.1.0"

// emit writes the estate where the operator asked for it.
//
// STDOUT REMAINS THE DEFAULT, and that is not laziness. It is how the test fixtures in this repo were
// captured, it is what makes `scanner scan | jq` work, and an air-gapped or heavily regulated
// customer will want to read the file themselves before anyone else does. Uploading is the addition,
// not the replacement.
func emit(est *contract.Estate, client *upload.Client) {
	if client == nil {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		// A truncated estate that exits 0 would be read as a complete one.
		if err := enc.Encode(est); err != nil {
			fmt.Fprintln(os.Stderr, "scan: writing estate:", err)
			os.Exit(1)
		}
		return
	}

	// Progress on stderr, so stdout stays clean for anything piping the estate.
	fmt.Fprintf(os.Stderr, "uploading %d resources to %s\n", est.Scan.ResourceCount, client.BaseURL)
	res, err := client.Send(context.Background(), est)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "accepted: scan %s, %d resources\n", res.ScanID, res.ResourceCount)
}

// destination validates the upload flags and returns a client, or nil for stdout.
//
// CALLED BEFORE THE SCAN RUNS, not after. A scan of a real subscription takes minutes, and finding
// out at the end that the url was http, or the key was empty, means paying for all of it again. Every
// reason to refuse is knowable up front, so it is checked up front.
func destination(apiURL, apiKey string) *upload.Client {
	if strings.TrimSpace(apiURL) == "" {
		return nil
	}
	client, err := upload.New(apiURL, apiKey)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	return client
}

// apiFlags registers the upload flags on a command.
//
// The key can come from the environment as well as a flag, because a flag lands in the process list
// and in shell history. In a container the environment is the normal route anyway.
func apiFlags(fs *flag.FlagSet) (url, key *string) {
	url = fs.String("api-url", os.Getenv("PARITY_API_URL"),
		"Parity API base url. Omitted, the estate goes to stdout instead")
	key = fs.String("api-key", os.Getenv("PARITY_API_KEY"),
		"Parity API key. Prefer PARITY_API_KEY: a flag is visible in the process list")
	return url, key
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "scan-cluster":
		// The APPLICATION plane. A separate subcommand rather than a --plane flag on scan, because
		// the two run in completely different places: this one runs as a Job INSIDE the cluster
		// using the pod's service-account token, while scan runs outside any network with an Azure
		// credential (AD-024).
		fs := flag.NewFlagSet("scan-cluster", flag.ExitOnError)
		clusterID := fs.String("cluster-id", "", "the cluster's ARM resource id (required)")
		apiURL, apiKey := apiFlags(fs)
		_ = fs.Parse(os.Args[2:])
		dest := destination(*apiURL, *apiKey)
		if *clusterID == "" {
			fmt.Fprintln(os.Stderr, "scan-cluster: --cluster-id is required. A pod cannot discover which")
			fmt.Fprintln(os.Stderr, "  AKS cluster it runs in, and without it no resource has an account, so")
			fmt.Fprintln(os.Stderr, "  the estate cannot join the infra plane (AD-025).")
			os.Exit(2)
		}
		c := k8s.New(*clusterID)
		res, deps, gaps, err := c.Collect(context.Background())
		if err != nil {
			fmt.Fprintln(os.Stderr, "scan-cluster:", err)
			os.Exit(1)
		}
		est := contract.Estate{
			ContractVersion: contract.ContractVersion,
			Scan: contract.ScanMeta{
				// All three taken FROM THE COLLECTOR, never restated here. Restating them is how
				// this branch ended up lowercasing the cluster id differently from the collector,
				// and how a hardcoded "k8s/0.1.0" made the package's own collectorVersion dead.
				Provider:      contract.Provider(c.Plane()),
				Account:       c.Account(),
				ScannedAt:     time.Now().UTC().Format(time.RFC3339),
				Collector:     fmt.Sprintf("%s/%s", c.Plane(), c.Version()),
				ResourceCount: len(res),
				Gaps:          gaps,
			},
			Resources:    res,
			Dependencies: deps,
		}
		emit(&est, dest)
	case "scan":
		fs := flag.NewFlagSet("scan", flag.ExitOnError)
		subscription := fs.String("subscription", "", "Azure subscription id to scan (required)")
		// The scanner cannot reliably work out which resource group it is running in from inside a
		// container, so the install template tells it. Without this a scan reports the scanner.
		excludeGroups := fs.String("exclude-groups", "", "comma-separated resource groups to leave out of the estate, normally the scanner's own")
		includePlatform := fs.Bool("include-platform-managed", false, "keep resources Azure creates and owns (ME_/MC_ groups, NetworkWatcher); off because none of them can be restored")
		apiURL, apiKey := apiFlags(fs)
		_ = fs.Parse(os.Args[2:]) // ExitOnError: Parse exits itself, it never returns an error
		dest := destination(*apiURL, *apiKey)
		if *subscription == "" {
			fmt.Fprintln(os.Stderr, "scan: --subscription is required")
			os.Exit(2)
		}
		// Lowercased once, here. Resource.Account is lowercased (a subscription GUID is
		// a key), so leaving ScanMeta.Account as the raw flag would make an uppercase
		// --subscription emit an estate that cannot join to itself: contract.md §5 gives
		// scans.account and resources.account their own columns, and the equality would
		// silently return no rows.
		account := strings.ToLower(*subscription)
		c := azure.New(account).IncludePlatformManaged(*includePlatform)
		for _, g := range strings.Split(*excludeGroups, ",") {
			if g = strings.TrimSpace(g); g != "" {
				c = c.ExcludeGroups(g)
			}
		}
		res, refs, gaps, err := c.Collect(context.Background())
		if err != nil {
			fmt.Fprintln(os.Stderr, "scan:", err)
			os.Exit(1)
		}
		est := contract.Estate{
			ContractVersion: contract.ContractVersion,
			Scan: contract.ScanMeta{
				// Taken from the collector, not hardcoded: a copy-paste for the next
				// cloud would otherwise emit provider "azure" with nothing to catch it.
				Provider:      contract.Provider(c.Plane()),
				Account:       account,
				ScannedAt:     time.Now().UTC().Format(time.RFC3339),
				Collector:     fmt.Sprintf("%s/%s", c.Plane(), collectorVersion),
				ResourceCount: len(res),
				Gaps:          gaps,
			},
			Resources:    res,
			Dependencies: refs,
		}
		emit(&est, dest)
	case "backup":
		// THE ONE LINE THAT STARTS A REAL BACKUP LOOP. It runs until it is signalled, so it has
		// its own exit codes and its own teardown — see backup.go, where the deferred drop of the
		// replication slot is why this is os.Exit of a return value rather than a fallthrough.
		os.Exit(backupCommand(os.Args[2:]))
	case "prune":
		// THE ONLY COMMAND IN THIS BINARY THAT DELETES A CUSTOMER'S BACKUP, and a separate one from
		// backup for exactly that reason — see prune.go. It is a dry run unless it is told
		// otherwise, so this line on its own reads a container and prints what it would do.
		os.Exit(pruneCommand(os.Args[2:]))
	case "closure":
		// Not implemented: loading the Estate from --estate and parsing --select is
		// https://github.com/cloudparity/scanner/issues/8.
		_ = plan.Closure(contract.Estate{}, contract.Selection{})
		fmt.Println("closure: not implemented yet")
	case "serve":
		// Not implemented: the contract §5 endpoints are https://github.com/cloudparity/scanner/issues/9.
		fmt.Println("serve: not implemented yet")
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: scanner <scan|scan-cluster|backup|prune|closure|serve> [flags]")
	fmt.Fprintln(os.Stderr, "  scan          Azure INFRA plane -> canonical Estate JSON")
	fmt.Fprintln(os.Stderr, "  scan-cluster  Kubernetes APPLICATION plane, from inside the cluster")
	fmt.Fprintln(os.Stderr, "  backup        keep a PostgreSQL backup chain on the RPO clock, until stopped")
	fmt.Fprintln(os.Stderr, "  prune         print what a retention policy would delete; --apply to delete it")
	fmt.Fprintln(os.Stderr, "  closure  compute a recovery closure from an Estate")
	fmt.Fprintln(os.Stderr, "  serve    serve the dashboard API")
}
