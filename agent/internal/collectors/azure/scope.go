package azure

import (
	"fmt"
	"sort"
	"strings"

	"github.com/manukyanv07/parity-scanner/contract"
)

// Scoping the estate: leaving out what a recovery plan can never act on.
//
// The product's question is "can this application be stood back up in a new subscription and a new
// region". Two categories of resource cannot contribute to that answer, and both were polluting the
// estate badly enough to change the numbers a customer would see:
//
//  1. THE SCANNER'S OWN STACK. A scan that reports the scanner is measuring itself. Its job,
//     identity, environment, workspace and storage account are not part of the customer's
//     application, they exist only to look at it, and nobody restores them - a fresh install
//     creates them. On the measured estate this was 5 of 79 resources plus their references.
//
//  2. AZURE PLATFORM-MANAGED RESOURCES. When a Container Apps environment is created, Azure builds
//     a load balancer, a public IP and protected-item records inside a resource group it owns and
//     names (ME_<env>_<rg>_<region>). Recreating the environment recreates all of them; there is
//     nothing to plan, restore, or even configure. The same is true of NetworkWatcher, which Azure
//     recreates automatically in NetworkWatcherRG whenever a VNet appears in a region.
//
// Both are DECLARED, not silently dropped - scopeGaps() reports what was excluded and why, and the
// behaviour is a flag, so a scan can include them when someone wants to look.
//
// The honest cost of this: Document is meant to be the source material for every later derivation,
// so that a Knowledge Base improvement can re-derive a stored estate with no re-scan. Rows excluded
// here are not in the estate and cannot be re-derived from it - closing that hole needs a re-scan
// with includePlatformManaged set. That is an acceptable trade for these two categories precisely
// because neither is restorable, but it is a trade rather than a free win.

// platformGroupPrefixes are resource groups Azure creates, names and owns.
//
// Matching on the GROUP rather than on managedBy is deliberate and measured: on a live estate the
// Container Apps load balancer, its public IP and both unifiedprotecteditems rows all had an EMPTY
// managedBy, so the field that ought to identify platform ownership does not. The group prefix
// identified all four correctly.
var platformGroupPrefixes = []string{
	"me_",                   // Container Apps managed environment infrastructure
	"mc_",                   // AKS node resource group
	"ma_",                   // App Service Environment
	"networkwatcherrg",      // recreated automatically per region
	"defaultresourcegroup-", // auto-created Log Analytics / App Insights
	"azurebackuprg_",        // Azure Backup instant restore
	"databricks-rg-",        // Databricks managed resource group
	"cloud-shell-storage-",  // Cloud Shell
	"microsoft-network",     // network manager artefacts
	"dynamicsdeployments",   // Dynamics-managed
	"aksmanagedrg",          // AKS managed
}

// platformOnlyTypes never describe customer-authored configuration, wherever they live.
var platformOnlyTypes = []string{
	"microsoft.network/networkwatchers",
	"microsoft.network/networkwatchers/flowlogs",
	// A read-only projection of what Azure Business Continuity already protects. It mirrors other
	// resources rather than configuring anything, so it cannot be restored, only re-derived.
	"microsoft.azurebusinesscontinuity/unifiedprotecteditems",
	"microsoft.azurebusinesscontinuity/deletedunifiedprotecteditems",
	// Defender posture. Deliberately not queried at all any more, but a type check costs nothing
	// and keeps the estate clean if a future table reintroduces them.
	"microsoft.security/assessments",
	"microsoft.security/securescores",
	"microsoft.security/securescores/securescorecontrols",
	"microsoft.security/pricings",
	"microsoft.security/securitycontacts",
}

// scopeReport records what scoping removed, so it can be declared rather than hidden.
type scopeReport struct {
	ownStack  []string
	platform  []string
	byGroup   map[string]int
	excluding []string // the groups that were named as the scanner's own
}

// scopeEstate splits resources into the ones a recovery plan can act on and the ones it cannot.
//
// excludeGroups is normally the single resource group the scanner itself was deployed into, passed
// in by the install template. Matching is case-insensitive because ARM's own casing of a resource
// group is inconsistent between the id and the resourceGroup column.
func scopeEstate(resources []contract.Resource, excludeGroups []string, includePlatformManaged bool) ([]contract.Resource, scopeReport) {
	report := scopeReport{byGroup: map[string]int{}}
	own := map[string]bool{}
	for _, g := range excludeGroups {
		if g = strings.ToLower(strings.TrimSpace(g)); g != "" {
			own[g] = true
			report.excluding = append(report.excluding, g)
		}
	}
	sort.Strings(report.excluding)

	kept := make([]contract.Resource, 0, len(resources))
	for _, r := range resources {
		group := strings.ToLower(r.Group)

		if own[group] {
			report.ownStack = append(report.ownStack, r.ID)
			report.byGroup[group]++
			continue
		}
		if !includePlatformManaged && platformManaged(r.Type, group) {
			report.platform = append(report.platform, r.ID)
			report.byGroup[group]++
			continue
		}
		kept = append(kept, r)
	}
	return kept, report
}

// platformManaged reports whether Azure owns this resource rather than the customer.
func platformManaged(resourceType, group string) bool {
	for _, t := range platformOnlyTypes {
		if resourceType == t {
			return true
		}
	}
	for _, prefix := range platformGroupPrefixes {
		if strings.HasPrefix(group, prefix) {
			return true
		}
	}
	return false
}

// maxScopeExamples bounds the declaration. The actionable fact is the count and the groups, not
// every id.
const maxScopeExamples = 5

// scopeGaps declares what scoping removed.
//
// §2.3 makes the gaps list the scanner's own statement about what it did not deliver, and an
// exclusion is exactly that even when it is deliberate. Reported as ONE gap per category rather
// than one per resource, for the same reason foreignAccountGaps groups by account: the useful fact
// is the category and the count.
func scopeGaps(report scopeReport) []contract.Gap {
	var gaps []contract.Gap

	if n := len(report.ownStack); n > 0 {
		gaps = append(gaps, contract.Gap{
			// EXCLUDED, not out-of-scope. The two are different claims and the coverage manifest acts
			// on the difference: out-of-scope means an account we were never invited into and genuinely
			// cannot read, which makes a resource cantSee. This is the scanner's own deployment, which
			// we can read perfectly well and deliberately skip.
			Reason: contract.GapExcluded,
			Target: "cloud-parity-scanner-own-stack",
			Detail: fmt.Sprintf("%d resources belonging to the scanner's own deployment were excluded, "+
				"in resource group(s) %s. They are the job, identity, environment, workspace and storage "+
				"account that run the scan, not part of the application under test, and a fresh install "+
				"recreates them - so a recovery plan has nothing to do with them. Examples: %s",
				n, strings.Join(report.excluding, ", "), examples(report.ownStack)),
		})
	}

	if n := len(report.platform); n > 0 {
		gaps = append(gaps, contract.Gap{
			// EXCLUDED, and this one was actively misleading. Reported as out-of-scope, every
			// platform-managed resource became "we cannot see this" in the coverage manifest, when the
			// truth is "we can see it and chose not to collect it, because recreating the owning
			// resource recreates it". --include-platform-managed proves we can read them.
			//
			// That is the manifest's own distinction getting it backwards: not claiming false
			// readiness, but claiming false blindness. Both mislead a customer reading the number.
			Reason: contract.GapExcluded,
			Target: "azure-platform-managed",
			Detail: fmt.Sprintf("%d Azure platform-managed resources were excluded. Azure creates, names "+
				"and owns these - a Container Apps environment's load balancer and public IP in its ME_ "+
				"group, NetworkWatcher, business-continuity projections - and recreating the owning "+
				"resource recreates them, so there is nothing to configure or restore. Re-run with "+
				"platform-managed resources included to see them. Examples: %s",
				n, examples(report.platform)),
		})
	}
	return gaps
}

func examples(ids []string) string {
	shown := ids
	if len(shown) > maxScopeExamples {
		shown = shown[:maxScopeExamples]
	}
	short := make([]string, 0, len(shown))
	for _, id := range shown {
		if i := strings.LastIndex(id, "/providers/"); i >= 0 {
			short = append(short, id[i+len("/providers/"):])
			continue
		}
		short = append(short, id)
	}
	return strings.Join(short, ", ")
}

// typesPresent is the set of resource types the estate actually holds, which is what makes a
// type-specific gap conditional instead of a standing claim.
func typesPresent(resources []contract.Resource) map[string]bool {
	present := make(map[string]bool, len(resources))
	for _, r := range resources {
		present[r.Type] = true
	}
	return present
}
