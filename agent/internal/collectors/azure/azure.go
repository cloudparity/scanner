// Package azure is the Azure collector — it reads the Azure control plane (ARM) via
// Resource Graph and implements collectors.Collector (infra-scanner spec §3–§5).
//
// It is the only code in the system that knows what an ARM resourceId looks like.
// Everything it emits is stated in the contract's vocabulary.
//
// The package is split along the pipeline: discover.go (§3) reads, translate.go (§4)
// restates identity in our vocabulary, link.go (§5) records references. This file holds
// only the wiring.
package azure

import (
	"context"
	"fmt"

	"github.com/manukyanv07/parity-scanner/agent/internal/collectors"
	"github.com/manukyanv07/parity-scanner/contract"
)

// Collector reads one Azure subscription (read-only by default, metadata only).
// One subscription per run: subscriptions are onboarded, never auto-adopted (AD-013).
type Collector struct {
	subscription string

	// excludeGroups are resource groups left out of the estate, normally the single group the
	// scanner itself was deployed into. Set by the install template, because the scanner cannot
	// reliably infer its own group from inside a container.
	excludeGroups []string

	// includePlatformManaged keeps resources Azure creates and owns. Off by default: they cannot
	// be restored, only recreated by recreating their owner.
	includePlatformManaged bool

	// client is nil in production and built on first Collect. Tests inject a fake so the
	// end-to-end suite exercises THIS method rather than a hand-copy of it; the previous
	// copy had already drifted from the gap text below.
	client graphClient

	// fetcher reads the children no ARG table returns, one ARM call per parent. Also nil in
	// production and injected by tests.
	fetcher armFetcher

	// secrets lists Key Vault secret NAMES. Nil in production and built on first Collect.
	secrets secretLister
}

// Compile-time check that the Azure collector satisfies the interface.
var _ collectors.Collector = (*Collector)(nil)

// New returns an Azure collector scoped to one subscription.
func New(subscription string) *Collector { return &Collector{subscription: subscription} }

// ExcludeGroups leaves the named resource groups out of the estate. Used for the scanner's own
// deployment, so a scan never reports the thing doing the scanning.
func (c *Collector) ExcludeGroups(groups ...string) *Collector {
	c.excludeGroups = append(c.excludeGroups, groups...)
	return c
}

// IncludePlatformManaged keeps Azure-owned resources in the estate. Off by default.
func (c *Collector) IncludePlatformManaged(include bool) *Collector {
	c.includePlatformManaged = include
	return c
}

// Plane reports which cloud this collector reads.
func (c *Collector) Plane() collectors.Plane { return collectors.PlaneAzure }

// Collect runs Discover -> Translate -> Fetch -> Translate -> Link for the subscription.
//
// Fetch sits between the two Translates because it needs translated resources to know which
// parents to ask about, and its own rows then need translating like any others.
func (c *Collector) Collect(ctx context.Context) ([]contract.Resource, []contract.Dependency, []contract.Gap, error) {
	client := c.client
	if client == nil {
		var err error
		if client, err = newGraphClient(); err != nil {
			return nil, nil, nil, err
		}
	}

	fetcher := c.fetcher
	if fetcher == nil {
		var err error
		if fetcher, err = newARMFetcher(); err != nil {
			return nil, nil, nil, err
		}
	}

	raw, gaps, err := discover(ctx, client, c.subscription)
	if err != nil {
		return nil, nil, nil, err
	}
	resources, unscreened := translate(c.subscription, raw)
	// Scoped BEFORE fetchChildren, so an excluded resource costs no ARM calls either.
	resources, scoped := scopeEstate(resources, c.excludeGroups, c.includePlatformManaged)
	// §2.4's flagging half: fields shipped without being checked against the redaction
	// list. Not a claim that a secret leaked - a claim that nobody has looked.
	gaps = append(gaps, unscreened...)
	// The scanner never claims more than it shipped: the difference between "the
	// subscription is empty" and "we read it and then dropped it", where only the second
	// is true. A count cannot name which resource vanished, which is why translateRow
	// drops only rows that cannot be identified at all.
	if len(resources)+len(scoped.ownStack)+len(scoped.platform) != len(raw) {
		gaps = append(gaps, contract.Gap{
			Reason: contract.GapNotAttempted,
			Target: "/subscriptions/" + c.subscription,
			Detail: fmt.Sprintf("discovered %d resources but translated %d; the rest are absent from this estate", len(raw), len(resources)),
		})
	}
	// Children that exist in no ARG table, fetched one ARM call per parent. A failed fetch
	// becomes a gap rather than failing the scan: a dropped Discover page makes the whole
	// resource list wrong, while a failed child fetch loses one known child of one known
	// resource, and saying so precisely beats discarding a good estate.
	// Key Vault secret NAMES, from the vault data plane. Attempted always: if the credential
	// lacks Key Vault Reader the failure becomes a permission gap that names the role, which is
	// more useful to a customer than silently omitting the secrets.
	lister := c.secrets
	if lister == nil {
		if lister, err = newSecretLister(); err != nil {
			return nil, nil, nil, err
		}
	}
	secretRows, secretGaps := collectSecretNames(ctx, lister, resources)
	gaps = append(gaps, secretGaps...)
	resources = append(resources, secretRows...)

	// Which app settings point at a Key Vault secret. Needs no permission beyond Reader, and it
	// is the only way to see the pointer at all: sites/config masks every setting VALUE, so the
	// @Microsoft.KeyVault(...) address is masked along with the real secrets.
	vaultRefs, vaultRefGaps := collectVaultReferences(ctx, fetcher, resources)
	gaps = append(gaps, vaultRefGaps...)
	resources = append(resources, vaultRefs...)

	childRows, fetchGaps := fetchChildren(ctx, fetcher, resources)
	gaps = append(gaps, fetchGaps...)
	if len(childRows) > 0 {
		children, childUnscreened := translate(c.subscription, childRows)
		gaps = append(gaps, childUnscreened...)
		// Children of kept parents only, but scoped again: a diagnostic setting attached to an
		// excluded resource is itself out of scope, and platformOnlyTypes can appear here too.
		children, childScoped := scopeEstate(children, c.excludeGroups, c.includePlatformManaged)
		scoped.ownStack = append(scoped.ownStack, childScoped.ownStack...)
		scoped.platform = append(scoped.platform, childScoped.platform...)
		resources = append(resources, children...)
	}
	gaps = append(gaps, scopeGaps(scoped)...)

	// Type-specific gaps are appended HERE, not in discover, because "was this unread" is only
	// answerable once we know which types the estate actually holds.
	gaps = append(gaps, unreadGaps(typesPresent(resources))...)

	references, linkGaps := link(resources)
	// An out-of-scan reference into another subscription is an un-onboarded account, which is
	// what GapOutOfScope exists to say. Nothing emitted it before link existed.
	gaps = append(gaps, linkGaps...)
	return resources, references, gaps, nil
}
