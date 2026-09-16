package azure

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strings"
	"testing"

	"github.com/manukyanv07/parity-scanner/contract"
)

type fakeLister struct {
	secrets map[string][]vaultSecret
	err     error
	asked   []string
}

func (f *fakeLister) ListSecrets(_ context.Context, uri string) ([]vaultSecret, error) {
	f.asked = append(f.asked, uri)
	if f.err != nil {
		return nil, f.err
	}
	return f.secrets[uri], nil
}

func vaultResource(id, uri string) contract.Resource {
	doc, _ := json.Marshal(map[string]any{
		"id":         id,
		"properties": map[string]any{"vaultUri": uri},
	})
	return contract.Resource{
		Provider: contract.ProviderAzure, ID: id, Type: "microsoft.keyvault/vaults",
		Name: "kv1", Account: "sub-1", Group: "rg", Document: doc,
	}
}

const kvID = "/subscriptions/sub-1/resourcegroups/rg/providers/microsoft.keyvault/vaults/kv1"

func TestSecretNamesAreCollectedAndParentedToTheVault(t *testing.T) {
	lister := &fakeLister{secrets: map[string][]vaultSecret{
		"https://kv1.vault.azure.net": {
			{ID: "https://kv1.vault.azure.net/secrets/db-password",
				Attributes: map[string]any{"enabled": true, "exp": float64(1800000000)}},
			{ID: "https://kv1.vault.azure.net/secrets/api-key",
				Attributes: map[string]any{"enabled": false}, ContentType: "text/plain"},
		},
	}}
	got, gaps := collectSecretNames(context.Background(), lister,
		[]contract.Resource{vaultResource(kvID, "https://kv1.vault.azure.net/")})

	if len(gaps) != 0 {
		t.Fatalf("unexpected gaps: %+v", gaps)
	}
	if len(got) != 2 {
		t.Fatalf("got %d secrets, want 2", len(got))
	}
	// Sorted, so a re-scan of an unchanged vault is byte-identical.
	if got[0].Name != "api-key" || got[1].Name != "db-password" {
		t.Errorf("names = %q,%q; want them sorted", got[0].Name, got[1].Name)
	}
	for _, s := range got {
		if s.ParentID != kvID {
			t.Errorf("%s parentId = %q, want the vault", s.Name, s.ParentID)
		}
		if s.Type != "microsoft.keyvault/vaults/secrets" {
			t.Errorf("type = %q", s.Type)
		}
		if s.Account != "sub-1" || s.Group != "rg" {
			t.Errorf("%s did not inherit the vault's account/group", s.Name)
		}
	}
}

// The whole reason this is defensible. If a value ever appeared in Document, the product's central
// promise would be broken - so it is asserted, not just intended.
func TestSecretDocumentsNeverContainAValue(t *testing.T) {
	// A hostile service response: a value field where none should exist.
	raw := []byte(`{"value":[{"id":"https://kv1.vault.azure.net/secrets/db-password",
	  "value":"sup3r-s3cret-do-not-store","attributes":{"enabled":true}}]}`)
	var page struct{ Value []vaultSecret }
	if err := json.Unmarshal(raw, &page); err != nil {
		t.Fatal(err)
	}
	lister := &fakeLister{secrets: map[string][]vaultSecret{"https://kv1.vault.azure.net": page.Value}}
	got, _ := collectSecretNames(context.Background(), lister,
		[]contract.Resource{vaultResource(kvID, "https://kv1.vault.azure.net")})

	if len(got) != 1 {
		t.Fatalf("got %d, want 1", len(got))
	}
	if strings.Contains(string(got[0].Document), "sup3r-s3cret") {
		t.Fatal("a secret VALUE reached the estate document")
	}
	// vaultSecret has no value field at all, which is what makes the above impossible rather
	// than merely absent today.
	if strings.Contains(string(got[0].Document), "\"value\"") {
		t.Errorf("document carries a value key: %s", got[0].Document)
	}
}

// A denial must name the role that fixes it, or a customer cannot act on the gap.
func TestDeniedSecretListNamesTheRoleThatFixesIt(t *testing.T) {
	lister := &fakeLister{err: errors.New(`HTTP 403: {"error":{"code":"Forbidden","innererror":{"code":"ForbiddenByRbac"}}}`)}
	got, gaps := collectSecretNames(context.Background(), lister,
		[]contract.Resource{vaultResource(kvID, "https://kv1.vault.azure.net")})
	if len(got) != 0 {
		t.Errorf("got %d secrets from a denied vault", len(got))
	}
	if len(gaps) != 1 {
		t.Fatalf("got %d gaps, want 1", len(gaps))
	}
	if gaps[0].Reason != contract.GapPermissionDenied {
		t.Errorf("reason = %q, want permission-denied", gaps[0].Reason)
	}
	if !strings.Contains(gaps[0].Detail, "Key Vault Reader") {
		t.Errorf("the gap does not name the role: %q", gaps[0].Detail)
	}
	if !strings.Contains(gaps[0].Detail, "getSecret") {
		t.Errorf("the gap does not say the role cannot read values: %q", gaps[0].Detail)
	}
}

// A private-endpoint-only vault is unreachable rather than forbidden, and saying "grant a role"
// there would send the customer down the wrong path.
//
// It is also a limit rather than a bug, so it must not be not-attempted either. Measured on a
// stranger's walk: the scan reported "lookup cloud-parity-vault.vault.azure.net: no such host" as
// not-attempted, which the console renders as "a bug on our side rather than a limit" while the
// gap's own detail says the opposite. The collector looked; the customer's network is what the
// scanner has no route into, and the fix is a collector that runs inside it - which does not exist
// yet. Every network failure on the vault host lands on the same reason, because the remedy is the
// same whichever way the network said no.
func TestUnreachableVaultIsALimitNotABug(t *testing.T) {
	for _, err := range []error{
		errors.New(`Get "https://kv1.vault.azure.net/secrets?api-version=7.4": dial tcp: lookup kv1.vault.azure.net: no such host`),
		errors.New("dial tcp: i/o timeout"),
		errors.New("dial tcp 10.0.0.4:443: connect: connection refused"),
		&url.Error{Op: "Get", URL: "https://kv1.vault.azure.net/secrets", Err: &net.OpError{Op: "dial", Net: "tcp",
			Err: &net.DNSError{Err: "no such host", Name: "kv1.vault.azure.net", IsNotFound: true}}},
	} {
		t.Run(err.Error(), func(t *testing.T) {
			lister := &fakeLister{err: err}
			got, gaps := collectSecretNames(context.Background(), lister,
				[]contract.Resource{vaultResource(kvID, "https://kv1.vault.azure.net")})
			if len(got) != 0 {
				t.Errorf("got %d secrets from an unreachable vault", len(got))
			}
			if len(gaps) != 1 {
				t.Fatalf("got %d gaps, want 1", len(gaps))
			}
			g := gaps[0]
			if g.Reason == contract.GapNotAttempted {
				t.Error("an unreachable vault was reported as not-attempted, which the contract defines as a bug on our side")
			}
			if g.Reason == contract.GapPermissionDenied {
				t.Error("an unreachable vault was reported as a permission problem - the remedy is opposite")
			}
			if g.Reason != contract.GapNoCollector {
				t.Errorf("reason = %q, want no-collector: the collector that can reach it runs inside the customer's network and does not exist yet", g.Reason)
			}
			if g.Target != kvID+"/secrets" {
				t.Errorf("target = %q, want the vault's secrets", g.Target)
			}
			if !strings.Contains(g.Detail, "private endpoint") {
				t.Errorf("the gap does not name the cause: %q", g.Detail)
			}
			if !strings.Contains(g.Detail, "not a bug") {
				t.Errorf("the gap does not say this is a limit rather than a bug: %q", g.Detail)
			}
			if !strings.Contains(g.Detail, "inside the customer's network") {
				t.Errorf("the gap does not say what closes it: %q", g.Detail)
			}
			if !strings.Contains(g.Detail, err.Error()) {
				t.Errorf("the gap discards the network's own words: %q", g.Detail)
			}
		})
	}
}

// A failure that is neither a 403 nor a network error is one this collector does not understand,
// and that IS ours to look at - so not-attempted stays honest there, but it must not blame the
// customer's network for something it has not established.
func TestUnrecognisedListFailureStaysNotAttemptedWithoutGuessingACause(t *testing.T) {
	lister := &fakeLister{err: errors.New("invalid character '<' looking for beginning of value")}
	_, gaps := collectSecretNames(context.Background(), lister,
		[]contract.Resource{vaultResource(kvID, "https://kv1.vault.azure.net")})
	if len(gaps) != 1 || gaps[0].Reason != contract.GapNotAttempted {
		t.Fatalf("gaps = %+v, want one not-attempted", gaps)
	}
	if strings.Contains(gaps[0].Detail, "private endpoint") {
		t.Errorf("the gap guesses at a network cause it never saw: %q", gaps[0].Detail)
	}
	if !strings.Contains(gaps[0].Detail, "invalid character") {
		t.Errorf("the gap discards the error: %q", gaps[0].Detail)
	}
}

func TestOnlyVaultsAreAsked(t *testing.T) {
	lister := &fakeLister{}
	collectSecretNames(context.Background(), lister, []contract.Resource{
		vaultResource(kvID, "https://kv1.vault.azure.net"),
		{Type: "microsoft.storage/storageaccounts", ID: "/x", Document: json.RawMessage(`{}`)},
	})
	if len(lister.asked) != 1 {
		t.Errorf("asked %v, want only the vault", lister.asked)
	}
}

func TestVaultWithNoURIIsReportedRatherThanSkipped(t *testing.T) {
	v := contract.Resource{
		Provider: contract.ProviderAzure, ID: kvID, Type: "microsoft.keyvault/vaults",
		Document: json.RawMessage(`{"id":"` + kvID + `","properties":{}}`),
	}
	_, gaps := collectSecretNames(context.Background(), &fakeLister{}, []contract.Resource{v})
	if len(gaps) != 1 || gaps[0].Reason != contract.GapNotAttempted {
		t.Fatalf("gaps = %+v, want one not-attempted", gaps)
	}
}

// The two 403s a vault can return mean opposite things, and getting it wrong sends the customer to
// grant a role they already hold. Measured: sealing a testbed vault to its private endpoint
// produced exactly this, and the first version of secretGap misreported it.
func TestNetworkBlockedVaultIsNotReportedAsAPermissionProblem(t *testing.T) {
	lister := &fakeLister{err: errors.New(`HTTP 403: {"error":{"code":"Forbidden",` +
		`"message":"Public network access is disabled and request is not from a trusted service nor via an approved private link.",` +
		`"innererror":{"code":"ForbiddenByConnection"}}}`)}
	_, gaps := collectSecretNames(context.Background(), lister,
		[]contract.Resource{vaultResource(kvID, "https://kv1.vault.azure.net")})
	if len(gaps) != 1 {
		t.Fatalf("got %d gaps, want 1", len(gaps))
	}
	g := gaps[0]
	if g.Reason == contract.GapPermissionDenied {
		t.Error("a network block was reported as a permission problem - the remedy is opposite")
	}
	// Same limit as a vault whose name never resolved: the network said no, in words this time.
	if g.Reason != contract.GapNoCollector {
		t.Errorf("reason = %q, want no-collector - a network block is a limit, not a bug", g.Reason)
	}
	if !strings.Contains(g.Detail, "Granting a role changes NOTHING") {
		t.Errorf("the gap does not say a role change is useless here: %q", g.Detail)
	}
	if !strings.Contains(g.Detail, "private endpoint") {
		t.Errorf("the gap does not name the real cause: %q", g.Detail)
	}
	// Azure's own words must survive, because they are what settles the diagnosis.
	if !strings.Contains(g.Detail, "Azure said:") {
		t.Errorf("the gap discards Azure's message: %q", g.Detail)
	}
}

// An unrecognised 403 must name BOTH causes rather than guess one.
func TestAmbiguous403NamesBothCauses(t *testing.T) {
	lister := &fakeLister{err: errors.New("HTTP 403: Forbidden")}
	_, gaps := collectSecretNames(context.Background(), lister,
		[]contract.Resource{vaultResource(kvID, "https://kv1.vault.azure.net")})
	if len(gaps) != 1 {
		t.Fatalf("got %d gaps, want 1", len(gaps))
	}
	d := gaps[0].Detail
	if !strings.Contains(d, "Key Vault Reader") || !strings.Contains(d, "public network access") {
		t.Errorf("an ambiguous 403 must name both causes: %q", d)
	}
	if !strings.Contains(d, "before granting anything") {
		t.Errorf("the gap does not tell the reader what to check first: %q", d)
	}
}
