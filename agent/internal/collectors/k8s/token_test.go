package k8s

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// fakeCredential counts calls so the caching behaviour is observable.
type fakeCredential struct {
	calls  int
	expiry time.Duration
	err    error
	value  string
}

func (f *fakeCredential) GetToken(_ context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	f.calls++
	if f.err != nil {
		return azcore.AccessToken{}, f.err
	}
	if len(opts.Scopes) != 1 || opts.Scopes[0] != aksScope {
		return azcore.AccessToken{}, errors.New("wrong scope: " + opts.Scopes[0])
	}
	return azcore.AccessToken{Token: f.value, ExpiresOn: time.Now().Add(f.expiry)}, nil
}

// A token good for an hour must be fetched once and reused. Requesting a fresh one per LIST would
// mean one Entra round trip per kind on every scan, for no benefit.
func TestEntraTokenIsCachedWhileValid(t *testing.T) {
	cred := &fakeCredential{expiry: time.Hour, value: "entra-token"}
	src := &entraTokenSource{cred: cred}
	for i := 0; i < 5; i++ {
		got, err := src.token(context.Background())
		if err != nil {
			t.Fatalf("token(): %v", err)
		}
		if got != "entra-token" {
			t.Fatalf("token() = %q", got)
		}
	}
	if cred.calls != 1 {
		t.Errorf("fetched the token %d times, want 1 - it is cached until nearly expired", cred.calls)
	}
}

// The mirror of the projected-token bug: a token expiring mid-scan turns the rest of the estate into
// permission gaps blaming the customer's role. Renewing inside the window prevents that.
func TestEntraTokenRenewsBeforeExpiry(t *testing.T) {
	cred := &fakeCredential{expiry: tokenRefreshWindow / 2, value: "nearly-expired"}
	src := &entraTokenSource{cred: cred}
	for i := 0; i < 3; i++ {
		if _, err := src.token(context.Background()); err != nil {
			t.Fatalf("token(): %v", err)
		}
	}
	if cred.calls != 3 {
		t.Errorf("fetched %d times, want 3: a token inside the refresh window must not be reused", cred.calls)
	}
}

// The scope is the AKS audience, not ARM. A wrong audience is rejected as a bare 401 that says
// nothing about audiences, so it is asserted rather than trusted.
func TestEntraTokenUsesTheAksAudience(t *testing.T) {
	if aksScope != "6dae42f8-4368-4678-94ff-3960e28e3630/.default" {
		t.Errorf("aksScope = %q, which is not the AKS server application id", aksScope)
	}
	cred := &fakeCredential{expiry: time.Hour, value: "t"}
	if _, err := (&entraTokenSource{cred: cred}).token(context.Background()); err != nil {
		t.Errorf("token() rejected the AKS scope: %v", err)
	}
}

func TestEntraTokenErrorsAreWrapped(t *testing.T) {
	src := &entraTokenSource{cred: &fakeCredential{err: errors.New("no managed identity assigned")}}
	_, err := src.token(context.Background())
	if err == nil {
		t.Fatal("want an error when the credential fails")
	}
	// The message must name the audience, because "failed to acquire token" alone sends people
	// looking at the wrong permission.
	if !strings.Contains(err.Error(), aksScope) ||
		!strings.Contains(err.Error(), "no managed identity assigned") {
		t.Errorf("error does not carry the scope and the cause: %v", err)
	}

	// An empty token with no error is the nastier case: it would be sent as "Bearer " and answered
	// with 401, which reads as a permission problem.
	empty := &entraTokenSource{cred: &fakeCredential{expiry: time.Hour, value: ""}}
	if _, err := empty.token(context.Background()); err == nil {
		t.Error("an empty token was accepted; it would be sent as a bare Bearer and 401")
	}
}
