package main

// These tests are the refusal and the policy, and nothing else — the same shape backup_test.go
// takes, for the command that DELETES. What `scanner prune` must never do is reach a container
// without being told which tree in it may be touched, so every case here stops at the
// configuration: no Azure, no credential, no listing, no network.

import (
	"flag"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/manukyanv07/parity-scanner/agent/internal/backup"
)

// THE SCOPE IS WHAT BOUNDS EVERY DELETION. Without it there is no anchored prefix, and a listing
// with no prefix is the whole container — in which every other source's backups read as this
// scope's debris. Refused where it costs an error rather than a backup.
func TestPruneRefusesWithoutTheTwoThingsThatBoundIt(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  pruneConfig
	}{
		{name: "nothing at all"},
		{name: "no scope", cfg: pruneConfig{containerURL: "https://acct.blob.core.windows.net/staging"}},
		{name: "no container", cfg: pruneConfig{scope: "install-7/pg1/orders"}},
		{name: "a scope that is only spaces", cfg: pruneConfig{
			containerURL: "https://acct.blob.core.windows.net/staging",
			scope:        "   ",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			if err := cfg.refuse(); err == nil {
				t.Error("the command got past its own configuration with nothing bounding it")
			}
		})
	}
}

// A NEGATIVE RETENTION WINDOW OPENS IN THE FUTURE, which retires every chain in the container. It
// is a typo with a minus sign in it, and it is refused before a credential is resolved.
func TestPruneRefusesARetentionWindowThatOpensInTheFuture(t *testing.T) {
	cfg := pruneConfig{
		containerURL: "https://acct.blob.core.windows.net/staging",
		scope:        "install-7/pg1/orders",
		keep:         -720 * time.Hour,
	}
	err := cfg.refuse()
	if err == nil {
		t.Fatal("a window that opens in the future was accepted")
	}
	if !strings.Contains(err.Error(), "install-7/pg1/orders") {
		t.Errorf("the refusal does not say which scope it would have emptied: %v", err)
	}
}

// The environment is the normal route in a container, and it must reach the same two flags an
// operator already sets for `scanner backup` — one who set PARITY_BACKUP_SCOPE and got "refusing to
// start without --scope" would go looking for a variable that is right there.
func TestPruneReadsTheSameEnvironmentTheBackupCommandDoes(t *testing.T) {
	t.Setenv("PARITY_BACKUP_CONTAINER", "https://acct.blob.core.windows.net/staging")
	t.Setenv("PARITY_BACKUP_SCOPE", "install-7/pg1/orders")

	fs := flag.NewFlagSet("prune", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	cfg := pruneFlags(fs)
	if err := fs.Parse(nil); err != nil {
		t.Fatalf("parse no arguments: %v", err)
	}
	if err := cfg.refuse(); err != nil {
		t.Fatalf("the command refused although the environment held both values: %v", err)
	}
	if cfg.scope != "install-7/pg1/orders" {
		t.Errorf("the scope came out as %q", cfg.scope)
	}
}

// THE ZERO CONFIGURATION RETIRES NO CHAIN AT ALL. It sweeps a killed cycle's debris and leaves
// every chain alone, which is the conservative default the whole of prune.go is built around:
// retention is a decision somebody makes, never one that happens.
func TestPruneRetiresNothingUntilSomebodySaysSo(t *testing.T) {
	now := time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

	if got := (pruneConfig{}).policy(now); got != (backup.Policy{}) {
		t.Errorf("an unconfigured prune would retire chains: %+v", got)
	}

	windowed := pruneConfig{keep: 720 * time.Hour}.policy(now)
	if want := now.Add(-720 * time.Hour); !windowed.Before.Equal(want) {
		t.Errorf("the retention window opens at %s, want %s", windowed.Before, want)
	}
	if windowed.Superseded {
		t.Error("a retention window turned on retiring superseded chains, which is a separate decision")
	}
}
