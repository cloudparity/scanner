package main

// These tests are the refusal, and nothing else. What `scanner backup` must never do is start
// against a server nobody named, so every case here asserts that it stops before it opens anything
// — with no server, no cloud and no clock.

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/manukyanv07/parity-scanner/agent/internal/backup/postgres"
	"github.com/manukyanv07/parity-scanner/contract"
)

// complete is a configuration with every required field filled, so a test can take exactly one
// thing away and see it named.
func complete() backupConfig {
	return backupConfig{
		pg: postgres.Config{ //gosec:disable G101 -- a fixture that says so in its own value
			Host:     "pg.postgres.database.azure.com",
			Database: "orders",
			User:     "parity_stream",
			Password: "not-a-real-secret",
		},
		port:        5432,
		slot:        "vp_orders",
		publication: "parity_pub",
		scope:       "install-7/pg1/orders",
		serverID:    "/subscriptions/x/resourceGroups/y/providers/Microsoft.DBforPostgreSQL/flexibleServers/pg1",
		interval:    5 * time.Minute,
		vault: postgres.Vault{
			SubscriptionID:  "x",
			ResourceGroup:   "y",
			VaultName:       "vault",
			BackupInstance:  "pg1-instance",
			PolicyRuleName:  "BackupDaily",
			RestoreLocation: "westeurope",
			ContainerURL:    "https://acct.blob.core.windows.net/parity",
		},
	}
}

func TestACompleteConfigurationIsAccepted(t *testing.T) {
	if err := complete().refuse(); err != nil {
		t.Fatalf("a fully configured run was refused: %v", err)
	}
}

func TestEveryRequiredFieldIsRefusedByName(t *testing.T) {
	for _, tc := range []struct {
		name  string
		strip func(*backupConfig)
		want  string
	}{
		// EACH OF THESE IS A FIELD pgx WOULD HAPPILY FILL FROM THE ENVIRONMENT, and the result is
		// a backup that succeeds against a server nobody chose. conn.go's build refuses them one
		// connection later; this refuses them before anything is opened.
		{"host", func(c *backupConfig) { c.pg.Host = "" }, "--pg-host"},
		{"database", func(c *backupConfig) { c.pg.Database = "" }, "--pg-database"},
		{"user", func(c *backupConfig) { c.pg.User = "" }, "--pg-user"},
		{"password", func(c *backupConfig) { c.pg.Password = "" }, "PARITY_PG_PASSWORD"},
		{"slot", func(c *backupConfig) { c.slot = "" }, "--slot"},
		{"publication", func(c *backupConfig) { c.publication = "" }, "--publication"},
		{"server id", func(c *backupConfig) { c.serverID = "" }, "--server-id"},
		{"scope", func(c *backupConfig) { c.scope = "" }, "--scope"},
		{"container", func(c *backupConfig) { c.vault.ContainerURL = "" }, "--container-url"},
		{"subscription", func(c *backupConfig) { c.vault.SubscriptionID = "" }, "--azure-subscription"},
		{"resource group", func(c *backupConfig) { c.vault.ResourceGroup = "" }, "--azure-resource-group"},
		{"vault", func(c *backupConfig) { c.vault.VaultName = "" }, "--azure-vault"},
		{"backup instance", func(c *backupConfig) { c.vault.BackupInstance = "" }, "--azure-backup-instance"},
		{"policy rule", func(c *backupConfig) { c.vault.PolicyRuleName = "" }, "--azure-policy-rule"},
		{"restore location", func(c *backupConfig) { c.vault.RestoreLocation = "" }, "--azure-restore-location"},
		// THE INTERVAL HAS NO DEFAULT ON PURPOSE: it is the recovery point objective, so a default
		// would be an RPO nobody chose and every install would silently share it.
		{"interval", func(c *backupConfig) { c.interval = 0 }, "--interval"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := complete()
			tc.strip(&cfg)

			err := cfg.refuse()
			if err == nil {
				t.Fatalf("a run with no %s was accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("the refusal does not name %s, so an operator cannot fix it: %v", tc.want, err)
			}
		})
	}
}

// TestEverythingMissingIsNamedAtOnce: the alternative is restarting a container fifteen times to
// discover fifteen missing variables.
func TestEverythingMissingIsNamedAtOnce(t *testing.T) {
	err := backupConfig{}.refuse()
	if err == nil {
		t.Fatal("an empty configuration was accepted")
	}
	for _, want := range []string{"--pg-host", "--slot", "--interval", "--container-url", "--azure-vault"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("the refusal stops before %s, so it names one hole at a time: %v", want, err)
		}
	}
}

// TestASlotOutsideOurConventionIsRefusedAtStartup is the cheapest moment this mistake can be
// caught. Creating a slot under a name this agent cannot afterwards recognise as its own puts WAL
// on the customer's primary that nothing downstream can claim, and a leak of it never reaches the
// brake (slot.go).
func TestASlotOutsideOurConventionIsRefusedAtStartup(t *testing.T) {
	for _, name := range []string{"orders_stream", "vp_", "VP_ORDERS", "vp_orders; DROP"} {
		t.Run(name, func(t *testing.T) {
			cfg := complete()
			cfg.slot = name
			if err := cfg.refuse(); err == nil {
				t.Fatalf("the slot name %q was accepted, and it is not one this agent can ever "+
					"recognise as its own", name)
			}
		})
	}
}

// TestAPortThatDoesNotFitIsRefusedRatherThanNarrowed: --pg-port is a uint and postgres.Config.Port
// is a uint16, so 70000 becomes 4464 and connects to whatever is listening there, while 65536
// becomes 0 and comes back from conn.go as "port is not set" — a missing-variable hunt for a value
// the operator typed.
func TestAPortThatDoesNotFitIsRefusedRatherThanNarrowed(t *testing.T) {
	for _, port := range []uint{0, 65536, 70000} {
		cfg := complete()
		cfg.port = port
		if err := cfg.refuse(); err == nil {
			t.Fatalf("--pg-port %d was accepted and would have been narrowed to %d", port, port%65536)
		}
	}
}

// TestValuesAreTrimmedBeforeAnythingUsesThem. A scope with stray spaces passes every emptiness test
// AND passes backup.checkPrefix, so the objects land under a second, disjoint blob prefix that
// nothing joins to the first.
func TestValuesAreTrimmedBeforeAnythingUsesThem(t *testing.T) {
	cfg := complete()
	cfg.scope = "  install-7/pg1/orders\n"
	cfg.serverID = " /subscriptions/x/resourceGroups/y "
	cfg.slot = "vp_orders\n"
	cfg.normalise()

	if cfg.scope != "install-7/pg1/orders" || cfg.serverID != "/subscriptions/x/resourceGroups/y" {
		t.Fatalf("normalise left scope %q and server id %q", cfg.scope, cfg.serverID)
	}
	// A slot name with a newline in it is not a name postgres.ValidateSlotName accepts, so an
	// untrimmed one would refuse a perfectly good configuration read out of a secret file.
	if err := cfg.refuse(); err != nil {
		t.Fatalf("a configuration that only needed trimming was refused: %v", err)
	}

	// The password keeps its spaces: they are legitimate characters in one, and changing a
	// credential silently produces "password authentication failed", which reads as a wrong
	// credential rather than a mangled one.
	cfg = complete()
	cfg.pg.Password = "  spaces  "
	cfg.normalise()
	if cfg.pg.Password != "  spaces  " {
		t.Fatal("normalise trimmed the password")
	}
}

func TestAMalformedDurationInTheEnvironmentIsAnErrorAndNotZero(t *testing.T) {
	// Zero would be reported as "--interval is not set", which sends an operator looking for a
	// variable that is right there and misspelt.
	t.Setenv("PARITY_BACKUP_INTERVAL", "5 minutes")
	if _, err := envDuration("PARITY_BACKUP_INTERVAL"); err == nil {
		t.Fatal("a duration the clock cannot read was accepted as zero")
	}

	t.Setenv("PARITY_BACKUP_INTERVAL", "5m")
	got, err := envDuration("PARITY_BACKUP_INTERVAL")
	if err != nil || got != 5*time.Minute {
		t.Fatalf("PARITY_BACKUP_INTERVAL=5m read as %v (%v)", got, err)
	}
}

func TestThePortIsPinnedRatherThanTakenFromPGPORT(t *testing.T) {
	t.Setenv("PARITY_PG_PORT", "")
	got, err := envPort()
	if err != nil || got != 5432 {
		t.Fatalf("with nothing configured the port is %d (%v), and it has to be the standard one "+
			"rather than zero — zero is what lets pgx read PGPORT", got, err)
	}

	t.Setenv("PARITY_PG_PORT", "0")
	if _, err := envPort(); err == nil {
		t.Fatal("port 0 was accepted, and it is the one value conn.go refuses precisely because " +
			"pgx fills it from PGPORT")
	}

	t.Setenv("PARITY_PG_PORT", "six thousand")
	if _, err := envPort(); err == nil {
		t.Fatal("a port the network stack cannot use was accepted")
	}
}

// THE ONE FAILURE MODE OF THE MANIFEST SUPPLIER report.Send READS. A chain that kept what the last
// cycle wrote would hand it to the next cycle that wrote nothing — a quiet database, a failure, a
// chain declared over — and the control plane would be told a backup happened that did not. Both
// entry points clear it before they can fail, and this is the assertion that they do.
//
// No server is opened: the context is dead before it starts, so Connect fails at once.
func TestACycleThatStoredNothingCarriesNoManifestForward(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for _, tc := range []struct {
		name string
		run  func(*pgChain) error
	}{
		{"a base copy that could not run", func(c *pgChain) error { _, err := c.Base(ctx); return err }},
		{"a change cycle that could not run", func(c *pgChain) error { _, err := c.Cycle(ctx); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newPGChain(complete(), nil, nil, io.Discard)
			c.wrote = &contract.Manifest{ReadPoint: contract.ReadPoint{Position: "0/1A2B000"}}

			if err := tc.run(c); err == nil {
				t.Fatal("the cycle reported success with no server, so this proves nothing")
			}
			if got := c.manifest(); got != nil {
				t.Errorf("the previous cycle's manifest survived a cycle that stored nothing: %+v", got)
			}
		})
	}
}

// The subscription is a KEY, not a name: it is what a cycle report joins to the scan of the same
// estate on, and the scanner writes it lower-case. An operator pasting the GUID as the Azure portal
// shows it would otherwise file every report under a boundary matching no estate, silently.
func TestTheSubscriptionIsFoldedBecauseItIsAJoinKey(t *testing.T) {
	cfg := complete()
	cfg.vault.SubscriptionID = "  A1B2C3D4-5E6F-4A7B-8C9D-0E1F2A3B4C5D "
	cfg.normalise()

	if cfg.vault.SubscriptionID != "a1b2c3d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d" {
		t.Errorf("normalise left the subscription as %q", cfg.vault.SubscriptionID)
	}
}

// brokenPipe is a stdout nobody is reading any more.
type brokenPipe struct{}

func (brokenPipe) Write([]byte) (int, error) { return 0, errors.New("write: broken pipe") }

// The progress log is a courtesy, not a dependency: a line that cannot be written is dropped,
// and the chain carries on exactly as it would have. This is what say() decides once for every
// progress line, and the test that keeps a future fmt.Fprintf from deciding otherwise.
func TestAProgressLineThatCannotBeWrittenIsDropped(t *testing.T) {
	var lines strings.Builder
	c := newPGChain(complete(), nil, nil, &lines)
	c.say("backup: replication slot %q dropped\n", "vp_orders")
	if got, want := lines.String(), "backup: replication slot \"vp_orders\" dropped\n"; got != want {
		t.Fatalf("say wrote %q, want %q", got, want)
	}

	// Nothing to assert but that it returns: say has no error to give back and no panic to raise.
	broken := newPGChain(complete(), nil, nil, brokenPipe{})
	broken.say("backup lag: behind=%dB messages=%d collected=%s\n", 0, 0, time.Second)
}
