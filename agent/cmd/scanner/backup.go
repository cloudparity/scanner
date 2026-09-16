package main

// backup.go is THE PRODUCTION ENTRY POINT FOR THE POSTGRES BACKUP — the thing that was missing.
//
// Everything under agent/internal/backup worked and NOTHING SHIPPING COULD RUN IT. The only program
// that drove the pipeline was agent/cmd/e2e-postgres, which is a test harness: it starts two
// throwaway containers, seeds a zoo and asserts a checksum. The agent a customer installs had no
// reference to backup anywhere in it.
//
// A SUBCOMMAND ON THE EXISTING AGENT RATHER THAN A SECOND BINARY, and the reason is the install:
// `make build` ships exactly one binary, and a second one is a second thing to distribute,
// credential, schedule and version in the customer's cloud for something the same process is already
// there to do.
//
// CONFIG IS FLAGS WITH ENVIRONMENT FALLBACKS, exactly as scan and scan-cluster do — and NOTHING HAS
// A DEFAULT THAT WOULD CONNECT SOMEWHERE. postgres/conn.go's build refuses an incomplete Config for
// precisely this reason: pgx fills an omitted host from PGHOST and the stream then runs, quite
// happily, against a server nobody chose. This file applies the same discipline one level up, over
// the whole of what a run needs, and refuses before it opens anything.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// WHAT THIS COMMAND GUARANTEES ON THE WAY OUT
// ─────────────────────────────────────────────────────────────────────────────────────────────
//
// NO LSN IS ACKNOWLEDGED THAT IS NOT DURABLE, and it is structural rather than careful. Confirm is
// reachable from exactly one place — pgchain.go's Cycle, after backup.Cycle.Run has returned a
// manifest, which is the object written LAST and only after every part is stored and audited. A
// cancelled cycle fails before that, so there is no path on which a signal advances what the server
// believes is safe to discard. The other order — confirm and then store — is the one way this
// product could lose a customer's data with every check still green.
//
// NO REPLICATION SLOT IS LEFT BEHIND on any path this process controls. The slot is created by the
// base copy and dropped by release(), which runs on a re-base and again from the one defer that
// covers every exit: a signal, a fatal error and a clean end all arrive there. THE DROP RUNS ON A
// CONTEXT THAT SURVIVES THE CANCELLATION, because a SIGTERM must not be the reason a thing only this
// role can remove is left holding WAL on the customer's primary (AD-034: an administrator cannot
// drop one). A drop that fails is reported as postgres.ErrSlotLeaked and exits non-zero — it is the
// loudest thing this command says. What no defer covers is SIGKILL and the OOM killer.
//
// THE BRAKE RUNS OUTSIDE THE CYCLE LOOP, on its own goroutine, its own ticker and its own
// connection, started BEFORE the first chain and stopped after the last. C6's own note is that a
// check which only runs inside the healthy loop is not a brake, and this is that note honoured
// STRUCTURALLY: a cycle wedged mid-upload holds the slot open and reports nothing, and the brake
// still ticks, reads the slot from the SERVER rather than from any counter of ours, and recognises
// the active backend as our own stream.
//
// AND IT CAN DROP. Brake.Disk is postgres.AzureMonitor, so both halves of the one number arrive on
// every tick — the WAL our slot retains from the primary, the disk from Azure Monitor — and Assess
// can reach Trip. A trip terminates our own wedged stream, drops our own slot, and the next cycle
// takes a new base copy.
//
// WHAT A CLIENT-SIDE BRAKE STILL CANNOT COVER — the agent gone for good, the process starved, a
// partition from the database, a disk Monitor will not report — is listed once, in brake.go, and the
// backstop for every item on it is max_slot_wal_keep_size on the server: the brake reports that
// loudly at startup when it is unlimited, which is the default, and it is the one lever the
// customer's own administrator can reach (AD-034).

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/manukyanv07/parity-scanner/agent/internal/backup/postgres"
	"github.com/manukyanv07/parity-scanner/agent/internal/backup/report"
	"github.com/manukyanv07/parity-scanner/agent/internal/backup/schedule"
	"github.com/manukyanv07/parity-scanner/agent/internal/backup/store"
)

// agentName goes in every manifest, so a backup that turns out bad traces to the build that wrote
// it (contract.Producer). The same version the estate carries.
const agentName = "scanner/" + collectorVersion

// releaseTimeout bounds the WHOLE of the teardown that runs after the run's own context has been
// cancelled: closing the stream, dialling again, and dropping the slot.
//
// TWENTY AND NOT THIRTY, and the ten seconds are the margin rather than slack. A Kubernetes
// terminationGracePeriodSeconds is 30 by default and ACI is similar, and what happens at the end of
// it is SIGKILL — which is precisely the signal that leaves the slot behind. A budget equal to the
// grace period has no room for the runtime's own overhead, and a budget per step has none at all.
const releaseTimeout = 20 * time.Second

// backupConfig is the whole of what an operator chooses.
type backupConfig struct {
	pg          postgres.Config
	port        uint
	slot        string
	publication string
	scope       string
	serverID    string
	interval    time.Duration
	brakeEvery  time.Duration
	vault       postgres.Vault
}

// backupFlags registers everything the command takes. Every flag falls back to an environment
// variable, because in a container the environment is the normal route.
//
// THERE IS NO PASSWORD FLAG AT ALL, only PARITY_PG_PASSWORD. scan's api-key says why in one line — a
// flag lands in the process list and in shell history — and this is the credential that can read
// every change in the customer's database, so it does not get the choice.
func backupFlags(fs *flag.FlagSet) (*backupConfig, error) {
	c := &backupConfig{}

	fs.StringVar(&c.pg.Host, "pg-host", os.Getenv("PARITY_PG_HOST"),
		"the Flexible Server to stream changes from (required)")
	// THE ONE FIELD WITH A DEFAULT THAT REACHES A SERVER, and it is safe for the reason the
	// others are not: a port selects nothing on its own, and pinning it here is what stops PGPORT
	// choosing one — which is the same discipline conn.go's build applies by refusing zero.
	standard, err := envPort()
	if err != nil {
		return nil, err
	}
	// Kept as a uint until Parse is done, because flag has no uint16: the narrowing happens once,
	// at the call site, on a value the operator has already been able to override.
	fs.UintVar(&c.port, "pg-port", standard, "the port on --pg-host")
	fs.StringVar(&c.pg.Database, "pg-database", os.Getenv("PARITY_PG_DATABASE"),
		"the database to back up (required)")
	fs.StringVar(&c.pg.User, "pg-user", os.Getenv("PARITY_PG_USER"),
		"the REPLICATION role the change stream authenticates as (required)")
	fs.StringVar(&c.slot, "slot", os.Getenv("PARITY_PG_SLOT"),
		"the replication slot this install owns; it must begin with vp_ (required)")
	fs.StringVar(&c.publication, "publication", os.Getenv("PARITY_PG_PUBLICATION"),
		"the publication pgoutput decodes against, created by the customer's administrator (required)")
	fs.StringVar(&c.serverID, "server-id", os.Getenv("PARITY_PG_SERVER_ID"),
		"the ARM resource id of the server, which is what a manifest says it is a backup OF (required)")
	fs.StringVar(&c.scope, "scope", os.Getenv("PARITY_BACKUP_SCOPE"),
		"the stable root in the container every cycle for this source writes under (required)")

	fs.StringVar(&c.vault.ContainerURL, "container-url", os.Getenv("PARITY_BACKUP_CONTAINER"),
		"https://<account>.blob.core.windows.net/<container> — where the base copy is restored to and the changes land (required)")
	fs.StringVar(&c.vault.SubscriptionID, "azure-subscription", os.Getenv("PARITY_AZURE_SUBSCRIPTION"), "(required)")
	fs.StringVar(&c.vault.ResourceGroup, "azure-resource-group", os.Getenv("PARITY_AZURE_RESOURCE_GROUP"), "(required)")
	fs.StringVar(&c.vault.VaultName, "azure-vault", os.Getenv("PARITY_AZURE_VAULT"), "(required)")
	fs.StringVar(&c.vault.BackupInstance, "azure-backup-instance", os.Getenv("PARITY_AZURE_BACKUP_INSTANCE"), "(required)")
	fs.StringVar(&c.vault.PolicyRuleName, "azure-policy-rule", os.Getenv("PARITY_AZURE_POLICY_RULE"),
		"the backup policy rule an on-demand backup borrows its retention from (required)")
	fs.StringVar(&c.vault.RestoreLocation, "azure-restore-location", os.Getenv("PARITY_AZURE_RESTORE_LOCATION"),
		"the region the restore-as-files runs in (required)")

	// NO DEFAULT, deliberately: the interval IS the recovery point objective, so a default here
	// would be an RPO nobody chose and every install would silently share it.
	envInterval, err := envDuration("PARITY_BACKUP_INTERVAL")
	if err != nil {
		return nil, err
	}
	fs.DurationVar(&c.interval, "interval", envInterval,
		"how long one change cycle collects, which is this install's RPO clock (required, e.g. 5m)")

	envBrake, err := envDuration("PARITY_BACKUP_BRAKE_EVERY")
	if err != nil {
		return nil, err
	}
	if envBrake == 0 {
		// A DEFAULT IS SAFE ON THIS ONE AND ONLY ON THIS ONE: it selects nothing and reaches
		// nowhere new. It is how often a brake that is already pointed at a configured slot looks
		// at it, and the thing it is racing takes hours (brake.go).
		envBrake = postgres.DefaultEvery
	}
	fs.DurationVar(&c.brakeEvery, "brake-every", envBrake,
		"how often the safety brake reads what our slot is holding on the primary")

	c.pg.Password = postgres.Secret(os.Getenv("PARITY_PG_PASSWORD"))
	return c, nil
}

// envPort is PARITY_PG_PORT, or 5432. An unreadable value is an error for the same reason
// envDuration's is: falling back would run the backup against a port nobody chose.
func envPort() (uint, error) {
	const standard = 5432
	raw := strings.TrimSpace(os.Getenv("PARITY_PG_PORT"))
	if raw == "" {
		return standard, nil
	}
	port, err := strconv.ParseUint(raw, 10, 16)
	if err != nil || port == 0 {
		return 0, fmt.Errorf("backup: PARITY_PG_PORT is %q, which is not a TCP port", raw)
	}
	return uint(port), nil
}

// envDuration reads a duration from the environment.
//
// AN UNPARSEABLE VALUE IS AN ERROR AND NEVER ZERO. Zero would be reported by refuse() as "not set",
// which sends an operator looking for a variable that is right there and misspelt.
func envDuration(key string) (time.Duration, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("backup: %s is %q, which is not a duration (5m, 30s, 1h): %w", key, raw, err)
	}
	return d, nil
}

// normalise trims every value before anything is compared or used, and it is not cosmetic.
//
// THE FAILURE IT PREVENTS IS SILENT AND PERMANENT. A scope of " install-7/pg1 " passes an emptiness
// test and passes backup.checkPrefix — no empty, "." or ".." segment — so every object lands under a
// blob prefix with stray spaces in it. Restart the container without the typo and you get a second,
// disjoint tree; nothing joins them, and retention or a listing by scope sees one of the two. A
// --server-id with a trailing newline (which is what a shell here-doc or a secret file hands you)
// goes into contract.BackupSource.ResourceID, and the manifest's subject then matches nothing the
// control plane holds.
func (c *backupConfig) normalise() {
	for _, field := range []*string{
		&c.pg.Host, &c.pg.Database, &c.pg.User,
		&c.slot, &c.publication, &c.scope, &c.serverID,
		&c.vault.ContainerURL, &c.vault.SubscriptionID, &c.vault.ResourceGroup,
		&c.vault.VaultName, &c.vault.BackupInstance, &c.vault.PolicyRuleName,
		&c.vault.RestoreLocation,
	} {
		*field = strings.TrimSpace(*field)
	}
	// The password is NOT trimmed: leading and trailing space are legitimate characters in one,
	// and silently changing a credential produces "password authentication failed", the single
	// most misread error on this path (conn.go).

	// FOLDED BECAUSE IT IS A KEY AND NOT A NAME. The subscription is what a cycle report joins to
	// the scan of the same estate on, and the scanner writes it lowercased (collectors/azure
	// translate.go: "a subscription GUID is a key"; contract.md §2.5 pins the bare identifier). An
	// operator who pastes the GUID as Azure's portal shows it — upper-case — would otherwise file
	// every report under a boundary that matches no estate, silently and forever. The same reason
	// pgchain.go already lowercases --server-id.
	c.vault.SubscriptionID = strings.ToLower(c.vault.SubscriptionID)
}

// refuse names everything this run was not told, all of it at once, and returns nil only when the
// command can safely open something.
//
// ALL AT ONCE RATHER THAN ONE AT A TIME, because the alternative is an operator restarting a
// container eight times to discover eight missing variables.
func (c backupConfig) refuse() error {
	var missing []string
	for _, f := range []struct{ flag, value string }{
		{"--pg-host", c.pg.Host},
		{"--pg-database", c.pg.Database},
		{"--pg-user", c.pg.User},
		{"PARITY_PG_PASSWORD", string(c.pg.Password)},
		{"--slot", c.slot},
		{"--publication", c.publication},
		{"--server-id", c.serverID},
		{"--scope", c.scope},
		{"--container-url", c.vault.ContainerURL},
		{"--azure-subscription", c.vault.SubscriptionID},
		{"--azure-resource-group", c.vault.ResourceGroup},
		{"--azure-vault", c.vault.VaultName},
		{"--azure-backup-instance", c.vault.BackupInstance},
		{"--azure-policy-rule", c.vault.PolicyRuleName},
		{"--azure-restore-location", c.vault.RestoreLocation},
	} {
		if strings.TrimSpace(f.value) == "" {
			missing = append(missing, f.flag)
		}
	}
	if c.interval <= 0 {
		missing = append(missing, "--interval")
	}
	if len(missing) > 0 {
		return fmt.Errorf("backup: refusing to start without %s. Nothing here has a default that "+
			"would reach a server nobody chose: pgx fills an omitted host, port, database or user "+
			"from PGHOST/PGPORT/PGDATABASE/PGUSER, and a backup taken against the wrong database "+
			"succeeds", strings.Join(missing, ", "))
	}
	// CHECKED HERE BECAUSE THE FLAG IS A uint AND THE FIELD IS A uint16. --pg-port 70000 narrows
	// silently to 4464 and connects to whatever is listening there; 65536 narrows to 0, which
	// conn.go reports as "port is not set" — the misdiagnosis envPort's own refusal exists to
	// prevent, arrived at through the flag rather than the environment.
	if c.port == 0 || c.port > 65535 {
		return fmt.Errorf("backup: --pg-port is %d, which is not a TCP port; refusing rather than "+
			"narrowing it to %d and connecting to whatever is listening there", c.port, c.port%65536)
	}
	// Asked here, where refusing is free, rather than at the first cycle: a name outside our
	// convention creates a slot on the customer's primary that nothing downstream can afterwards
	// tell from theirs, so a leak of it never reaches the brake (slot.go). The postgres package's
	// own rule is asked rather than restated — there is exactly one.
	return postgres.ValidateSlotName(c.slot)
}

// backupCommand is `scanner backup` with a return value, so that every exit path runs the deferred
// teardown that drops the slot. There is ONE way out of this function and one teardown behind it.
//
//	0  the run ended because it was asked to
//	1  the run stopped on something that has to be looked at
//	2  it was misconfigured, and nothing was opened
func backupCommand(args []string) (code int) {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	cfg, err := backupFlags(fs)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	// THE SAME TWO FLAGS scan AND scan-cluster TAKE, and the same meaning: omitted, the run reports
	// to stdout alone. Reporting is not a precondition for backing up — the objects and the manifest
	// are in the customer's own container either way — so an install with no API url is an ordinary
	// install and not a misconfiguration.
	apiURL, apiKey := apiFlags(fs)
	_ = fs.Parse(args) // ExitOnError: Parse exits itself, it never returns an error
	cfg.normalise()

	if err := cfg.refuse(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	// Narrowed only after refuse() has established it fits.
	cfg.pg.Port = uint16(cfg.port) //gosec:disable G115 -- refuse() above rejected port == 0 || port > 65535

	// CHECKED BEFORE ANYTHING IS OPENED, for the reason destination's own comment gives one command
	// over: every reason to refuse a url is knowable up front, and finding out after a nine-minute
	// base copy that it was http means paying for all of it again.
	//
	// ASSIGNED THROUGH A NIL CHECK RATHER THAN DIRECTLY. destination returns a typed nil when there
	// is no url, and a typed nil in an interface field is NOT nil — report.Send would find a Sender
	// to call and dereference it mid-cycle.
	var dest report.Sender
	if client := destination(*apiURL, *apiKey); client != nil {
		dest = client
	}

	// A signal ends the run exactly as a fatal error does, so there is ONE way out and one
	// teardown behind it rather than a handler racing the loop.
	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "backup: resolve an Azure credential:", err)
		return 2
	}
	blobs, err := store.NewBlob(cred, cfg.vault.ContainerURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "backup:", err)
		return 2
	}
	cloud, err := postgres.NewAzureBackup(cred, cfg.vault)
	if err != nil {
		fmt.Fprintln(os.Stderr, "backup:", err)
		return 2
	}
	// THE DISK HALF OF THE SAFETY BRAKE, and the reason it can stop rather than only warn. Built
	// HERE, before anything opens, because a resource id that is not a Flexible Server is a
	// misconfiguration and the alternative is a brake that warns for the life of the process about
	// a metric that was never going to answer. --server-id is the same id the manifest says the
	// backup is OF, so there is one resource in this command and not two that can disagree.
	monitor, err := postgres.NewAzureMonitor(cred, cfg.serverID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "backup:", err)
		return 2
	}

	link := newPGChain(*cfg, blobs, cloud, os.Stdout)

	// THE ONE DEFER THAT COVERS EVERY EXIT PATH — a signal, a stop, a panic. It closes the stream
	// and drops the slot on a context that outlives the cancellation, because a shutdown must not
	// be the reason a slot only this role can drop is left holding WAL on the customer's primary.
	defer func() {
		if err := link.release(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "backup:", err)
			code = 1
		}
	}()

	// STARTED BEFORE THE FIRST CHAIN AND STOPPED AFTER THE LAST — see the header. Its connection
	// is its OWN: the stream's is in CopyBoth and serves no statement, and a brake sharing a
	// wedged loop's connection is wedged with it.
	stopBrake, err := startBrake(ctx, *cfg, link, monitor.Space)
	if err != nil {
		fmt.Fprintln(os.Stderr, "backup:", err)
		return 1
	}
	defer stopBrake()

	// EVERY CYCLE GOES TO STDOUT, AND TO THE CONTROL PLANE IF THERE IS ONE. The line is written
	// first and unconditionally: the reader at 3am is a human with `docker logs`, and a run whose
	// API url is unset is an ordinary run rather than a misconfiguration. Why a refused report
	// cannot cost this loop anything is argued once, at report.Send.
	clock := &schedule.Scheduler{
		Chain:    link,
		Interval: cfg.interval,
		Report: report.Send{
			To:       dest,
			Chain:    cfg.scope,
			Account:  cfg.vault.SubscriptionID,
			Manifest: link.manifest,
			Also:     schedule.Log{To: os.Stdout},
			Errs:     os.Stderr,
			// CLAMPED TO THE INTERVAL, because the scheduler times the next cycle from the previous
			// one's START: on an install with a shorter RPO than the default send budget, an API
			// that hangs would push every cycle late by the difference. The whole point of bounding
			// the send is that a dashboard row never moves the RPO clock.
			Timeout: min(report.DefaultTimeout, cfg.interval),
		},
	}
	fmt.Printf("backup: %s every %s under %s, slot %q, into %s\n",
		cfg.pg.Database, cfg.interval, cfg.scope, cfg.slot, cfg.vault.ContainerURL)

	if err := clock.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "backup:", err)
		return 1
	}
	fmt.Println("backup: stopped")
	return 0
}

// startBrake opens the brake's own connection and puts it on its own goroutine.
//
// IT CAN DROP, AND IT SAYS SO AT START — because the state of a safety brake is not something to
// discover from its silence, and the line it prints also names what it cannot do.
//
// ITS ALARM IS DEDUPLICATED ON THE VERDICT AND NOT ON THE LINE, and the difference is the whole
// point of doing it at all. A sustained Warn ticks once a minute for the life of the process, and
// brake.go says plainly that the alarm it repeats "must not be the alarm anybody learns to skip".
// Comparing the rendered text would not deduplicate anything now that a real disk is behind it: Why
// carries the retained WAL and the headroom to a tenth of a mebibyte, and on any live server both
// move every tick. So what is compared is the verdict, whether it carried an error, and whether it
// dropped — the three things that change what an operator would DO — and a drop is never a repeat.
//
// ITS CONNECTION DOES NOT RECONNECT, and that is stated rather than hidden: pgconn does not, and a
// brake whose socket died reports the failure through Alert — which is the same news as a trip,
// because nobody is watching the WAL.
func startBrake(ctx context.Context, cfg backupConfig, link *pgChain, disk postgres.Disk) (func(), error) {
	conn, err := postgres.Connect(ctx, cfg.pg)
	if err != nil {
		return nil, fmt.Errorf("open the safety brake's own connection to the primary: %w", err)
	}
	fmt.Fprintf(os.Stderr, "brake: watching slot %q every %s, reading the disk of %s from Azure "+
		"Monitor. IT CAN DROP: once our slot holds about as much WAL as the disk has left before "+
		"the read-only line, it terminates our own stream, drops our own slot, and the chain takes "+
		"a new base copy. It cannot act if THIS process dies — SIGKILL, the OOM killer, an "+
		"uninstall or a lost credential leave the slot holding WAL, and only the role that created "+
		"it can drop one. Set max_slot_wal_keep_size on the server for that case; nothing else "+
		"covers it\n", cfg.slot, cfg.brakeEvery, cfg.serverID)

	var said string
	brakeCtx, stop := context.WithCancel(ctx)
	brake := &postgres.Brake{
		Slot:  cfg.slot,
		Query: postgres.Query(conn),
		Every: cfg.brakeEvery,
		// The stream's backend, read fresh on every tick because the stream reconnects and the
		// brake outlives any one session of it. It is what lets the brake kill a wedged stream of
		// OURS and stops it destroying a slot somebody else is consuming.
		StreamPID: link.streamPID,
		// The primary's disk, from Azure Monitor. It is what makes Trip reachable at all: without
		// it pressure is NaN on every tick and an unknown disk warns and never drops.
		Disk: disk,
		Alert: func(a postgres.Alarm) {
			line := fmt.Sprintf("brake %s: slot=%q %s", a.Decision.Verdict, a.Slot, a.Decision.Why)
			if a.Dropped {
				line += " — DROPPED, so this chain is over and the next cycle takes a new base copy"
			}
			if a.Err != nil {
				line += "\n  " + a.Err.Error()
			}
			// The verdict, whether it carried an error, and whether it dropped — the three things
			// that change what an operator would do. NOT the rendered line: it carries byte counts
			// that move on every tick of any live server, so comparing it would deduplicate
			// nothing. A DROP is never a repeat: it says the slot is gone, which is a different
			// event every time it happens.
			key := fmt.Sprintf("%v|%t|%t", a.Decision.Verdict, a.Err != nil, a.Dropped)
			if key == said && !a.Dropped {
				return
			}
			said = key
			fmt.Fprintln(os.Stderr, line)
		},
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = brake.Watch(brakeCtx)
	}()

	return func() {
		stop()
		<-done
		_ = conn.Close(context.WithoutCancel(ctx))
	}, nil
}
