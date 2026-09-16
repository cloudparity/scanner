package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	armruntime "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	azruntime "github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"

	"github.com/manukyanv07/parity-scanner/agent/internal/backup"
	"github.com/manukyanv07/parity-scanner/contract"
)

// AzureBackup is the ControlPlane in base.go, spoken over ARM REST.
//
// ARM REST AND NOT THE `az` CLI, and that is not a preference. AD-033 measured both operations
// with `az dataprotection`, but the agent ships as a `scratch` image: there is no shell, no Python
// and no CLI to invoke, so the measurement's vocabulary has to be translated into the calls the
// CLI itself makes. Every endpoint below carries the Microsoft reference it came from and the
// api-version it is pinned to. Nothing here was inferred from the CLI's flags.
//
// NO DATA PROTECTION SDK EITHER. The Azure collector reads ARM as JSON over HTTPS through an
// azcore pipeline and the k8s collector says why in full: an agent meant to be open source and
// auditable does not carry a generated client per resource provider for four calls. This adds no
// module to go.mod — azcore and azidentity are already here.
//
// THE TWO CALLS ARE LONG-RUNNING OPERATIONS AND THE 202 IS NOT THE ANSWER. Nine minutes for the
// backup, two for the restore; both answer immediately with 202 Accepted and a header naming
// somewhere to ask again. A caller that reads the 202 as success returns a recovery point that
// does not exist yet, and everything downstream vouches for bytes nobody took. await is where
// that is prevented, and it is the reason this file has more polling in it than calling.

// dataProtectionAPIVersion pins every Microsoft.DataProtection call below.
//
// PINNED, because ARM has no "latest" and an unpinned call is a silent behaviour change whenever
// the provider ships a new version — the same rule the collector's childSpecs follow. This is the
// version of the reference pages cited at each endpoint, read 2026-08-21.
const dataProtectionAPIVersion = "2026-06-01"

// defaultPollEvery is how long to wait between polls when the service sends no Retry-After. It
// answers with Retry-After: 60 in the documented examples, and retryAfter prefers that; this is
// only the floor for a response that carries none.
const defaultPollEvery = 15 * time.Second

// pagesBudget bounds any paged read. A service that keeps handing back a continuation must not
// turn a backup into an unbounded loop.
const pagesBudget = 100

// Vault names the ONE backup instance this agent may act on and the ONE container it may land
// files in. Nothing here is discovered: every value is configuration, checked at construction,
// because the alternative is finding out at minute nine of a backup.
//
// THE ARM ACTIONS THESE FIELDS AUTHORISE, for E6.5, which owns turning them into the
// customer-facing permission list. Recorded as the operations this file actually calls, at the
// scope it calls them on — role NAMES are E6.5's to pin against a live subscription and are
// deliberately not guessed here:
//
//	POST .../backupVaults/{vault}/backupInstances/{instance}/backup    — Backup, an ARM WRITE
//	GET  .../backupVaults/{vault}/backupInstances/{instance}/recoveryPoints
//	POST .../backupVaults/{vault}/backupInstances/{instance}/restore   — RestoreAsFiles, an ARM WRITE
//	GET  the Azure-AsyncOperation URL of each of the two writes (operationStatus)
//	GET  {ContainerURL}?restype=container&comp=list  — data plane, Microsoft.Storage/storageAccounts/
//	                                                   blobServices/containers/blobs/read
//	GET  {ContainerURL}/{blob}                       — data plane, same action
//
// The two writes are why E6 §0.1's old claim of "Reader, and no write at all" is retired: asking
// for a backup IS a write. What they can reach is one backup instance and one container, which is
// the sentence a security reviewer needs and the thing E6.5's negative tests have to demonstrate.
type Vault struct {
	SubscriptionID string
	ResourceGroup  string
	VaultName      string
	BackupInstance string

	// PolicyRuleName is the rule of the backup policy the adhoc backup runs under. Required by
	// the API: an adhoc backup borrows a rule's retention rather than inventing one.
	PolicyRuleName string

	// RestoreLocation is the region the restore runs in.
	RestoreLocation string

	// ContainerURL is OUR container, the one the restore writes into and the parts are read back
	// from: https://<account>.blob.core.windows.net/<container>.
	ContainerURL string
}

// AzureBackup implements ControlPlane. One instance is one backup instance and one container.
type AzureBackup struct {
	vault Vault

	// arm carries the ARM credential and azcore's retry and throttling policies.
	arm      azruntime.Pipeline
	endpoint string

	// blobs reads back what the cloud wrote. A SECOND credential scope, not a second credential:
	// the same identity, asked for a token for storage rather than for management.
	blobs *container

	pollEvery time.Duration
}

// Compile-time proof this is the shape base.go's sequence calls. If ControlPlane changes, this
// line fails before any test does.
var _ ControlPlane = (*AzureBackup)(nil)

// NewAzureBackup builds the real adapter. The credential is the caller's — AD-035: the ARM
// identity and the Postgres role meet in Base and nowhere else, and neither is created here.
func NewAzureBackup(cred azcore.TokenCredential, v Vault) (*AzureBackup, error) {
	for _, required := range []struct{ name, value string }{
		{"SubscriptionID", v.SubscriptionID},
		{"ResourceGroup", v.ResourceGroup},
		{"VaultName", v.VaultName},
		{"BackupInstance", v.BackupInstance},
		{"PolicyRuleName", v.PolicyRuleName},
		{"RestoreLocation", v.RestoreLocation},
		{"ContainerURL", v.ContainerURL},
	} {
		if strings.TrimSpace(required.value) == "" {
			return nil, fmt.Errorf("postgres: the control plane needs %s; without it the backup "+
				"fails after it has been asked for", required.name)
		}
	}

	containerURL, err := url.Parse(strings.TrimRight(v.ContainerURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("postgres: the container URL %q is not a URL: %w", v.ContainerURL, err)
	}
	// A URL naming only the account is the misconfiguration worth catching here: the restore
	// would be asked to write to the account root, and the listing would ask the account for its
	// containers rather than a container for its blobs.
	if containerURL.Host == "" || strings.Trim(containerURL.Path, "/") == "" {
		return nil, fmt.Errorf("postgres: the container URL %q names no container; it must be "+
			"https://<account>.blob.core.windows.net/<container>", v.ContainerURL)
	}

	pipeline, err := armruntime.NewPipeline("parity-scanner", collectorVersion, cred,
		azruntime.PipelineOptions{}, &arm.ClientOptions{
			ClientOptions: azcore.ClientOptions{Retry: policy.RetryOptions{MaxRetries: 5}},
		})
	if err != nil {
		return nil, fmt.Errorf("postgres: arm pipeline: %w", err)
	}

	return &AzureBackup{
		vault:     v,
		arm:       pipeline,
		endpoint:  "https://management.azure.com",
		blobs:     &container{url: containerURL, tokens: cred, http: http.DefaultClient},
		pollEvery: defaultPollEvery,
	}, nil
}

// collectorVersion is stamped into the ARM user agent so a customer reading their Activity Log
// can tell which build asked for the backup. Same string the Azure collector sends.
const collectorVersion = "0.1.0"

// Backup asks for an on-demand backup, waits for it, and returns the recovery point it produced.
//
//	POST /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.DataProtection
//	     /backupVaults/{vault}/backupInstances/{instance}/backup?api-version=2026-06-01
//	https://learn.microsoft.com/en-us/rest/api/dataprotection/backup-instances/adhoc-backup
//
// AND THEN ASKS WHICH RECOVERY POINT THAT WAS, because the operation does not say. Its result is
// an OperationJobExtendedInfo — a jobId and nothing else — and the job resource has no field
// naming a recovery point it created (Jobs - Get: sourceRecoverPoint and targetRecoverPoint are
// restore-side). So the recovery point is READ BACK from the list, and the read is narrowed by
// the time the request was made: a scheduled backup landing in the same window would otherwise be
// handed to the restore, and a copy taken BEFORE the slot is exactly the silent gap AD-033
// measured, arrived at through the back door.
func (a *AzureBackup) Backup(ctx context.Context) (string, error) {
	// Before the request, never after: a recovery point stamped a moment before we asked is not
	// ours, and rounding that boundary the wrong way accepts somebody else's copy.
	asked := time.Now().UTC()

	body := map[string]any{
		"backupRuleOptions": map[string]any{"ruleName": a.vault.PolicyRuleName},
	}
	if err := a.call(ctx, http.MethodPost, a.instancePath()+"/backup", body, "the on-demand backup"); err != nil {
		return "", err
	}

	point, err := a.newestRecoveryPointSince(ctx, asked)
	if err != nil {
		return "", err
	}
	return point, nil
}

// RestoreAsFiles restores that recovery point into OUR container as files, and returns what
// landed as the parts of a batch.
//
//	POST /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.DataProtection
//	     /backupVaults/{vault}/backupInstances/{instance}/restore?api-version=2026-06-01
//	https://learn.microsoft.com/en-us/rest/api/dataprotection/backup-instances/trigger-restore
//
// The body is the documented "Trigger Restore As Files" example:
// AzureBackupRecoveryPointBasedRestoreRequest wrapping a RestoreFilesTargetInfo, whose
// targetDetails carry restoreTargetLocationType AzureBlobs and the container's URL.
//
// THE BYTES ARE MOVED BY THE CLOUD, NOT BY US (contract.RouteProviderCopy). So the parts returned
// here READ BACK what Azure wrote rather than producing it, which is a weaker guarantee than
// hashing a stream in flight and is recorded as an open shape in backup-shape.md §6.
func (a *AzureBackup) RestoreAsFiles(ctx context.Context, recoveryPoint string) ([]backup.Part, error) {
	if strings.TrimSpace(recoveryPoint) == "" {
		return nil, errors.New("postgres: the restore was given no recovery point")
	}

	prefix := filePrefix(recoveryPoint)
	body := map[string]any{
		"objectType":          "AzureBackupRecoveryPointBasedRestoreRequest",
		"recoveryPointId":     recoveryPoint,
		"sourceDataStoreType": "VaultStore",
		"restoreTargetInfo": map[string]any{
			"objectType": "RestoreFilesTargetInfo",
			// The only value RecoveryOption defines. It also means a second restore of the SAME
			// recovery point fails rather than overwriting the first, which is the side of that
			// trade a backup product wants.
			"recoveryOption":  "FailIfExists",
			"restoreLocation": a.vault.RestoreLocation,
			"targetDetails": map[string]any{
				"filePrefix":                prefix,
				"restoreTargetLocationType": "AzureBlobs",
				// The parsed form, so the container Azure writes into and the one the parts are
				// read back from cannot differ by a trailing slash.
				"url": a.blobs.url.String(),
			},
		},
	}
	if err := a.call(ctx, http.MethodPost, a.instancePath()+"/restore", body, "the restore as files"); err != nil {
		return nil, err
	}

	// Listed only now. A container listed while the restore is still running is a half-written
	// batch that checksums and manifests exactly like a whole one.
	written, err := a.blobs.list(ctx, prefix)
	if err != nil {
		return nil, err
	}
	return a.partsFrom(ctx, written, prefix)
}

// filePrefix is what every file of one restore is named under.
//
// Derived from the recovery point so a container can be read months later and each file traced to
// the copy it came from — and so two restores cannot land on top of each other, which with
// FailIfExists is a refusal rather than a silent overwrite.
func filePrefix(recoveryPoint string) string { return "parity-" + recoveryPoint }

// partsFrom labels what landed. THE LABELS ARE THE POINT (AD-037): four files arrive, one of them
// is the archive, and with nothing on the wire saying which, a restore reports success having
// applied the archive and silently dropped the roles, the grants and the tablespaces.
func (a *AzureBackup) partsFrom(ctx context.Context, written []blobEntry, prefix string) ([]backup.Part, error) {
	parts := make([]backup.Part, 0, len(written))
	seen := map[string]bool{}
	archive := false

	for _, blob := range written {
		// The last path element, because Part.Name becomes the object's path in the store and
		// must be a single element. filePrefix contains no separator, so this is the file Azure
		// wrote either way.
		name := blob.Name
		if cut := strings.LastIndex(name, "/"); cut >= 0 {
			name = name[cut+1:]
		}

		format, role, known := label(name)
		if !known {
			// REFUSED RATHER THAN PASSED THROUGH UNLABELLED. contract.Part treats an empty Role
			// as "nobody said" and a restorer refuses it, so an unknown file would travel all the
			// way to a restore before anyone found out. It is also the only evidence we would get
			// that Azure changed what it writes.
			return nil, fmt.Errorf("postgres: the restore wrote %q, which is not one of the files "+
				"a restore-as-files produces (database.sql, roles.sql, schema.sql, tablespaces.sql); "+
				"nothing downstream can tell a restorer what it is", blob.Name)
		}
		if seen[name] {
			// Two parts sharing a Name overwrite each other in the store and leave a manifest
			// listing both — a short backup that looks complete.
			return nil, fmt.Errorf("postgres: the restore wrote two files called %q", name)
		}
		seen[name] = true
		archive = archive || role == contract.PartDatabase

		parts = append(parts, backup.Part{
			Name: name,
			// WHERE THE OBJECT ALREADY IS, because the cloud put it there and the agent never
			// will. It is the blob's own name in our container, so the base manifest names the
			// object where it lies rather than describing a copy nobody made — and without it
			// nothing downstream could ever find these four files again.
			Path:   blob.Name,
			Format: format,
			Role:   role,
			// A FRESH READER ON EVERY CALL: the pipeline retries an upload, and a second Open
			// handing back a spent reader uploads zero bytes with every check still green.
			//
			// The context is the one this restore was asked on, deliberately. The read is part of
			// the same cycle, so a cancelled backup must not go on pulling gigabytes out of a
			// container on behalf of work that has been abandoned.
			Open: func() (io.ReadCloser, error) { return a.blobs.open(ctx, blob.Name) },
		})
	}

	if len(parts) == 0 {
		return nil, fmt.Errorf("postgres: the restore reported success and left nothing under %q "+
			"in the container", prefix)
	}
	if !archive {
		// Everything else is plain SQL beside it. Without database.sql there is no data — and the
		// manifest over the other three would be a claim that there is.
		return nil, fmt.Errorf("postgres: the restore wrote %d files under %q and none of them is "+
			"the database archive", len(parts), prefix)
	}
	return parts, nil
}

// label says what one file Azure wrote is, in contract's vocabulary.
//
// Matched on the SUFFIX rather than the whole name, because every file carries our filePrefix and
// because Azure writes one database file PER DATABASE — Microsoft's own restore-as-files
// documentation says "Database.sql file per database", so the archive's name is not a constant.
//
// https://learn.microsoft.com/en-us/azure/backup/restore-azure-database-postgresql-flex
type labelled struct {
	suffix string
	format string
	role   contract.PartRole
}

func label(name string) (format string, role contract.PartRole, known bool) {
	lower := strings.ToLower(name)
	for _, l := range []labelled{
		// The only part pg_restore can be fed, and the only one that is not plain SQL.
		{"database.sql", contract.FormatPGDumpCustom, contract.PartDatabase},
		{"roles.sql", contract.FormatPlainSQL, contract.PartRoles},
		{"schema.sql", contract.FormatPlainSQL, contract.PartSchema},
		// AD-033 measured "tablespaces.sql"; the portal documentation calls it "Tablespace.sql".
		// Both are accepted because being wrong about which costs a refused backup, and neither
		// spelling can be confused with anything else.
		{"tablespaces.sql", contract.FormatPlainSQL, contract.PartTablespaces},
		{"tablespace.sql", contract.FormatPlainSQL, contract.PartTablespaces},
	} {
		if strings.HasSuffix(lower, l.suffix) {
			return l.format, l.role, true
		}
	}
	return "", "", false
}

// newestRecoveryPointSince reads the list and picks the one this cycle produced.
//
//	GET /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.DataProtection
//	    /backupVaults/{vault}/backupInstances/{instance}/recoveryPoints?api-version=2026-06-01
//	https://learn.microsoft.com/en-us/rest/api/dataprotection/recovery-points/list
//
// The recovery point's ID is the resource's NAME: Recovery Points - Get addresses one at
// .../recoveryPoints/{recoveryPointId}, so the name is what Trigger Restore's recoveryPointId
// takes.
func (a *AzureBackup) newestRecoveryPointSince(ctx context.Context, asked time.Time) (string, error) {
	type point struct {
		Name       string `json:"name"`
		Properties struct {
			RecoveryPointTime  time.Time `json:"recoveryPointTime"`
			RecoveryPointState string    `json:"recoveryPointState"`
		} `json:"properties"`
	}

	newest, newestTime := "", time.Time{}
	next := a.endpoint + a.instancePath() + "/recoveryPoints?api-version=" + dataProtectionAPIVersion

	for page := 0; page < pagesBudget; page++ {
		body, err := a.get(ctx, next)
		if err != nil {
			return "", fmt.Errorf("postgres: read the recovery points of backup instance %q: %w",
				a.vault.BackupInstance, err)
		}
		var list struct {
			Value    []point `json:"value"`
			NextLink string  `json:"nextLink"`
		}
		if err := json.Unmarshal(body, &list); err != nil {
			return "", fmt.Errorf("postgres: the recovery point list did not parse: %w", err)
		}
		for _, p := range list.Value {
			// Partial means only some of the intended items were backed up. A partial copy is not
			// a base copy, and a manifest over one would claim it is.
			if !strings.EqualFold(p.Properties.RecoveryPointState, "Completed") {
				continue
			}
			if p.Properties.RecoveryPointTime.Before(asked) {
				continue
			}
			if p.Properties.RecoveryPointTime.After(newestTime) {
				newest, newestTime = p.Name, p.Properties.RecoveryPointTime
			}
		}
		if list.NextLink == "" {
			break
		}
		if err := a.sameHost(list.NextLink); err != nil {
			return "", err
		}
		next = list.NextLink
	}

	if newest == "" {
		// The operation said Succeeded and there is nothing to restore. Reported rather than
		// returned empty: an empty recovery point reaches RestoreAsFiles and fails there, several
		// minutes later, describing the wrong thing.
		return "", fmt.Errorf("postgres: the on-demand backup of %q completed and no recovery "+
			"point at or after %s appeared in the vault", a.vault.BackupInstance,
			asked.Format(time.RFC3339))
	}
	return newest, nil
}

func (a *AzureBackup) instancePath() string {
	return fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.DataProtection"+
		"/backupVaults/%s/backupInstances/%s",
		a.vault.SubscriptionID, a.vault.ResourceGroup, a.vault.VaultName, a.vault.BackupInstance)
}

// call makes one control-plane request and does not return until the work behind it is done.
func (a *AzureBackup) call(ctx context.Context, method, path string, body any, what string) error {
	request, err := azruntime.NewRequest(ctx, method,
		a.endpoint+path+"?api-version="+dataProtectionAPIVersion)
	if err != nil {
		return fmt.Errorf("postgres: build the request for %s: %w", what, err)
	}
	if err := azruntime.MarshalAsJSON(request, body); err != nil {
		return fmt.Errorf("postgres: encode the request for %s: %w", what, err)
	}

	response, err := a.arm.Do(request)
	if err != nil {
		return fmt.Errorf("postgres: ask for %s: %w", what, err)
	}
	switch response.StatusCode {
	case http.StatusOK:
		// Documented alongside the 202: the service may answer a short operation outright.
		_ = response.Body.Close()
		return nil
	case http.StatusAccepted:
		return a.await(ctx, response, what)
	default:
		return fmt.Errorf("postgres: ask for %s: %w", what, azruntime.NewResponseError(response))
	}
}

// await follows a 202 to a terminal state.
//
// THIS IS THE FUNCTION THAT DECIDES WHETHER A BACKUP HAPPENED. Nine minutes of it, and every way
// out but one is a failure: the operation can fail, the poll can stop parsing, the context can be
// cancelled while we are waiting. Only "Succeeded" returns nil.
//
// The 202 carries Azure-AsyncOperation and Location; the async header is the one that reports a
// STATUS rather than a result, which is what a nine-minute job needs.
// https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/async-operations
func (a *AzureBackup) await(ctx context.Context, accepted *http.Response, what string) error {
	poll := accepted.Header.Get("Azure-AsyncOperation")
	if poll == "" {
		poll = accepted.Header.Get("Location")
	}
	wait := retryAfter(accepted, a.pollEvery)
	_ = accepted.Body.Close()

	if poll == "" {
		return fmt.Errorf("postgres: %s was accepted with no operation to poll, so there is no "+
			"way to learn whether it finished", what)
	}
	// The poll URL arrives in a header and the request that follows it carries our ARM token. A
	// host we did not ask is a host we do not hand it to.
	if err := a.sameHost(poll); err != nil {
		return fmt.Errorf("postgres: %s: %w", what, err)
	}

	for {
		// The wait comes first: the work was accepted a moment ago and Azure asks for 60 seconds
		// before the first question.
		select {
		case <-ctx.Done():
			return fmt.Errorf("postgres: waiting for %s: %w", what, ctx.Err())
		case <-time.After(wait):
		}

		response, err := a.do(ctx, poll)
		if err != nil {
			return fmt.Errorf("postgres: poll %s: %w", what, err)
		}
		// Read before the body is consumed: every poll carries its own pacing, and using only the
		// 202's would keep asking every 15 seconds for nine minutes after the service said 60.
		wait = retryAfter(response, a.pollEvery)
		body, err := azruntime.Payload(response)
		if err != nil {
			return fmt.Errorf("postgres: read the status of %s: %w", what, err)
		}
		var status struct {
			Status string `json:"status"`
			Error  struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(body, &status); err != nil {
			return fmt.Errorf("postgres: the status of %s did not parse, so whether it finished is "+
				"unknown: %w", what, err)
		}

		switch {
		case strings.EqualFold(status.Status, "Succeeded"):
			return nil
		case strings.EqualFold(status.Status, "Failed"),
			strings.EqualFold(status.Status, "Canceled"),
			strings.EqualFold(status.Status, "Cancelled"):
			// The service's own words, kept. An operator reading "the backup failed" goes looking
			// in the wrong place; the vault already said which server it could not reach.
			return fmt.Errorf("postgres: %s ended as %s%s", what, status.Status,
				reason(status.Error.Code, status.Error.Message))
		case inProgress(status.Status):
			// wait already holds this poll's Retry-After.
		default:
			// NEITHER ASSUMED DONE NOR WAITED ON FOREVER. An empty status is a document we did not
			// understand; an unrecognised one is a state this code has never seen. Reporting it is
			// how we find out, and both alternatives are worse: one claims a backup that may not
			// exist, the other polls until the context expires with nothing to show.
			return fmt.Errorf("postgres: %s reported status %q, which this agent does not "+
				"recognise as running, finished or failed", what, status.Status)
		}
	}
}

// inProgress lists the non-terminal states. Generous on purpose: ARM lets a provider use its own
// wording for "still going", and a status wrongly called unrecognised fails a backup that was
// merely slow.
func inProgress(status string) bool {
	for _, running := range []string{
		"InProgress", "NotStarted", "Started", "Running", "Accepted", "Pending", "Cancelling",
	} {
		if strings.EqualFold(status, running) {
			return true
		}
	}
	return false
}

// retryAfter reads the service's own pacing, falling back when it offers none. A nil or absent
// header, a value that is not a number and a zero all fall back: a zero would turn the wait into a
// spin against ARM's throttle, which costs the whole cycle a 429.
func retryAfter(response *http.Response, fallback time.Duration) time.Duration {
	if response == nil {
		return fallback
	}
	seconds, err := strconv.Atoi(strings.TrimSpace(response.Header.Get("Retry-After")))
	if err != nil || seconds <= 0 {
		return fallback
	}
	return time.Duration(seconds) * time.Second
}

// do performs one ARM GET through the pipeline, which is what carries the credential. The
// response rather than its body, because a poll's headers pace the next one.
func (a *AzureBackup) do(ctx context.Context, absolute string) (*http.Response, error) {
	request, err := azruntime.NewRequest(ctx, http.MethodGet, absolute)
	if err != nil {
		return nil, err
	}
	request.Raw().Header.Set("Accept", "application/json")

	response, err := a.arm.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		return nil, azruntime.NewResponseError(response)
	}
	return response, nil
}

func (a *AzureBackup) get(ctx context.Context, absolute string) ([]byte, error) {
	response, err := a.do(ctx, absolute)
	if err != nil {
		return nil, err
	}
	return azruntime.Payload(response)
}

// reason appends the service's own explanation when it gave one, and nothing when it did not. A
// message ending in a bare colon reads as a truncated error rather than as an absent detail.
func reason(code, message string) string {
	detail := strings.TrimSpace(code + " " + message)
	if detail == "" {
		return ""
	}
	return ": " + detail
}

// sameHost refuses a URL the service handed us that points anywhere but where we were talking.
func (a *AzureBackup) sameHost(absolute string) error {
	target, err := url.Parse(absolute)
	if err != nil {
		return fmt.Errorf("the service returned %q, which is not a URL: %w", absolute, err)
	}
	endpoint, err := url.Parse(a.endpoint)
	if err != nil {
		return fmt.Errorf("the ARM endpoint %q is not a URL: %w", a.endpoint, err)
	}
	if !strings.EqualFold(target.Host, endpoint.Host) {
		return fmt.Errorf("the service pointed at %s, which is not %s; following it would send "+
			"this agent's ARM token to a host it was not issued for", target.Host, endpoint.Host)
	}
	return nil
}
