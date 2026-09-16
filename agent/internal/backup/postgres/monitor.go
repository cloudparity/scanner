package postgres

// monitor.go IS THE HALF OF THE SAFETY BRAKE THAT WAS MISSING, and without it the brake could warn
// and never stop anything.
//
// brake.go computes ONE number out of two: the WAL our slot is holding, and how full the primary's
// disk is. The first comes from the database. The second CANNOT: there is no way to ask a Flexible
// Server how full its volume is over port 5432 — pg_stat_file and pg_ls_dir are superuser-only, the
// agent's role is a REPLICATION role with access to no table at all (AD-036), and no catalog view
// carries free space. So the disk arrives from the control plane, which is what this file is.
//
// Until it existed, Brake.Disk was nil on every install, pressure was NaN on every tick, and Assess
// read that as Warn — never Fine and NEVER TRIP. The brake watched and alerted and could not drop.
//
// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE METRICS, AND WHY THESE TWO
// ─────────────────────────────────────────────────────────────────────────────────────────────
//
// Microsoft publishes four storage metrics for Microsoft.DBforPostgreSQL/flexibleServers, and the
// brake needs BYTES rather than a percentage, because pressure divides retained WAL by the bytes
// left before the read-only line:
//
//	storage_used         Bytes    "Amount of storage space that's used. The storage used by the
//	                              service can include the database files, transaction logs, and
//	                              the server logs."
//	storage_free         Bytes    "Amount of storage space that's available."
//	storage_percent      Percent  the same fact with the byte counts thrown away
//	txlogs_storage_used  Bytes    the WAL half only
//
// https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-monitoring
// https://learn.microsoft.com/en-us/azure/azure-monitor/reference/supported-metrics/microsoft-dbforpostgresql-flexibleservers-metrics
//
// storage_used AND storage_free, and each of the other two is a trap.
//
//   - storage_percent would need a disk SIZE to turn back into bytes, and there is no size metric.
//     Reading the size from the ARM resource instead would be a second call, a second permission
//     and a value that goes stale the moment the customer grows the disk — including the growth
//     that autogrow performs precisely when the disk is filling, which is exactly the moment the
//     brake is deciding.
//
//   - txlogs_storage_used is the WAL on the server, and it is TEMPTING AND WRONG. It counts all
//     WAL, not the WAL OUR slot is retaining, so a busy server with a healthy stream would read as
//     ours. The retention that belongs to us comes from restart_lsn on the primary (brake.go), and
//     it is the only number the brake may treat as its own share of the problem.
//
// THE TOTAL IS DERIVED, used + free, because Monitor publishes no size. That is also the right
// answer under autogrow: both halves move together and the sum follows the disk the server has
// right now, which a configured size would not.
//
// AND THE SAME DOCUMENTED SENTENCE THAT MAKES storage_used USABLE IS WHAT MAKES THE BRAKE WORK AT
// ALL: the storage it reports INCLUDES the transaction logs. WAL our slot retains lands in this
// number, so retained WAL and the disk it is filling are the same disk, and pressure is a ratio
// between two quantities that really do compete.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	armruntime "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	azruntime "github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
)

// monitorAPIVersion pins the Metrics - List call below.
//
// PINNED for the reason dataProtectionAPIVersion is: ARM has no "latest", and an unpinned call is a
// silent behaviour change whenever the provider ships a new version. This is the version of the
// reference page cited on read, read 2026-08-23.
//
//	GET https://management.azure.com/{resourceUri}/providers/Microsoft.Insights/metrics
//	    ?api-version=2023-10-01
//	https://learn.microsoft.com/en-us/rest/api/monitor/metrics/list
const monitorAPIVersion = "2023-10-01"

// The two metric ids, spelled exactly as the supported-metrics reference spells them.
const (
	storageUsedMetric = "storage_used"
	storageFreeMetric = "storage_free"
)

// metricWindow is how far back the query looks. Wider than one grain deliberately: a request for
// exactly the last minute lands in the gap between emission and availability and comes back empty,
// which is indistinguishable at this layer from a server that stopped reporting.
const metricWindow = 15 * time.Minute

// staleAfter is how old the newest point may be before the reading is refused.
//
// THE STALE READING IS THE DANGEROUS ONE, and it is the only failure here that looks like success.
// A point from an hour ago parses, carries a unit and carries a number, and describes the disk as
// it was before whatever went wrong — so a brake that accepted it would compute a real-looking
// pressure from the past and answer Fine while the disk filled. Ten minutes is well outside the
// normal minute or two of metric latency and well inside the hours a slot takes to matter.
const staleAfter = 10 * time.Minute

// monitorTimeout bounds ONE reading, and it exists because of what the brake is.
//
// The brake's whole job is to notice a wedge, and a request with no bound of its own wedges the
// goroutine that would have noticed. Half the tick, so a slow endpoint costs a reading rather than
// the brake, and a reading that is missing is Warn — which is the correct news.
const monitorTimeout = DefaultEvery / 2

// AzureMonitor reads the primary's disk. Its Space method is what Brake.Disk takes.
//
// ARM REST over an azcore pipeline, not a generated client and not the `az` CLI — controlplane.go
// argues that once, and it adds no module to go.mod.
type AzureMonitor struct {
	// arm carries the credential and azcore's retry and throttling policies.
	arm      azruntime.Pipeline
	endpoint string

	// serverID is the ARM resource id of the Flexible Server, checked at construction.
	serverID string

	timeout time.Duration
}

// NewAzureMonitor builds the reader. The credential is the caller's, the same one the control plane
// and the blob store are given — AD-035: nothing here creates an identity.
//
// THE RESOURCE ID IS CHECKED HERE, WHERE REFUSING IS FREE. Monitor answers a request for a resource
// that publishes no storage_used with a 200 and an empty value[], so an id pointing at the vault, at
// a Single Server, or at nothing at all would otherwise surface as "no data point" on every tick of
// a running agent — a brake permanently warning for a reason nobody can read off the message.
func NewAzureMonitor(cred azcore.TokenCredential, serverResourceID string) (*AzureMonitor, error) {
	// The type segment, lower-cased on both sides: ARM hands the same resource back with several
	// different casings and every one of them names the same server.
	const flexibleServers = "/providers/microsoft.dbforpostgresql/flexibleservers/"

	id := strings.TrimRight(strings.TrimSpace(serverResourceID), "/")
	if id == "" {
		return nil, errors.New("postgres: the safety brake needs the ARM resource id of the " +
			"Flexible Server to read its disk from Azure Monitor; without it the disk half of the " +
			"brake is unknown, and an unknown disk warns and never drops")
	}
	// THE SERVER AND NOT A CHILD OF IT. The name must be the LAST segment: a database or a
	// configuration under the server is a different resource, and Monitor publishes no
	// storage_used for either — it answers with a 200 and an empty result.
	lower := strings.ToLower(id)
	_, name, isServer := strings.Cut(lower, flexibleServers)
	if !strings.HasPrefix(lower, "/subscriptions/") || !isServer || name == "" ||
		strings.Contains(name, "/") {
		return nil, fmt.Errorf("postgres: %q is not the ARM resource id of an Azure Database for "+
			"PostgreSQL flexible server; it must be /subscriptions/{sub}/resourceGroups/{rg}"+
			"/providers/Microsoft.DBforPostgreSQL/flexibleServers/{name}, and Azure Monitor answers "+
			"a request for anything else with an empty result rather than an error", serverResourceID)
	}

	pipeline, err := armruntime.NewPipeline("parity-scanner", collectorVersion, cred,
		azruntime.PipelineOptions{}, &arm.ClientOptions{
			ClientOptions: azcore.ClientOptions{Retry: policy.RetryOptions{MaxRetries: 3}},
		})
	if err != nil {
		return nil, fmt.Errorf("postgres: arm pipeline for Azure Monitor: %w", err)
	}

	return &AzureMonitor{
		arm:      pipeline,
		endpoint: "https://management.azure.com",
		serverID: id,
		timeout:  monitorTimeout,
	}, nil
}

// Compile-time proof this is the shape the brake takes.
var _ Disk = (*AzureMonitor)(nil).Space

// Space reads storage_used and storage_free and returns the disk they describe.
//
// ONE CALL FOR BOTH, because metricnames takes a comma-separated list of up to twenty. Two calls
// would ask at two instants; one call at least asks about one.
//
// EVERY WAY OUT BUT ONE IS AN ERROR, and the error is the point: the brake reads a failure as
// unknown pressure, which warns and never drops. A Space returned alongside a problem would be read
// as a real disk, which is the one outcome a safety brake cannot have.
func (m *AzureMonitor) Space(ctx context.Context) (Space, error) {
	ctx, cancel := context.WithTimeout(ctx, m.timeout)
	defer cancel()

	now := time.Now().UTC()
	query := url.Values{
		"api-version": {monitorAPIVersion},
		"metricnames": {storageUsedMetric + "," + storageFreeMetric},
		// BOTH AGGREGATIONS, AND THE CHOICE BETWEEN THEM IS A SAFETY CHOICE. Of the newest point
		// the brake takes its GREATEST used and its LEAST free. Taking the greatest of both would
		// overstate the disk — used and free are complements on a fixed volume — which overstates
		// the headroom, understates the pressure, and fires the brake late.
		"aggregation": {"maximum,minimum"},
		// One minute is the finest real resolution: both metrics are emitted at that grain and
		// neither is one of the five-minute-batched ones (no ^ in the reference).
		"interval": {"PT1M"},
		"timespan": {now.Add(-metricWindow).Format(time.RFC3339) + "/" +
			now.Format(time.RFC3339)},
	}
	target := m.endpoint + m.serverID + "/providers/Microsoft.Insights/metrics?" + query.Encode()

	request, err := azruntime.NewRequest(ctx, http.MethodGet, target)
	if err != nil {
		return Space{}, fmt.Errorf("postgres: build the request for the primary's disk: %w", err)
	}
	request.Raw().Header.Set("Accept", "application/json")

	response, err := m.arm.Do(request)
	if err != nil {
		return Space{}, fmt.Errorf("postgres: ask Azure Monitor for the primary's disk: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		// azruntime.NewResponseError carries the status and the service's own error document, so
		// a 403 reads as a permission problem and a 429 as throttling rather than as one word.
		return Space{}, fmt.Errorf("postgres: ask Azure Monitor for the primary's disk: %w",
			azruntime.NewResponseError(response))
	}
	body, err := azruntime.Payload(response)
	if err != nil {
		return Space{}, fmt.Errorf("postgres: read the primary's disk from Azure Monitor: %w", err)
	}

	var answer metricsResponse
	if err := json.Unmarshal(body, &answer); err != nil {
		return Space{}, fmt.Errorf("postgres: the primary's disk did not parse, so how full it is "+
			"is unknown: %w", err)
	}

	used, usedAt, err := answer.newest(storageUsedMetric, takeMaximum, now)
	if err != nil {
		return Space{}, err
	}
	free, freeAt, err := answer.newest(storageFreeMetric, takeMinimum, now)
	if err != nil {
		return Space{}, err
	}
	// THE SUM IS ONLY A DISK IF BOTH HALVES ARE THE SAME INSTANT, and one HTTP call does not
	// guarantee that: Monitor emits points with no value for minutes it has nothing for, so the
	// newest point carrying a used can be minutes newer than the newest carrying a free. On a
	// filling disk the older free is the LARGER one, so the sum overstates the disk, overstates
	// the headroom, understates the pressure and fires the brake late — the one direction this
	// file exists to prevent. A grain apart is the same minute; more than that is refused.
	if skew := usedAt.Sub(freeAt); skew > time.Minute || skew < -time.Minute {
		return Space{}, fmt.Errorf("postgres: Azure Monitor's newest %s of the primary is stamped "+
			"%s and its newest %s is stamped %s; these are not the same disk at the same instant, "+
			"and their sum is not a size", storageUsedMetric, usedAt.Format(time.RFC3339),
			storageFreeMetric, freeAt.Format(time.RFC3339))
	}
	if total := used + free; total > 0 {
		return Space{Total: total, Used: used}, nil
	}
	return Space{}, fmt.Errorf("postgres: Azure Monitor reports the primary's disk with no size at "+
		"all — %s is %d bytes and %s is %d — which is not a disk this brake can measure anything "+
		"against", storageUsedMetric, used, storageFreeMetric, free)
}

// metricsResponse is the documented Metrics - List answer, narrowed to what the brake reads.
type metricsResponse struct {
	Value []struct {
		Name struct {
			Value string `json:"value"`
		} `json:"name"`
		Unit string `json:"unit"`
		// 'Success' or the error details on query failures for THIS metric — a 200 can carry a
		// metric that did not work, and the service already said why.
		ErrorCode    string `json:"errorCode"`
		ErrorMessage string `json:"errorMessage"`
		Timeseries   []struct {
			Data []struct {
				TimeStamp time.Time `json:"timeStamp"`
				// Pointers because ABSENT AND ZERO ARE DIFFERENT HERE. Monitor emits points with
				// no value at all for minutes it has nothing for, and a zero read off one of those
				// is a disk with nothing on it — the most reassuring possible lie.
				Maximum *float64 `json:"maximum"`
				Minimum *float64 `json:"minimum"`
			} `json:"data"`
		} `json:"timeseries"`
	} `json:"value"`
}

// takeMaximum and takeMinimum say which aggregation of the newest point newest reads. The choice is
// the caller's rather than inferred from the metric name, so the safety reasoning for the pairing
// lives in exactly one place — the aggregation comment in Space.
const (
	takeMaximum = true
	takeMinimum = false
)

// newest finds one metric and returns its most recent value in bytes, and when it was stamped.
func (r metricsResponse) newest(name string, takeMax bool, now time.Time) (int64, time.Time, error) {
	for _, metric := range r.Value {
		if !strings.EqualFold(metric.Name.Value, name) {
			continue
		}
		if metric.ErrorCode != "" && !strings.EqualFold(metric.ErrorCode, "Success") {
			return 0, time.Time{}, fmt.Errorf("postgres: Azure Monitor could not read %s of the "+
				"primary: %s %s", name, metric.ErrorCode, metric.ErrorMessage)
		}
		// The whole computation below is in bytes. A unit that changed would rescale every
		// pressure this brake ever computes, silently and in the direction of firing late.
		if !strings.EqualFold(metric.Unit, "Bytes") {
			return 0, time.Time{}, fmt.Errorf("postgres: Azure Monitor reports %s of the primary "+
				"in %q rather than in Bytes, and this brake divides byte counts", name, metric.Unit)
		}

		var value float64
		var stamp time.Time
		for _, series := range metric.Timeseries {
			for _, point := range series.Data {
				at := point.Minimum
				if takeMax {
					at = point.Maximum
				}
				if at == nil || !point.TimeStamp.After(stamp) {
					continue
				}
				value, stamp = *at, point.TimeStamp
			}
		}

		switch {
		case stamp.IsZero():
			return 0, time.Time{}, fmt.Errorf("postgres: Azure Monitor returned %s of the primary "+
				"with no data point carrying a value in the last %s", name, metricWindow)
		case now.Sub(stamp) > staleAfter:
			return 0, time.Time{}, fmt.Errorf("postgres: the newest %s of the primary is %s old, "+
				"which is stale — reading it would measure the disk as it was before whatever "+
				"stopped the metric, and answer that the disk is fine while it fills",
				name, now.Sub(stamp).Round(time.Second))
		case value < 0, value >= math.MaxInt64:
			return 0, time.Time{}, fmt.Errorf("postgres: Azure Monitor reports %s of the primary "+
				"as %v, which is not a byte count", name, value)
		}
		return int64(value), stamp, nil
	}
	return 0, time.Time{}, fmt.Errorf("postgres: Azure Monitor returned no %s for the primary, so "+
		"how full its disk is cannot be worked out", name)
}
