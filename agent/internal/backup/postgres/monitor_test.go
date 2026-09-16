package postgres

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	azruntime "github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
)

// NOT ONE OF THESE TESTS TOUCHES AZURE, for the reason controlplane_test.go states and one more
// that is specific to this file: what has to be proved here is what the brake does when Monitor
// does NOT answer. A live subscription can demonstrate the happy path and nothing else, and the
// happy path is not where a brake that silently reads "the disk is fine" comes from.
//
// The fake speaks the shape Microsoft documents for Metrics - List, cited in monitor.go: a value[]
// of metrics, each with a name.value, a unit, an errorCode, and timeseries[].data[] points carrying
// timeStamp, maximum and minimum.

// theServer is the ARM id of the Flexible Server every test below reads.
const theServer = "/subscriptions/sub-1/resourceGroups/rg-1/providers/" +
	"Microsoft.DBforPostgreSQL/flexibleServers/pg-1"

// monitorFake is the fake Azure Monitor. Each field is one knob; the rest keep the happy path so a
// test reads as the one thing it changes.
type monitorFake struct {
	t *testing.T

	// used and free are the bytes the newest data point carries.
	used, free float64

	// age is how long ago the newest point was stamped. Metrics land a minute behind reality, so
	// the happy path is not "now".
	age time.Duration

	// The knobs that make the answer unusable, one per failure mode.
	status     int    // a status other than 200
	body       string // a raw body, overriding the generated one
	unit       string // the unit the fake claims, defaulting to Bytes
	errorCode  string // a per-metric errorCode other than Success
	omitFree   bool   // storage_free missing from the answer altogether
	emptyData  bool   // the metric is there and carries no points
	sleep      time.Duration
	queryCount int

	query  url.Values // the query string of the last request
	path   string     // and its path
	server *httptest.Server
}

func newMonitorFake(t *testing.T) *monitorFake {
	t.Helper()
	m := &monitorFake{t: t, used: 700 << 20, free: 324 << 20, age: time.Minute, unit: "Bytes"}

	m.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.queryCount++
		m.path, m.query = r.URL.Path, r.URL.Query()

		if m.sleep > 0 {
			select {
			case <-time.After(m.sleep):
			case <-r.Context().Done():
				return
			}
		}
		if m.status != 0 {
			w.WriteHeader(m.status)
			_, _ = io.WriteString(w, `{"error":{"code":"Refused","message":"the fake refused"}}`)
			return
		}
		if m.body != "" {
			_, _ = io.WriteString(w, m.body)
			return
		}
		_, _ = io.WriteString(w, m.answer())
	}))
	t.Cleanup(m.server.Close)
	return m
}

// answer builds a documented Metrics - List response with one point per metric.
func (m *monitorFake) answer() string {
	stamp := time.Now().UTC().Add(-m.age).Format(time.RFC3339)
	metric := func(name string, value float64) string {
		data := fmt.Sprintf(`{"timeStamp":%q,"average":%[2]f,"maximum":%[2]f,"minimum":%[2]f}`, stamp, value)
		if m.emptyData {
			data = ""
		}
		return fmt.Sprintf(`{"id":"/x/providers/Microsoft.Insights/metrics/%[1]s",
			"type":"Microsoft.Insights/metrics",
			"name":{"value":%[1]q,"localizedValue":%[1]q},
			"unit":%[2]q,"errorCode":%[3]q,
			"timeseries":[{"metadatavalues":[],"data":[%[4]s]}]}`,
			name, m.unit, m.errorCodeOr("Success"), data)
	}

	metrics := []string{metric("storage_used", m.used)}
	if !m.omitFree {
		metrics = append(metrics, metric("storage_free", m.free))
	}
	return fmt.Sprintf(`{"cost":59,"timespan":"x","interval":"PT1M","value":[%s],
		"namespace":"microsoft.dbforpostgresql/flexibleservers","resourceregion":"westeurope"}`,
		strings.Join(metrics, ","))
}

func (m *monitorFake) errorCodeOr(fallback string) string {
	if m.errorCode != "" {
		return m.errorCode
	}
	return fallback
}

// testMonitor wires the real client to the fake. It builds what the constructor builds, minus the
// credential policy, so the code under test is the code that ships.
//
// RETRIES ARE OFF, and only here: azcore's retry policy is not this repo's code, and leaving it on
// would make the 429 test wait out Azure's own backoff for something it does not measure.
func testMonitor(t *testing.T, f *monitorFake) *AzureMonitor {
	t.Helper()
	m, err := NewAzureMonitor(staticToken{}, theServer)
	if err != nil {
		t.Fatalf("build the monitor client: %v", err)
	}
	m.endpoint = f.server.URL
	m.arm = azruntime.NewPipeline("parity-scanner-test", "0.0.0", azruntime.PipelineOptions{},
		&policy.ClientOptions{Retry: policy.RetryOptions{MaxRetries: -1}})
	return m
}

// The happy path, and every assertion on it is about the REQUEST as much as the answer: an
// api-version that drifted or a metric name that moved would be a brake reading a number that is
// not the disk.
func TestMonitorReadsTheDiskOfTheFlexibleServer(t *testing.T) {
	f := newMonitorFake(t)
	f.used, f.free = 700<<20, 324<<20

	space, err := testMonitor(t, f).Space(t.Context())
	if err != nil {
		t.Fatalf("Space: %v", err)
	}

	if space.Used != 700<<20 {
		t.Errorf("used = %d, want %d", space.Used, int64(700)<<20)
	}
	// THE TOTAL IS DERIVED AND NOT READ: Monitor publishes used and free and no size, so the
	// disk is their sum. A brake that assumed a size would be wrong on every resized server.
	if space.Total != 1024<<20 {
		t.Errorf("total = %d, want %d (used + free)", space.Total, int64(1024)<<20)
	}

	if want := theServer + "/providers/Microsoft.Insights/metrics"; f.path != want {
		t.Errorf("asked %q, want %q", f.path, want)
	}
	for _, want := range []struct{ key, value string }{
		{"api-version", monitorAPIVersion},
		{"metricnames", storageUsedMetric + "," + storageFreeMetric},
		// Both aggregations, because the brake takes the WORST used and the LEAST free.
		{"aggregation", "maximum,minimum"},
		{"interval", "PT1M"},
	} {
		if got := f.query.Get(want.key); got != want.value {
			t.Errorf("%s = %q, want %q", want.key, got, want.value)
		}
	}
	if span := f.query.Get("timespan"); !strings.Contains(span, "/") {
		t.Errorf("timespan = %q, want an ISO start/end pair", span)
	}
}

// The conservative pairing, stated as a test because the unsafe version reads identically. Taking
// the MAXIMUM of both would overstate the disk, overstate the headroom and understate the pressure
// — which fires the brake late, and late is the failure this whole file exists to prevent.
func TestMonitorTakesTheWorstUsedAndTheLeastFree(t *testing.T) {
	f := newMonitorFake(t)
	stamp := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	older := time.Now().UTC().Add(-5 * time.Minute).Format(time.RFC3339)
	f.body = fmt.Sprintf(`{"value":[
		{"name":{"value":"storage_used"},"unit":"Bytes","errorCode":"Success","timeseries":[{"data":[
			{"timeStamp":%[2]q,"maximum":1,"minimum":1},
			{"timeStamp":%[1]q,"maximum":800,"minimum":700}]}]},
		{"name":{"value":"storage_free"},"unit":"Bytes","errorCode":"Success","timeseries":[{"data":[
			{"timeStamp":%[2]q,"maximum":999,"minimum":999},
			{"timeStamp":%[1]q,"maximum":300,"minimum":224}]}]}]}`, stamp, older)

	space, err := testMonitor(t, f).Space(t.Context())
	if err != nil {
		t.Fatalf("Space: %v", err)
	}
	// The NEWEST point of each, its maximum for used and its minimum for free.
	if space.Used != 800 || space.Total != 1024 {
		t.Fatalf("got %+v, want used 800 and total 1024 (800 + 224)", space)
	}
}

// A point with no value at all is skipped rather than read as a zero, and the point behind it is
// used. Monitor emits empty points for minutes it has nothing for, and a zero taken off one of those
// is a disk with nothing on it — the most reassuring possible lie.
func TestAPointWithNoValueIsSkippedRatherThanReadAsZero(t *testing.T) {
	f := newMonitorFake(t)
	newest := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	behind := time.Now().UTC().Add(-2 * time.Minute).Format(time.RFC3339)
	f.body = fmt.Sprintf(`{"value":[
		{"name":{"value":"storage_used"},"unit":"Bytes","errorCode":"Success","timeseries":[{"data":[
			{"timeStamp":%[2]q,"maximum":700,"minimum":700},
			{"timeStamp":%[1]q}]}]},
		{"name":{"value":"storage_free"},"unit":"Bytes","errorCode":"Success","timeseries":[{"data":[
			{"timeStamp":%[2]q,"maximum":324,"minimum":324},
			{"timeStamp":%[1]q}]}]}]}`, newest, behind)

	space, err := testMonitor(t, f).Space(t.Context())
	if err != nil {
		t.Fatalf("Space: %v", err)
	}
	if space.Used != 700 || space.Total != 1024 {
		t.Fatalf("got %+v, want the last point that carried a value", space)
	}
}

// THE SUM OF TWO INSTANTS IS NOT A DISK. A used from now and a free from five minutes ago is, on a
// filling disk, a total larger than the disk really is — which overstates the headroom, understates
// the pressure and fires the brake late.
func TestAUsedAndAFreeFromDifferentInstantsAreRefused(t *testing.T) {
	f := newMonitorFake(t)
	now := time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	old := time.Now().UTC().Add(-6 * time.Minute).Format(time.RFC3339)
	f.body = fmt.Sprintf(`{"value":[
		{"name":{"value":"storage_used"},"unit":"Bytes","errorCode":"Success","timeseries":[{"data":[
			{"timeStamp":%[1]q,"maximum":900,"minimum":900}]}]},
		{"name":{"value":"storage_free"},"unit":"Bytes","errorCode":"Success","timeseries":[{"data":[
			{"timeStamp":%[2]q,"maximum":500,"minimum":500}]}]}]}`, now, old)

	space, err := testMonitor(t, f).Space(t.Context())
	if err == nil {
		t.Fatalf("Space returned %+v, a disk assembled out of two different minutes", space)
	}
	if space != (Space{}) {
		t.Errorf("Space returned %+v alongside its error", space)
	}
	if !strings.Contains(err.Error(), "same instant") {
		t.Errorf("error %q does not say the two halves disagree", err)
	}
}

// EVERY WAY THIS CAN FAIL MUST FAIL LOUDLY, and none of them may come back as a Space. A Space of
// zeroes is what Assess reads as "unknown" and would be survivable; a Space with a plausible number
// in it is the silent failure this brake cannot have, because it reads as "the disk is fine".
func TestAnUnusableAnswerIsAnErrorAndNeverASpace(t *testing.T) {
	for _, tc := range []struct {
		name  string
		set   func(*monitorFake)
		wants string
	}{
		{
			name:  "forbidden",
			set:   func(f *monitorFake) { f.status = http.StatusForbidden },
			wants: "403",
		},
		{
			// The one an over-frequent brake causes itself. It must not read as an empty disk.
			name:  "throttled",
			set:   func(f *monitorFake) { f.status = http.StatusTooManyRequests },
			wants: "429",
		},
		{
			name:  "a body that is not JSON",
			set:   func(f *monitorFake) { f.body = `{"value":[{"name":` },
			wants: "did not parse",
		},
		{
			// Microsoft's own documented failure shape: a 200 whose per-metric errorCode is not
			// Success. The metric is absent from the payload in every way that matters and the
			// service already said why.
			name:  "a metric that failed inside a 200",
			set:   func(f *monitorFake) { f.errorCode = "InvalidSamplingType" },
			wants: "InvalidSamplingType",
		},
		{
			// The whole computation is in bytes. A unit change would rescale it silently.
			name:  "a unit that is not bytes",
			set:   func(f *monitorFake) { f.unit = "Percent" },
			wants: "Percent",
		},
		{
			name:  "storage_free missing altogether",
			set:   func(f *monitorFake) { f.omitFree = true },
			wants: storageFreeMetric,
		},
		{
			name:  "a metric with no data points",
			set:   func(f *monitorFake) { f.emptyData = true },
			wants: "no data point",
		},
		{
			// THE ONE THAT LOOKS LIKE SUCCESS. A stale point parses, has a unit, has a value,
			// and describes a disk from before whatever went wrong. A brake reading it is
			// reading the past and calling it now.
			name:  "a reading old enough to be the past",
			set:   func(f *monitorFake) { f.age = staleAfter + time.Minute },
			wants: "stale",
		},
		{
			name:  "a negative byte count",
			set:   func(f *monitorFake) { f.used = -1 },
			wants: "not a byte count",
		},
		{
			name:  "a disk of no size at all",
			set:   func(f *monitorFake) { f.used, f.free = 0, 0 },
			wants: "no size",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMonitorFake(t)
			tc.set(f)

			space, err := testMonitor(t, f).Space(t.Context())
			if err == nil {
				t.Fatalf("Space returned %+v and no error", space)
			}
			if space != (Space{}) {
				t.Errorf("Space returned %+v alongside its error; a half-filled disk reads as a "+
					"real, tiny one", space)
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Errorf("error %q does not say %q, and this error is what an operator gets",
					err, tc.wants)
			}
		})
	}
}

// A metrics endpoint that never answers must not stop the brake ticking. Without a bound of its
// own, one hung request wedges the goroutine whose whole job is to notice a wedge.
func TestMonitorGivesUpRatherThanHangingTheBrake(t *testing.T) {
	f := newMonitorFake(t)
	f.sleep = time.Minute

	m := testMonitor(t, f)
	m.timeout = 50 * time.Millisecond

	start := time.Now()
	space, err := m.Space(t.Context())
	if err == nil {
		t.Fatalf("Space returned %+v and no error", space)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Fatalf("the call took %s; the brake's tick is %s", took, DefaultEvery)
	}
	if space != (Space{}) {
		t.Errorf("Space returned %+v alongside its timeout", space)
	}
}

// THE POINT OF ALL OF THE ABOVE, wired the way the agent wires it: a Monitor that will not answer
// leaves the brake WARNING and never dropping. Never Fine, because nobody is watching the WAL;
// never Trip, because destroying a chain on half the evidence is the worse trade.
func TestAMonitorThatWillNotAnswerWarnsAndNeverDrops(t *testing.T) {
	f := newMonitorFake(t)
	f.status = http.StatusForbidden

	dropped := false
	var alarms []Alarm
	b := &Brake{
		Slot: "vp_stream",
		Query: func(_ context.Context, sql string) ([][]string, error) {
			if strings.Contains(sql, "pg_drop_replication_slot") {
				dropped = true
			}
			return [][]string{{"0", fmt.Sprint(int64(8192) << 20)}}, nil
		},
		Disk:  testMonitor(t, f).Space,
		Alert: func(a Alarm) { alarms = append(alarms, a) },
	}

	decision, err := b.Check(t.Context())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if decision.Verdict != Warn {
		t.Fatalf("verdict = %v, want warn", decision.Verdict)
	}
	if dropped {
		t.Fatal("the brake dropped a slot on a reading it never got")
	}
	if len(alarms) != 1 || alarms[0].Err == nil {
		t.Fatalf("alarms = %v, want one carrying why the disk could not be read", alarms)
	}
	if !strings.Contains(alarms[0].Err.Error(), "403") {
		t.Errorf("the alarm says %q, which does not name what Monitor answered", alarms[0].Err)
	}
}

// A resource id that is not a Flexible Server is refused where refusing is free. Monitor answers a
// request for a resource that has no storage_used with an empty value[] and a 200, so the misconfig
// would otherwise arrive as "no data point" on every tick of a running agent.
func TestMonitorRefusesAResourceThatIsNotAFlexibleServer(t *testing.T) {
	for _, id := range []string{
		"",
		"pg-1",
		"/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DataProtection/backupVaults/v",
		// Single Server, which is a different resource provider path and a retired service.
		"/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DBforPostgreSQL/servers/pg-1",
		// The type with no server named after it.
		"/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.DBforPostgreSQL/flexibleServers",
		// A CHILD of the server. It is a real resource and it publishes no storage_used, so
		// Monitor answers with a 200 and an empty result rather than with an error.
		theServer + "/databases/appdb",
	} {
		if _, err := NewAzureMonitor(staticToken{}, id); err == nil {
			t.Errorf("NewAzureMonitor accepted %q", id)
		}
	}
	// And the documented casing is not the only casing ARM returns.
	if _, err := NewAzureMonitor(staticToken{}, strings.ToLower(theServer)); err != nil {
		t.Errorf("NewAzureMonitor refused a lower-cased id, which is what ARM hands back: %v", err)
	}
}
