package postgres

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

// The whole point of Assess is that it needs no server: lag and disk go in, a decision comes out.
// So the table below is the specification of the brake, and everything about connections, tickers
// and drops is plumbing around this.
//
// The numbers are in mebibytes to stay readable. A "disk" of 1024 has its read-only line at 972.8.
const mib = 1 << 20

// readOnlyLine is the byte at which Azure would turn a disk of this size read-only. The boundary
// rows below are built backwards from it, because "exactly at the threshold" has to be exact.
func readOnlyLine(total int64) int64 { return int64(float64(total) * readOnlyAt) }

func TestAssessCombinesLagAndDisk(t *testing.T) {
	for _, tc := range []struct {
		name         string
		reading      Reading
		wantVerdict  Verdict
		wantPressure float64
	}{
		{
			// The case that proves lag alone cannot decide: 8 GiB of retained WAL, which
			// would trip any absolute lag threshold worth having on a small server, is
			// nothing at all on a large mostly-empty one.
			name: "a large slot on a large empty disk is fine",
			reading: Reading{
				Present:       true,
				RetainedBytes: 8192 * mib,
				Disk:          Space{Total: 4194304 * mib, Used: 400 * mib}, // 4 TiB
			},
			wantVerdict:  Fine,
			wantPressure: 0.0020519,
		},
		{
			// The same 8 GiB, on the disk it actually kills. Same lag, opposite answer:
			// this pair is the argument for one number rather than two metrics.
			name: "the same slot on a small disk trips",
			reading: Reading{
				Present:       true,
				RetainedBytes: 8192 * mib,
				Disk:          Space{Total: 32768 * mib, Used: 24000 * mib},
			},
			wantVerdict:  Trip,
			wantPressure: 0.5346700,
		},
		{
			// The case that proves disk alone cannot decide: a nearly full disk that we
			// did not fill. Dropping our slot would buy the customer nothing and would
			// destroy the chain, so the brake keeps its hands off.
			name: "a disk the customer filled is not ours to act on",
			reading: Reading{
				Present:       true,
				RetainedBytes: 1 * mib,
				Disk:          Space{Total: 32768 * mib, Used: 31000 * mib},
			},
			wantVerdict:  Fine,
			wantPressure: 0.0076570,
		},
		{
			// Half the room our slot may eat is eaten. Dropping now gives back about as
			// much as is left, and the disk is at 57% — well before the 95% line.
			name: "retained about equal to the headroom is the trip point",
			reading: Reading{
				Present:       true,
				RetainedBytes: 400 * mib,
				Disk:          Space{Total: 1024 * mib, Used: 580 * mib},
			},
			wantVerdict:  Trip,
			wantPressure: 0.5045406,
		},
		{
			name: "a quarter of the room is a warning and not a drop",
			reading: Reading{
				Present:       true,
				RetainedBytes: 300 * mib,
				Disk:          Space{Total: 1024 * mib, Used: 300 * mib},
			},
			wantVerdict:  Warn,
			wantPressure: 0.3083882,
		},
		{
			// Past the read-only line with WAL of ours on the disk: there is no headroom
			// left to divide, so every byte of the problem we can reach is ours.
			name: "past the line with WAL of ours is pressure one",
			reading: Reading{
				Present:       true,
				RetainedBytes: 100 * mib,
				Disk:          Space{Total: 1024 * mib, Used: 1000 * mib},
			},
			wantVerdict:  Trip,
			wantPressure: 1,
		},
		{
			// THE BOUNDARY ITSELF, and it is >= rather than >. A disk of 1024 MiB puts the
			// read-only line at 1020054732 bytes, so a headroom of exactly 400 MiB and a
			// retention of exactly 400 MiB is pressure 0.5 to the byte.
			name: "exactly at the trip threshold trips",
			reading: Reading{
				Present:       true,
				RetainedBytes: 400 * mib,
				Disk:          Space{Total: 1024 * mib, Used: readOnlyLine(1024*mib) - 400*mib},
			},
			wantVerdict:  Trip,
			wantPressure: 0.5,
		},
		{
			// And one byte under it does not. Stated as a row because "fires at half" and
			// "fires just past half" are the same sentence in English and different code.
			name: "one byte under the trip threshold only warns",
			reading: Reading{
				Present:       true,
				RetainedBytes: 400*mib - 1,
				Disk:          Space{Total: 1024 * mib, Used: readOnlyLine(1024*mib) - 400*mib},
			},
			wantVerdict:  Warn,
			wantPressure: 0.4999999994,
		},
		{
			// The other boundary: a retention of exactly a third of the headroom is a
			// quarter of the room our slot may take.
			name: "exactly at the warn threshold warns",
			reading: Reading{
				Present:       true,
				RetainedBytes: 100 * mib,
				Disk:          Space{Total: 1024 * mib, Used: readOnlyLine(1024*mib) - 300*mib},
			},
			wantVerdict:  Warn,
			wantPressure: 0.25,
		},
		{
			// The brake must never drop on half the evidence. A metrics outage downgrades
			// it to an alarm; the server-side ceiling is what covers this case, and
			// dropping a chain because monitoring blinked would be the worse trade.
			name: "an unknown disk warns and never trips",
			reading: Reading{
				Present:       true,
				RetainedBytes: 8192 * mib,
				Disk:          Space{},
			},
			wantVerdict:  Warn,
			wantPressure: math.NaN(),
		},
		{
			name:         "no slot of ours is nothing to brake",
			reading:      Reading{Present: false, Disk: Space{Total: 1024 * mib, Used: 1000 * mib}},
			wantVerdict:  Fine,
			wantPressure: 0,
		},
		{
			// Nothing of ours and no room: pressure is a share of the problem, and none
			// of this one is ours. Reported as zero rather than as a division by zero.
			name: "no room and nothing of ours divides by nothing",
			reading: Reading{
				Present: true,
				Disk:    Space{Total: 1024 * mib, Used: 1024 * mib},
			},
			wantVerdict:  Fine,
			wantPressure: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Assess(tc.reading)

			if got.Verdict != tc.wantVerdict {
				t.Errorf("verdict = %v, want %v (pressure %v, why: %s)",
					got.Verdict, tc.wantVerdict, got.Pressure, got.Why)
			}
			switch {
			case math.IsNaN(tc.wantPressure):
				if !math.IsNaN(got.Pressure) {
					t.Errorf("pressure = %v, want NaN — an unknown disk must not read as a number", got.Pressure)
				}
			case math.Abs(got.Pressure-tc.wantPressure) > 1e-6:
				t.Errorf("pressure = %v, want %v", got.Pressure, tc.wantPressure)
			}
			if got.Why == "" {
				t.Error("no Why; the alarm this becomes is read by someone deciding whether to act")
			}
		})
	}
}

// Pressure has to move the right way in both variables or the single number is worse than the two
// it replaces. Checked as a property rather than as more rows, because the rows above pin points
// and this pins the shape between them.
func TestPressureIsMonotonicInBoth(t *testing.T) {
	disk := Space{Total: 1024 * mib, Used: 500 * mib}

	previous := -1.0
	for retained := int64(0); retained <= 900*mib; retained += 50 * mib {
		got := Assess(Reading{Present: true, RetainedBytes: retained, Disk: disk}).Pressure
		if got <= previous {
			t.Fatalf("pressure did not rise with retained WAL: %v at %d MiB after %v", got, retained/mib, previous)
		}
		previous = got
	}

	previous = 2.0
	for used := int64(900 * mib); used >= 0; used -= 50 * mib {
		got := Assess(Reading{Present: true, RetainedBytes: 100 * mib, Disk: Space{Total: 1024 * mib, Used: used}}).Pressure
		if got >= previous {
			t.Fatalf("pressure did not fall as the disk emptied: %v at %d MiB used after %v", got, used/mib, previous)
		}
		previous = got
	}
}

// A negative retention is not a thing a healthy server reports, but pg_wal_lsn_diff is a numeric
// subtraction and the brake must not turn an odd reading into a negative pressure that reads as
// health.
func TestNegativeRetentionIsClampedRatherThanTrusted(t *testing.T) {
	got := Assess(Reading{Present: true, RetainedBytes: -1, Disk: Space{Total: 1024 * mib, Used: 500 * mib}})
	if got.Pressure != 0 || got.Verdict != Fine {
		t.Fatalf("got %v at pressure %v, want Fine at 0", got.Verdict, got.Pressure)
	}
}

// The other half of the decision, and the half that answers the epic's open item: two Parity
// installs cannot be told apart by slot name, so the brake establishes who is CONSUMING the slot
// before it destroys one.
func TestMayDrop(t *testing.T) {
	for _, tc := range []struct {
		name      string
		reading   Reading
		streamPID uint32
		wantErr   string
	}{
		{
			name:    "an idle slot is ours to drop",
			reading: Reading{Present: true},
		},
		{
			// The case the brake exists for: our own stream is wedged mid-batch, still
			// holding the slot open, and the loop that would have released it is the
			// thing that is sick. Dropping means terminating our own backend first.
			name:      "a slot our own stream is holding is ours to drop",
			reading:   Reading{Present: true, ActivePID: 4242},
			streamPID: 4242,
		},
		{
			name:      "a slot somebody else is consuming is left alone",
			reading:   Reading{Present: true, ActivePID: 99},
			streamPID: 4242,
			wantErr:   "another consumer",
		},
		{
			// No stream of ours at all — the brake ticking before the stream opened, or
			// after it died — and something is reading the slot. That something is not us.
			name:      "an active slot with no stream of ours is left alone",
			reading:   Reading{Present: true, ActivePID: 99},
			streamPID: 0,
			wantErr:   "another consumer",
		},
		{
			name:    "a slot that is not there cannot be dropped",
			reading: Reading{Present: false},
			wantErr: "is not on the server",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := mayDrop("vp_stream", tc.reading, tc.streamPID)
			switch {
			case tc.wantErr == "" && err != nil:
				t.Fatalf("mayDrop refused: %v", err)
			case tc.wantErr != "" && err == nil:
				t.Fatalf("mayDrop allowed a drop it must refuse")
			case tc.wantErr != "" && !strings.Contains(err.Error(), tc.wantErr):
				t.Fatalf("mayDrop said %q, want it to mention %q", err, tc.wantErr)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Check — one tick of the brake, with a fake database and a fake disk.
// ─────────────────────────────────────────────────────────────────────────────────────────────

// fakeDB answers the statements the brake sends and records them in order.
type fakeDB struct {
	slotRows   [][]string
	show       [][]string
	terminated string
	sent       []string
	fail       map[string]error
}

func (f *fakeDB) query(_ context.Context, sql string) ([][]string, error) {
	f.sent = append(f.sent, sql)
	for fragment, err := range f.fail {
		if strings.Contains(sql, fragment) {
			return nil, err
		}
	}
	if strings.Contains(sql, "pg_replication_slots") {
		return f.slotRows, nil
	}
	if strings.HasPrefix(sql, "SHOW ") {
		return f.show, nil
	}
	if strings.Contains(sql, "pg_terminate_backend") {
		// "t" is what a real server answers when the backend really did stop within the
		// timeout, and it is the default here because every other row wants that.
		if f.terminated == "" {
			return [][]string{{"t"}}, nil
		}
		return [][]string{{f.terminated}}, nil
	}
	return nil, nil
}

func (f *fakeDB) did(fragment string) bool {
	for _, sql := range f.sent {
		if strings.Contains(sql, fragment) {
			return true
		}
	}
	return false
}

func slotRow(pid uint32, retained int64) [][]string {
	return [][]string{{fmt.Sprint(pid), fmt.Sprint(retained)}}
}

func TestCheckDropsOnlyWhenItTrips(t *testing.T) {
	for _, tc := range []struct {
		name          string
		rows          [][]string
		disk          Space
		streamPID     uint32
		wantVerdict   Verdict
		wantDrop      bool
		wantTerminate bool
	}{
		{
			name:        "a healthy slot is read and left alone",
			rows:        slotRow(0, 10*mib),
			disk:        Space{Total: 1024 * mib, Used: 300 * mib},
			wantVerdict: Fine,
		},
		{
			name:        "a warning alerts and drops nothing",
			rows:        slotRow(0, 300*mib),
			disk:        Space{Total: 1024 * mib, Used: 300 * mib},
			wantVerdict: Warn,
		},
		{
			name:        "a trip on an idle slot drops it without terminating anything",
			rows:        slotRow(0, 400*mib),
			disk:        Space{Total: 1024 * mib, Used: 580 * mib},
			wantVerdict: Trip,
			wantDrop:    true,
		},
		{
			// The sick agent: our own wedged stream is still holding the slot. The brake
			// kills our backend and then drops. Both statements, in that order.
			name:          "a trip on our own wedged stream terminates it first",
			rows:          slotRow(4242, 400*mib),
			disk:          Space{Total: 1024 * mib, Used: 580 * mib},
			streamPID:     4242,
			wantVerdict:   Trip,
			wantDrop:      true,
			wantTerminate: true,
		},
		{
			// Tripping and refusing to drop is a real outcome and must alert, not silently
			// do nothing: somebody else is consuming a slot on our name.
			name:        "a trip on somebody else's consumer alerts and drops nothing",
			rows:        slotRow(99, 400*mib),
			disk:        Space{Total: 1024 * mib, Used: 580 * mib},
			streamPID:   4242,
			wantVerdict: Trip,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := &fakeDB{slotRows: tc.rows}
			var alarms []Alarm

			b := &Brake{
				Slot:      "vp_stream",
				Query:     db.query,
				Disk:      func(context.Context) (Space, error) { return tc.disk, nil },
				StreamPID: func() uint32 { return tc.streamPID },
				Alert:     func(a Alarm) { alarms = append(alarms, a) },
			}

			got, err := b.Check(context.Background())
			if err != nil {
				t.Fatalf("Check: %v", err)
			}
			if got.Verdict != tc.wantVerdict {
				t.Fatalf("verdict = %v, want %v (%s)", got.Verdict, tc.wantVerdict, got.Why)
			}
			if did := db.did("pg_drop_replication_slot"); did != tc.wantDrop {
				t.Errorf("dropped = %v, want %v; statements: %v", did, tc.wantDrop, db.sent)
			}
			if did := db.did("pg_terminate_backend"); did != tc.wantTerminate {
				t.Errorf("terminated = %v, want %v; statements: %v", did, tc.wantTerminate, db.sent)
			}
			if tc.wantTerminate {
				// Order, not merely presence: dropping first fails against a live
				// consumer and leaves the WAL exactly where it was.
				kill, drop := indexOf(db.sent, "pg_terminate_backend"), indexOf(db.sent, "pg_drop_replication_slot")
				if kill > drop {
					t.Errorf("dropped before terminating: %v", db.sent)
				}
			}
			// Every verdict above Fine is alertable, including the one where the drop was
			// refused: a brake that trips and does nothing in silence is not a brake.
			wantAlarm := tc.wantVerdict != Fine
			if got := len(alarms) > 0; got != wantAlarm {
				t.Errorf("alarms = %v, want an alarm: %v", alarms, wantAlarm)
			}
			if tc.wantDrop {
				if !alarms[0].Dropped {
					t.Error("the alarm does not say the slot was dropped, so nothing downstream schedules a re-base")
				}
			}
		})
	}
}

// A slot that is not there at all is C4's dead chain, not the brake's business — and above all it
// is not something to alarm about every minute.
func TestCheckIsSilentWhenTheSlotIsGone(t *testing.T) {
	db := &fakeDB{slotRows: nil}
	var alarms []Alarm

	b := &Brake{Slot: "vp_stream", Query: db.query, Alert: func(a Alarm) { alarms = append(alarms, a) },
		Disk: func(context.Context) (Space, error) { return Space{Total: 1024 * mib, Used: 900 * mib}, nil }}

	got, err := b.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got.Verdict != Fine || len(alarms) != 0 {
		t.Fatalf("verdict %v with %d alarms, want Fine and silence", got.Verdict, len(alarms))
	}
}

// The disk half failing must not make the brake read as healthy. It is the direction that matters:
// a metrics outage turns the brake into an alarm, never into an all-clear and never into a drop.
func TestCheckWarnsWhenTheDiskCannotBeRead(t *testing.T) {
	db := &fakeDB{slotRows: slotRow(0, 8192*mib)}
	var alarms []Alarm

	b := &Brake{
		Slot:  "vp_stream",
		Query: db.query,
		Disk:  func(context.Context) (Space, error) { return Space{}, errors.New("metrics are down") },
		Alert: func(a Alarm) { alarms = append(alarms, a) },
	}

	got, err := b.Check(context.Background())
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if got.Verdict != Warn {
		t.Fatalf("verdict = %v, want Warn", got.Verdict)
	}
	if db.did("pg_drop_replication_slot") {
		t.Fatal("dropped a slot on half the evidence")
	}
	if len(alarms) != 1 || alarms[0].Err == nil {
		t.Fatalf("alarms = %v, want one carrying the reason the disk could not be read", alarms)
	}
}

// The brake refuses to be pointed at a name it cannot claim, for the same reason CreateSlot does:
// a name outside our convention belongs to the customer, and this is the one function in the repo
// whose job is to destroy a slot.
func TestCheckRefusesASlotThatIsNotOurs(t *testing.T) {
	db := &fakeDB{slotRows: slotRow(0, 8192*mib)}
	b := &Brake{Slot: "customer_slot", Query: db.query}

	if _, err := b.Check(context.Background()); err == nil {
		t.Fatal("the brake accepted a slot name that is not ours")
	}
	if len(db.sent) != 0 {
		t.Fatalf("statements were sent for a name we refuse: %v", db.sent)
	}
}

// A drop that fails is the worst news the brake has, and it must reach the ALARM rather than the
// return value alone: at this point the WAL is still growing, nobody but us can stop it, and a
// caller that logged the error and carried on would have lost the only warning anyone gets.
func TestCheckAlertsWhenTheDropFails(t *testing.T) {
	db := &fakeDB{
		slotRows: slotRow(0, 400*mib),
		fail:     map[string]error{"pg_drop_replication_slot": errors.New("connection reset")},
	}
	var alarms []Alarm

	b := &Brake{
		Slot:  "vp_stream",
		Query: db.query,
		Disk:  func(context.Context) (Space, error) { return Space{Total: 1024 * mib, Used: 580 * mib}, nil },
		Alert: func(a Alarm) { alarms = append(alarms, a) },
	}

	got, err := b.Check(context.Background())
	if err == nil {
		t.Fatal("a failed drop was reported as success")
	}
	if got.Verdict != Trip {
		t.Errorf("verdict = %v, want the decision that was reached before the drop failed", got.Verdict)
	}
	if len(alarms) != 1 {
		t.Fatalf("alarms = %v, want exactly one", alarms)
	}
	if alarms[0].Dropped {
		t.Error("the alarm claims the slot was dropped; the WAL is still there and still growing")
	}
	if alarms[0].Err == nil {
		t.Error("the alarm carries no error, so nothing says why the WAL is still accumulating")
	}
}

// ONE FAILURE IS ONE ALARM, and this is the whole reason the alarms live in Check rather than in
// its callers. The failed drop is the path where both used to speak: Check alerted because a trip
// it could not carry out is the loudest thing it says, and the loop alerted again on the error it
// got back. Two alarms for one event teaches whoever reads them that the count means nothing, and
// this brake drops a replication slot — the alarm it repeats is the one that must not be ignored.
//
// THE CONTEXT MUST BE LIVE FOR THE ONE TICK THIS TAKES, which is the whole reason for the deadline
// rather than a cancel up front: the loop only ever raised its second alarm while the context was
// still good, so a brake cancelled before the tick hides the very fault under test. Every is an hour
// so exactly one Check runs, and the deadline is what ends Watch afterwards.
func TestWatchAlarmsOnceForOneFailedDrop(t *testing.T) {
	db := &fakeDB{
		slotRows: slotRow(0, 400*mib),
		fail:     map[string]error{"pg_drop_replication_slot": errors.New("connection reset")},
	}
	var alarms []Alarm

	// Three orders of magnitude more than a tick against a fake needs, and it is spent waiting
	// in the select rather than doing anything, so it costs the suite this once.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	b := &Brake{
		Slot:  "vp_stream",
		Query: db.query,
		Every: time.Hour, // Never reached: Check runs before the first tick.
		Disk:  func(context.Context) (Space, error) { return Space{Total: 1024 * mib, Used: 580 * mib}, nil },
		Alert: func(a Alarm) { alarms = append(alarms, a) },
	}

	if err := b.Watch(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Watch = %v, want the context's error", err)
	}
	if len(alarms) != 1 {
		t.Fatalf("alarms = %v, want exactly one for one failed drop (none means the tick never ran)", alarms)
	}
	if alarms[0].Decision.Verdict != Trip {
		t.Errorf("the surviving alarm is %v, want the Trip that could not be carried out",
			alarms[0].Decision.Verdict)
	}
}

// The agent being told to stop is not the brake going blind. Every other way of failing to read the
// slot means nobody is watching the WAL and is alarmed on as such, but a cancelled context means
// this process is shutting down — and an agent that crash-loops would then raise that same alarm on
// every loop, which is the repeating alarm this file is trying not to become.
//
// The error is still returned. It is the ALARM that is withheld, and only before a verdict exists.
func TestCheckIsSilentWhenTheContextEnded(t *testing.T) {
	db := &fakeDB{fail: map[string]error{"pg_replication_slots": context.Canceled}}
	var alarms []Alarm

	ctx, cancel := context.WithCancel(context.Background())
	b := &Brake{Slot: "vp_stream", Query: db.query, Alert: func(a Alarm) { alarms = append(alarms, a) }}
	cancel()

	if _, err := b.Check(ctx); err == nil {
		t.Fatal("a read that failed was reported as success")
	}
	if len(alarms) != 0 {
		t.Fatalf("alarms = %v, want silence: the context ended, which is a shutdown and not news", alarms)
	}
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// The backstop — the only layer that survives this process not existing.
// ─────────────────────────────────────────────────────────────────────────────────────────────

func TestUnlimitedCeiling(t *testing.T) {
	for setting, want := range map[string]bool{
		"-1":     true,
		"-1MB":   true,
		" -1 ":   true, //nolint:gocritic // mapKey: the padding is the fixture; the parser must trim it
		"0":      false,
		"1GB":    false,
		"1024MB": false,
	} {
		if got := unlimitedCeiling(setting); got != want {
			t.Errorf("unlimitedCeiling(%q) = %v, want %v", setting, got, want)
		}
	}
}

// Watch says at START whether anything on the server would stop this WITHOUT us, because that is
// the one failure the rest of this file cannot cover: the agent gone for good, holding the only
// credential that can drop the slot. It also proves Watch checks BEFORE its first tick — an agent
// crash-looping faster than the interval would otherwise never brake, and a crash loop is exactly
// the sick agent this is for.
func TestWatchReportsAnUnlimitedCeilingBeforeItStreams(t *testing.T) {
	for _, tc := range []struct {
		name    string
		setting string
		want    bool
	}{
		{name: "unlimited is reported", setting: "-1", want: true},
		{name: "a real ceiling is not", setting: "1GB", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := &fakeDB{slotRows: slotRow(0, 1*mib), show: [][]string{{tc.setting}}}
			var alarms []Alarm

			ctx, cancel := context.WithCancel(context.Background())
			b := &Brake{
				Slot:  "vp_stream",
				Query: db.query,
				Every: time.Hour, // Never reached: the point is that Check runs before the tick.
				Disk:  func(context.Context) (Space, error) { return Space{Total: 1024 * mib, Used: 300 * mib}, nil },
				Alert: func(a Alarm) { alarms = append(alarms, a) },
			}
			cancel()
			if err := b.Watch(ctx); !errors.Is(err, context.Canceled) {
				t.Fatalf("Watch = %v, want the context's error", err)
			}

			if !db.did("pg_replication_slots") {
				t.Error("Watch returned without reading the slot once, so an agent restarting " +
					"faster than the tick would never brake at all")
			}
			if got := len(alarms) > 0; got != tc.want {
				t.Errorf("alarms = %v, want an alarm about the ceiling: %v", alarms, tc.want)
			}
			if tc.want && !strings.Contains(alarms[0].Err.Error(), "max_slot_wal_keep_size") {
				t.Errorf("the alarm does not name the parameter an administrator would have to set: %v", alarms[0].Err)
			}
		})
	}
}

// The server waits for our own backend and then reports that it did not die. Dropping anyway would
// fail against a still-active slot, and reporting success would be worse: the WAL would keep growing
// with the chain already written off.
func TestCheckDoesNotDropWhenOurOwnBackendWillNotDie(t *testing.T) {
	db := &fakeDB{slotRows: slotRow(4242, 400*mib), terminated: "f"}
	var alarms []Alarm

	b := &Brake{
		Slot:      "vp_stream",
		Query:     db.query,
		Disk:      func(context.Context) (Space, error) { return Space{Total: 1024 * mib, Used: 580 * mib}, nil },
		StreamPID: func() uint32 { return 4242 },
		Alert:     func(a Alarm) { alarms = append(alarms, a) },
	}

	if _, err := b.Check(context.Background()); err == nil {
		t.Fatal("a backend that would not die was reported as a clean drop")
	}
	if db.did("pg_drop_replication_slot") {
		t.Error("dropped against a slot still held open; the statement can only fail")
	}
	if len(alarms) != 1 || alarms[0].Dropped {
		t.Fatalf("alarms = %v, want exactly one that does not claim the slot is gone", alarms)
	}
}

func indexOf(all []string, fragment string) int {
	for i, s := range all {
		if strings.Contains(s, fragment) {
			return i
		}
	}
	return -1
}
