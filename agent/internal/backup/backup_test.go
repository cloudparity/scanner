package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

var (
	errStreamDied  = errors.New("connection reset while copying")
	errRefused     = errors.New("permission denied for schema public")
	errFlushFailed = errors.New("exit status 1: pg_dump: error: query failed")
)

// drain stands in for the pipeline that does not exist yet (E6.9): open every part, read it
// whole, keep what arrived. If the fake can drive this, it can drive the real one — which
// is the claim §7 makes about the seam and the only way to check it today.
func drain(b Batch) (map[string]string, error) {
	got := map[string]string{}
	for _, p := range b.Parts {
		r, err := p.Open()
		if err != nil {
			return got, fmt.Errorf("open %s: %w", p.Name, err)
		}
		body, readErr := io.ReadAll(r)
		got[p.Name] = string(body)
		closeErr := r.Close()
		// A clean read is not a whole stream. Close is where a process on a pipe reports its
		// exit status, and it is the last moment the pipeline can still refuse to write a
		// manifest over a short object. When both fire they are joined rather than ranked:
		// the read says "connection reset" and Close says "pg_dump: error: query failed", and
		// E6.13 wants the one a human can act on, which is not reliably the first.
		switch {
		case readErr != nil && closeErr != nil:
			return got, fmt.Errorf("read and close %s: %w", p.Name, errors.Join(readErr, closeErr))
		case readErr != nil:
			return got, fmt.Errorf("read %s: %w", p.Name, readErr)
		case closeErr != nil:
			return got, fmt.Errorf("close %s: %w", p.Name, closeErr)
		}
	}
	return got, nil
}

func TestTheFakeDrivesAPipelineWithNoDatabaseBehindIt(t *testing.T) {
	src := &fakeSource{base: Batch{
		Position: "0/1A2B000",
		Schema:   "sha256:abc",
		Parts:    []Part{wholePart("db.dump", "PGDMP-one"), wholePart("roles.sql", "CREATE ROLE")},
	}}

	b, err := src.Base(context.Background())
	if err != nil {
		t.Fatalf("a good Base failed: %v", err)
	}
	if b.Position != "0/1A2B000" || b.Schema != "sha256:abc" {
		t.Errorf("batch %+v lost its position or schema", b)
	}
	got, err := drain(b)
	if err != nil {
		t.Fatalf("draining a clean batch failed: %v", err)
	}
	if got["db.dump"] != "PGDMP-one" || got["roles.sql"] != "CREATE ROLE" {
		t.Errorf("the bytes changed on the way through: %v", got)
	}
}

// The pipeline will retry an upload, and a retry that reads a spent reader uploads nothing
// while reporting success. Open must hand back a fresh stream every time.
func TestAPartYieldsAFreshReaderEveryTime(t *testing.T) {
	p := wholePart("db.dump", "PGDMP-one")

	for attempt := 1; attempt <= 2; attempt++ {
		r, err := p.Open()
		if err != nil {
			t.Fatalf("open %d failed: %v", attempt, err)
		}
		body, err := io.ReadAll(r)
		_ = r.Close()
		if err != nil {
			t.Fatalf("read %d failed: %v", attempt, err)
		}
		if string(body) != "PGDMP-one" {
			t.Fatalf("attempt %d read %q — the reader was not fresh", attempt, body)
		}
	}
}

// The three failure shapes the pipeline has to tell apart. One wrote bytes it must not
// trust; one wrote nothing at all; and one read to a clean EOF and only then admitted the
// stream was never whole.
func TestAPartFailsBeforeDuringOrAtTheEndOfTheStream(t *testing.T) {
	tests := []struct {
		name       string
		part       Part
		wantBytes  string
		wantErr    error
		wantErrMsg string
	}{
		{
			name:       "mid-stream, after bytes have already landed",
			part:       truncatedPart("db.dump", "PGDMP-hal", errStreamDied),
			wantBytes:  "PGDMP-hal",
			wantErr:    errStreamDied,
			wantErrMsg: "read db.dump",
		},
		{
			name:       "at open, before a single byte",
			part:       unopenablePart("db.dump", errRefused),
			wantBytes:  "",
			wantErr:    errRefused,
			wantErrMsg: "open db.dump",
		},
		{
			// pg_dump is a process on the end of a pipe, and a process reports failure by
			// exiting, not by breaking the pipe. Read returns every byte and then a clean
			// EOF; Close is where "exit status 1" finally arrives. A pipeline that discards
			// what Close says — as this drain did until this row was written — stores a dump
			// that ends mid-COPY, checksums it, and writes a manifest over it. Every check
			// green, the loss found at restore (E6.13).
			name:       "at close, after the whole stream read clean",
			part:       flushFailsPart("db.dump", "PGDMP-one", errFlushFailed),
			wantBytes:  "PGDMP-one",
			wantErr:    errFlushFailed,
			wantErrMsg: "close db.dump",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := drain(Batch{Position: "0/1A2B000", Parts: []Part{tc.part}})
			if err == nil {
				t.Fatal("a failing part drained cleanly")
			}
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("error %v does not carry %v", err, tc.wantErr)
			}
			if got["db.dump"] != tc.wantBytes {
				t.Errorf("got %q of the stream, want %q", got["db.dump"], tc.wantBytes)
			}
			// Which of the three shapes it was must be legible in the message, not only in
			// the sentinel: "open", "read" and "close" are different incidents.
			if !strings.Contains(err.Error(), tc.wantErrMsg) {
				t.Errorf("error %q does not say %q", err, tc.wantErrMsg)
			}
		})
	}
}

// The retry that actually matters, and the one the two-clean-opens test above cannot reach:
// the first attempt died with bytes already in hand, and the second must start over from
// byte zero rather than resume. A pipeline that keeps what the failed attempt gave it and
// appends the retry to it stores a duplicated prefix; one whose Part resumes at the offset
// it reached stores only the tail. Both checksum happily and both carry a manifest, which is
// the E6.10 shape of a backup that exists and cannot restore. The fake could not express
// "fails once, then succeeds" before this — truncatedPart fails identically forever — so the
// pipeline's whole recovery path had no driver.
func TestAPartRetriedAfterAFailedReadStartsOver(t *testing.T) {
	const whole = "PGDMP-one-two"
	b := Batch{Position: "0/1A2B000", Parts: []Part{flakyPart("db.dump", whole, errStreamDied)}}

	got, err := drain(b)
	if !errors.Is(err, errStreamDied) {
		t.Fatalf("the first attempt was meant to die mid-stream, got %v", err)
	}
	if got["db.dump"] == whole {
		t.Fatal("the first attempt returned the whole body — it never failed")
	}

	got, err = drain(b)
	if err != nil {
		t.Fatalf("the retry failed: %v", err)
	}
	// Not got[...] != "" and not a suffix check: the retry owes the pipeline the entire
	// stream, because the pipeline is going to overwrite the object with it.
	if got["db.dump"] != whole {
		t.Errorf("the retry yielded %q, want the whole %q — it resumed instead of starting over", got["db.dump"], whole)
	}
}

// A source with nothing new says so with a sentinel, not an empty Batch (§4). The pipeline
// will wrap that error with its own context before anyone reads it, so it has to survive
// the wrap.
func TestNoChangesIsIdentifiableThroughAWrap(t *testing.T) {
	src := &fakeSource{}

	_, err := src.Since(context.Background(), "0/1A2B000")
	if !errors.Is(err, ErrNoChanges) {
		t.Fatalf("Since with nothing new returned %v", err)
	}
	wrapped := fmt.Errorf("cycle at 09:00: %w", err)
	if !errors.Is(wrapped, ErrNoChanges) {
		t.Errorf("ErrNoChanges did not survive a wrap: %v", wrapped)
	}
}

// The pipeline stores a Position and hands it straight back. Nothing between the two ends
// looks inside it, which is what lets a snapshot id and a WAL LSN share one seam (§5).
func TestSinceIsHandedBackThePositionItIssued(t *testing.T) {
	var saw Position
	src := &fakeSource{since: func(from Position) (Batch, error) {
		saw = from
		// One part, not zero: a Batch handed back with a nil error always carries one.
		return Batch{Position: from + "-later", Parts: []Part{wholePart("changes.0001", "CDC")}}, nil
	}}

	b, err := src.Since(context.Background(), "file.000123:4096")
	if err != nil {
		t.Fatalf("Since failed: %v", err)
	}
	if saw != "file.000123:4096" {
		t.Errorf("the source was handed %q", saw)
	}
	if b.Position != "file.000123:4096-later" {
		t.Errorf("batch position %q", b.Position)
	}
}
