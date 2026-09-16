package contract

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// sampleChanges is one of each operation, in the exact shapes AD-039 measured on live Azure —
// including the two that a replay written from intuition gets wrong.
func sampleChanges() []Change {
	text := func(s string) *string { return &s }

	return []Change{
		{
			Position: "0/1A2B000",
			Op:       ChangeInsert,
			Schema:   "sales",
			Table:    "customers",
			Key:      []string{"id"},
			Row: map[string]*string{
				"id":         text("999001"),
				"name":       text("c1 spike"),
				"email":      text("c1@spike.test"),
				"created_at": text("2026-01-01 00:00:00+00"),
			},
		},
		{
			// THE UPDATE WITH NO OLD TUPLE. Measured: an update that does not move the key
			// carries no old tuple at all, so the identity of the row is in Row, read through
			// Key. Nothing here holds a "before" and nothing may start to.
			Position: "0/1A2B0C8",
			Op:       ChangeUpdate,
			Schema:   "sales",
			Table:    "customers",
			Key:      []string{"id"},
			Row: map[string]*string{
				"id":         text("999001"),
				"name":       text("c1 spike updated"),
				"email":      text("c1@spike.test"),
				"created_at": text("2026-01-01 00:00:00+00"),
			},
		},
		{
			// THE DELETE THAT CARRIES THE KEY AND NOTHING ELSE. Measured: every column that is
			// not part of the key arrives NULL, and those NULLs are not values. Row therefore
			// holds the key columns alone — a producer that writes the NULLs anyway is still
			// read correctly, because Key is what a replay reads.
			Position: "0/1A2B190",
			Op:       ChangeDelete,
			Schema:   "sales",
			Table:    "customers",
			Key:      []string{"id"},
			Row:      map[string]*string{"id": text("999001")},
		},
		{
			// A composite key, and a NULL that IS a value: ops.notes holds one.
			Position: "0/1A2B200",
			Op:       ChangeUpdate,
			Schema:   "ops",
			Table:    "daily_totals",
			Key:      []string{"day", "customer_id"},
			Row: map[string]*string{
				"day":         text("2026-01-01"),
				"customer_id": text("7"),
				"order_count": nil,
			},
		},
		{
			// The update that MOVED the key, which is the one case that does carry a before.
			Position: "0/1A2B280",
			Op:       ChangeUpdate,
			Schema:   "ops",
			Table:    "daily_totals",
			Key:      []string{"day", "customer_id"},
			OldKey:   map[string]*string{"day": text("2026-01-01"), "customer_id": text("7")},
			Row: map[string]*string{
				"day":         text("2026-01-02"),
				"customer_id": text("7"),
				"order_count": text("3"),
			},
		},
	}
}

// The wire format has a golden file for the reason the manifest and the chain do: it is what one
// program writes and another reads months later, and a field renamed here is a change file nobody
// can replay.
func TestChangeGolden(t *testing.T) {
	got, err := json.MarshalIndent(sampleChanges(), "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got = append(got, '\n')

	path := filepath.Join("testdata", "change.golden.json")
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}

	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run: go test ./contract -update): %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("change wire format changed.\n got:\n%s\nwant:\n%s", got, want)
	}
}

// A NULL and an absent column are different facts and must survive a round trip as different
// facts. They mean different things to a replay — absent is "unchanged", NULL is "set it to
// NULL" — and a decoder that collapses them writes NULLs over a customer's data.
func TestNullIsNotAbsent(t *testing.T) {
	const line = `{"position":"0/1","op":"update","schema":"s","table":"t","key":["id"],` +
		`"row":{"id":"1","nulled":null}}`

	var c Change
	if err := json.Unmarshal([]byte(line), &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	value, present := c.Row["nulled"]
	if !present {
		t.Fatal("a column written as JSON null did not survive as a column at all; a replay would " +
			"leave the old value in place instead of nulling it")
	}
	if value != nil {
		t.Errorf("a column written as JSON null decoded as %q, not NULL", *value)
	}
	if _, present := c.Row["absent"]; present {
		t.Error("a column nobody wrote decoded as present")
	}
}
