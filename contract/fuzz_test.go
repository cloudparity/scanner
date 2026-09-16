package contract

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// FuzzEstateJSONRoundTrip pins the wire format against bytes nobody on this side wrote.
//
// The Estate is simultaneously the payload a collector sends, the row the engine stores and
// the response the API returns, so the same bytes are decoded by three parties who never
// see each other's code. What must hold for any input that decodes at all: encoding it
// again and decoding that yields the same bytes a third time (one pass is enough to reach
// the canonical form, and the canonical form is a fixed point); every Document comes back
// as valid JSON, because it is stored as JSONB and the store will refuse anything else;
// and none of it panics, because the decoder runs inside a request handler.
//
// Seeded from every golden file under testdata/, which is the corpus the JSON contract is
// already pinned by.
func FuzzEstateJSONRoundTrip(f *testing.F) {
	goldens, err := filepath.Glob(filepath.Join("testdata", "*.golden.json"))
	if err != nil {
		f.Fatalf("glob testdata: %v", err)
	}
	for _, path := range goldens {
		raw, err := os.ReadFile(path) //gosec:disable G304 -- a fixed glob over the package's own testdata
		if err != nil {
			f.Fatalf("read %s: %v", path, err)
		}
		f.Add(raw)
	}
	for _, seed := range []string{
		`{}`,
		`null`,
		`[]`,
		`{"contractVersion":1,"scan":{},"resources":[],"dependencies":[]}`,
		`{"contractVersion":1,"scan":{"provider":"azure","gaps":null},"resources":[{"document":null}],"dependencies":null}`,
		`{"resources":[{"id":"/a","document":{"nested":[1,2.5,"three",null,true,{"k":"<v>"}]},"tags":{"b":"2","a":"1"},"redactions":[{"path":"p","reason":"r"}]}]}`,
		`{"resources":[{"document":"a string is a JSON value too"}]}`,
		`{"resources":[{"document":1e400}]}`,
		`{"contractVersion":"1"}`,
		`{"scan":{"resourceCount":1.5}}`,
	} {
		f.Add([]byte(seed))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var first Estate
		if err := json.Unmarshal(data, &first); err != nil {
			// Rejected bytes are the decoder's business; the contract only speaks to bytes it
			// accepts.
			return
		}

		once, err := json.Marshal(first)
		if err != nil {
			t.Fatalf("an Estate that decoded could not be encoded: %v\n input: %s", err, data)
		}
		var second Estate
		if err := json.Unmarshal(once, &second); err != nil {
			t.Fatalf("the contract's own encoding does not decode: %v\n bytes: %s", err, once)
		}
		twice, err := json.Marshal(second)
		if err != nil {
			t.Fatalf("second encode failed: %v", err)
		}
		if !bytes.Equal(once, twice) {
			t.Errorf("encoding is not a fixed point after one pass:\n once:  %s\n twice: %s", once, twice)
		}

		for i, r := range second.Resources {
			if len(r.Document) > 0 && !json.Valid(r.Document) {
				t.Errorf("resources[%d].document came back as invalid JSON: %s", i, r.Document)
			}
		}
	})
}
