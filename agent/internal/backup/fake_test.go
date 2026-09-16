package backup

import (
	"context"
	"io"
	"strings"
)

// The fake Source is the whole reason the seam has this shape (backup-shape.md §7). A
// pipeline test needs canned bytes, not a database: everything the real sources do that
// the pipeline must survive — a part that will not open, a part that dies halfway through
// the stream, a call with no changes behind it — is reproducible here with no Azure and no
// Postgres. Those are exactly the paths that are untestable against a real server, and so
// exactly the paths that would otherwise ship untested.
//
// It lives in package backup, not in a testdata helper, so the pipeline's own tests (B3)
// can drive it directly.

// Compile-time proof the fake satisfies the seam. If Source ever grows a method, this line
// fails before any test does.
var _ Source = (*fakeSource)(nil)

// fakeSource answers Base and Since from canned values. A nil since func means the source
// has nothing new, which is ErrNoChanges and not an empty Batch (§4).
type fakeSource struct {
	base Batch

	// baseFails is a source that cannot take a base copy at all — a control plane that would
	// not start the backup, a restore that never landed. B5 is the first caller of Base in the
	// repo, so until it there was no path here that could fail.
	baseFails error

	since func(from Position) (Batch, error)
}

func (f *fakeSource) Base(_ context.Context) (Batch, error) {
	if f.baseFails != nil {
		return Batch{}, f.baseFails
	}
	return f.base, nil
}

func (f *fakeSource) Since(_ context.Context, from Position) (Batch, error) {
	if f.since == nil {
		return Batch{}, ErrNoChanges
	}
	return f.since(from)
}

// wholePart streams cleanly, and does so again on every Open.
func wholePart(name, body string) Part {
	return Part{Name: name, Open: func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(body)), nil
	}}
}

// truncatedPart opens, yields prefix, and then fails. THIS IS THE SHAPE SILENT DATA LOSS
// TAKES: bytes arrived, the upload looked like it was working, and the copy is short. A
// pipeline that treats a read error as end-of-stream writes a manifest over a half object.
func truncatedPart(name, prefix string, failure error) Part {
	return Part{Name: name, Open: func() (io.ReadCloser, error) {
		return &truncatedReader{rest: []byte(prefix), err: failure}, nil
	}}
}

// unopenablePart never yields a byte. A different failure from truncatedPart's, and the
// pipeline needs both: nothing was written here, so there is nothing to clean up.
func unopenablePart(name string, failure error) Part {
	return Part{Name: name, Open: func() (io.ReadCloser, error) {
		return nil, failure
	}}
}

// flushFailsPart streams every byte, ends at a clean EOF, and fails on Close. THE FAILURE
// THAT LOOKS LIKE A SUCCESS: a real part is a process on a pipe or a body on a socket, and
// both report their verdict at Close — exit status, or a length that did not match. The read
// side saw nothing wrong, so a pipeline that ignores Close cannot tell this apart from a
// complete dump.
func flushFailsPart(name, body string, failure error) Part {
	return Part{Name: name, Open: func() (io.ReadCloser, error) {
		return &flushFailsReader{Reader: strings.NewReader(body), err: failure}, nil
	}}
}

// flakyPart dies mid-stream on the first Open and streams whole on every one after —
// a reset connection, a throttled read, the ordinary transient. truncatedPart fails forever
// and wholePart never fails, so neither can drive a pipeline PAST a failure into its
// recovery path; this is the only shape here where a retry has something to prove.
func flakyPart(name, body string, failure error) Part {
	opens := 0
	return Part{Name: name, Open: func() (io.ReadCloser, error) {
		opens++
		if opens == 1 {
			return &truncatedReader{rest: []byte(body[:len(body)/2]), err: failure}, nil
		}
		return io.NopCloser(strings.NewReader(body)), nil
	}}
}

type truncatedReader struct {
	rest []byte
	err  error
}

func (r *truncatedReader) Read(p []byte) (int, error) {
	if len(r.rest) == 0 {
		return 0, r.err
	}
	n := copy(p, r.rest)
	r.rest = r.rest[n:]
	return n, nil
}

func (r *truncatedReader) Close() error { return nil }

type flushFailsReader struct {
	io.Reader
	err error
}

func (r *flushFailsReader) Close() error { return r.err }
