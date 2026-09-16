// Package store is where the pipeline's bytes land.
//
// ONE IMPLEMENTATION AND NO INTERFACE IN HERE (backup-shape.md §6: a second store waits for the
// first AWS source). The interfaces this satisfies are declared where they are CONSUMED — the
// pipeline's one-method Store in run.go, and pruning's one-method Container in prune.go — so this
// package ships a blob client and not a framework, and nothing in it points back at the pipeline.
//
// THEY ARE TWO INTERFACES AND NOT ONE OF THREE METHODS. Store writes and Container destroys, and
// keeping Delete off the interface a backup Cycle holds means no path through a backup can reach
// it. That is a property of the shape rather than of a code review.
//
// NO STORAGE SDK, for the reason container.go gives on the read side: blob is HTTP with a bearer
// token, and azblob would add a module to go.mod for one call. The agent ships as a `scratch`
// image and is meant to be auditable.
package store

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// storageAPIVersion pins the blob service version. Bearer-token authorization requires
// 2017-11-09 or later; pinned rather than latest because an unpinned call is a silent behaviour
// change whenever the service ships a version. The same value the read side pins to.
//
// https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-azure-active-directory
const storageAPIVersion = "2021-08-06"

// storageScope is the resource a data-plane token is issued for. An ARM token is not accepted
// here, which is why the credential is asked again rather than reused as a token.
const storageScope = "https://storage.azure.com/.default"

// Blob is the staging container, written to. One instance is one container.
type Blob struct {
	// url is https://<account>.blob.core.windows.net/<container>, checked at construction.
	url *url.URL

	tokens azcore.TokenCredential

	// http carries NO client-level timeout on purpose. A batch of changes is as large as the
	// changes were, and a deadline that fits a small one cuts a large one in half — which is
	// the shape of silent loss the pipeline's checks exist to catch. The context bounds it.
	http *http.Client
}

// NewBlob builds the store. The credential is the caller's — AD-035: nothing here creates one.
func NewBlob(cred azcore.TokenCredential, containerURL string) (*Blob, error) {
	parsed, err := url.Parse(strings.TrimRight(containerURL, "/"))
	if err != nil {
		// The URL is reported without its query. A container URL is normally a plain one, but
		// the SAS form carries sig= — and a credential in a log line is a credential leaked.
		return nil, fmt.Errorf("store: the container URL %q is not a URL: %w", redact(containerURL), err)
	}
	// HTTPS OR NOTHING. Every Put sends a storage OAuth token in an Authorization header, and
	// over http:// that token goes out in cleartext — a credential disclosure from a single
	// character of misconfiguration. Refused here, where it costs a start-up error, rather than
	// on the wire.
	if !strings.EqualFold(parsed.Scheme, "https") {
		return nil, fmt.Errorf("store: the container URL %q is not https, and every write to it "+
			"carries a storage token that would go out in cleartext", redact(containerURL))
	}
	// A URL naming only the account is the misconfiguration worth catching here rather than at
	// minute nine of a backup: every object would be written to the account root.
	if parsed.Host == "" || strings.Trim(parsed.Path, "/") == "" {
		return nil, fmt.Errorf("store: the container URL %q names no container; it must be "+
			"https://<account>.blob.core.windows.net/<container>", redact(containerURL))
	}
	return &Blob{url: parsed, tokens: cred, http: http.DefaultClient}, nil
}

// redact drops a URL's query, which is where a SAS puts its signature.
func redact(raw string) string {
	if cut := strings.IndexByte(raw, '?'); cut >= 0 {
		return raw[:cut] + "?<redacted>"
	}
	return raw
}

// Put writes one object.
//
//	PUT https://<account>.blob.core.windows.net/<container>/<path>
//	https://learn.microsoft.com/en-us/rest/api/storageservices/put-blob
//
// THE LENGTH IS ANNOUNCED AND NOT DISCOVERED. Azure Storage requires a Content-Length and does
// not accept a chunked transfer encoding, so a body of unknown length is refused outright — which
// is why this takes the chunk itself: NewRequest reads the length straight off a *bytes.Reader,
// including the zero-length case, where it substitutes http.NoBody rather than going chunked.
// Keeping the whole stream out of memory is the pipeline's job; this call sees one chunk of it.
func (b *Blob) Put(ctx context.Context, path string, chunk []byte) error {
	target, err := b.objectURL(path)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, target, bytes.NewReader(chunk))
	if err != nil {
		return fmt.Errorf("store: build the request for %q: %w", path, err)
	}
	request.Header.Set("x-ms-blob-type", "BlockBlob")
	request.Header.Set("Content-Type", "application/octet-stream")

	if err := b.authorize(ctx, request); err != nil {
		return fmt.Errorf("store: get a storage token to write %q: %w", path, err)
	}

	response, err := b.http.Do(request)
	if err != nil {
		return fmt.Errorf("store: write %q to the container: %w", path, err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusCreated {
		// Blob answers in XML and the message names the reason. Both the reasons that matter
		// are configuration, and both are unreadable if only the status code survives.
		//
		// KNOWN GAP: the status goes out inside the message, so nothing can match on it and a
		// 403 and a 429 get the same three immediate retries. Owned by pacing, and written down
		// rather than left in nobody's lap — backup-shape.md §6.
		detail, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		return fmt.Errorf("store: write %q to the container: HTTP %d: %s",
			path, response.StatusCode, strings.TrimSpace(string(detail)))
	}
	return nil
}

// objectURL is where one object lives, and IT REFUSES A NAME url.JoinPath WOULD REWRITE.
//
// JoinPath cleans "./" and "../" out of a path, collapses runs of "/" into one, and treats what it
// is given as already escaped. Azure blob names legally contain all three, so a name can address a
// DIFFERENT object than the one it spells: "a//b" reaches a/b, "x/../y" reaches y, "a%2Fb" reaches
// a/b, and "" reaches the container itself.
//
// PUT NEVER SEES SUCH A NAME AND DELETE DOES. Every path the pipeline writes came through
// checkPrefix (run.go); the paths pruning deletes come out of a container listing and from the base
// copy's cloud-chosen Part.Path (base.go, AD-033), and neither is validated anywhere. A delete that
// lands somewhere other than where the plan said is the one failure this cannot have — the plan a
// human approved would name one object and the request would remove another, with every check in
// prune.go having passed on the name that was approved.
//
// Checked by round trip rather than by a list of forbidden characters, because the rewriting is
// JoinPath's and only JoinPath knows all of it.
func (b *Blob) objectURL(path string) (string, error) {
	if path == "" {
		return "", errors.New("store: an empty object name addresses the container itself, not an " +
			"object in it")
	}
	target := b.url.JoinPath(path)
	if want := b.url.Path + "/" + path; target.Path != want {
		return "", fmt.Errorf("store: the object name %q cannot be addressed as written — it would "+
			"reach %q instead of %q, so a request for it would touch a different object",
			path, target.Path, want)
	}
	return target.String(), nil
}

// authorize puts the pinned service version and a storage token on a request. Every call to the
// data plane needs both, and one place to set them is one place to get them right.
func (b *Blob) authorize(ctx context.Context, request *http.Request) error {
	request.Header.Set("x-ms-version", storageAPIVersion)
	token, err := b.tokens.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{storageScope}})
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token.Token)
	return nil
}

// List is every object under a prefix, and when each was last written.
//
//	GET https://<account>.blob.core.windows.net/<container>?restype=container&comp=list&prefix=…
//	https://learn.microsoft.com/en-us/rest/api/storageservices/list-blobs
//
// THE PREFIX IS ANCHORED AT A SEPARATOR, and that is the dangerous half rather than a tidy-up.
// Azure matches `prefix` as raw text, so listing "install-7/pg1/orders" also returns everything
// under "install-7/pg1/orders-archive/" and "install-7/pg1/orders2/" — chains this prune was never
// handed, therefore unclaimed, therefore debris. A scope whose name happens to be another scope's
// prefix would delete it, with no operator mistake anywhere. So "/" is appended and the results are
// filtered against it.
//
// IT PAGES TO THE END OR IT FAILS. A short listing can only ever under-delete — the sweep iterates
// what came back — so the cost of a dropped page is an object nobody reclaims rather than one
// nobody meant to lose. It still fails rather than truncating, because a caller that cannot tell a
// complete listing from a partial one cannot reason about the container at all.
//
// A MAP BECAUSE A CONTAINER IS A SET. Blob names are unique, so nothing is lost by it — and the
// order a listing arrives in is not information anything here may act on, which a slice would
// invite somebody to believe it was.
func (b *Blob) List(ctx context.Context, prefix string) (map[string]time.Time, error) {
	if prefix == "" {
		return nil, errors.New("store: listing with no prefix returns the whole container, and " +
			"pruning reads \"no manifest names this object\" off a listing — so every other scope's " +
			"backups in it would read as this one's debris")
	}
	root := strings.TrimSuffix(prefix, "/") + "/"
	listed := map[string]time.Time{}

	marker := ""
	for {
		page, err := b.listPage(ctx, root, marker)
		if err != nil {
			return nil, err
		}
		for _, blob := range page.Blobs.Blob {
			// The service was asked for the anchored prefix; this is the belt to that braces, and
			// it costs one comparison per object to be sure nothing outside the scope is handed to
			// something that deletes what a listing does not account for.
			if !strings.HasPrefix(blob.Name, root) {
				return nil, fmt.Errorf("store: listing %q returned %s, which is not under it",
					root, blob.Name)
			}
			// http.ParseTime reads the RFC 1123 GMT stamp the service sends. AN UNREADABLE ONE IS
			// REFUSED RATHER THAN DEFAULTED: the zero time reads as older than any window, which
			// is exactly the value that sweeps an object a cycle is still writing.
			when, err := http.ParseTime(blob.Properties.LastModified)
			if err != nil {
				return nil, fmt.Errorf("store: %s was last written %q, which is not a time this "+
					"can read, so nothing can say whether it is a killed cycle's debris or a "+
					"cycle that is still writing: %w", blob.Name, blob.Properties.LastModified, err)
			}
			listed[blob.Name] = when.UTC()
		}
		if page.NextMarker == "" {
			return listed, nil
		}
		// A marker that does not advance is a service, or something between us and it, that would
		// spin this loop forever. A pruner that stops is better than an agent that never returns.
		if page.NextMarker == marker {
			return nil, fmt.Errorf("store: listing %q handed back the same continuation marker %q "+
				"twice, so this listing never ends", prefix, marker)
		}
		marker = page.NextMarker
	}
}

// enumeration is List Blobs' answer, cut down to the two things pruning reads.
type enumeration struct {
	XMLName xml.Name `xml:"EnumerationResults"`
	Blobs   struct {
		Blob []struct {
			Name       string `xml:"Name"`
			Properties struct {
				LastModified string `xml:"Last-Modified"`
			} `xml:"Properties"`
		} `xml:"Blob"`
	} `xml:"Blobs"`
	NextMarker string `xml:"NextMarker"`
}

// listPage fetches one page of the listing.
//
// It starts from the container URL's OWN query rather than an empty one, because a container in the
// SAS form carries its credential there — and a listing that dropped it would be the one call of
// the three that could not authenticate, on a URL NewBlob accepts.
func (b *Blob) listPage(ctx context.Context, prefix, marker string) (enumeration, error) {
	query := b.url.Query()
	query.Set("restype", "container")
	query.Set("comp", "list")
	query.Set("prefix", prefix)
	if marker != "" {
		query.Set("marker", marker)
	}

	target := *b.url
	target.RawQuery = query.Encode()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return enumeration{}, fmt.Errorf("store: build the listing request for %q: %w", prefix, err)
	}
	if err := b.authorize(ctx, request); err != nil {
		return enumeration{}, fmt.Errorf("store: get a storage token to list %q: %w", prefix, err)
	}

	response, err := b.http.Do(request)
	if err != nil {
		return enumeration{}, fmt.Errorf("store: list %q: %w", prefix, err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		return enumeration{}, fmt.Errorf("store: list %q: HTTP %d: %s",
			prefix, response.StatusCode, strings.TrimSpace(string(detail)))
	}

	var page enumeration
	if err := xml.NewDecoder(response.Body).Decode(&page); err != nil {
		return enumeration{}, fmt.Errorf("store: read the listing of %q: %w", prefix, err)
	}
	return page, nil
}

// maxGetBytes is the ceiling on what Get will pull into memory.
//
// GET IS FOR THE CLAIMS AND NEVER FOR THE BYTES. The only objects anything reads back through this
// client are manifest.json and rebase.json — a few kilobytes each — while the objects they NAME are
// a base copy, which is the largest thing this product ever touches. A Get with no ceiling is one
// OOM away from being pointed at database.sql by a path that came out of a listing, so the limit is
// here rather than in the discipline of every caller. Generous enough that a manifest over a
// thousand-part artifact still fits.
const maxGetBytes = 8 << 20

// Get reads one object back whole.
//
//	GET https://<account>.blob.core.windows.net/<container>/<path>
//	https://learn.microsoft.com/en-us/rest/api/storageservices/get-blob
//
// AN OBJECT THAT IS NOT THERE IS AN ERROR HERE, and that is the opposite of Delete's rule on
// purpose. Delete is told what the caller wants gone; Get is asked what the container HOLDS, and an
// answer of "nothing" invented for a manifest that a listing named a moment ago would assemble a
// chain with a segment silently missing from the middle of it — which is the one shape
// prune.go exists to keep out of a plan.
func (b *Blob) Get(ctx context.Context, path string) ([]byte, error) {
	// Through the same check Put and Delete use: a name a listing handed back is not a name this
	// package constructed, and reading the WRONG object is how a manifest gets attributed to a chain
	// it does not belong to.
	target, err := b.objectURL(path)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("store: build the read request for %q: %w", path, err)
	}
	if err := b.authorize(ctx, request); err != nil {
		return nil, fmt.Errorf("store: get a storage token to read %q: %w", path, err)
	}

	response, err := b.http.Do(request)
	if err != nil {
		return nil, fmt.Errorf("store: read %q from the container: %w", path, err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		detail, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		return nil, fmt.Errorf("store: read %q from the container: HTTP %d: %s",
			path, response.StatusCode, strings.TrimSpace(string(detail)))
	}

	// One byte over the ceiling is read so that a full buffer can be told from an object that
	// happens to be exactly the ceiling. A truncated manifest would parse — JSON or not — into
	// something, and the thing it parsed into would be believed.
	body, err := io.ReadAll(io.LimitReader(response.Body, maxGetBytes+1))
	if err != nil {
		return nil, fmt.Errorf("store: read %q from the container: %w", path, err)
	}
	if len(body) > maxGetBytes {
		return nil, fmt.Errorf("store: %q is larger than the %d bytes this reads back; only a "+
			"manifest is ever read whole, and an object this size is one of the ones a manifest "+
			"names", path, maxGetBytes)
	}
	return body, nil
}

// Exists says whether one object is in the container, WITHOUT READING IT.
//
//	HEAD https://<account>.blob.core.windows.net/<container>/<path>
//	https://learn.microsoft.com/en-us/rest/api/storageservices/get-blob-properties
//
// IT EXISTS FOR THE OBJECTS A SCOPED LISTING CANNOT COVER, which is a base copy's: Azure wrote them
// where it chose, outside the prefix the cycle's manifest lives under (AD-033). Widening the listing
// to reach them is not the answer — everything a listing covers becomes a candidate for pruning's
// debris sweep — and asking about ONE NAMED OBJECT is, because a question cannot delete anything.
// The full argument is at backup.Stored.Elsewhere, which is the field this answer lands on.
//
// A HEAD AND NOT A GET, because the objects this is asked about are the four largest in the system
// and the question is whether they are there, not what is in them.
//
// 404 IS AN ANSWER AND NOT A FAILURE. Anything else is a container that will not say, which is not
// the same as "it is gone" and must never be rounded to it.
//
// AN ARCHIVED BLOB ANSWERS 200 AND THIS CALL SAYS IT IS THERE — decided, not overlooked. A
// lifecycle rule moving a base copy to the archive tier is the ordinary case and the object is not
// lost by it: rehydration is hours, and the question this call is asked is whether the bytes exist,
// because the thing it protects is "do not delete the last chain anything could be restored from".
// A tier is a delay and a deletion is permanent. What this does NOT do is tell a caller that a
// restore from it would take hours, and the response carries x-ms-access-tier and
// x-ms-archive-status for whoever needs to.
func (b *Blob) Exists(ctx context.Context, path string) (bool, error) {
	target, err := b.objectURL(path)
	if err != nil {
		return false, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodHead, target, nil)
	if err != nil {
		return false, fmt.Errorf("store: build the properties request for %q: %w", path, err)
	}
	if err := b.authorize(ctx, request); err != nil {
		return false, fmt.Errorf("store: get a storage token to look for %q: %w", path, err)
	}

	response, err := b.http.Do(request)
	if err != nil {
		return false, fmt.Errorf("store: look for %q in the container: %w", path, err)
	}
	defer func() { _ = response.Body.Close() }()

	switch response.StatusCode {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		// A HEAD carries no body, so the status is all there is to report — and it is reported
		// rather than read as absence.
		return false, fmt.Errorf("store: look for %q in the container: HTTP %d",
			path, response.StatusCode)
	}
}

// Delete removes one object.
//
//	DELETE https://<account>.blob.core.windows.net/<container>/<path>
//	https://learn.microsoft.com/en-us/rest/api/storageservices/delete-blob
//
// AN OBJECT THAT IS ALREADY GONE IS SUCCESS. A prune stopped halfway is resumed by running it
// again, and the second run asks for objects the first one removed; a base copy's objects are
// named by a manifest rather than found in a listing, so one moved or removed by hand would
// otherwise stop the sweep for good. The caller wanted it not to be there, and it is not there.
//
// IT IS THE ONLY DESTRUCTIVE CALL IN THIS PACKAGE, and it is reached through backup.Container,
// which the pipeline does not hold — see prune.go.
func (b *Blob) Delete(ctx context.Context, path string) error {
	// The name is checked BEFORE it reaches the wire, and this is the call objectURL exists for.
	target, err := b.objectURL(path)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodDelete, target, nil)
	if err != nil {
		return fmt.Errorf("store: build the delete request for %q: %w", path, err)
	}
	if err := b.authorize(ctx, request); err != nil {
		return fmt.Errorf("store: get a storage token to delete %q: %w", path, err)
	}

	response, err := b.http.Do(request)
	if err != nil {
		return fmt.Errorf("store: delete %q from the container: %w", path, err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusAccepted && response.StatusCode != http.StatusNotFound {
		detail, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		return fmt.Errorf("store: delete %q from the container: HTTP %d: %s",
			path, response.StatusCode, strings.TrimSpace(string(detail)))
	}
	return nil
}
