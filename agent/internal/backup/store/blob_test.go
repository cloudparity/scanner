package store

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"

	"github.com/manukyanv07/parity-scanner/agent/internal/backup"
)

// Compile-time proof this is the shape the pipeline calls. The interface is declared where it is
// consumed (run.go), so nothing in the shipped store package points back at the pipeline — but a
// signature that drifted apart would otherwise be found by the first caller, which does not exist
// yet. In a test, so the dependency is the test's and not the binary's.
var _ backup.Store = (*Blob)(nil)

// And the shape pruning deletes through (prune.go). A second interface rather than a third method
// on the first: the pipeline's Store writes and this one destroys, and no path through a backup
// cycle can reach a method the interface it holds does not have.
var _ backup.Container = (*Blob)(nil)

// NO AZURE. The container is an httptest server that answers the documented Put Blob call, so
// the code under test is the code that ships and the only thing faked is the far end.

// staticToken stands in for azidentity. A credential and not a header, because that is the seam
// the real client authenticates through.
type staticToken struct{}

func (staticToken) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "test-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

type written struct {
	path             string
	body             string
	contentLength    int64
	transferEncoding string
	blobType         string
	version          string
	authorization    string
}

// fakeContainer answers Put Blob with 201 Created, or with whatever status a test asks for.
//
// TLS, because NewBlob refuses a plaintext container: every write carries a storage token, and
// a test over http:// could only pass if that refusal had been dropped.
func fakeContainer(t *testing.T, status int, detail string) (*Blob, *[]written) {
	t.Helper()
	var puts []written

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("the container was asked %s, want PUT", r.Method)
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read the uploaded body: %v", err)
		}
		puts = append(puts, written{
			path:             r.URL.Path,
			body:             string(body),
			contentLength:    r.ContentLength,
			transferEncoding: strings.Join(r.TransferEncoding, ","),
			blobType:         r.Header.Get("x-ms-blob-type"),
			version:          r.Header.Get("x-ms-version"),
			authorization:    r.Header.Get("Authorization"),
		})
		if status != http.StatusCreated {
			http.Error(w, detail, status)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	blob, err := NewBlob(staticToken{}, server.URL+"/staging")
	if err != nil {
		t.Fatalf("build the store: %v", err)
	}
	// The httptest certificate is not one the system trusts. Only the transport is swapped;
	// everything the code under test does with the request is its own.
	blob.http = server.Client()
	return blob, &puts
}

func TestPutWritesTheObjectWhereItWasAskedTo(t *testing.T) {
	blob, puts := fakeContainer(t, http.StatusCreated, "")
	const body = "CDC-one"

	err := blob.Put(context.Background(), "install-7/cycle-3/changes.0001.0000", []byte(body))
	if err != nil {
		t.Fatalf("Put failed: %v", err)
	}
	if len(*puts) != 1 {
		t.Fatalf("%d requests reached the container", len(*puts))
	}

	got := (*puts)[0]
	if got.path != "/staging/install-7/cycle-3/changes.0001.0000" {
		t.Errorf("the object was written to %q", got.path)
	}
	if got.body != body {
		t.Errorf("the container received %q, want %q", got.body, body)
	}
	// AZURE BLOB REQUIRES A LENGTH AND REFUSES A CHUNKED TRANSFER ENCODING. A request that
	// announces -1 is rejected by the real service, and the object never lands at all.
	if got.contentLength != int64(len(body)) {
		t.Errorf("Content-Length %d, want %d", got.contentLength, len(body))
	}
	if got.transferEncoding != "" {
		t.Errorf("Transfer-Encoding %q; Azure Storage refuses a chunked body outright", got.transferEncoding)
	}
	if got.blobType != "BlockBlob" {
		t.Errorf("x-ms-blob-type %q; Put Blob has no default", got.blobType)
	}
	if got.version != storageAPIVersion {
		t.Errorf("x-ms-version %q, want %q — bearer authorization needs one", got.version, storageAPIVersion)
	}
	if got.authorization == "" {
		t.Error("the object was written with no Authorization header")
	}
}

// The service answers in XML and the message names the reason —
// AuthorizationPermissionMismatch on a container we were not granted, ContainerNotFound on the
// wrong URL. Both are configuration, and both are unreadable if only the status survives.
func TestPutReportsWhatTheServiceSaidItRefusedFor(t *testing.T) {
	blob, _ := fakeContainer(t, http.StatusForbidden, "AuthorizationPermissionMismatch")

	err := blob.Put(context.Background(), "cycle/changes.0001.0000", []byte("CDC"))
	if err == nil {
		t.Fatal("a 403 was reported as a stored object")
	}
	if !strings.Contains(err.Error(), "AuthorizationPermissionMismatch") {
		t.Errorf("error %q does not carry the service's own reason", err)
	}
	if !strings.Contains(err.Error(), "cycle/changes.0001.0000") {
		t.Errorf("error %q does not name the object", err)
	}
}

// The misconfigurations worth catching at construction rather than at minute nine of a backup.
// The plaintext one is the serious member of the set: every write carries a storage OAuth
// token, so an http:// container puts that credential on the wire in the clear.
func TestTheContainerURLIsCheckedBeforeAnythingIsBackedUp(t *testing.T) {
	for _, bad := range []string{
		"",
		"https://acct.blob.core.windows.net",  // the account, with no container
		"https://acct.blob.core.windows.net/", // the same, trailing slash
		"http://acct.blob.core.windows.net/staging",
		"://not a url",
	} {
		t.Run(bad, func(t *testing.T) {
			if _, err := NewBlob(staticToken{}, bad); err == nil {
				t.Errorf("%q was accepted as a container", bad)
			}
		})
	}
}

// pagedContainer answers List Blobs across two pages and records what it was asked, so the
// marker loop is driven by the same continuation the real service sends.
func pagedContainer(t *testing.T, pages []string) (*Blob, *[]url.Values) {
	t.Helper()
	var asked []url.Values

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("the container was asked %s, want GET", r.Method)
		}
		query := r.URL.Query()
		asked = append(asked, query)

		page := 0
		if marker := query.Get("marker"); marker != "" {
			var err error
			page, err = strconv.Atoi(marker)
			if err != nil {
				t.Errorf("the client sent the marker %q", marker)
			}
		}
		if page >= len(pages) {
			t.Errorf("the client asked for page %d and there are %d", page, len(pages))
			return
		}
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, pages[page])
	}))
	t.Cleanup(server.Close)

	blob, err := NewBlob(staticToken{}, server.URL+"/staging")
	if err != nil {
		t.Fatalf("build the store: %v", err)
	}
	blob.http = server.Client()
	return blob, &asked
}

// listPage is one EnumerationResults, in the shape the service actually sends it.
func listPage(next string, blobs ...[2]string) string {
	var out strings.Builder
	out.WriteString(`<?xml version="1.0" encoding="utf-8"?><EnumerationResults><Blobs>`)
	for _, blob := range blobs {
		fmt.Fprintf(&out, `<Blob><Name>%s</Name><Properties><Last-Modified>%s</Last-Modified>`+
			`<Content-Length>8</Content-Length></Properties></Blob>`, blob[0], blob[1])
	}
	fmt.Fprintf(&out, `</Blobs><NextMarker>%s</NextMarker></EnumerationResults>`, next)
	return out.String()
}

// THE LISTING IS WHAT PRUNING READS "NO MANIFEST NAMES THIS OBJECT" OFF, so a page quietly
// dropped turns a live chain's objects into debris. It pages to the end or it fails.
func TestListPagesToTheEndOfTheContainer(t *testing.T) {
	blob, asked := pagedContainer(t, []string{
		listPage("1",
			[2]string{"install-7/pg1/orders/cycle-a/manifest.json", "Wed, 19 Aug 2026 09:00:00 GMT"},
			[2]string{"install-7/pg1/orders/cycle-a/changes.0000", "Wed, 19 Aug 2026 08:59:00 GMT"}),
		listPage("",
			[2]string{"install-7/pg1/orders/cycle-b/manifest.json", "Thu, 20 Aug 2026 09:00:00 GMT"}),
	})

	listed, err := blob.List(context.Background(), "install-7/pg1/orders")
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(listed) != 3 {
		t.Fatalf("%d objects listed, want 3 across two pages: %v", len(listed), listed)
	}
	when, held := listed["install-7/pg1/orders/cycle-a/changes.0000"]
	if !held {
		t.Fatalf("the first page's objects are missing: %v", listed)
	}
	// The age is the whole reason the modified time is carried: it is what tells a killed cycle's
	// debris from a cycle that is uploading right now.
	if want := time.Date(2026, 8, 19, 8, 59, 0, 0, time.UTC); !when.Equal(want) {
		t.Errorf("the object was last written %s, want %s", when, want)
	}

	if len(*asked) != 2 {
		t.Fatalf("%d requests reached the container, want one per page", len(*asked))
	}
	firstPage := (*asked)[0]
	if firstPage.Get("restype") != "container" || firstPage.Get("comp") != "list" {
		t.Errorf("the request was not a List Blobs: %v", firstPage)
	}
	// ANCHORED AT A SEPARATOR. Azure matches the prefix as raw text, so the unanchored form also
	// returns "install-7/pg1/orders-archive/..." — chains the pruner was never handed, which it
	// would therefore read as debris and delete.
	if firstPage.Get("prefix") != "install-7/pg1/orders/" {
		t.Errorf("the listing was not anchored at a separator: %q", firstPage.Get("prefix"))
	}
	if (*asked)[1].Get("marker") != "1" {
		t.Errorf("the second page was asked for with marker %q", (*asked)[1].Get("marker"))
	}
}

// A marker that does not advance is a service — or a proxy — that would spin this loop forever.
// Refused, because a pruner blocked is better than an agent that never returns.
func TestListRefusesAMarkerThatNeverAdvances(t *testing.T) {
	blob, _ := pagedContainer(t, []string{
		listPage("0", [2]string{"install-7/a", "Wed, 19 Aug 2026 09:00:00 GMT"}),
	})

	if _, err := blob.List(context.Background(), "install-7"); err == nil {
		t.Fatal("a listing that never ends was returned as a complete one")
	}
}

// A Last-Modified nothing can read is refused rather than defaulted. A zero time reads as "older
// than any window", which is the value that sweeps an object a cycle is still writing.
func TestListRefusesAnObjectWhoseAgeItCannotRead(t *testing.T) {
	blob, _ := pagedContainer(t, []string{
		listPage("", [2]string{"install-7/a", "the day before yesterday"}),
	})

	_, err := blob.List(context.Background(), "install-7")
	if err == nil {
		t.Fatal("an object with an unreadable Last-Modified was listed as arbitrarily old")
	}
	if !strings.Contains(err.Error(), "install-7/a") {
		t.Errorf("the error does not name the object: %v", err)
	}
}

// A listing with no prefix is the whole container, and pruning reads "no manifest names this
// object" off a listing — so every other scope's backups in it would read as this one's debris.
func TestListRefusesToReturnTheWholeContainer(t *testing.T) {
	blob, _ := pagedContainer(t, []string{listPage("")})

	if _, err := blob.List(context.Background(), ""); err == nil {
		t.Fatal("a listing with no prefix was allowed")
	}
}

// The belt to the anchored prefix's braces: an object the service hands back that is not under the
// prefix must not reach something that deletes what a listing does not account for.
func TestListRefusesAnObjectOutsideThePrefixItAskedFor(t *testing.T) {
	blob, _ := pagedContainer(t, []string{
		listPage("",
			[2]string{"install-7/pg1/orders/cycle-a/manifest.json", "Wed, 19 Aug 2026 09:00:00 GMT"},
			[2]string{"install-7/pg1/orders-archive/keep.0000", "Wed, 19 Aug 2026 09:00:00 GMT"}),
	})

	_, err := blob.List(context.Background(), "install-7/pg1/orders")
	if err == nil {
		t.Fatal("an object from a neighbouring scope was returned as part of this one")
	}
	if !strings.Contains(err.Error(), "orders-archive") {
		t.Errorf("the error does not name the object: %v", err)
	}
}

// A NAME THAT WOULD BE REWRITTEN IS REFUSED BEFORE IT REACHES THE WIRE. url.JoinPath collapses
// runs of "/", resolves "..", and treats its argument as already escaped — and Azure blob names
// legally contain all three. Put never sees such a name (checkPrefix stops it upstream); Delete
// gets its paths from a container listing and from the cloud's own Part.Path, so it does.
//
// The failure this prevents: the plan a human approved names one object and the request removes a
// different one, with every check in prune.go having passed on the name that was approved.
func TestAnObjectNameThatWouldAddressADifferentObjectIsRefused(t *testing.T) {
	for _, bad := range []string{
		"", // the container itself
		"install-7/pg1/orders//cycle-a/changes.0000", // collapses onto the live object
		"install-7/pg1/orders/../../elsewhere",       // resolves out of the container
		"install-7/pg1/orders/a%2Fb",                 // Azure decodes this to a/b
	} {
		t.Run(bad, func(t *testing.T) {
			var reached []string
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				reached = append(reached, r.URL.Path)
				w.WriteHeader(http.StatusAccepted)
			}))
			t.Cleanup(server.Close)

			blob, err := NewBlob(staticToken{}, server.URL+"/staging")
			if err != nil {
				t.Fatalf("build the store: %v", err)
			}
			blob.http = server.Client()

			if err := blob.Delete(context.Background(), bad); err == nil {
				t.Errorf("%q was deleted as written", bad)
			}
			if len(reached) != 0 {
				t.Errorf("the request went out anyway, to %v", reached)
			}
			// The same name must be refused on the way in, not only on the way out.
			if err := blob.Put(context.Background(), bad, []byte("x")); err == nil {
				t.Errorf("%q was written as given", bad)
			}
		})
	}
}

func TestDeleteRemovesTheObjectAndTreatsOneAlreadyGoneAsDone(t *testing.T) {
	for _, status := range []int{http.StatusAccepted, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var deleted []string
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodDelete {
					t.Errorf("the container was asked %s, want DELETE", r.Method)
				}
				if r.Header.Get("Authorization") == "" {
					t.Error("the object was deleted with no Authorization header")
				}
				if r.Header.Get("x-ms-version") != storageAPIVersion {
					t.Errorf("x-ms-version %q", r.Header.Get("x-ms-version"))
				}
				deleted = append(deleted, r.URL.Path)
				w.WriteHeader(status)
			}))
			t.Cleanup(server.Close)

			blob, err := NewBlob(staticToken{}, server.URL+"/staging")
			if err != nil {
				t.Fatalf("build the store: %v", err)
			}
			blob.http = server.Client()

			// AN OBJECT THAT IS ALREADY GONE IS SUCCESS. A prune stopped halfway is resumed by
			// running it again, and the second run asks for objects the first one removed.
			if err := blob.Delete(context.Background(), "install-7/cycle-a/changes.0000"); err != nil {
				t.Fatalf("Delete failed: %v", err)
			}
			if len(deleted) != 1 || deleted[0] != "/staging/install-7/cycle-a/changes.0000" {
				t.Errorf("the container was asked to delete %v", deleted)
			}
		})
	}
}

// The refusal that matters here is the one that means we were never granted the container. It is
// configuration, and it is unreadable if only the status survives.
func TestDeleteReportsWhatTheServiceSaidItRefusedFor(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "AuthorizationPermissionMismatch", http.StatusForbidden)
	}))
	t.Cleanup(server.Close)

	blob, err := NewBlob(staticToken{}, server.URL+"/staging")
	if err != nil {
		t.Fatalf("build the store: %v", err)
	}
	blob.http = server.Client()

	err = blob.Delete(context.Background(), "install-7/cycle-a/changes.0000")
	if err == nil {
		t.Fatal("a 403 was reported as a deleted object")
	}
	if !strings.Contains(err.Error(), "AuthorizationPermissionMismatch") {
		t.Errorf("error %q does not carry the service's own reason", err)
	}
}

// A container URL in the SAS form carries its signature in the query, and an error message is
// a log line. The one must not put the other where it can be read.
func TestAConstructionErrorDoesNotEchoASignature(t *testing.T) {
	_, err := NewBlob(staticToken{}, "http://acct.blob.core.windows.net/staging?sig=SECRETSIGNATURE")
	if err == nil {
		t.Fatal("a plaintext container was accepted")
	}
	if strings.Contains(err.Error(), "SECRETSIGNATURE") {
		t.Errorf("the error carries the signature: %v", err)
	}
}

// answering is a container that replies to one request however a test tells it to, and records
// what it was asked. Get and Exists are both single-request calls, so one fake serves both.
func answering(t *testing.T, status int, body string) (*Blob, *[]*http.Request) {
	t.Helper()
	var asked []*http.Request

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asked = append(asked, r.Clone(context.Background()))
		if r.Header.Get("Authorization") == "" {
			t.Error("the container was asked with no Authorization header")
		}
		if r.Header.Get("x-ms-version") != storageAPIVersion {
			t.Errorf("x-ms-version %q", r.Header.Get("x-ms-version"))
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(server.Close)

	blob, err := NewBlob(staticToken{}, server.URL+"/staging")
	if err != nil {
		t.Fatalf("build the store: %v", err)
	}
	blob.http = server.Client()
	return blob, &asked
}

// Reading a manifest back out of the container is what turns a listing into chains, and until this
// call existed nothing in the repo could do it — pgchain.go says so in as many words.
func TestGetReadsTheObjectBack(t *testing.T) {
	blob, asked := answering(t, http.StatusOK, `{"kind":"base"}`)

	body, err := blob.Get(context.Background(), "install-7/pg1/orders/cycle-a/manifest.json")
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}
	if string(body) != `{"kind":"base"}` {
		t.Errorf("read back %q", body)
	}
	if len(*asked) != 1 || (*asked)[0].Method != http.MethodGet {
		t.Fatalf("the container was asked %v", *asked)
	}
	if got := (*asked)[0].URL.Path; got != "/staging/install-7/pg1/orders/cycle-a/manifest.json" {
		t.Errorf("the request went to %q", got)
	}
}

// A MANIFEST A LISTING NAMED AND THE CONTAINER THEN DOES NOT HOLD IS AN ERROR, and it is the
// opposite of Delete's rule on purpose: an absent manifest read as "no segment" assembles a chain
// with a hole in the middle of it that every later check passes.
func TestGetRefusesAnObjectThatIsNotThere(t *testing.T) {
	blob, _ := answering(t, http.StatusNotFound, "BlobNotFound")

	_, err := blob.Get(context.Background(), "install-7/pg1/orders/cycle-a/manifest.json")
	if err == nil {
		t.Fatal("an object that is not there was read back as an empty one")
	}
	if !strings.Contains(err.Error(), "cycle-a/manifest.json") {
		t.Errorf("the error does not name the object: %v", err)
	}
}

// Get is for the claims and never for the bytes. Pointed at a base copy by a path out of a
// listing, an unbounded read is one OOM.
func TestGetRefusesAnObjectTooLargeToBeAClaim(t *testing.T) {
	blob, _ := answering(t, http.StatusOK, strings.Repeat("x", maxGetBytes+1))

	_, err := blob.Get(context.Background(), "database.sql")
	if err == nil {
		t.Fatal("an object past the ceiling was read whole into memory")
	}
	if !strings.Contains(err.Error(), "database.sql") {
		t.Errorf("the error does not name the object: %v", err)
	}
}

// THE CALL THAT VOUCHES FOR A BASE COPY. Its objects sit outside the scope a prune lists (AD-033),
// so the floor that says "never leave zero complete chains" cannot see them — and a HEAD is how one
// named object is asked about without widening the listing that bounds the sweep.
func TestExistsAsksForThePropertiesAndNotTheBytes(t *testing.T) {
	blob, asked := answering(t, http.StatusOK, "")

	found, err := blob.Exists(context.Background(), "database.sql")
	if err != nil {
		t.Fatalf("Exists failed: %v", err)
	}
	if !found {
		t.Error("an object the container holds was reported missing")
	}
	if len(*asked) != 1 || (*asked)[0].Method != http.MethodHead {
		t.Fatalf("the container was asked %v, want one HEAD", *asked)
	}
	if got := (*asked)[0].URL.Path; got != "/staging/database.sql" {
		t.Errorf("the request went to %q", got)
	}
}

func TestExistsReportsAnObjectThatIsGone(t *testing.T) {
	blob, _ := answering(t, http.StatusNotFound, "")

	found, err := blob.Exists(context.Background(), "database.sql")
	if err != nil {
		t.Fatalf("a 404 is an answer and not a failure: %v", err)
	}
	if found {
		t.Error("an object that is not there was reported present")
	}
}

// A CONTAINER THAT WILL NOT SAY IS NOT "IT IS GONE". Rounding a 403 to absence would report a base
// copy missing and refuse every retirement; rounding it to presence would license deleting every
// other chain on the strength of one nobody could see. It is neither: it is an error.
func TestExistsRefusesToReadAServiceFailureAsAnAnswer(t *testing.T) {
	blob, _ := answering(t, http.StatusForbidden, "")

	if _, err := blob.Exists(context.Background(), "database.sql"); err == nil {
		t.Fatal("a 403 was reported as an answer about whether the object is there")
	}
}

// The path check Put and Delete go through covers these two as well: a name out of a listing is not
// a name this package constructed, and reading the wrong object attributes a manifest to a chain it
// does not belong to.
func TestGetAndExistsRefuseANameThatWouldAddressADifferentObject(t *testing.T) {
	blob, asked := answering(t, http.StatusOK, "{}")

	if _, err := blob.Get(context.Background(), "install-7//cycle-a/manifest.json"); err == nil {
		t.Error("Get accepted a name that addresses a different object")
	}
	if _, err := blob.Exists(context.Background(), "install-7/../database.sql"); err == nil {
		t.Error("Exists accepted a name that addresses a different object")
	}
	if len(*asked) != 0 {
		t.Errorf("%d requests reached the container for names refused before the wire", len(*asked))
	}
}
