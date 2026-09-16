package postgres

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

// container is OUR staging container, read back.
//
// WHY THE AGENT READS A CONTAINER AT ALL. Azure moved the bytes (AD-033): a restore-as-files
// writes the base copy into a container we name, and nothing streamed through this process. The
// parts a batch is made of therefore have to be READ rather than produced, and this is the whole
// of the data-plane surface that needs — one list and one get, on one container.
//
// NO STORAGE SDK. Blob is HTTP with a bearer token and an XML body; azblob would add a module to
// go.mod for two calls. The Azure and Kubernetes collectors read their APIs the same way and the
// latter says why in full.
type container struct {
	// url is https://<account>.blob.core.windows.net/<container>, checked at construction.
	url *url.URL

	// tokens is the same credential the ARM side holds, asked for a different scope.
	tokens azcore.TokenCredential

	// http carries NO client-level timeout on purpose. A base copy is as large as the customer's
	// database, and a deadline that fits a listing would cut a download of it in half — which is
	// the shape of silent loss the pipeline's Close check exists to catch. The context bounds it.
	http *http.Client
}

// storageAPIVersion pins the blob service version. Bearer-token authorization requires a version
// of 2017-11-09 or later, and 2019-12-12 or later to get the bearer challenge on a bad token;
// pinned rather than latest for the same reason every ARM call here is.
//
// https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-azure-active-directory
const storageAPIVersion = "2021-08-06"

// storageScope is the resource a data-plane token is issued for. The ARM token is NOT accepted
// here and vice versa, which is why the credential is asked twice.
const storageScope = "https://storage.azure.com/.default"

// blobEntry is one object the restore wrote.
type blobEntry struct {
	Name  string
	Bytes int64
}

// list walks every page of the container under one prefix.
//
//	GET https://<account>.blob.core.windows.net/<container>?restype=container&comp=list&prefix=
//	https://learn.microsoft.com/en-us/rest/api/storageservices/list-blobs
//
// EVERY PAGE, and the loop is not defensive decoration. A listing that stops at the first page
// returns a batch with a file missing, and a missing file is not visible anywhere downstream: the
// parts that did arrive checksum and manifest exactly like a whole copy.
func (c *container) list(ctx context.Context, prefix string) ([]blobEntry, error) {
	var found []blobEntry
	marker := ""

	for page := 0; page < pagesBudget; page++ {
		query := url.Values{}
		query.Set("restype", "container")
		query.Set("comp", "list")
		query.Set("prefix", prefix)
		if marker != "" {
			query.Set("marker", marker)
		}
		listing := *c.url
		listing.RawQuery = query.Encode()

		response, err := c.do(ctx, listing.String())
		if err != nil {
			return nil, fmt.Errorf("postgres: list the restored files under %q: %w", prefix, err)
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("postgres: read the listing of %q: %w", prefix, err)
		}

		var results struct {
			XMLName xml.Name `xml:"EnumerationResults"`
			Blobs   struct {
				Blob []struct {
					Name       string `xml:"Name"`
					Properties struct {
						ContentLength int64 `xml:"Content-Length"`
					} `xml:"Properties"`
				} `xml:"Blob"`
			} `xml:"Blobs"`
			NextMarker string `xml:"NextMarker"`
		}
		if err := xml.Unmarshal(body, &results); err != nil {
			return nil, fmt.Errorf("postgres: the listing of %q did not parse: %w", prefix, err)
		}
		for _, blob := range results.Blobs.Blob {
			found = append(found, blobEntry{Name: blob.Name, Bytes: blob.Properties.ContentLength})
		}
		if results.NextMarker == "" {
			return found, nil
		}
		marker = results.NextMarker
	}
	return nil, fmt.Errorf("postgres: listing %q exceeded %d pages, which means the container kept "+
		"returning a continuation", prefix, pagesBudget)
}

// open starts a read of one object. The caller closes it.
//
//	GET https://<account>.blob.core.windows.net/<container>/<blob>
//	https://learn.microsoft.com/en-us/rest/api/storageservices/get-blob
func (c *container) open(ctx context.Context, name string) (io.ReadCloser, error) {
	// JoinPath escapes the element, so a blob name with a space or a percent in it addresses the
	// object rather than a URL we made up.
	response, err := c.do(ctx, c.url.JoinPath(name).String())
	if err != nil {
		return nil, fmt.Errorf("postgres: read %q back from the container: %w", name, err)
	}
	return response.Body, nil
}

// do sends one authorized request and hands back a response whose body is the caller's to close.
func (c *container) do(ctx context.Context, absolute string) (*http.Response, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, absolute, nil)
	if err != nil {
		return nil, err
	}
	token, err := c.tokens.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{storageScope}})
	if err != nil {
		return nil, fmt.Errorf("get a storage token: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+token.Token)
	request.Header.Set("x-ms-version", storageAPIVersion)

	response, err := c.http.Do(request)
	if err != nil {
		return nil, err
	}
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusPartialContent {
		// Blob answers in XML and the message names the reason — AuthorizationPermissionMismatch
		// on a container we were not granted, ContainerNotFound on the wrong URL. Both are
		// configuration, and both are unreadable if only the status code survives.
		detail, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		_ = response.Body.Close()
		return nil, fmt.Errorf("HTTP %d from the container: %s",
			response.StatusCode, strings.TrimSpace(string(detail)))
	}
	return response, nil
}
