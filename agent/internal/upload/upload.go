// Package upload sends a finished estate to the Parity API.
//
// Kept out of the collectors on purpose: they read a customer's cloud and know nothing about us. This
// is the one place in the agent that talks to Parity, so "what does this binary send, and where" has
// a single answer someone can audit.
//
// Dependency-clean like the rest of agent/: standard library only, plus the shared contract. The
// agent is the half of this repo intended to be readable by a customer's security team, and a
// dependency tree is a thing they have to read too.
package upload

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/manukyanv07/parity-scanner/contract"
)

// KeyHeader must match internal/auth.KeyHeader in parity-lambdas.
const KeyHeader = "x-parity-api-key"

// Client posts estates to one API.
type Client struct {
	BaseURL string
	APIKey  string
	HTTP    *http.Client
}

// New builds a client with a timeout appropriate to a multi-megabyte upload over a customer's
// egress, which may be slow, metered, or behind a proxy.
func New(baseURL, apiKey string) (*Client, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	switch {
	case baseURL == "":
		return nil, errors.New("upload: no api url")
	case !strings.HasPrefix(baseURL, "https://"):
		// Refused rather than warned about. This request carries a credential and a complete map of
		// the customer's infrastructure; sending either over plaintext is not a thing to allow with a
		// note in the log. Localhost included - a developer testing against http should have to say so
		// by changing this line, and notice that they did.
		return nil, fmt.Errorf("upload: the api url must be https, got %q", baseURL)
	case strings.TrimSpace(apiKey) == "":
		return nil, errors.New("upload: no api key")
	}
	return &Client{
		BaseURL: baseURL,
		APIKey:  apiKey,
		HTTP:    &http.Client{Timeout: 2 * time.Minute},
	}, nil
}

// Result is what the API said about an accepted scan.
type Result struct {
	ScanID        string `json:"scanId"`
	ResourceCount int    `json:"resourceCount"`
}

// problem is the API's shape for a refusal. Its `problems` list names the exact field at fault, which
// is the difference between "the upload failed" and a message someone can act on.
type problem struct {
	Error    string `json:"error"`
	Problems []struct {
		Path    string `json:"path"`
		Message string `json:"message"`
	} `json:"problems"`
}

// Send posts one estate.
func (c *Client) Send(ctx context.Context, e *contract.Estate) (Result, error) {
	body, err := json.Marshal(e)
	if err != nil {
		return Result{}, fmt.Errorf("upload: encode estate: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/scans", bytes.NewReader(body))
	if err != nil {
		return Result{}, fmt.Errorf("upload: %w", err)
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set(KeyHeader, c.APIKey)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		// The URL can appear in an error; the key never can, because it only ever lives in a header.
		return Result{}, fmt.Errorf("upload: %w", err)
	}
	// Close's error is dropped here and below: the body is read to its bound first, and a failure
	// to release the connection afterwards is not a failed upload.
	defer func() { _ = resp.Body.Close() }()

	// Bounded: a proxy or a captive portal can answer with a page of HTML, and that should not become
	// a megabyte of error message in a customer's log.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return Result{}, fmt.Errorf("upload: reading the response: %w", err)
	}

	switch resp.StatusCode {
	case http.StatusCreated:
		var out Result
		if err := json.Unmarshal(raw, &out); err != nil {
			return Result{}, fmt.Errorf("upload: the api accepted the scan but its reply was unreadable: %w", err)
		}
		return out, nil

	case http.StatusUnauthorized:
		// The single most likely failure in the field, and the one worth naming precisely rather than
		// printing a status code at somebody.
		return Result{}, errors.New("upload: the api key was refused - check it is the whole key, " +
			"that it has not been revoked, and that it belongs to this account")

	case http.StatusRequestEntityTooLarge:
		return Result{}, fmt.Errorf("upload: the estate is too large for the api (%d resources)", e.Scan.ResourceCount)

	case http.StatusBadRequest:
		return Result{}, rejected("estate", raw)

	default:
		return Result{}, fmt.Errorf("upload: the api returned %d: %s", resp.StatusCode, snippet(raw))
	}
}

// rejected turns a 400 into a message with the fix in it.
//
// Shared by both payloads because a validator's refusal reads the same either way: a caller who
// sees "400" has nothing, and one who sees "resources[3].type: required" has the change to make.
// Bounded at five, because a payload with forty faults is one mistake and forty lines of it is a
// log nobody reads.
func rejected(what string, raw []byte) error {
	var p problem
	if json.Unmarshal(raw, &p) == nil && len(p.Problems) > 0 {
		var b strings.Builder
		fmt.Fprintf(&b, "upload: the api rejected the %s: %s", what, p.Error)
		for i, item := range p.Problems {
			if i == 5 {
				fmt.Fprintf(&b, "\n  ... and %d more", len(p.Problems)-5)
				break
			}
			fmt.Fprintf(&b, "\n  %s: %s", item.Path, item.Message)
		}
		return errors.New(b.String())
	}
	return fmt.Errorf("upload: the api rejected the %s: %s", what, snippet(raw))
}

// SendCycle posts one backup cycle's report.
//
// IT RETURNS NOTHING BUT AN ERROR, and that is the contract. A send failure is not a lost backup:
// the bytes are in the store and the manifest is beside them long before this is called, so a 404
// costs a row on a dashboard and nothing else. The caller logs it, keeps its LSN acknowledgement,
// and the next cycle's report carries the same read point forward. NOTHING HERE MAY FAIL A BACKUP
// CYCLE — which also means it must always come back, so every refusal is an error rather than a
// retry loop inside a method the cycle is waiting on.
//
// /v1/backups is unbuilt today and /v1/scans is not deployed, so a 404 is the expected answer in
// the field right now and is treated as exactly what it is: a send that did not land.
func (c *Client) SendCycle(ctx context.Context, r *contract.CycleReport) error {
	body, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("upload: encode the cycle report: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/v1/backups", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("upload: the cycle report: %w", err)
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set(KeyHeader, c.APIKey)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		// A timeout, a refused connection, a DNS failure. The URL can appear in an error; the key
		// never can, because it only ever lives in a header.
		return fmt.Errorf("upload: the cycle report was not sent: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return fmt.Errorf("upload: reading the response to the cycle report: %w", err)
	}

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		// ANY 2xx, and not 201 alone. The ingest for this does not exist yet; whether it answers
		// with the row it created or queues and says 202 is not settled, and an agent that treats
		// one of those as a failure would report a healthy chain as broken.
		return nil

	case resp.StatusCode == http.StatusUnauthorized:
		return errors.New("upload: the api key was refused for the cycle report - check it is the " +
			"whole key, that it has not been revoked, and that it belongs to this account")

	case resp.StatusCode == http.StatusBadRequest:
		return rejected("cycle report", raw)

	default:
		return fmt.Errorf("upload: the cycle report was not accepted, the api returned %d: %s",
			resp.StatusCode, snippet(raw))
	}
}

// snippet keeps an unexpected response readable in a log.
func snippet(raw []byte) string {
	const limit = 200
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return "(no body)"
	}
	if len(s) > limit {
		return s[:limit] + "…"
	}
	return s
}
