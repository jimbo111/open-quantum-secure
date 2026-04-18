package ctlookup

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	defaultHTTPTimeout = 10 * time.Second
	defaultBaseURL     = "https://crt.sh"
	// maxBodyBytes caps the response body to prevent memory exhaustion from
	// unexpectedly large responses.
	maxBodyBytes = 4 << 20 // 4 MiB for JSON list, 1 MiB for DER cert
	maxDERBytes  = 1 << 20 // 1 MiB
	// maxCertsToFetch limits per-hostname DER fetches. Most hostnames have O(10)
	// active certs; fetching more than this provides diminishing value relative to
	// the additional HTTP round-trips against the shared rate limiter budget.
	maxCertsToFetch = 5
)

// crtShClient handles HTTP communication with the crt.sh CT log search API.
// It is not safe to modify baseURL or httpClient after Scan() has been called.
type crtShClient struct {
	httpClient *http.Client
	baseURL    string
}

func newCrtShClient(timeout time.Duration) *crtShClient {
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}
	return &crtShClient{
		httpClient: &http.Client{Timeout: timeout},
		baseURL:    defaultBaseURL,
	}
}

// queryHostname fetches the JSON entry list for hostname from crt.sh.
// Parameters: exclude=expired to omit stale certs; deduplicate=Y to collapse
// certs with the same serial across logs.
func (c *crtShClient) queryHostname(ctx context.Context, hostname string) ([]crtShEntry, error) {
	u, err := url.Parse(c.baseURL)
	if err != nil {
		return nil, fmt.Errorf("ctlookup: parse base URL: %w", err)
	}
	q := url.Values{}
	q.Set("q", hostname)
	q.Set("output", "json")
	q.Set("exclude", "expired")
	q.Set("deduplicate", "Y")
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("ctlookup: build request: %w", err)
	}
	req.Header.Set("User-Agent", "oqs-scanner/ct-lookup")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ctlookup: crt.sh query %s: %w", hostname, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ctlookup: crt.sh returned HTTP %d for %s", resp.StatusCode, hostname)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("ctlookup: read crt.sh response: %w", err)
	}
	return parseCrtShJSON(body)
}

// fetchCertDER downloads the DER-encoded certificate for the given crt.sh cert ID.
// The DER is returned as-is for parsing by crypto/x509.
func (c *crtShClient) fetchCertDER(ctx context.Context, certID int64) ([]byte, error) {
	u := fmt.Sprintf("%s/?d=%d", c.baseURL, certID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("ctlookup: build DER request: %w", err)
	}
	req.Header.Set("User-Agent", "oqs-scanner/ct-lookup")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ctlookup: fetch DER id=%d: %w", certID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ctlookup: cert DER fetch returned HTTP %d for id=%d", resp.StatusCode, certID)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDERBytes))
	if err != nil {
		return nil, fmt.Errorf("ctlookup: read DER id=%d: %w", certID, err)
	}
	return data, nil
}
