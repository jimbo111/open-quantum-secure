package ctlookup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	defaultHTTPTimeout = 10 * time.Second
	defaultBaseURL     = "https://crt.sh"
	// maxBodyBytes caps the JSON list response; maxDERBytes caps DER certificate
	// responses. Both prevent memory exhaustion from unexpectedly large responses.
	maxBodyBytes = 4 << 20 // 4 MiB for JSON list
	maxDERBytes  = 1 << 20 // 1 MiB for DER cert
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

func newCrtShClient(timeout time.Duration, baseURL string) *crtShClient {
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	parsed, _ := url.Parse(baseURL)
	baseHost := ""
	if parsed != nil {
		baseHost = parsed.Host
	}
	return &crtShClient{
		httpClient: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("ctlookup: too many redirects")
				}
				// Only follow same-host redirects (prevents SSRF via open redirects).
				if req.URL.Host != baseHost {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		baseURL: baseURL,
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

	resp, err := c.doWithRetry(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("ctlookup: crt.sh query for host %q: %w", hostname, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10)) //nolint:errcheck
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

	resp, err := c.doWithRetry(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("ctlookup: fetch DER id=%d: %w", certID, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10)) //nolint:errcheck
		return nil, fmt.Errorf("ctlookup: cert DER fetch returned HTTP %d for id=%d", resp.StatusCode, certID)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxDERBytes))
	if err != nil {
		return nil, fmt.Errorf("ctlookup: read DER id=%d: %w", certID, err)
	}
	return data, nil
}

// doWithRetry executes req and retries once on 429 or 5xx. The Retry-After
// header is respected (fallback 2s). Both attempts are bounded by ctx.
func (c *crtShClient) doWithRetry(ctx context.Context, req *http.Request) (*http.Response, error) {
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode < 500 {
		return resp, nil
	}

	wait := retryAfterDuration(resp)
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10)) //nolint:errcheck
	resp.Body.Close()

	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-t.C:
	}

	req2, err := http.NewRequestWithContext(ctx, req.Method, req.URL.String(), nil)
	if err != nil {
		return nil, err
	}
	req2.Header = req.Header.Clone()
	return c.httpClient.Do(req2)
}

// retryAfterDuration parses the Retry-After response header as seconds.
// Falls back to 2s when the header is absent or unparseable. An
// attacker-controlled Retry-After must not overflow or stall the scanner,
// so values beyond maxRetryAfter are clamped.
func retryAfterDuration(resp *http.Response) time.Duration {
	const maxRetryAfter = 1 * time.Hour
	if s := resp.Header.Get("Retry-After"); s != "" {
		var secs float64
		if _, err := fmt.Sscanf(s, "%f", &secs); err == nil && secs > 0 {
			// Clamp before multiplying — secs * 1e9 can overflow int64
			// (float→int conversion of an out-of-range value is
			// implementation-defined per Go spec; observed to saturate
			// to MaxInt64 on darwin and wrap to MinInt64 on linux).
			if secs >= maxRetryAfter.Seconds() {
				return maxRetryAfter
			}
			return time.Duration(secs * float64(time.Second))
		}
	}
	return 2 * time.Second
}
