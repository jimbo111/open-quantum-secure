package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"strings"
)

const apiPath = "/api/v1"

// Client is the REST client for the OQS platform.
type Client struct {
	baseURL    string
	httpClient *http.Client
	version    string
	tokenFn    func(ctx context.Context) (string, error)

	// optErr captures any error produced by a ClientOption during NewClient.
	// Options are void-returning (for ergonomic call sites) but some — like
	// WithCACert — can fail. NewClient inspects optErr after running all
	// options and reports the first failure.
	optErr error
}

// ClientOption is a functional option for Client configuration.
type ClientOption func(*Client)

// WithHTTPClient sets a custom http.Client (useful for testing or custom CA cert).
func WithHTTPClient(c *http.Client) ClientOption {
	return func(cl *Client) {
		cl.httpClient = c
	}
}

// WithCACert configures TLS to trust the given PEM certificate file.
// If certPath cannot be read or the file contains no PEM blocks, NewClient
// returns an error rather than silently falling back to the OS default roots
// — operators who typo a pinned-cert path should learn immediately, not at
// the first TLS handshake hours later.
func WithCACert(certPath string) ClientOption {
	return func(cl *Client) {
		if cl.optErr != nil {
			return
		}
		pem, err := os.ReadFile(certPath)
		if err != nil {
			cl.optErr = fmt.Errorf("api: read CA cert %q: %w", certPath, err)
			return
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			cl.optErr = fmt.Errorf("api: parse CA cert %q: no PEM blocks found", certPath)
			return
		}
		cl.httpClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: pool},
			},
		}
	}
}

// NewClient creates a new API client.
//
// endpoint: base URL like "https://api.oqs.dev" (without /api/v1).
// version: scanner version for the User-Agent header.
// tokenFn: function that returns the current access token (may return "" for anonymous).
// opts: optional ClientOption functions applied after defaults.
//
// Returns an error when any option fails (e.g. WithCACert on a bad PEM).
func NewClient(endpoint, version string, tokenFn func(ctx context.Context) (string, error), opts ...ClientOption) (*Client, error) {
	c := &Client{
		baseURL:    strings.TrimRight(endpoint, "/") + apiPath,
		version:    version,
		tokenFn:    tokenFn,
		httpClient: &http.Client{},
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.optErr != nil {
		return nil, c.optErr
	}
	return c, nil
}

// do executes an HTTP request with standard OQS headers and returns the response.
// The caller is responsible for closing resp.Body.
func (c *Client) do(ctx context.Context, method, path string, body interface{}) (*http.Response, error) {
	if !strings.HasPrefix(strings.ToLower(c.baseURL), "https://") {
		return nil, fmt.Errorf("api: endpoint must use HTTPS (got %q)", c.baseURL)
	}
	var bodyReader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("api: marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	url := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("api: create request: %w", err)
	}

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", fmt.Sprintf("oqs-scanner/%s (%s/%s)", c.version, runtime.GOOS, runtime.GOARCH))

	reqID, err := generateRequestID()
	if err != nil {
		return nil, fmt.Errorf("api: generate request ID: %w", err)
	}
	req.Header.Set("X-Request-ID", reqID)

	if c.tokenFn != nil {
		token, err := c.tokenFn(ctx)
		if err != nil {
			return nil, fmt.Errorf("api: resolve token: %w", err)
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("api: %s %s: %w", method, path, err)
	}
	return resp, nil
}

// generateRequestID generates a UUID v4 formatted as 8-4-4-4-12 hex using crypto/rand.
func generateRequestID() (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", err
	}
	// Set version 4 and variant bits per RFC 4122.
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%12x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
