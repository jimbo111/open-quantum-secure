package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strings"
)

// maxCacheUploadBytes is the maximum allowed gzip payload for a cache upload (50 MB).
const maxCacheUploadBytes = 50 * 1024 * 1024

// UploadCache uploads a gzipped cache blob to the remote platform.
// The cache is scoped to (project, branch, engineVersionsHash).
//
// Returns an error if the payload exceeds 50 MB, authentication fails, or
// the server returns a non-2xx status.
func (c *Client) UploadCache(ctx context.Context, req CacheUploadRequest) (*CacheUploadResponse, error) {
	if req.Project == "" {
		return nil, errors.New("api: cache upload: project must not be empty")
	}
	if len(req.Data) > maxCacheUploadBytes {
		return nil, fmt.Errorf("api: cache upload: payload too large (%d bytes, max %d)", len(req.Data), maxCacheUploadBytes)
	}

	escapedProject := url.PathEscape(req.Project)
	path := fmt.Sprintf("/cache/%s", escapedProject)

	resp, err := c.doRaw(ctx, http.MethodPut, path, req.Data, func(r *http.Request) {
		r.Header.Set("Content-Type", "application/gzip")
		r.Header.Set("X-Engine-Versions-Hash", req.EngineVersionsHash)
		r.Header.Set("X-Branch", req.Branch)
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseError(resp)
	}

	var envelope apiResponse[CacheUploadResponse]
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("api: cache upload: decode response: %w", err)
	}
	return &envelope.Data, nil
}

// DownloadCache retrieves a gzipped cache blob from the remote platform.
// Returns the raw gzip bytes on success.
// Returns nil, nil when no cache is found (404).
func (c *Client) DownloadCache(ctx context.Context, req CacheDownloadRequest) ([]byte, error) {
	if req.Project == "" {
		return nil, errors.New("api: cache download: project must not be empty")
	}

	escapedProject := url.PathEscape(req.Project)
	q := url.Values{}
	q.Set("branch", req.Branch)
	q.Set("engineVersionsHash", req.EngineVersionsHash)
	path := fmt.Sprintf("/cache/%s?%s", escapedProject, q.Encode())

	resp, err := c.doRaw(ctx, http.MethodGet, path, nil, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseError(resp)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, maxCacheUploadBytes+1))
	if err != nil {
		return nil, fmt.Errorf("api: cache download: read body: %w", err)
	}
	if int64(len(data)) > maxCacheUploadBytes {
		return nil, fmt.Errorf("api: cache download: response exceeds %d byte limit", maxCacheUploadBytes)
	}
	return data, nil
}

// InvalidateCache deletes cached entries for a project.
// If branch is non-empty, only that branch's cache is deleted.
// Returns nil on success (including 204 No Content).
func (c *Client) InvalidateCache(ctx context.Context, project, branch string) error {
	if project == "" {
		return errors.New("api: cache invalidate: project must not be empty")
	}

	escapedProject := url.PathEscape(project)
	path := fmt.Sprintf("/cache/%s", escapedProject)

	if branch != "" {
		q := url.Values{}
		q.Set("branch", branch)
		path = path + "?" + q.Encode()
	}

	resp, err := c.doRaw(ctx, http.MethodDelete, path, nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent || (resp.StatusCode >= 200 && resp.StatusCode < 300) {
		return nil
	}
	return parseError(resp)
}

// doRaw executes an HTTP request with a raw (non-JSON) body. The mutate
// callback, if non-nil, is called after standard headers are applied so that
// callers can inject extra headers (e.g. Content-Type: application/gzip).
//
// The caller is responsible for closing resp.Body.
func (c *Client) doRaw(ctx context.Context, method, path string, body []byte, mutate func(*http.Request)) (*http.Response, error) {
	if !strings.HasPrefix(strings.ToLower(c.baseURL), "https://") {
		return nil, fmt.Errorf("api: endpoint must use HTTPS (got %q)", c.baseURL)
	}

	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}

	fullURL := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("api: create request: %w", err)
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

	// Caller-supplied header mutations applied last so they can override defaults.
	if mutate != nil {
		mutate(req)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("api: %s %s: %w", method, path, err)
	}
	return resp, nil
}
