package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// ListScans retrieves paginated scan history for a project.
//
// project: the project name (may contain slashes; will be URL-encoded).
// limit: maximum number of entries to return (0 uses server default).
func (c *Client) ListScans(ctx context.Context, project string, limit int) (*ScanListResponse, error) {
	if project == "" {
		return nil, errors.New("api: project name must not be empty")
	}

	// URL-encode project — it may contain slashes.
	escapedProject := url.PathEscape(project)
	path := fmt.Sprintf("/projects/%s/scans", escapedProject)

	if limit > 0 {
		q := url.Values{}
		q.Set("limit", fmt.Sprintf("%d", limit))
		path = path + "?" + q.Encode()
	}

	resp, err := c.doWithRetry(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseError(resp)
	}

	var envelope apiResponse[ScanListResponse]
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, err
	}
	return &envelope.Data, nil
}
