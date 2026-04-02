package api

import (
	"context"
	"encoding/json"
	"net/http"
)

// UploadCBOM uploads a CBOM to the OQS platform and returns the scan result.
// It uses retry logic for transient failures.
func (c *Client) UploadCBOM(ctx context.Context, req UploadRequest) (*UploadResponse, error) {
	resp, err := c.doWithRetry(ctx, http.MethodPost, "/scans", req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseError(resp)
	}

	var envelope apiResponse[UploadResponse]
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, err
	}
	return &envelope.Data, nil
}
