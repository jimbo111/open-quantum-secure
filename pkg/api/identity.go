package api

import (
	"context"
	"encoding/json"
	"net/http"
)

// GetIdentity returns the authenticated user's profile from the OQS platform.
func (c *Client) GetIdentity(ctx context.Context) (*Identity, error) {
	resp, err := c.doWithRetry(ctx, http.MethodGet, "/auth/me", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseError(resp)
	}

	var envelope apiResponse[Identity]
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, err
	}
	return &envelope.Data, nil
}
