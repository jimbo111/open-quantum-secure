package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
)

// CreateAPIKey creates a new API key with the given human-readable name.
// The raw key is returned exactly once in the response and cannot be recovered.
// The caller must present a valid user authentication token.
func (c *Client) CreateAPIKey(ctx context.Context, name string) (*APIKeyCreateResponse, error) {
	if name == "" {
		return nil, errors.New("api: API key name must not be empty")
	}

	body := struct {
		Name string `json:"name"`
	}{Name: name}

	resp, err := c.doWithRetry(ctx, http.MethodPost, "/auth/api-keys", body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseError(resp)
	}

	var envelope apiResponse[APIKeyCreateResponse]
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("api: decode create-api-key response: %w", err)
	}
	return &envelope.Data, nil
}

// ListAPIKeys returns all API keys for the authenticated user.
// Keys are masked in the response — only the prefix and metadata are returned.
func (c *Client) ListAPIKeys(ctx context.Context) (*APIKeyListResponse, error) {
	resp, err := c.doWithRetry(ctx, http.MethodGet, "/auth/api-keys", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseError(resp)
	}

	var envelope apiResponse[APIKeyListResponse]
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("api: decode list-api-keys response: %w", err)
	}

	// Guarantee the slice is never nil so callers can range safely.
	if envelope.Data.Keys == nil {
		envelope.Data.Keys = []APIKeyEntry{}
	}
	return &envelope.Data, nil
}

// RevokeAPIKey revokes the API key identified by keyPrefix.
// The server returns 204 No Content on success.
func (c *Client) RevokeAPIKey(ctx context.Context, keyPrefix string) error {
	if keyPrefix == "" {
		return errors.New("api: key prefix must not be empty")
	}

	path := fmt.Sprintf("/auth/api-keys/%s", url.PathEscape(keyPrefix))
	resp, err := c.doWithRetry(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return parseError(resp)
	}
	return nil
}
