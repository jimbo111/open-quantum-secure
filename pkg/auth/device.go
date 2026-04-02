package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// validateEndpointHTTPS rejects non-HTTPS endpoints to prevent cleartext
// transmission of OAuth tokens.
func validateEndpointHTTPS(endpoint string) error {
	if !strings.HasPrefix(strings.ToLower(endpoint), "https://") {
		return fmt.Errorf("auth: endpoint must use HTTPS (got %q)", endpoint)
	}
	return nil
}

// DeviceCodeResponse is the response from POST /api/v1/auth/device.
type DeviceCodeResponse struct {
	DeviceCode      string `json:"device_code"`
	UserCode        string `json:"user_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       int    `json:"expires_in"`
	Interval        int    `json:"interval"`
}

// TokenResponse is the response from POST /api/v1/auth/token and /api/v1/auth/refresh.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// deviceErrorResponse represents an OAuth 2.0 error response body.
type deviceErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// Sentinel errors for poll outcomes.
var (
	ErrAccessDenied  = errors.New("auth: access denied by user")
	ErrExpiredToken  = errors.New("auth: device code has expired")
)

// DeviceAuth handles the OAuth 2.0 Device Authorization Grant (RFC 8628).
type DeviceAuth struct {
	// Endpoint is the base URL, e.g. "https://api.oqs.dev".
	Endpoint string

	// HTTPClient is used for all HTTP requests. If nil, http.DefaultClient is used.
	HTTPClient *http.Client
}

func (d *DeviceAuth) client() *http.Client {
	if d.HTTPClient != nil {
		return d.HTTPClient
	}
	return http.DefaultClient
}

// RequestDeviceCode initiates the device authorization flow.
// POST {endpoint}/api/v1/auth/device
func (d *DeviceAuth) RequestDeviceCode(ctx context.Context) (*DeviceCodeResponse, error) {
	if err := validateEndpointHTTPS(d.Endpoint); err != nil {
		return nil, err
	}
	payload := map[string]string{
		"client_id": "oqs-cli",
		"scope":     "scan:read scan:write org:read",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("auth: marshal device code request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		d.Endpoint+"/api/v1/auth/device", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("auth: create device code request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := d.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth: device code request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("auth: device code request: unexpected status %d", resp.StatusCode)
	}

	var dc DeviceCodeResponse
	if err := json.NewDecoder(resp.Body).Decode(&dc); err != nil {
		return nil, fmt.Errorf("auth: decode device code response: %w", err)
	}
	return &dc, nil
}

// PollForToken polls the token endpoint until the user authorizes the device,
// the device code expires, or the context is cancelled.
//
// It handles RFC 8628 error codes:
//   - "authorization_pending" → keep polling
//   - "slow_down"             → increase interval by 5 s
//   - "expired_token"         → return ErrExpiredToken
//   - "access_denied"         → return ErrAccessDenied
func (d *DeviceAuth) PollForToken(ctx context.Context, deviceCode string, interval int) (*TokenResponse, error) {
	if err := validateEndpointHTTPS(d.Endpoint); err != nil {
		return nil, err
	}
	if interval <= 0 {
		interval = 5
	}

	for {
		// Check context before sleeping to avoid unnecessary wait.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		timer := time.NewTimer(time.Duration(interval) * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}

		tok, oauthErr, err := d.postTokenRequest(ctx, map[string]string{
			"grant_type":  "urn:ietf:params:oauth:grant-type:device_code",
			"device_code": deviceCode,
			"client_id":   "oqs-cli",
		})
		if err != nil {
			return nil, err
		}
		if tok != nil {
			return tok, nil
		}

		// Handle OAuth error codes.
		switch oauthErr.Error {
		case "authorization_pending":
			// Continue polling.
		case "slow_down":
			interval += 5
		case "expired_token":
			return nil, ErrExpiredToken
		case "access_denied":
			return nil, ErrAccessDenied
		default:
			return nil, fmt.Errorf("auth: token poll error %q: %s", oauthErr.Error, oauthErr.ErrorDescription)
		}
	}
}

// RefreshToken exchanges a refresh token for a new access token.
// POST {endpoint}/api/v1/auth/refresh
func (d *DeviceAuth) RefreshToken(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	if err := validateEndpointHTTPS(d.Endpoint); err != nil {
		return nil, err
	}
	payload := map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
		"client_id":     "oqs-cli",
	}

	tok, oauthErr, err := d.postJSON(ctx, d.Endpoint+"/api/v1/auth/refresh", payload)
	if err != nil {
		return nil, fmt.Errorf("auth: refresh token: %w", err)
	}
	if oauthErr != nil {
		return nil, fmt.Errorf("auth: refresh token error %q: %s", oauthErr.Error, oauthErr.ErrorDescription)
	}
	return tok, nil
}

// RevokeToken invalidates both the access and refresh tokens.
// POST {endpoint}/api/v1/auth/revoke
func (d *DeviceAuth) RevokeToken(ctx context.Context, accessToken, refreshToken string) error {
	if err := validateEndpointHTTPS(d.Endpoint); err != nil {
		return err
	}
	payload := map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"client_id":     "oqs-cli",
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("auth: marshal revoke request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		d.Endpoint+"/api/v1/auth/revoke", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("auth: create revoke request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := d.client().Do(req)
	if err != nil {
		return fmt.Errorf("auth: revoke request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("auth: revoke request: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// postTokenRequest posts to /api/v1/auth/token. It returns either a TokenResponse
// (on success) or an oauthErr (on OAuth error responses that should be retried),
// or a hard error.
func (d *DeviceAuth) postTokenRequest(ctx context.Context, payload map[string]string) (*TokenResponse, *deviceErrorResponse, error) {
	tok, oauthErr, err := d.postJSON(ctx, d.Endpoint+"/api/v1/auth/token", payload)
	if err != nil {
		return nil, nil, fmt.Errorf("auth: token request: %w", err)
	}
	return tok, oauthErr, nil
}

// postJSON marshals payload, POSTs to url, and decodes the response.
// On HTTP 200, it decodes a TokenResponse.
// On HTTP 4xx with an OAuth error body, it returns a deviceErrorResponse.
// Any other status is a hard error.
func (d *DeviceAuth) postJSON(ctx context.Context, url string, payload map[string]string) (*TokenResponse, *deviceErrorResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := d.client().Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var tok TokenResponse
		if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
			return nil, nil, err
		}
		if tok.AccessToken == "" {
			return nil, nil, errors.New("auth: server returned empty access token")
		}
		return &tok, nil, nil
	}

	// Attempt to decode an OAuth error body.
	var oauthErr deviceErrorResponse
	if jsonErr := json.NewDecoder(resp.Body).Decode(&oauthErr); jsonErr == nil && oauthErr.Error != "" {
		return nil, &oauthErr, nil
	}

	return nil, nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
}
