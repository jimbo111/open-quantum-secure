package auth

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
)

// apiKeyPrefix is the well-known prefix for OQS platform API keys.
// Tokens with this prefix are long-lived and must never be refreshed.
const apiKeyPrefix = "oqs_k_"

// RefreshFunc is a function that obtains a new credential using a refresh token.
// It is called when the stored credential is expired.
type RefreshFunc func(ctx context.Context, endpoint, refreshToken string) (*Credential, error)

// Resolver resolves an auth token from multiple sources in order of precedence.
type Resolver struct {
	// APIKeyFlag holds the value of the --api-key CLI flag (highest precedence).
	APIKeyFlag string

	// Store is the credential store to load saved credentials from.
	Store *Store

	// RefreshFn is called when the stored credential is expired. If nil,
	// expired credentials are treated as absent and anonymous is returned.
	RefreshFn RefreshFunc

	// refreshMu serializes token refresh calls to prevent thundering herd.
	refreshMu sync.Mutex
}

// Resolve returns an API token and the source it was resolved from.
//
// Precedence:
//  1. APIKeyFlag (--api-key CLI flag)  → source "flag"
//  2. OQS_API_KEY environment variable → source "env"
//  3. Stored credential (valid)        → source "credentials"
//  4. Stored credential (expired)      → attempt refresh via RefreshFn
//  5. Anonymous (no token)             → source "anonymous", nil error
func (r *Resolver) Resolve(ctx context.Context) (token, source string, err error) {
	// 1. CLI flag
	if r.APIKeyFlag != "" {
		return r.APIKeyFlag, "flag", nil
	}

	// 2. Environment variable
	if envKey := os.Getenv("OQS_API_KEY"); envKey != "" {
		return envKey, "env", nil
	}

	// 3. Stored credential
	if r.Store != nil {
		cred, loadErr := r.Store.Load()
		if loadErr == nil {
			// API keys are long-lived and never expire via OAuth refresh.
			// Skip the expiry check and refresh path for them entirely.
			if strings.HasPrefix(cred.AccessToken, apiKeyPrefix) {
				return cred.AccessToken, "credentials", nil
			}
			if !r.Store.IsExpired(cred) {
				return cred.AccessToken, "credentials", nil
			}
			// 4. Expired — attempt refresh with mutex to prevent thundering herd
			if r.RefreshFn != nil {
				r.refreshMu.Lock()
				defer r.refreshMu.Unlock()
				// Double-check: re-load in case another goroutine already refreshed.
				recheckCred, recheckErr := r.Store.Load()
				if recheckErr == nil && !r.Store.IsExpired(recheckCred) {
					return recheckCred.AccessToken, "credentials", nil
				}
				newCred, refreshErr := r.RefreshFn(ctx, cred.Endpoint, cred.RefreshToken)
				if refreshErr == nil && newCred != nil && newCred.AccessToken != "" {
					if saveErr := r.Store.Save(*newCred); saveErr != nil {
						// Log-worthy but not fatal — still return the new token.
						_ = saveErr
					}
					return newCred.AccessToken, "credentials", nil
				}
				// Refresh failed — fall through to anonymous.
			}
		} else if !errors.Is(loadErr, ErrNoCredentials) {
			// Unexpected read error (e.g., corrupt JSON, permission denied).
			return "", "", loadErr
		}
	}

	// 5. Anonymous — not an error.
	return "", "anonymous", nil
}
