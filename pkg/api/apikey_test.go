package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ---- CreateAPIKey tests ----

func TestCreateAPIKey(t *testing.T) {
	t.Run("success returns APIKeyCreateResponse", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/api/v1/auth/api-keys" {
				t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
			}
			writeJSON(w, 201, apiResponse[APIKeyCreateResponse]{
				Data: APIKeyCreateResponse{
					KeyPrefix: "oqs_k_Ab",
					RawKey:    "oqs_k_Ab1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab",
					Name:      "github-actions-prod",
					CreatedAt: "2026-03-09T00:00:00Z",
				},
			})
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", fixedToken("user-jwt-tok"))
		result, err := c.CreateAPIKey(context.Background(), "github-actions-prod")
		if err != nil {
			t.Fatal(err)
		}
		if result.KeyPrefix != "oqs_k_Ab" {
			t.Errorf("KeyPrefix: got %q", result.KeyPrefix)
		}
		if result.RawKey == "" {
			t.Error("RawKey: must not be empty")
		}
		if result.Name != "github-actions-prod" {
			t.Errorf("Name: got %q", result.Name)
		}
		if result.CreatedAt != "2026-03-09T00:00:00Z" {
			t.Errorf("CreatedAt: got %q", result.CreatedAt)
		}
	})

	t.Run("401 when not logged in", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Request-ID", "rid-401")
			writeJSON(w, 401, map[string]interface{}{
				"error": map[string]string{"code": "UNAUTHORIZED", "message": "authentication required"},
			})
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", noToken)
		_, err := c.CreateAPIKey(context.Background(), "my-key")
		if err == nil {
			t.Fatal("expected error for 401")
		}
		apiErr, ok := err.(*APIError)
		if !ok {
			t.Fatalf("expected *APIError, got %T: %v", err, err)
		}
		if apiErr.Code != "UNAUTHORIZED" {
			t.Errorf("code: got %q", apiErr.Code)
		}
		if apiErr.RequestID != "rid-401" {
			t.Errorf("requestID: got %q", apiErr.RequestID)
		}
	})

	t.Run("empty name returns client-side error", func(t *testing.T) {
		// No server needed — validation is client-side.
		c := NewClient("https://localhost", "1.0.0", noToken)
		_, err := c.CreateAPIKey(context.Background(), "")
		if err == nil {
			t.Fatal("expected error for empty name")
		}
	})

	t.Run("request body includes name field", func(t *testing.T) {
		var gotBody map[string]interface{}
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewDecoder(r.Body).Decode(&gotBody)
			writeJSON(w, 201, apiResponse[APIKeyCreateResponse]{
				Data: APIKeyCreateResponse{
					KeyPrefix: "oqs_k_Cd",
					RawKey:    "oqs_k_Cd0000000000000000000000000000000000000000000000000000000000cd",
					Name:      "ci-deploy",
					CreatedAt: "2026-03-09T01:00:00Z",
				},
			})
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", fixedToken("tok"))
		_, _ = c.CreateAPIKey(context.Background(), "ci-deploy")

		if gotBody["name"] != "ci-deploy" {
			t.Errorf("name in request body: got %v", gotBody["name"])
		}
	})
}

// ---- ListAPIKeys tests ----

func TestListAPIKeys(t *testing.T) {
	t.Run("success returns list of keys", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet || r.URL.Path != "/api/v1/auth/api-keys" {
				t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
			}
			writeJSON(w, 200, apiResponse[APIKeyListResponse]{
				Data: APIKeyListResponse{
					Keys: []APIKeyEntry{
						{
							KeyPrefix: "oqs_k_Ab",
							Name:      "github-actions-prod",
							LastUsed:  "2026-03-08T12:00:00Z",
							CreatedAt: "2026-01-01T00:00:00Z",
							Revoked:   false,
						},
						{
							KeyPrefix: "oqs_k_Cd",
							Name:      "ci-deploy",
							CreatedAt: "2026-02-01T00:00:00Z",
							Revoked:   false,
						},
					},
				},
			})
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", fixedToken("user-jwt-tok"))
		result, err := c.ListAPIKeys(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Keys) != 2 {
			t.Fatalf("keys count: got %d, want 2", len(result.Keys))
		}
		if result.Keys[0].KeyPrefix != "oqs_k_Ab" {
			t.Errorf("first key prefix: got %q", result.Keys[0].KeyPrefix)
		}
		if result.Keys[1].Name != "ci-deploy" {
			t.Errorf("second key name: got %q", result.Keys[1].Name)
		}
	})

	t.Run("empty list returns non-nil slice", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, apiResponse[APIKeyListResponse]{
				Data: APIKeyListResponse{Keys: nil},
			})
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", fixedToken("tok"))
		result, err := c.ListAPIKeys(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if result.Keys == nil {
			t.Error("Keys slice must not be nil for empty response")
		}
		if len(result.Keys) != 0 {
			t.Errorf("expected 0 keys, got %d", len(result.Keys))
		}
	})

	t.Run("revoked key status is preserved", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, apiResponse[APIKeyListResponse]{
				Data: APIKeyListResponse{
					Keys: []APIKeyEntry{
						{
							KeyPrefix: "oqs_k_Zz",
							Name:      "old-key",
							Revoked:   true,
							CreatedAt: "2025-01-01T00:00:00Z",
						},
					},
				},
			})
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", fixedToken("tok"))
		result, err := c.ListAPIKeys(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(result.Keys) != 1 {
			t.Fatalf("expected 1 key, got %d", len(result.Keys))
		}
		if !result.Keys[0].Revoked {
			t.Error("Revoked flag: expected true")
		}
	})

	t.Run("401 when not authenticated", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Request-ID", "rid-list-401")
			writeJSON(w, 401, map[string]interface{}{
				"error": map[string]string{"code": "UNAUTHORIZED", "message": "authentication required"},
			})
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", noToken)
		_, err := c.ListAPIKeys(context.Background())
		if err == nil {
			t.Fatal("expected error")
		}
		apiErr, ok := err.(*APIError)
		if !ok {
			t.Fatalf("expected *APIError, got %T", err)
		}
		if apiErr.Code != "UNAUTHORIZED" {
			t.Errorf("code: got %q", apiErr.Code)
		}
	})
}

// ---- RevokeAPIKey tests ----

func TestRevokeAPIKey(t *testing.T) {
	t.Run("success on 204 No Content", func(t *testing.T) {
		var capturedMethod, capturedPath string
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedMethod = r.Method
			capturedPath = r.URL.Path
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", fixedToken("user-jwt-tok"))
		err := c.RevokeAPIKey(context.Background(), "oqs_k_Ab")
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if capturedMethod != http.MethodDelete {
			t.Errorf("method: got %q, want DELETE", capturedMethod)
		}
		if capturedPath != "/api/v1/auth/api-keys/oqs_k_Ab" {
			t.Errorf("path: got %q", capturedPath)
		}
	})

	t.Run("success on 200 OK", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, 200, map[string]string{"status": "revoked"})
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", fixedToken("tok"))
		if err := c.RevokeAPIKey(context.Background(), "oqs_k_Ef"); err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
	})

	t.Run("404 returns error", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Request-ID", "rid-404")
			writeJSON(w, 404, map[string]interface{}{
				"error": map[string]string{"code": "NOT_FOUND", "message": "api key not found"},
			})
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", fixedToken("tok"))
		err := c.RevokeAPIKey(context.Background(), "oqs_k_Xx")
		if err == nil {
			t.Fatal("expected error for 404")
		}
		apiErr, ok := err.(*APIError)
		if !ok {
			t.Fatalf("expected *APIError, got %T: %v", err, err)
		}
		if apiErr.Code != "NOT_FOUND" {
			t.Errorf("code: got %q", apiErr.Code)
		}
		if apiErr.RequestID != "rid-404" {
			t.Errorf("requestID: got %q", apiErr.RequestID)
		}
	})

	t.Run("empty prefix returns client-side error", func(t *testing.T) {
		c := NewClient("https://localhost", "1.0.0", noToken)
		err := c.RevokeAPIKey(context.Background(), "")
		if err == nil {
			t.Fatal("expected error for empty prefix")
		}
	})

	t.Run("401 on unauthorized revoke", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Request-ID", "rid-revoke-401")
			writeJSON(w, 401, map[string]interface{}{
				"error": map[string]string{"code": "UNAUTHORIZED", "message": "not authenticated"},
			})
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", noToken)
		err := c.RevokeAPIKey(context.Background(), "oqs_k_Ab")
		if err == nil {
			t.Fatal("expected error")
		}
		apiErr, ok := err.(*APIError)
		if !ok {
			t.Fatalf("expected *APIError, got %T", err)
		}
		if apiErr.Code != "UNAUTHORIZED" {
			t.Errorf("code: got %q", apiErr.Code)
		}
	})

	t.Run("key prefix included in request path", func(t *testing.T) {
		var capturedPath string
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedPath = r.URL.Path
			w.WriteHeader(http.StatusNoContent)
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", fixedToken("tok"))
		_ = c.RevokeAPIKey(context.Background(), "oqs_k_MyPrefix")

		want := "/api/v1/auth/api-keys/oqs_k_MyPrefix"
		if capturedPath != want {
			t.Errorf("path: got %q, want %q", capturedPath, want)
		}
	})
}

// ---- Integration-style: API key as auth token ----

func TestAPIKeyAsAuthToken(t *testing.T) {
	t.Run("api key token passed as Bearer in Authorization header", func(t *testing.T) {
		var capturedAuth string
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			capturedAuth = r.Header.Get("Authorization")
			writeJSON(w, 200, apiResponse[APIKeyListResponse]{
				Data: APIKeyListResponse{Keys: []APIKeyEntry{}},
			})
		}))
		defer srv.Close()

		apiKey := "oqs_k_Ab1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab"
		c := newTestClient(srv, "1.0.0", fixedToken(apiKey))
		_, err := c.ListAPIKeys(context.Background())
		if err != nil {
			t.Fatal(err)
		}

		want := "Bearer " + apiKey
		if capturedAuth != want {
			t.Errorf("Authorization header: got %q, want %q", capturedAuth, want)
		}
	})

	t.Run("revoked key returns 401 on subsequent requests", func(t *testing.T) {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// First call: DELETE (revoke) succeeds.
			if r.Method == http.MethodDelete {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			// Subsequent GET: simulates the revoked key being rejected.
			w.Header().Set("X-Request-ID", "rid-revoked")
			writeJSON(w, 401, map[string]interface{}{
				"error": map[string]string{"code": "UNAUTHORIZED", "message": "api key has been revoked"},
			})
		}))
		defer srv.Close()

		c := newTestClient(srv, "1.0.0", fixedToken("oqs_k_Ab"))

		// Revoke the key.
		if err := c.RevokeAPIKey(context.Background(), "oqs_k_Ab"); err != nil {
			t.Fatalf("revoke failed: %v", err)
		}

		// Attempt to use the revoked key — server returns 401.
		_, err := c.ListAPIKeys(context.Background())
		if err == nil {
			t.Fatal("expected 401 error after revoke")
		}
		apiErr, ok := err.(*APIError)
		if !ok {
			t.Fatalf("expected *APIError, got %T", err)
		}
		if apiErr.Code != "UNAUTHORIZED" {
			t.Errorf("code after revoke: got %q", apiErr.Code)
		}
	})
}
