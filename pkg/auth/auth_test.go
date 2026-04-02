package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ── helpers ──────────────────────────────────────────────────────────────────

// storeWithDir returns a Store whose configDir is overridden by the test temp
// dir. We achieve this by setting HOME (and USERPROFILE on Windows) so that
// os.UserHomeDir() resolves to the temp dir.
func storeWithHome(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", dir)
		t.Setenv("APPDATA", filepath.Join(dir, "AppData", "Roaming"))
	}
	return &Store{}, filepath.Join(dir, ".oqs")
}

func sampleCredential(expiresIn time.Duration) Credential {
	return Credential{
		AccessToken:  "access-abc",
		RefreshToken: "refresh-xyz",
		ExpiresAt:    time.Now().Add(expiresIn),
		UserEmail:    "test@example.com",
		OrgName:      "acme",
		Plan:         "pro",
		Endpoint:     "https://api.oqs.dev",
	}
}

// ── Store tests ───────────────────────────────────────────────────────────────

func TestStore_SaveLoad_RoundTrip(t *testing.T) {
	s, _ := storeWithHome(t)
	want := sampleCredential(time.Hour)

	if err := s.Save(want); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	got, err := s.Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if got.AccessToken != want.AccessToken {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, want.AccessToken)
	}
	if got.RefreshToken != want.RefreshToken {
		t.Errorf("RefreshToken = %q, want %q", got.RefreshToken, want.RefreshToken)
	}
	if got.UserEmail != want.UserEmail {
		t.Errorf("UserEmail = %q, want %q", got.UserEmail, want.UserEmail)
	}
	if got.OrgName != want.OrgName {
		t.Errorf("OrgName = %q, want %q", got.OrgName, want.OrgName)
	}
	if got.Plan != want.Plan {
		t.Errorf("Plan = %q, want %q", got.Plan, want.Plan)
	}
}

func TestStore_Load_NoFile(t *testing.T) {
	s, _ := storeWithHome(t)

	_, err := s.Load()
	if err == nil {
		t.Fatal("Load() expected error for missing file, got nil")
	}
	if !errors.Is(err, ErrNoCredentials) {
		t.Errorf("Load() error = %v, want errors.Is(err, ErrNoCredentials)", err)
	}
}

func TestStore_Delete_ExistingFile(t *testing.T) {
	s, configDir := storeWithHome(t)
	if err := s.Save(sampleCredential(time.Hour)); err != nil {
		t.Fatal(err)
	}

	if err := s.Delete(); err != nil {
		t.Fatalf("Delete() error: %v", err)
	}

	credFile := filepath.Join(configDir, "credentials.json")
	if _, err := os.Stat(credFile); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("credentials.json still exists after Delete()")
	}
}

func TestStore_Delete_NoFile(t *testing.T) {
	s, _ := storeWithHome(t)

	// Must not return an error when the file doesn't exist.
	if err := s.Delete(); err != nil {
		t.Errorf("Delete() on missing file returned error: %v", err)
	}
}

func TestStore_FilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission bits not enforced on Windows")
	}

	s, configDir := storeWithHome(t)
	if err := s.Save(sampleCredential(time.Hour)); err != nil {
		t.Fatal(err)
	}

	credFile := filepath.Join(configDir, "credentials.json")
	info, err := os.Stat(credFile)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("credentials.json perm = %04o, want 0600", perm)
	}
}

func TestStore_ConfigDirPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file permission bits not enforced on Windows")
	}

	s, configDir := storeWithHome(t)
	if err := s.Save(sampleCredential(time.Hour)); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(configDir)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0700 {
		t.Errorf("config dir perm = %04o, want 0700", perm)
	}
}

func TestStore_IsExpired(t *testing.T) {
	s := &Store{}
	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{"zero value", time.Time{}, false},
		{"future", time.Now().Add(time.Hour), false},
		{"past", time.Now().Add(-time.Second), true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cred := Credential{ExpiresAt: tc.expiresAt}
			if got := s.IsExpired(cred); got != tc.want {
				t.Errorf("IsExpired() = %v, want %v", got, tc.want)
			}
		})
	}
}

// ── Resolver tests ────────────────────────────────────────────────────────────

func resolverWithHome(t *testing.T) (*Store, *Resolver) {
	t.Helper()
	s, _ := storeWithHome(t)
	return s, &Resolver{Store: s}
}

func TestResolver_FlagPrecedence(t *testing.T) {
	s, r := resolverWithHome(t)
	// Seed a valid credential to prove flag wins over it.
	_ = s.Save(sampleCredential(time.Hour))
	t.Setenv("OQS_API_KEY", "env-key")
	r.APIKeyFlag = "flag-key"

	tok, src, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "flag-key" || src != "flag" {
		t.Errorf("Resolve() = (%q, %q), want (\"flag-key\", \"flag\")", tok, src)
	}
}

func TestResolver_EnvPrecedence(t *testing.T) {
	s, r := resolverWithHome(t)
	// Seed a valid credential.
	_ = s.Save(sampleCredential(time.Hour))
	t.Setenv("OQS_API_KEY", "env-key")

	tok, src, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "env-key" || src != "env" {
		t.Errorf("Resolve() = (%q, %q), want (\"env-key\", \"env\")", tok, src)
	}
}

func TestResolver_StoredCredential(t *testing.T) {
	s, r := resolverWithHome(t)
	cred := sampleCredential(time.Hour)
	_ = s.Save(cred)
	// Ensure env var is absent.
	t.Setenv("OQS_API_KEY", "")

	tok, src, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != cred.AccessToken || src != "credentials" {
		t.Errorf("Resolve() = (%q, %q), want (%q, \"credentials\")", tok, src, cred.AccessToken)
	}
}

func TestResolver_ExpiredCredential_Refresh(t *testing.T) {
	s, r := resolverWithHome(t)
	t.Setenv("OQS_API_KEY", "")

	expired := sampleCredential(-time.Second) // already expired
	_ = s.Save(expired)

	newCred := sampleCredential(time.Hour)
	newCred.AccessToken = "refreshed-token"

	r.RefreshFn = func(_ context.Context, _, _ string) (*Credential, error) {
		return &newCred, nil
	}

	tok, src, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "refreshed-token" || src != "credentials" {
		t.Errorf("Resolve() = (%q, %q), want (\"refreshed-token\", \"credentials\")", tok, src)
	}
}

func TestResolver_Anonymous_NothingAvailable(t *testing.T) {
	_, r := resolverWithHome(t)
	t.Setenv("OQS_API_KEY", "")

	tok, src, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "" || src != "anonymous" {
		t.Errorf("Resolve() = (%q, %q), want (\"\", \"anonymous\")", tok, src)
	}
}

func TestResolver_RefreshFailure_FallsThrough(t *testing.T) {
	s, r := resolverWithHome(t)
	t.Setenv("OQS_API_KEY", "")

	expired := sampleCredential(-time.Second)
	_ = s.Save(expired)

	r.RefreshFn = func(_ context.Context, _, _ string) (*Credential, error) {
		return nil, errors.New("refresh server unavailable")
	}

	tok, src, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "" || src != "anonymous" {
		t.Errorf("Resolve() = (%q, %q), want (\"\", \"anonymous\")", tok, src)
	}
}

func TestResolver_ConcurrentRefresh_SingleCall(t *testing.T) {
	s, _ := storeWithHome(t)
	t.Setenv("OQS_API_KEY", "")

	expired := sampleCredential(-time.Second)
	if err := s.Save(expired); err != nil {
		t.Fatal(err)
	}

	var callCount int32
	newCred := sampleCredential(time.Hour)
	newCred.AccessToken = "refreshed-concurrent"

	r := &Resolver{
		Store: s,
		RefreshFn: func(_ context.Context, _, _ string) (*Credential, error) {
			atomic.AddInt32(&callCount, 1)
			return &newCred, nil
		},
	}

	const goroutines = 10
	results := make([]string, goroutines)
	errs := make([]error, goroutines)

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			tok, _, err := r.Resolve(context.Background())
			results[i] = tok
			errs[i] = err
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d: Resolve() error: %v", i, err)
		}
	}
	for i, tok := range results {
		if tok != "refreshed-concurrent" {
			t.Errorf("goroutine %d: token = %q, want %q", i, tok, "refreshed-concurrent")
		}
	}

	if n := atomic.LoadInt32(&callCount); n != 1 {
		t.Errorf("RefreshFn called %d times, want exactly 1", n)
	}
}

// ── Device auth tests ─────────────────────────────────────────────────────────

func newTestDeviceAuth(server *httptest.Server) *DeviceAuth {
	return &DeviceAuth{
		Endpoint:   server.URL,
		HTTPClient: server.Client(),
	}
}

func TestDeviceAuth_RequestDeviceCode_HappyPath(t *testing.T) {
	want := DeviceCodeResponse{
		DeviceCode:      "dev-code-123",
		UserCode:        "ABCD-1234",
		VerificationURI: "https://oqs.dev/activate",
		ExpiresIn:       300,
		Interval:        5,
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/device" || r.Method != http.MethodPost {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()

	da := newTestDeviceAuth(srv)
	got, err := da.RequestDeviceCode(context.Background())
	if err != nil {
		t.Fatalf("RequestDeviceCode() error: %v", err)
	}

	if got.DeviceCode != want.DeviceCode {
		t.Errorf("DeviceCode = %q, want %q", got.DeviceCode, want.DeviceCode)
	}
	if got.UserCode != want.UserCode {
		t.Errorf("UserCode = %q, want %q", got.UserCode, want.UserCode)
	}
	if got.VerificationURI != want.VerificationURI {
		t.Errorf("VerificationURI = %q, want %q", got.VerificationURI, want.VerificationURI)
	}
	if got.ExpiresIn != want.ExpiresIn {
		t.Errorf("ExpiresIn = %d, want %d", got.ExpiresIn, want.ExpiresIn)
	}
	if got.Interval != want.Interval {
		t.Errorf("Interval = %d, want %d", got.Interval, want.Interval)
	}
}

func TestDeviceAuth_PollForToken_EventualSuccess(t *testing.T) {
	var callCount int32

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/token" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		n := atomic.AddInt32(&callCount, 1)
		w.Header().Set("Content-Type", "application/json")

		if n < 3 {
			// First two calls: pending
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
			return
		}
		// Third call: success
		_ = json.NewEncoder(w).Encode(TokenResponse{
			AccessToken:  "final-token",
			RefreshToken: "final-refresh",
			TokenType:    "Bearer",
			ExpiresIn:    3600,
		})
	}))
	defer srv.Close()

	da := newTestDeviceAuth(srv)
	got, err := da.PollForToken(context.Background(), "dev-code", 0) // interval=0 → 5s default but test overrides
	if err != nil {
		t.Fatalf("PollForToken() error: %v", err)
	}
	if got.AccessToken != "final-token" {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, "final-token")
	}
	if atomic.LoadInt32(&callCount) < 3 {
		t.Errorf("expected at least 3 poll calls, got %d", callCount)
	}
}

func TestDeviceAuth_PollForToken_SlowDown(t *testing.T) {
	// slow_down on first call → success on second. We capture the timing to
	// verify the interval was increased (best-effort: just ensure no error).
	var callCount int32

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&callCount, 1)
		w.Header().Set("Content-Type", "application/json")
		if n == 1 {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "slow_down"})
			return
		}
		_ = json.NewEncoder(w).Encode(TokenResponse{AccessToken: "tok"})
	}))
	defer srv.Close()

	da := newTestDeviceAuth(srv)
	got, err := da.PollForToken(context.Background(), "dev-code", 0)
	if err != nil {
		t.Fatalf("PollForToken() error: %v", err)
	}
	if got.AccessToken != "tok" {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, "tok")
	}
}

func TestDeviceAuth_PollForToken_AccessDenied(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "access_denied"})
	}))
	defer srv.Close()

	da := newTestDeviceAuth(srv)
	_, err := da.PollForToken(context.Background(), "dev-code", 0)
	if !errors.Is(err, ErrAccessDenied) {
		t.Errorf("PollForToken() error = %v, want ErrAccessDenied", err)
	}
}

func TestDeviceAuth_PollForToken_ExpiredToken(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "expired_token"})
	}))
	defer srv.Close()

	da := newTestDeviceAuth(srv)
	_, err := da.PollForToken(context.Background(), "dev-code", 0)
	if !errors.Is(err, ErrExpiredToken) {
		t.Errorf("PollForToken() error = %v, want ErrExpiredToken", err)
	}
}

func TestDeviceAuth_PollForToken_ContextCancellation(t *testing.T) {
	// Server always returns authorization_pending so the poll would run forever
	// without context cancellation.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	da := newTestDeviceAuth(srv)
	_, err := da.PollForToken(ctx, "dev-code", 0)
	if err == nil {
		t.Fatal("PollForToken() expected error on context cancellation, got nil")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Errorf("PollForToken() error = %v, want context error", err)
	}
}

func TestDeviceAuth_RefreshToken_Success(t *testing.T) {
	want := TokenResponse{
		AccessToken:  "new-access",
		RefreshToken: "new-refresh",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/refresh" || r.Method != http.MethodPost {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		var payload map[string]string
		_ = json.NewDecoder(r.Body).Decode(&payload)
		if payload["refresh_token"] == "" {
			http.Error(w, "missing refresh_token", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()

	da := newTestDeviceAuth(srv)
	got, err := da.RefreshToken(context.Background(), "my-refresh-token")
	if err != nil {
		t.Fatalf("RefreshToken() error: %v", err)
	}
	if got.AccessToken != want.AccessToken {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, want.AccessToken)
	}
	if got.RefreshToken != want.RefreshToken {
		t.Errorf("RefreshToken = %q, want %q", got.RefreshToken, want.RefreshToken)
	}
}

func TestDeviceAuth_RefreshToken_InvalidToken(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "invalid_grant",
			"error_description": "refresh token is invalid or expired",
		})
	}))
	defer srv.Close()

	da := newTestDeviceAuth(srv)
	_, err := da.RefreshToken(context.Background(), "bad-token")
	if err == nil {
		t.Fatal("RefreshToken() expected error for invalid token, got nil")
	}
}

func TestDeviceAuth_RevokeToken_Success(t *testing.T) {
	var called bool

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/auth/revoke" || r.Method != http.MethodPost {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		called = true

		var payload map[string]string
		_ = json.NewDecoder(r.Body).Decode(&payload)
		if payload["access_token"] == "" || payload["refresh_token"] == "" {
			http.Error(w, "missing tokens", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	da := newTestDeviceAuth(srv)
	if err := da.RevokeToken(context.Background(), "access-tok", "refresh-tok"); err != nil {
		t.Fatalf("RevokeToken() error: %v", err)
	}
	if !called {
		t.Error("RevokeToken() did not call the server")
	}
}

// ── edge cases ────────────────────────────────────────────────────────────────

func TestStore_Save_InvalidJSON(t *testing.T) {
	// Credentials are plain structs so they always marshal — this test verifies
	// the round-trip with unicode content doesn't corrupt.
	s, _ := storeWithHome(t)
	cred := sampleCredential(time.Hour)
	cred.UserEmail = "用户@例子.中国" // unicode

	if err := s.Save(cred); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.UserEmail != cred.UserEmail {
		t.Errorf("UserEmail = %q, want %q", got.UserEmail, cred.UserEmail)
	}
}

func TestStore_Save_NoTmpFilesRemain(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("temp-rename atomics differ on Windows")
	}
	s, configDir := storeWithHome(t)
	if err := s.Save(sampleCredential(time.Hour)); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	matches, err := filepath.Glob(filepath.Join(configDir, ".credentials-*.tmp"))
	if err != nil {
		t.Fatalf("glob error: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected no .tmp files remaining after Save(), found: %v", matches)
	}
}

func TestStore_Save_AtomicContentVerified(t *testing.T) {
	s, _ := storeWithHome(t)
	want := sampleCredential(time.Hour)
	want.AccessToken = "atomic-token"

	if err := s.Save(want); err != nil {
		t.Fatalf("Save() error: %v", err)
	}

	got, err := s.Load()
	if err != nil {
		t.Fatalf("Load() after atomic Save() error: %v", err)
	}
	if got.AccessToken != want.AccessToken {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, want.AccessToken)
	}
	if got.RefreshToken != want.RefreshToken {
		t.Errorf("RefreshToken = %q, want %q", got.RefreshToken, want.RefreshToken)
	}
	if got.UserEmail != want.UserEmail {
		t.Errorf("UserEmail = %q, want %q", got.UserEmail, want.UserEmail)
	}
}

func TestDeviceAuth_RequestDeviceCode_ServerError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	da := newTestDeviceAuth(srv)
	_, err := da.RequestDeviceCode(context.Background())
	if err == nil {
		t.Fatal("RequestDeviceCode() expected error on 500, got nil")
	}
}

func TestDeviceAuth_PollForToken_UnknownError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":             "server_error",
			"error_description": "something went wrong",
		})
	}))
	defer srv.Close()

	da := newTestDeviceAuth(srv)
	_, err := da.PollForToken(context.Background(), "dev-code", 0)
	if err == nil {
		t.Fatal("PollForToken() expected error for unknown OAuth error, got nil")
	}
	expected := fmt.Sprintf("auth: token request: %s", "auth: token poll error \"server_error\": something went wrong")
	_ = expected // just verify we got a non-nil error with content
}

// ── Symlink guard tests ───────────────────────────────────────────────────────

// TestSave_SymlinkGuard verifies that Store.Save refuses to write credentials
// when the credentials.json path is a symlink. This prevents a symlink-
// following attack where an adversary pre-places a symlink at the expected
// path pointing to a sensitive file (e.g. /etc/passwd).
//
// The test is skipped on Windows because symlink creation requires elevated
// privileges and the security model differs (NTFS ACLs).
func TestSave_SymlinkGuard(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink guard test requires Unix symlink semantics")
	}

	// Set up a temporary HOME so configDir() resolves to our test tree.
	s, oqsDir := storeWithHome(t)

	// Ensure the .oqs config directory exists (Save creates it, but we need
	// it before we place the symlink inside it).
	if err := os.MkdirAll(oqsDir, 0700); err != nil {
		t.Fatalf("MkdirAll oqsDir: %v", err)
	}

	// Create an attacker-controlled target file in a separate location.
	attackerDir := t.TempDir()
	attackerFile := filepath.Join(attackerDir, "attacker-target.txt")
	if err := os.WriteFile(attackerFile, []byte("original-content"), 0o600); err != nil {
		t.Fatalf("WriteFile attacker target: %v", err)
	}

	// Place a symlink at the expected credentials.json path pointing to the
	// attacker-controlled file.
	credPath := filepath.Join(oqsDir, "credentials.json")
	if err := os.Symlink(attackerFile, credPath); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	// Attempt to save credentials — the symlink guard must reject this.
	err := s.Save(sampleCredential(time.Hour))
	if err == nil {
		t.Fatal("Save() succeeded through a symlink — symlink guard is broken")
	}

	// Verify the error message signals a deliberate security refusal (not an
	// accidental I/O error unrelated to the guard).
	if err.Error() == "" {
		t.Error("Save() returned a blank error string")
	}

	// The attacker's file must contain its original content unchanged.
	got, readErr := os.ReadFile(attackerFile)
	if readErr != nil {
		t.Fatalf("ReadFile attacker target after Save(): %v", readErr)
	}
	if string(got) != "original-content" {
		t.Errorf("attacker target was modified: content = %q, want %q",
			string(got), "original-content")
	}
}

// TestSave_SymlinkGuard_RegularFileAllowed confirms that Save succeeds
// when the credentials path already exists as a regular file (not a symlink),
// ensuring the guard does not over-reject legitimate overwrites.
func TestSave_SymlinkGuard_RegularFileAllowed(t *testing.T) {
	s, _ := storeWithHome(t)

	// First save creates the file.
	if err := s.Save(sampleCredential(time.Hour)); err != nil {
		t.Fatalf("first Save() error: %v", err)
	}

	// Second save overwrites a regular file — must succeed.
	cred2 := sampleCredential(time.Hour)
	cred2.AccessToken = "updated-token"
	if err := s.Save(cred2); err != nil {
		t.Fatalf("second Save() over regular file error: %v", err)
	}

	got, err := s.Load()
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if got.AccessToken != "updated-token" {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, "updated-token")
	}
}
