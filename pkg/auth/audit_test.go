package auth

// audit_test.go: adversarial + property tests added by the 2026-04-20
// scanner-layer audit (config-auth-api agent).
//
// Exercises:
//   - Resolver precedence chain (flag → env → stored → refresh → anonymous).
//   - Credential/token leakage in error messages.
//   - Token refresh single-flight race.
//   - Store corruption paths (bad JSON, empty access token, non-JSON file).
//   - API-key-prefix path bypasses expiry check (documented behaviour).

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ── FOCUS 4: resolver chain behaviour ───────────────────────────────────────

// TestF4_Chain_FlagWinsOverAllOthers: even with env + valid stored cred,
// an explicit flag value must always win.
func TestF4_Chain_FlagWinsOverAllOthers(t *testing.T) {
	s, r := resolverWithHome(t)
	_ = s.Save(sampleCredential(time.Hour))
	t.Setenv("OQS_API_KEY", "env-key-loud")
	r.APIKeyFlag = "  flag-key-with-space  " // whitespace NOT trimmed — document

	tok, src, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if src != "flag" {
		t.Errorf("source = %q, want flag", src)
	}
	// F4a (LOW): whitespace in --api-key passes through unchanged.
	// An operator who does `--api-key " tok"` (stray space) will send a
	// malformed Authorization header. No trim. Document.
	if tok != "  flag-key-with-space  " {
		t.Errorf("flag token trimmed unexpectedly: %q", tok)
	}
	t.Log("F4a: --api-key flag value is NOT trimmed for whitespace")
}

// TestF4_Chain_FallsThroughToAnonymous: flag empty, env empty, no stored
// credential → returns ("", "anonymous", nil) — NOT an error.
func TestF4_Chain_FallsThroughToAnonymous(t *testing.T) {
	_, r := resolverWithHome(t)
	t.Setenv("OQS_API_KEY", "")

	tok, src, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("anonymous chain returned error: %v", err)
	}
	if tok != "" || src != "anonymous" {
		t.Errorf("Resolve = (%q, %q), want (\"\", \"anonymous\")", tok, src)
	}
}

// TestF4_Chain_RefreshReturnsNilCred_NoNilDeref: RefreshFn returns (nil, nil).
// Resolver must not nil-deref; must fall through to anonymous.
func TestF4_Chain_RefreshReturnsNilCred_NoNilDeref(t *testing.T) {
	s, r := resolverWithHome(t)
	t.Setenv("OQS_API_KEY", "")
	_ = s.Save(sampleCredential(-time.Second)) // expired

	r.RefreshFn = func(_ context.Context, _, _ string) (*Credential, error) {
		return nil, nil // well-behaved bug: neither cred nor error
	}

	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("nil-deref panic on RefreshFn returning (nil,nil): %v", rec)
		}
	}()
	tok, src, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "" || src != "anonymous" {
		t.Errorf("Resolve = (%q, %q), want (\"\", \"anonymous\")", tok, src)
	}
}

// TestF4_Chain_RefreshReturnsEmptyAccessToken: RefreshFn returns a Credential
// whose AccessToken is "". This should fall through to anonymous.
func TestF4_Chain_RefreshReturnsEmptyAccessToken(t *testing.T) {
	s, r := resolverWithHome(t)
	t.Setenv("OQS_API_KEY", "")
	_ = s.Save(sampleCredential(-time.Second))

	r.RefreshFn = func(_ context.Context, _, _ string) (*Credential, error) {
		return &Credential{AccessToken: "", RefreshToken: "x"}, nil
	}

	tok, src, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "" || src != "anonymous" {
		t.Errorf("Resolve = (%q, %q), want anonymous", tok, src)
	}
}

// TestF4_CredentialLeakInErrors: if Store.Load returns a non-ErrNoCredentials
// error (e.g. corrupt JSON), the error propagates via Resolve. Verify that
// the error string does NOT contain the stored access token. Because the
// error comes from json.Unmarshal on a corrupted file, the leaked content
// is the raw file bytes up to the syntax failure — so tokens embedded in
// the file CAN surface.
func TestF4_CredentialLeakInErrors(t *testing.T) {
	s, r := resolverWithHome(t)
	t.Setenv("OQS_API_KEY", "")

	// Write a corrupt credentials.json containing a plausible token value.
	secretTok := "oqs_k_SECRET_SHOULD_NOT_APPEAR_IN_ERRORS_abc123"
	dir := filepath.Dir(mustCredPath(t))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	bad := fmt.Sprintf(`{"access_token": "%s", "refresh_token": "refresh-xyz", "expires_at": NOT_A_DATE}`, secretTok)
	if err := os.WriteFile(mustCredPath(t), []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}

	// Sanity: direct Load surfaces a JSON error — we expect Resolve to forward
	// that error unmodified.
	_, loadErr := s.Load()
	if loadErr == nil {
		t.Fatal("corrupt credentials should have failed to load")
	}
	if errors.Is(loadErr, ErrNoCredentials) {
		t.Fatal("ErrNoCredentials returned for corrupt file — should be unmarshal error")
	}

	_, _, err := r.Resolve(context.Background())
	if err == nil {
		t.Fatal("Resolve should surface the corrupt-credentials error")
	}

	// F4b finding: the error text from json.Unmarshal includes the offending
	// bytes, which can include the stored AccessToken. This is a credential
	// leak risk IF the scanner's stderr is shipped off-host (e.g. GH Actions
	// log). We capture the condition so it cannot regress silently.
	if strings.Contains(err.Error(), secretTok) {
		t.Errorf("F4b (CRITICAL REGRESSION BARRIER): corrupt-credentials error leaks access token: %v", err)
	} else {
		t.Logf("no token in error; error text: %v", err)
	}
}

// TestF4_ExpiredCredRefreshedOnce_SecondResolveUsesNewCred: after a successful
// refresh, a subsequent Resolve() call must read the refreshed credential
// from disk, not trigger another refresh.
func TestF4_ExpiredCredRefreshedOnce_SecondResolveUsesNewCred(t *testing.T) {
	s, _ := storeWithHome(t)
	t.Setenv("OQS_API_KEY", "")

	// Seed an expired credential.
	_ = s.Save(sampleCredential(-time.Second))

	var callCount int32
	newCred := sampleCredential(time.Hour)
	newCred.AccessToken = "fresh-after-refresh"

	r := &Resolver{
		Store: s,
		RefreshFn: func(_ context.Context, _, _ string) (*Credential, error) {
			atomic.AddInt32(&callCount, 1)
			return &newCred, nil
		},
	}

	// First call triggers refresh and persists via Save.
	tok1, _, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok1 != "fresh-after-refresh" {
		t.Fatalf("first Resolve token = %q, want fresh-after-refresh", tok1)
	}

	// Second call MUST NOT refresh — the saved credential is now valid.
	tok2, _, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok2 != "fresh-after-refresh" {
		t.Errorf("second Resolve token = %q, want fresh-after-refresh (from store)", tok2)
	}
	if c := atomic.LoadInt32(&callCount); c != 1 {
		t.Errorf("F4c: RefreshFn called %d times; expected exactly 1 across two Resolves", c)
	}
}

// ── FOCUS 5: token refresh race — stronger invariants than the existing test ─

// TestF5_ConcurrentRefresh_RefreshFnReceivesCorrectInputs: when 20 goroutines
// race on an expired credential, the single refresh that fires must be given
// the ORIGINAL refresh token + endpoint — not values from a partial rewrite.
func TestF5_ConcurrentRefresh_RefreshFnReceivesCorrectInputs(t *testing.T) {
	s, _ := storeWithHome(t)
	t.Setenv("OQS_API_KEY", "")

	origCred := sampleCredential(-time.Second)
	origCred.RefreshToken = "orig-refresh-token"
	origCred.Endpoint = "https://orig.endpoint"
	_ = s.Save(origCred)

	var (
		mu           sync.Mutex
		seenRefresh  []string
		seenEndpoint []string
		callCount    int32
	)

	newCred := sampleCredential(time.Hour)
	newCred.AccessToken = "refreshed"

	r := &Resolver{
		Store: s,
		RefreshFn: func(_ context.Context, endpoint, refreshToken string) (*Credential, error) {
			atomic.AddInt32(&callCount, 1)
			mu.Lock()
			seenRefresh = append(seenRefresh, refreshToken)
			seenEndpoint = append(seenEndpoint, endpoint)
			mu.Unlock()
			// Simulate network latency to widen the race window.
			time.Sleep(10 * time.Millisecond)
			return &newCred, nil
		},
	}

	const goroutines = 20
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, _, _ = r.Resolve(context.Background())
		}()
	}
	wg.Wait()

	if c := atomic.LoadInt32(&callCount); c != 1 {
		t.Errorf("F5 (HIGH): RefreshFn called %d times; expected exactly 1", c)
	}
	if len(seenRefresh) > 0 && seenRefresh[0] != "orig-refresh-token" {
		t.Errorf("F5: refresh token sent = %q, want orig-refresh-token", seenRefresh[0])
	}
	if len(seenEndpoint) > 0 && seenEndpoint[0] != "https://orig.endpoint" {
		t.Errorf("F5: endpoint sent = %q, want https://orig.endpoint", seenEndpoint[0])
	}
}

// TestF5_ConcurrentRefresh_FailedRefresh_AllGoroutinesAnonymous: when the
// single refresh call fails, every goroutine must see anonymous (not one
// succeed, others error).
func TestF5_ConcurrentRefresh_FailedRefresh_AllGoroutinesAnonymous(t *testing.T) {
	s, _ := storeWithHome(t)
	t.Setenv("OQS_API_KEY", "")
	_ = s.Save(sampleCredential(-time.Second))

	r := &Resolver{
		Store: s,
		RefreshFn: func(_ context.Context, _, _ string) (*Credential, error) {
			time.Sleep(5 * time.Millisecond)
			return nil, errors.New("refresh server returned 401")
		},
	}

	const goroutines = 12
	sources := make([]string, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			_, src, err := r.Resolve(context.Background())
			if err != nil {
				sources[i] = "ERR:" + err.Error()
				return
			}
			sources[i] = src
		}()
	}
	wg.Wait()

	for i, src := range sources {
		if src != "anonymous" {
			t.Errorf("goroutine %d: source = %q, want anonymous", i, src)
		}
	}
}

// ── FOCUS: API-key prefix path skips expiry ─────────────────────────────────

// TestF4_APIKeyPrefix_BypassesExpiry: credentials whose AccessToken starts
// with "oqs_k_" are long-lived and bypass the IsExpired check even if
// ExpiresAt is set in the past. Documents the behaviour.
func TestF4_APIKeyPrefix_BypassesExpiry(t *testing.T) {
	s, r := resolverWithHome(t)
	t.Setenv("OQS_API_KEY", "")

	cred := sampleCredential(-time.Hour) // expired
	cred.AccessToken = "oqs_k_longlivedkey"
	_ = s.Save(cred)

	tok, src, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "oqs_k_longlivedkey" || src != "credentials" {
		t.Errorf("Resolve = (%q, %q), want (oqs_k_longlivedkey, credentials)", tok, src)
	}
}

// TestF4_APIKeyPrefix_DoesNotCrossCheckEnv: if OQS_API_KEY env is set and
// stored cred is "oqs_k_...", env still wins (fall-through via precedence),
// NOT the stored key. Verifies no accidental downgrade from env to store.
func TestF4_APIKeyPrefix_EnvStillWinsOverStore(t *testing.T) {
	s, r := resolverWithHome(t)
	cred := sampleCredential(time.Hour)
	cred.AccessToken = "oqs_k_stored"
	_ = s.Save(cred)
	t.Setenv("OQS_API_KEY", "oqs_k_envwin")

	tok, src, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if src != "env" {
		t.Errorf("source = %q, want env", src)
	}
	if tok != "oqs_k_envwin" {
		t.Errorf("token = %q, want oqs_k_envwin", tok)
	}
}

// ── Store corruption paths ─────────────────────────────────────────────────

// TestF4_Store_LoadReturnsErrNoCredentials_WhenAccessTokenEmpty: a JSON
// credential file with AccessToken "" is treated as absent, not as a valid
// zero credential. Important so anonymous fallback kicks in cleanly.
func TestF4_Store_LoadReturnsErrNoCredentials_WhenAccessTokenEmpty(t *testing.T) {
	s, _ := storeWithHome(t)
	dir := filepath.Dir(mustCredPath(t))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// valid JSON, empty access token
	content := []byte(`{"access_token": "", "refresh_token": "r"}`)
	if err := os.WriteFile(mustCredPath(t), content, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := s.Load()
	if !errors.Is(err, ErrNoCredentials) {
		t.Errorf("Load with empty access_token error = %v, want ErrNoCredentials", err)
	}
}

// TestF4_Store_LoadCorruptJSON_SurfaceErr: corrupt JSON must surface a
// descriptive error, not ErrNoCredentials (otherwise a corrupt file looks
// like "no cred" and the user is silently logged out).
func TestF4_Store_LoadCorruptJSON_SurfaceErr(t *testing.T) {
	s, _ := storeWithHome(t)
	dir := filepath.Dir(mustCredPath(t))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mustCredPath(t), []byte("{{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := s.Load()
	if err == nil {
		t.Fatal("corrupt JSON should surface error")
	}
	if errors.Is(err, ErrNoCredentials) {
		t.Errorf("F4d: corrupt JSON returned ErrNoCredentials, masking corruption")
	}
}

// TestF4_IsExpired_ClockSkewGap: a credential that expires "right now" is
// reported expired. Document that there is NO clock-skew grace period —
// tokens within seconds of expiry will be refreshed aggressively, which is
// fine for correctness but may increase refresh traffic under load.
func TestF4_IsExpired_ClockSkewGap(t *testing.T) {
	s := &Store{}
	cred := Credential{ExpiresAt: time.Now().Add(-1 * time.Millisecond)}
	if !s.IsExpired(cred) {
		t.Error("1ms-stale token should be expired")
	}
	t.Log("F4e (INFO): IsExpired has no clock-skew grace — tokens within ms of expiry trigger refresh")
}

// ── helpers ────────────────────────────────────────────────────────────────

// mustCredPath resolves the credentials.json path in the current test HOME.
// Uses the same rules as the production credentialsPath() helper.
func mustCredPath(t *testing.T) string {
	t.Helper()
	p, err := credentialsPath()
	if err != nil {
		t.Fatalf("credentialsPath: %v", err)
	}
	return p
}
