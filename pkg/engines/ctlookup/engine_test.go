package ctlookup

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
)

// TestEngine_Interface verifies the Engine implements the engines.Engine contract.
func TestEngine_Interface(t *testing.T) {
	e := New()
	if e.Name() != "ct-lookup" {
		t.Errorf("Name() = %q, want ct-lookup", e.Name())
	}
	if e.Tier() != engines.Tier5Network {
		t.Errorf("Tier() = %v, want Tier5Network", e.Tier())
	}
	if !e.Available() {
		t.Error("Available() = false, want true")
	}
	if e.Version() != "embedded" {
		t.Errorf("Version() = %q, want embedded", e.Version())
	}
	if langs := e.SupportedLanguages(); langs != nil {
		t.Errorf("SupportedLanguages() = %v, want nil", langs)
	}
}

// TestEngine_SelfGate_NoTargets verifies Scan returns nil when CTLookupTargets is empty.
func TestEngine_SelfGate_NoTargets(t *testing.T) {
	e := New()
	ff, err := e.Scan(context.Background(), engines.ScanOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ff) != 0 {
		t.Errorf("expected 0 findings, got %d", len(ff))
	}
}

// TestEngine_SelfGate_NoNetwork verifies Scan returns nil when NoNetwork is true,
// even when CTLookupTargets is non-empty.
func TestEngine_SelfGate_NoNetwork(t *testing.T) {
	e := New()
	opts := engines.ScanOptions{
		CTLookupTargets: []string{"example.com"},
		NoNetwork:       true,
	}
	ff, err := e.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ff) != 0 {
		t.Errorf("expected 0 findings with NoNetwork=true, got %d", len(ff))
	}
}

// TestEngine_Scan_MockHTTP exercises the full Scan→queryHostname→fetchCertDER
// pipeline using a local httptest server, verifying that findings are emitted
// for each certificate returned.
func TestEngine_Scan_MockHTTP(t *testing.T) {
	// Generate a self-signed ECDSA cert to serve as the "CT log cert".
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: "mock.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	// Build a fake crt.sh server.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Query().Get("output") == "json":
			// JSON entry list.
			entries := []crtShEntry{{
				IssuerCAID:   1,
				IssuerName:   "CN=Mock CA",
				CommonName:   "mock.example.com",
				NameValue:    "mock.example.com",
				ID:           1001,
				NotBefore:    "2024-01-01T00:00:00",
				NotAfter:     "2025-01-01T00:00:00",
				SerialNumber: "2A",
			}}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(entries)

		case strings.Contains(r.URL.RawQuery, "d="):
			// DER cert fetch.
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(certDER)

		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	e := New()
	// Inject the test server URL.
	e.client.baseURL = srv.URL
	e.client.httpClient = srv.Client()

	opts := engines.ScanOptions{
		CTLookupTargets: []string{"mock.example.com"},
	}
	ff, err := e.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(ff) == 0 {
		t.Fatal("expected at least one finding")
	}

	for _, f := range ff {
		if f.SourceEngine != "ct-lookup" {
			t.Errorf("SourceEngine = %q, want ct-lookup", f.SourceEngine)
		}
		if f.Algorithm == nil {
			t.Fatal("Algorithm is nil")
		}
		if f.Algorithm.Name != "ECDSA" {
			t.Errorf("Algorithm.Name = %q, want ECDSA", f.Algorithm.Name)
		}
		if !strings.HasPrefix(f.Location.File, "(ct-lookup)/") {
			t.Errorf("Location.File = %q, want (ct-lookup)/... prefix", f.Location.File)
		}
		if f.PartialInventory {
			t.Error("CT-derived finding should have PartialInventory=false")
		}
	}
}

// TestEngine_Scan_Deduplication verifies that duplicate hostnames in
// CTLookupTargets are collapsed to a single CT query.
func TestEngine_Scan_Deduplication(t *testing.T) {
	var callCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("output") == "json" {
			callCount++
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, "[]") // empty result
	}))
	defer srv.Close()

	e := New()
	e.client.baseURL = srv.URL
	e.client.httpClient = srv.Client()

	opts := engines.ScanOptions{
		CTLookupTargets: []string{"dup.com", "dup.com", "dup.com"},
	}
	_, err := e.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if callCount != 1 {
		t.Errorf("expected 1 unique CT query, got %d", callCount)
	}
}

// TestEngine_Scan_HTTPError verifies that HTTP errors from crt.sh are reported
// to stderr and don't cause a panic — Scan returns without error.
func TestEngine_Scan_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	e := New()
	e.client.baseURL = srv.URL
	e.client.httpClient = srv.Client()

	opts := engines.ScanOptions{
		CTLookupTargets: []string{"error.example.com"},
	}
	ff, err := e.Scan(context.Background(), opts)
	// HTTP error → warning to stderr, no findings, no returned error.
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}
	if len(ff) != 0 {
		t.Errorf("expected 0 findings on HTTP error, got %d", len(ff))
	}
}

// TestEngine_Scan_ContextCancellation verifies the engine honours ctx.Done().
func TestEngine_Scan_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Scan

	e := New()
	opts := engines.ScanOptions{
		CTLookupTargets: []string{"example.com"},
	}
	// Should return quickly — context already done.
	start := time.Now()
	_, _ = e.Scan(ctx, opts)
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Scan took %v with cancelled context, want < 2s", elapsed)
	}
}
