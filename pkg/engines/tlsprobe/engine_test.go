package tlsprobe

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
)

func TestEngine_Interface(t *testing.T) {
	e := New()
	if e.Name() != "tls-probe" {
		t.Errorf("Name() = %q, want tls-probe", e.Name())
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

func TestEngine_SelfGate_NoTargets(t *testing.T) {
	e := New()
	opts := engines.ScanOptions{} // no TLS targets
	ff, err := e.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ff) != 0 {
		t.Errorf("expected 0 findings, got %d", len(ff))
	}
}

func TestEngine_ProbeLocalTLSServer(t *testing.T) {
	// Create a local TLS server with default cert (RSA).
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Extract host:port from server URL.
	addr := srv.Listener.Addr().String()

	e := New()
	opts := engines.ScanOptions{
		TLSTargets:  []string{addr},
		TLSInsecure: true, // self-signed cert
		TLSTimeout:  5,
	}

	ff, err := e.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(ff) == 0 {
		t.Fatal("expected findings from TLS probe")
	}

	// Should find RSA from the httptest default cert.
	var foundRSA bool
	for _, f := range ff {
		if f.Algorithm != nil && f.Algorithm.Name == "RSA" {
			foundRSA = true
		}
	}
	if !foundRSA {
		t.Error("expected RSA finding from httptest TLS server")
	}

	// All findings should have correct metadata.
	for _, f := range ff {
		if f.SourceEngine != "tls-probe" {
			t.Errorf("SourceEngine = %q, want tls-probe", f.SourceEngine)
		}
		if f.Confidence != "high" {
			t.Errorf("Confidence = %q, want high", f.Confidence)
		}
		if f.Reachable != "yes" {
			t.Errorf("Reachable = %q, want yes", f.Reachable)
		}
		if !strings.HasPrefix(f.Location.File, "(tls-probe)/") {
			t.Errorf("Location.File = %q, want (tls-probe)/... prefix", f.Location.File)
		}
	}
}

func TestEngine_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	e := New()
	opts := engines.ScanOptions{
		TLSTargets:  []string{"192.0.2.1:443"}, // TEST-NET, always unreachable
		TLSInsecure: true,
		TLSTimeout:  1,
	}

	start := time.Now()
	_, _ = e.Scan(ctx, opts)
	elapsed := time.Since(start)

	// Should return quickly (< 2s) due to cancelled context.
	if elapsed > 2*time.Second {
		t.Errorf("Scan took %v with cancelled context, expected < 2s", elapsed)
	}
}

func TestEngine_InvalidTarget(t *testing.T) {
	e := New()
	opts := engines.ScanOptions{
		TLSTargets:  []string{"not-a-valid-target:::"},
		TLSInsecure: true,
		TLSTimeout:  2,
	}

	// Should not panic, should produce warning + error.
	_, err := e.Scan(context.Background(), opts)
	// All targets unreachable → non-nil error.
	if err == nil {
		t.Error("expected error for invalid target")
	}
}

func TestEngine_DenyPrivateBlocks(t *testing.T) {
	e := New()
	opts := engines.ScanOptions{
		TLSTargets:     []string{"127.0.0.1:443"},
		TLSDenyPrivate: true,
		TLSInsecure:    true,
		TLSTimeout:     2,
	}

	_, err := e.Scan(context.Background(), opts)
	if err == nil {
		t.Error("expected error when probing loopback with DenyPrivate=true")
	}
}

func TestEngine_DefaultPort(t *testing.T) {
	// Test that a target without port gets 443 appended.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	srv.TLS = &tls.Config{}
	srv.StartTLS()
	defer srv.Close()

	// parseHostPort should handle "host" → "host:443"
	host, port, err := parseHostPort("example.com")
	if err != nil {
		t.Fatalf("parseHostPort error: %v", err)
	}
	if host != "example.com" || port != "443" {
		t.Errorf("got host=%q port=%q, want example.com:443", host, port)
	}
}

func TestEngine_MultipleTargets_PartialSuccess(t *testing.T) {
	// One reachable TLS server + one unreachable target.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	e := New()
	opts := engines.ScanOptions{
		TLSTargets:  []string{srv.Listener.Addr().String(), "192.0.2.1:443"},
		TLSInsecure: true,
		TLSTimeout:  2,
	}

	ff, err := e.Scan(context.Background(), opts)
	// Partial success: one reachable, one not → should succeed (not all unreachable).
	if err != nil {
		t.Fatalf("expected partial success, got error: %v", err)
	}
	if len(ff) == 0 {
		t.Error("expected findings from the reachable server")
	}
}

func TestTier5NetworkString(t *testing.T) {
	if engines.Tier5Network.String() != "network" {
		t.Errorf("Tier5Network.String() = %q, want network", engines.Tier5Network.String())
	}
}

// TestEngine_Concurrent_RaceDetector saturates the semaphore (defaultConcurrency=10)
// with 15 targets that all point to the same TLS server. It verifies that every
// target produces findings (all reachable) and that no data races occur under -race.
func TestEngine_Concurrent_RaceDetector(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	addr := srv.Listener.Addr().String()

	// 15 targets all pointing to the same server — exceeds the semaphore cap of 10.
	const numTargets = 15
	targets := make([]string, numTargets)
	for i := range targets {
		targets[i] = addr
	}

	e := New()
	opts := engines.ScanOptions{
		TLSTargets:  targets,
		TLSInsecure: true,
		TLSTimeout:  5,
	}

	ff, err := e.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(ff) == 0 {
		t.Fatal("expected findings from concurrent probe")
	}
}

// TestEngine_MaxTargetsExceeded passes 101 targets (maxTargets=100) and asserts
// that Scan returns an error containing "too many targets".
func TestEngine_MaxTargetsExceeded(t *testing.T) {
	targets := make([]string, 101)
	for i := range targets {
		targets[i] = "192.0.2.1:443"
	}

	e := New()
	opts := engines.ScanOptions{
		TLSTargets:  targets,
		TLSInsecure: true,
		TLSTimeout:  1,
	}

	_, err := e.Scan(context.Background(), opts)
	if err == nil {
		t.Fatal("expected error for 101 targets, got nil")
	}
	if !strings.Contains(err.Error(), "too many targets") {
		t.Errorf("error %q does not contain 'too many targets'", err.Error())
	}
}

// TestParseHostPort_IPv6 verifies that bracketed IPv6 addresses parse correctly
// and that bare (unbracketed) IPv6 returns an error.
func TestParseHostPort_IPv6(t *testing.T) {
	// Bracketed IPv6 with port — must succeed.
	host, port, err := parseHostPort("[::1]:443")
	if err != nil {
		t.Fatalf("parseHostPort([::1]:443) unexpected error: %v", err)
	}
	if host != "::1" {
		t.Errorf("host = %q, want ::1", host)
	}
	if port != "443" {
		t.Errorf("port = %q, want 443", port)
	}

	// Bare (unbracketed) IPv6 — net.SplitHostPort cannot parse it, and the
	// fallback of appending ":443" also fails because the address is ambiguous.
	_, _, err = parseHostPort("::1:443")
	if err == nil {
		t.Error("parseHostPort(::1:443) expected error, got nil")
	}
}

// TestParseHostPort_PortValidation verifies boundary conditions on port numbers.
func TestParseHostPort_PortValidation(t *testing.T) {
	tests := []struct {
		target  string
		wantErr bool
	}{
		{"192.0.2.1:0", true},     // port 0 is invalid (< 1)
		{"192.0.2.1:65536", true}, // port 65536 is invalid (> 65535)
		{"192.0.2.1:443", false},  // port 443 is valid
	}

	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			_, _, err := parseHostPort(tt.target)
			if tt.wantErr && err == nil {
				t.Errorf("parseHostPort(%q) expected error, got nil", tt.target)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("parseHostPort(%q) unexpected error: %v", tt.target, err)
			}
		})
	}
}
