package tlsprobe

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
)

// TestProbeTLS12_TLS13Only verifies that probeTLS12 returns AcceptedTLS12=false
// when the server does not support TLS 1.2 (TLS 1.3 only).
// httptest.NewTLSServer uses the Go TLS stack, which supports TLS 1.2 by default,
// so we verify the behavior using a mock server that rejects TLS 1.2.
func TestProbeTLS12_ServerUnreachable(t *testing.T) {
	// Use a closed listener — any dial will fail immediately.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()

	_, err = probeTLS12(context.Background(), addr, "localhost", 2*time.Second, false)
	if err == nil {
		t.Error("expected error when server is unreachable, got nil")
	}
}

// TestProbeTLS12_AcceptsServerTLS12 verifies that probeTLS12 returns
// AcceptedTLS12=true when a server accepts TLS 1.2.
func TestProbeTLS12_AcceptsServerTLS12(t *testing.T) {
	// httptest.NewTLSServer uses Go's default TLS config which accepts TLS 1.2.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	addr := net.JoinHostPort(host, port)

	res, err := probeTLS12(context.Background(), addr, "127.0.0.1", 5*time.Second, false)
	if err != nil {
		t.Fatalf("probeTLS12 error: %v", err)
	}
	if !res.AcceptedTLS12 {
		t.Error("AcceptedTLS12 = false, want true")
	}
	if res.CipherSuiteID == 0 {
		t.Error("CipherSuiteID = 0, want non-zero")
	}
	if res.CipherSuiteName == "" {
		t.Error("CipherSuiteName is empty")
	}
}

// TestProbeTLS12_ContextCancellation verifies that probeTLS12 respects context cancellation.
func TestProbeTLS12_ContextCancellation(t *testing.T) {
	// Bind a listener but never accept — so the dial succeeds but TLS handshake hangs.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err = probeTLS12(ctx, addr, "localhost", 5*time.Second, false)
	if err == nil {
		t.Error("expected error with cancelled context, got nil")
	}
}

// TestProbeTLS12_DenyPrivateRejects verifies that DenyPrivate=true blocks loopback IPs.
func TestProbeTLS12_DenyPrivateRejects(t *testing.T) {
	_, err := probeTLS12(context.Background(), "127.0.0.1:443", "localhost", 2*time.Second, true)
	if err == nil {
		t.Error("expected rejection of loopback IP with DenyPrivate=true")
	}
	if !strings.Contains(err.Error(), "private IP rejected") {
		t.Errorf("error = %q, want to contain 'private IP rejected'", err.Error())
	}
}

// TestEngine_SkipTLS12Fallback verifies that the TLS 1.2 probe is never called
// when SkipTLS12Fallback=true.
func TestEngine_SkipTLS12Fallback(t *testing.T) {
	var tls12Called atomic.Bool

	orig := tls12probeFn
	tls12probeFn = func(_ context.Context, _, _ string, _ time.Duration, _ bool) (TLS12ProbeResult, error) {
		tls12Called.Store(true)
		return TLS12ProbeResult{}, errors.New("should not be called")
	}
	defer func() { tls12probeFn = orig }()

	// Use a real TLS server as the probe target.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	e := New()
	opts := engines.ScanOptions{
		TLSTargets:        []string{srv.Listener.Addr().String()},
		TLSInsecure:       true,
		TLSTimeout:        5,
		SkipTLS12Fallback: true,
	}
	_, _ = e.Scan(context.Background(), opts)

	if tls12Called.Load() {
		t.Error("tls12probeFn was called despite SkipTLS12Fallback=true")
	}
}

// TestEngine_TLS12FallbackFinding verifies that a TLS_1.2_Fallback finding is
// emitted when the server accepted both TLS 1.3 PQC and TLS 1.2.
func TestEngine_TLS12FallbackFinding(t *testing.T) {
	// Inject mock probe functions so we don't need real PQC servers.
	origProbe := probeFn
	origTLS12 := tls12probeFn
	defer func() {
		probeFn = origProbe
		tls12probeFn = origTLS12
	}()

	// Primary probe: simulate a TLS 1.3 handshake with X25519MLKEM768.
	probeFn = func(_ context.Context, target string, _ ProbeOpts) ProbeResult {
		return ProbeResult{
			Target:            target,
			ResolvedIP:        "93.184.216.34",
			TLSVersion:        tls.VersionTLS13,
			CipherSuiteID:     tls.TLS_AES_128_GCM_SHA256,
			CipherSuiteName:   "TLS_AES_128_GCM_SHA256",
			NegotiatedGroupID: 0x11EC, // X25519MLKEM768 — PQCPresent=true
			LeafCertKeyAlgo:   "RSA",
			LeafCertKeySize:   2048,
			LeafCertSigAlgo:   "SHA256-RSA",
		}
	}

	// TLS 1.2 fallback probe: server accepts TLS 1.2.
	tls12probeFn = func(_ context.Context, addr, sni string, _ time.Duration, _ bool) (TLS12ProbeResult, error) {
		return TLS12ProbeResult{
			AcceptedTLS12:   true,
			CipherSuiteID:   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			CipherSuiteName: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		}, nil
	}

	e := New()
	opts := engines.ScanOptions{
		TLSTargets:        []string{"example.com:443"},
		TLSInsecure:       true,
		TLSTimeout:        5,
		SkipTLS12Fallback: false,
	}
	ff, err := e.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	var fallbackFinding bool
	for _, f := range ff {
		if strings.HasSuffix(f.Location.File, "#tls12-fallback") {
			fallbackFinding = true
			if f.Algorithm == nil || f.Algorithm.Name != "TLS_1.2_Fallback" {
				t.Errorf("fallback finding Algorithm.Name = %v, want TLS_1.2_Fallback", f.Algorithm)
			}
			if f.QuantumRisk != "quantum-vulnerable" {
				t.Errorf("fallback finding QuantumRisk = %q, want quantum-vulnerable", f.QuantumRisk)
			}
		}
	}
	if !fallbackFinding {
		t.Error("expected a #tls12-fallback finding, got none")
	}
}
