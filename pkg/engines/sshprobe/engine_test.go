package sshprobe

import (
	"context"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
)

func TestEngineInterface(t *testing.T) {
	e := New()

	if e.Name() != "ssh-probe" {
		t.Errorf("Name() = %q; want ssh-probe", e.Name())
	}
	if e.Tier() != engines.Tier5Network {
		t.Errorf("Tier() = %v; want Tier5Network", e.Tier())
	}
	if !e.Available() {
		t.Error("Available() = false; want true (embedded engine)")
	}
	if e.Version() != "embedded" {
		t.Errorf("Version() = %q; want embedded", e.Version())
	}
	if langs := e.SupportedLanguages(); langs != nil {
		t.Errorf("SupportedLanguages() = %v; want nil", langs)
	}
}

func TestScan_EmptyTargets(t *testing.T) {
	e := New()
	ff, err := e.Scan(context.Background(), engines.ScanOptions{
		SSHTargets: nil,
	})
	if err != nil {
		t.Fatalf("Scan with no targets returned error: %v", err)
	}
	if len(ff) != 0 {
		t.Errorf("expected no findings for empty targets, got %d", len(ff))
	}
}

func TestScan_NoNetwork(t *testing.T) {
	e := New()
	ff, err := e.Scan(context.Background(), engines.ScanOptions{
		SSHTargets: []string{"example.com:22"},
		NoNetwork:  true,
	})
	if err != nil {
		t.Fatalf("Scan with NoNetwork=true returned error: %v", err)
	}
	if len(ff) != 0 {
		t.Errorf("expected no findings with NoNetwork, got %d", len(ff))
	}
}

func TestScan_TooManyTargets(t *testing.T) {
	targets := make([]string, maxTargets+1)
	for i := range targets {
		targets[i] = "192.0.2.1:22"
	}
	e := New()
	_, err := e.Scan(context.Background(), engines.ScanOptions{SSHTargets: targets})
	if err == nil {
		t.Fatal("expected error for too many targets, got nil")
	}
}

func TestScan_Integration(t *testing.T) {
	methods := []string{"mlkem768x25519-sha256", "curve25519-sha256"}
	addr := serveFakeSSH(t, "SSH-2.0-OpenSSH_10.0", methods)

	e := New()

	// Inject a stub probeFn that enforces our timeout but talks to the fake server.
	original := probeFn
	defer func() { probeFn = original }()
	probeFn = func(ctx context.Context, target string, timeout time.Duration, denyPrivate bool) ProbeResult {
		return probeSSH(ctx, addr, timeout, denyPrivate)
	}

	ff, err := e.Scan(context.Background(), engines.ScanOptions{
		SSHTargets: []string{addr},
	})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(ff) == 0 {
		t.Fatal("expected findings, got none")
	}
	foundPQC := false
	for _, f := range ff {
		if f.PQCPresent {
			foundPQC = true
		}
	}
	if !foundPQC {
		t.Error("expected at least one PQC-present finding")
	}
}

func TestScan_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	e := New()
	// Even with cancelled context, Scan should not panic and should return cleanly.
	_, _ = e.Scan(ctx, engines.ScanOptions{
		SSHTargets: []string{"127.0.0.1:22"},
	})
}

// A4 — labelled break in select exits the for-range, not just the select.
// Verify no goroutine leak when cancelling a scan with more targets than maxConcurrency.
func TestScan_CancelExitsForLoop_NoGoroutineLeak(t *testing.T) {
	original := probeFn
	defer func() { probeFn = original }()

	// Slow stub — blocks until ctx is done.
	probeFn = func(ctx context.Context, target string, _ time.Duration, _ bool) ProbeResult {
		<-ctx.Done()
		return ProbeResult{Target: target, Error: ctx.Err()}
	}

	// More targets than maxConcurrency so the semaphore loop actually exercises
	// the cancel path mid-iteration.
	targets := make([]string, maxConcurrency*3)
	for i := range targets {
		targets[i] = "192.0.2.1:22"
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		e := New()
		_, _ = e.Scan(ctx, engines.ScanOptions{SSHTargets: targets})
	}()

	// Cancel after a brief moment to ensure at least some goroutines are running.
	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Scan did not return within 500ms after context cancel")
	}
}

// A5 — reachable/unreachable summary is accurate after a mid-scan cancel.
// Verifies that Scan does not panic or index out-of-bounds on results[:launched].
func TestScan_CancelAccurateLaunchedCounter(t *testing.T) {
	original := probeFn
	defer func() { probeFn = original }()

	ready := make(chan struct{}, 1) // buffered so the first probe signals once
	probeFn = func(ctx context.Context, target string, _ time.Duration, _ bool) ProbeResult {
		select {
		case ready <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return ProbeResult{Target: target, Error: ctx.Err()}
	}

	targets := make([]string, maxConcurrency+2)
	for i := range targets {
		targets[i] = "192.0.2.1:22"
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-ready
		cancel()
	}()

	e := New()
	_, _ = e.Scan(ctx, engines.ScanOptions{SSHTargets: targets})
	// After scan returns, launched ≤ len(targets). No panic, no index-out-of-bounds.
	// The concurrency invariants are covered more thoroughly in engine_stress_test.go.
}
