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
