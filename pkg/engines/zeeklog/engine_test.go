package zeeklog

import (
	"context"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
)

func TestEngineMetadata(t *testing.T) {
	e := New()
	if e.Name() != "zeek-log" {
		t.Errorf("Name() = %q, want %q", e.Name(), "zeek-log")
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

func TestScanEmptyPaths(t *testing.T) {
	e := New()
	got, err := e.Scan(context.Background(), engines.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan with empty paths: unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Scan with empty paths: got %d findings, want 0", len(got))
	}
}

func TestScanBadSSLPath(t *testing.T) {
	e := New()
	_, err := e.Scan(context.Background(), engines.ScanOptions{
		ZeekSSLPath: "/nonexistent/path/ssl.log",
	})
	if err == nil {
		t.Error("Scan with bad ssl path: expected error, got nil")
	}
}

func TestScanBadX509Path(t *testing.T) {
	e := New()
	_, err := e.Scan(context.Background(), engines.ScanOptions{
		ZeekX509Path: "/nonexistent/path/x509.log",
	})
	if err == nil {
		t.Error("Scan with bad x509 path: expected error, got nil")
	}
}

func TestScanCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	e := New()
	// With an already-cancelled context and non-empty path, first select fires.
	_, err := e.Scan(ctx, engines.ScanOptions{ZeekSSLPath: "testdata/ssl_tsv.log"})
	if err == nil {
		t.Error("Scan with cancelled context: expected error, got nil")
	}
}
