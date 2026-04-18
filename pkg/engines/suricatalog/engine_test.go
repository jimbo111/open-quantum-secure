package suricatalog

import (
	"context"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
)

func TestEngineInterface(t *testing.T) {
	e := New()
	if e.Name() != "suricata-log" {
		t.Fatalf("Name() = %q, want %q", e.Name(), "suricata-log")
	}
	if e.Tier() != engines.Tier5Network {
		t.Fatalf("Tier() = %v, want Tier5Network", e.Tier())
	}
	if !e.Available() {
		t.Fatal("Available() should always return true (pure Go engine)")
	}
	if e.Version() != "embedded" {
		t.Fatalf("Version() = %q, want %q", e.Version(), "embedded")
	}
	if langs := e.SupportedLanguages(); langs != nil {
		t.Fatalf("SupportedLanguages() = %v, want nil", langs)
	}
}

func TestScanEmptyPath(t *testing.T) {
	e := New()
	findings, err := e.Scan(context.Background(), engines.ScanOptions{})
	if err != nil {
		t.Fatalf("Scan with empty path returned error: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("Scan with empty path returned %d findings, want 0", len(findings))
	}
}

func TestScanBadPath(t *testing.T) {
	e := New()
	_, err := e.Scan(context.Background(), engines.ScanOptions{
		SuricataEvePath: "/nonexistent/path/to/eve.json",
	})
	if err == nil {
		t.Fatal("Scan with bad path should return error")
	}
}

func TestScanContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	e := New()
	_, err := e.Scan(ctx, engines.ScanOptions{
		SuricataEvePath: "testdata/eve_mixed.json",
	})
	if err == nil {
		t.Fatal("expected context cancellation error")
	}
}
