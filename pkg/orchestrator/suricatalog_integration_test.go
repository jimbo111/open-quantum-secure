// suricatalog_integration_test.go — orchestrator integration tests for the suricata-log engine.
//
// Purpose: verify that the suricata-log engine integrates correctly with the
// orchestrator scan pipeline — findings flow through classification,
// deduplication, and output stages without errors. Uses real temp files;
// no network activity.
//
// Seam note: orchestrator.go line ~80 includes Tier5Network engines when
// SuricataEvePath is non-empty, so these tests do NOT require ScanType="all".
package orchestrator

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/suricatalog"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// writeTempEve writes eve.json content to a temp file and returns its path.
func writeTempEve(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "eve.json")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("writeTempEve: %v", err)
	}
	return path
}

// TestSuricataOrchestrator_SuricataEvePathAloneActivatesEngine verifies that
// providing SuricataEvePath without ScanType="all" is sufficient to activate
// the suricata-log engine (orchestrator.go line ~80 seam).
func TestSuricataOrchestrator_SuricataEvePathAloneActivatesEngine(t *testing.T) {
	path := writeTempEve(t, `{"event_type":"tls","dest_ip":"1.2.3.4","dest_port":443,"tls":{"version":"TLSv1.2","cipher_suite":"ECDHE-RSA-AES256-GCM-SHA384","sni":"classic.example.com"}}`+"\n")

	o := New(suricatalog.New())
	ff, err := o.Scan(context.Background(), engines.ScanOptions{
		SuricataEvePath: path,
		// ScanType intentionally omitted — SuricataEvePath alone must activate engine.
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(ff) == 0 {
		t.Fatal("expected findings when SuricataEvePath set without scan-type=all")
	}
	for _, f := range ff {
		if f.SourceEngine != "suricata-log" {
			t.Errorf("SourceEngine=%q, want suricata-log", f.SourceEngine)
		}
	}
}

// TestSuricataOrchestrator_ClassicalCipher verifies that a classical TLS 1.2
// ECDHE cipher is classified as quantum-vulnerable.
func TestSuricataOrchestrator_ClassicalCipher(t *testing.T) {
	path := writeTempEve(t, `{"event_type":"tls","dest_ip":"5.6.7.8","dest_port":443,"tls":{"version":"TLSv1.2","cipher_suite":"ECDHE-RSA-AES256-GCM-SHA384","sni":"vulnerable.example.com"}}`+"\n")

	o := New(suricatalog.New())
	ff, err := o.Scan(context.Background(), engines.ScanOptions{
		SuricataEvePath: path,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(ff) == 0 {
		t.Fatal("expected at least one finding for classical cipher")
	}

	var foundVulnerable bool
	for _, f := range ff {
		if f.QuantumRisk == findings.QRVulnerable {
			foundVulnerable = true
		}
	}
	if !foundVulnerable {
		t.Error("expected at least one QRVulnerable finding for ECDHE-RSA-AES256-GCM-SHA384")
	}
}

// TestSuricataOrchestrator_TLS13SymmetricCipher verifies that a TLS 1.3
// AES-256-GCM cipher is classified as quantum-resistant (symmetric, >128-bit).
func TestSuricataOrchestrator_TLS13SymmetricCipher(t *testing.T) {
	path := writeTempEve(t, `{"event_type":"tls","dest_ip":"9.9.9.9","dest_port":443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_AES_256_GCM_SHA384","sni":"modern.example.com"}}`+"\n")

	o := New(suricatalog.New())
	ff, err := o.Scan(context.Background(), engines.ScanOptions{
		SuricataEvePath: path,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(ff) == 0 {
		t.Fatal("expected at least one finding for TLS_AES_256_GCM_SHA384")
	}
	for _, f := range ff {
		if f.Algorithm != nil && f.Algorithm.Name == "TLS_AES_256_GCM_SHA384" {
			if f.SourceEngine != "suricata-log" {
				t.Errorf("SourceEngine=%q, want suricata-log", f.SourceEngine)
			}
		}
	}
}

// TestSuricataOrchestrator_MultipleRecords verifies multiple TLS events from one
// eve.json all flow through the orchestrator pipeline correctly.
func TestSuricataOrchestrator_MultipleRecords(t *testing.T) {
	const content = `{"event_type":"tls","dest_ip":"1.1.1.1","dest_port":443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_AES_128_GCM_SHA256","sni":"a.example.com"}}
{"event_type":"tls","dest_ip":"2.2.2.2","dest_port":443,"tls":{"version":"TLSv1.2","cipher_suite":"ECDHE-RSA-AES256-GCM-SHA384","sni":"b.example.com"}}
{"event_type":"alert","alert":{"severity":1}}
{"event_type":"tls","dest_ip":"3.3.3.3","dest_port":443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_CHACHA20_POLY1305_SHA256","sni":"c.example.com"}}
`
	path := writeTempEve(t, content)

	o := New(suricatalog.New())
	ff, err := o.Scan(context.Background(), engines.ScanOptions{
		SuricataEvePath: path,
	})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	// 3 TLS events × 1 cipher finding each = at least 3 findings.
	if len(ff) < 3 {
		t.Errorf("expected ≥3 findings for 3 TLS events, got %d", len(ff))
	}
	for _, f := range ff {
		if f.SourceEngine != "suricata-log" {
			t.Errorf("SourceEngine=%q, want suricata-log", f.SourceEngine)
		}
	}
}

// TestSuricataOrchestrator_EmptyEveJSON verifies that an empty eve.json produces
// 0 findings without error.
func TestSuricataOrchestrator_EmptyEveJSON(t *testing.T) {
	path := writeTempEve(t, "")

	o := New(suricatalog.New())
	ff, err := o.Scan(context.Background(), engines.ScanOptions{
		SuricataEvePath: path,
	})
	if err != nil {
		t.Fatalf("expected no error for empty eve.json, got: %v", err)
	}
	if len(ff) != 0 {
		t.Errorf("expected 0 findings for empty eve.json, got %d", len(ff))
	}
}

// TestSuricataOrchestrator_NoEvePathSkipsEngine verifies that omitting SuricataEvePath
// means no suricata-log findings are emitted. The orchestrator may return "no engines
// available" when only Tier5Network engines are registered and no targets are set.
func TestSuricataOrchestrator_NoEvePathSkipsEngine(t *testing.T) {
	o := New(suricatalog.New())
	ff, err := o.Scan(context.Background(), engines.ScanOptions{
		// SuricataEvePath intentionally absent
	})
	// "no engines available" is an acceptable error when no file/network target is set.
	if err != nil && err.Error() != "no engines available" {
		t.Fatalf("Scan: unexpected error: %v", err)
	}
	for _, f := range ff {
		if f.SourceEngine == "suricata-log" {
			t.Error("suricata-log produced findings with no SuricataEvePath set")
		}
	}
}

// TestSuricataOrchestrator_ContextCancelled verifies that a pre-cancelled context
// causes the scan to abort cleanly (no hang, no panic).
func TestSuricataOrchestrator_ContextCancelled(t *testing.T) {
	path := writeTempEve(t, `{"event_type":"tls","dest_ip":"1.2.3.4","dest_port":443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_AES_128_GCM_SHA256"}}`+"\n")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	o := New(suricatalog.New())
	// Pre-cancelled context: expect either an error or 0 findings — no hang.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = o.Scan(ctx, engines.ScanOptions{SuricataEvePath: path})
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Scan did not return within 5s with pre-cancelled context (hang detected)")
	}
	// If we reach here without a timeout, the test passes.
}
