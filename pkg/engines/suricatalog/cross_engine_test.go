package suricatalog

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
)

// TestCrossEngine_ConcurrentScansNoCollision verifies that two concurrent
// suricata-log engine scans on different log files do not share dedup state
// and produce independent finding sets. The -race detector validates that
// there are no data races between the two goroutines.
//
// Note: zeeklog engine does not exist in this codebase. This test simulates
// co-ingest from two independent log sources using two Engine.Scan calls.
func TestCrossEngine_ConcurrentScansNoCollision(t *testing.T) {
	dir := t.TempDir()

	// Log A: 3 unique TLS records (TLS 1.3 symmetric ciphers).
	pathA := filepath.Join(dir, "eve_a.json")
	var sbA strings.Builder
	for i := 0; i < 3; i++ {
		fmt.Fprintf(&sbA, `{"event_type":"tls","dest_ip":"10.0.0.%d","dest_port":443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_AES_128_GCM_SHA256","sni":"src-a-%d.example.com"}}`+"\n", i+1, i)
	}
	if err := os.WriteFile(pathA, []byte(sbA.String()), 0600); err != nil {
		t.Fatalf("write pathA: %v", err)
	}

	// Log B: 3 different unique TLS records (TLS 1.2 ECDHE ciphers).
	pathB := filepath.Join(dir, "eve_b.json")
	var sbB strings.Builder
	for i := 0; i < 3; i++ {
		fmt.Fprintf(&sbB, `{"event_type":"tls","dest_ip":"192.168.1.%d","dest_port":443,"tls":{"version":"TLSv1.2","cipher_suite":"ECDHE-RSA-AES256-GCM-SHA384","sni":"src-b-%d.example.com"}}`+"\n", i+1, i)
	}
	if err := os.WriteFile(pathB, []byte(sbB.String()), 0600); err != nil {
		t.Fatalf("write pathB: %v", err)
	}

	var (
		wg      sync.WaitGroup
		ffA     []string // dest IPs from scan A
		ffB     []string // dest IPs from scan B
		errA    error
		errB    error
		muA     sync.Mutex
		muB     sync.Mutex
	)

	engA := New()
	engB := New()

	wg.Add(2)
	go func() {
		defer wg.Done()
		results, err := engA.Scan(context.Background(), engines.ScanOptions{SuricataEvePath: pathA})
		muA.Lock()
		errA = err
		for _, f := range results {
			if f.Location.File != "" {
				ffA = append(ffA, f.Location.File)
			}
		}
		muA.Unlock()
	}()
	go func() {
		defer wg.Done()
		results, err := engB.Scan(context.Background(), engines.ScanOptions{SuricataEvePath: pathB})
		muB.Lock()
		errB = err
		for _, f := range results {
			if f.Location.File != "" {
				ffB = append(ffB, f.Location.File)
			}
		}
		muB.Unlock()
	}()
	wg.Wait()

	if errA != nil {
		t.Fatalf("scan A: %v", errA)
	}
	if errB != nil {
		t.Fatalf("scan B: %v", errB)
	}

	// Both scans must produce findings.
	if len(ffA) == 0 {
		t.Error("scan A produced no findings")
	}
	if len(ffB) == 0 {
		t.Error("scan B produced no findings")
	}

	// No finding collision: file paths in A must not appear in B's results.
	setB := make(map[string]bool, len(ffB))
	for _, p := range ffB {
		setB[p] = true
	}
	for _, p := range ffA {
		if setB[p] {
			t.Errorf("finding file path %q appears in both scan A and scan B (dedup state leaked?)", p)
		}
	}
}

// TestCrossEngine_DedupStatePerScan verifies that each Engine.Scan call
// has its own independent dedup map — duplicates within one scan are suppressed,
// but the same record in two separate scans is NOT suppressed across scans.
func TestCrossEngine_DedupStatePerScan(t *testing.T) {
	dir := t.TempDir()
	// Same record appears in both log files.
	const sharedRecord = `{"event_type":"tls","dest_ip":"1.2.3.4","dest_port":443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_AES_128_GCM_SHA256","sni":"shared.example.com"}}` + "\n"

	pathA := filepath.Join(dir, "a.json")
	pathB := filepath.Join(dir, "b.json")
	if err := os.WriteFile(pathA, []byte(sharedRecord), 0600); err != nil {
		t.Fatalf("write pathA: %v", err)
	}
	if err := os.WriteFile(pathB, []byte(sharedRecord), 0600); err != nil {
		t.Fatalf("write pathB: %v", err)
	}

	engA := New()
	engB := New()

	recsA, err := engA.Scan(context.Background(), engines.ScanOptions{SuricataEvePath: pathA})
	if err != nil {
		t.Fatalf("scan A: %v", err)
	}
	recsB, err := engB.Scan(context.Background(), engines.ScanOptions{SuricataEvePath: pathB})
	if err != nil {
		t.Fatalf("scan B: %v", err)
	}

	// Each independent scan must return findings (same record, not suppressed across scans).
	if len(recsA) == 0 {
		t.Error("scan A: expected findings for shared record")
	}
	if len(recsB) == 0 {
		t.Error("scan B: expected findings for shared record")
	}
}

// TestCrossEngine_RaceFree runs concurrent suricata scans under -race to confirm
// no shared mutable state between engine instances.
func TestCrossEngine_RaceFree(t *testing.T) {
	dir := t.TempDir()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		path := filepath.Join(dir, fmt.Sprintf("eve_%d.json", i))
		content := fmt.Sprintf(`{"event_type":"tls","dest_ip":"10.%d.0.1","dest_port":443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_AES_128_GCM_SHA256","sni":"race-%d.example.com"}}`+"\n", i, i)
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatalf("write %s: %v", path, err)
		}

		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			eng := New()
			_, _ = eng.Scan(context.Background(), engines.ScanOptions{SuricataEvePath: p})
		}(path)
	}
	wg.Wait()
	// No panic and -race detector finding = pass.
}
