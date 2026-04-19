package suricatalog

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// TestDedupCapStress_1M streams 1,000,000 unique TLS events through parseEveJSON
// and asserts that exactly maxSuricataRecords (500,000) records are retained.
//
// Required seam (fix-blocker): the current implementation silently drops records
// when the dedup cap is reached (parser.go:131). A stderr warning "suricata-log:
// dedup cap reached, dropping further unique records" should be emitted exactly once
// so operators are alerted to potentially incomplete inventory. This test does NOT
// yet assert the warning because the seam is absent — see task #5 (S6 Fix Blockers).
func TestDedupCapStress_1M(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping 1M-record stress test in -short mode")
	}

	const total = 1_000_000
	var sb strings.Builder
	// Pre-allocate roughly: each line ≈ 115 bytes; 1M lines ≈ 115MB.
	sb.Grow(total * 120)

	for i := 0; i < total; i++ {
		// Unique key per record: vary dest_ip across all four octets.
		fmt.Fprintf(&sb,
			"{\"event_type\":\"tls\",\"dest_ip\":\"%d.%d.%d.%d\",\"dest_port\":443,\"tls\":{\"version\":\"TLSv1.3\",\"cipher_suite\":\"TLS_AES_128_GCM_SHA256\"}}\n",
			(i>>24)&0xFF, (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)
	}

	recs, err := parseEveJSON(context.Background(), strings.NewReader(sb.String()))
	if err != nil {
		t.Fatalf("parseEveJSON: %v", err)
	}
	if len(recs) != maxSuricataRecords {
		t.Errorf("1M unique events: got %d records retained, want exactly %d (cap=%d)",
			len(recs), maxSuricataRecords, maxSuricataRecords)
	}
}

// TestDedupCapStress_ExactBoundary verifies the exact cap boundary with no off-by-one:
//   - 500,000 records: all retained.
//   - 500,001 records: exactly 500,000 retained (one dropped).
func TestDedupCapStress_ExactBoundary(t *testing.T) {
	makeLines := func(n int) string {
		var sb strings.Builder
		sb.Grow(n * 120)
		for i := 0; i < n; i++ {
			fmt.Fprintf(&sb,
				"{\"event_type\":\"tls\",\"dest_ip\":\"%d.%d.%d.%d\",\"dest_port\":443,\"tls\":{\"version\":\"TLSv1.3\",\"cipher_suite\":\"TLS_AES_128_GCM_SHA256\"}}\n",
				(i>>24)&0xFF, (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)
		}
		return sb.String()
	}

	// Exactly at cap: all retained.
	recsAtCap, err := parseEveJSON(context.Background(), strings.NewReader(makeLines(maxSuricataRecords)))
	if err != nil {
		t.Fatalf("parseEveJSON at cap: %v", err)
	}
	if len(recsAtCap) != maxSuricataRecords {
		t.Errorf("at cap (%d): got %d records, want %d", maxSuricataRecords, len(recsAtCap), maxSuricataRecords)
	}

	// One over cap: exactly cap retained.
	recsOverCap, err := parseEveJSON(context.Background(), strings.NewReader(makeLines(maxSuricataRecords+1)))
	if err != nil {
		t.Fatalf("parseEveJSON at cap+1: %v", err)
	}
	if len(recsOverCap) != maxSuricataRecords {
		t.Errorf("at cap+1 (%d): got %d records, want %d (one must be dropped)",
			maxSuricataRecords+1, len(recsOverCap), maxSuricataRecords)
	}
}

// TestDedupCapStress_DuplicatesNotCountedTowardsCap verifies that duplicate records
// are not counted towards the dedup cap — the cap is on unique keys, not total lines.
func TestDedupCapStress_DuplicatesNotCountedTowardsCap(t *testing.T) {
	// One unique record repeated maxSuricataRecords+1000 times.
	const line = `{"event_type":"tls","dest_ip":"1.2.3.4","dest_port":443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_AES_128_GCM_SHA256","sni":"dup.example.com"}}` + "\n"
	repeated := strings.Repeat(line, maxSuricataRecords+1000)

	recs, err := parseEveJSON(context.Background(), strings.NewReader(repeated))
	if err != nil {
		t.Fatalf("parseEveJSON: %v", err)
	}
	// Only 1 unique record should be retained (duplicates deduplicated).
	if len(recs) != 1 {
		t.Errorf("repeated identical records: got %d, want 1 (dedup must collapse all duplicates)", len(recs))
	}
}
