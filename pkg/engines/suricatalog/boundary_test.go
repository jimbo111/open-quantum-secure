package suricatalog

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestParseEmptyFile(t *testing.T) {
	recs, err := parseEveJSON(context.Background(), strings.NewReader(""))
	if err != nil {
		t.Fatalf("empty file should not error: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("empty file should produce 0 records, got %d", len(recs))
	}
}

func TestParseOnlyBlankLines(t *testing.T) {
	recs, err := parseEveJSON(context.Background(), strings.NewReader("\n\n\n"))
	if err != nil {
		t.Fatalf("blank lines should not error: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("blank lines should produce 0 records, got %d", len(recs))
	}
}

func TestParseEOFMidJSON(t *testing.T) {
	// Truncated JSON at end (simulates log rotation mid-write).
	const data = `{"event_type":"tls","dest_ip":"1.2.3.4","dest_port":443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_AES_128_GCM_SHA256"}}
{"event_type":"tls","dest_ip":"5.6.7.8","dest_port`
	recs, err := parseEveJSON(context.Background(), strings.NewReader(data))
	if err != nil {
		t.Fatalf("EOF mid-JSON should not error: %v", err)
	}
	// Only the complete line should be parsed.
	if len(recs) != 1 {
		t.Fatalf("got %d records (truncated line should be skipped), want 1", len(recs))
	}
}

func TestDedupeCapMaxRecords(t *testing.T) {
	// Generate more than maxSuricataRecords unique records to verify the cap.
	// Use minimal JSON to keep this fast.
	var sb strings.Builder
	limit := maxSuricataRecords + 100
	for i := 0; i < limit; i++ {
		fmt.Fprintf(&sb, `{"event_type":"tls","dest_ip":"%d.%d.%d.%d","dest_port":443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_AES_128_GCM_SHA256"}}`+"\n",
			(i>>24)&0xFF, (i>>16)&0xFF, (i>>8)&0xFF, i&0xFF)
	}

	recs, err := parseEveJSON(context.Background(), strings.NewReader(sb.String()))
	if err != nil {
		t.Fatalf("parseEveJSON: %v", err)
	}
	if len(recs) > maxSuricataRecords {
		t.Fatalf("dedup cap exceeded: got %d records, max is %d", len(recs), maxSuricataRecords)
	}
}

func TestParseSingleRecord(t *testing.T) {
	const data = `{"event_type":"tls","dest_ip":"10.0.0.1","dest_port":443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_AES_256_GCM_SHA384","sni":"single.example.com"}}
`
	recs, err := parseEveJSON(context.Background(), strings.NewReader(data))
	if err != nil {
		t.Fatalf("parseEveJSON: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	if recs[0].SNI != "single.example.com" {
		t.Errorf("SNI = %q, want %q", recs[0].SNI, "single.example.com")
	}
}
