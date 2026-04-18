package suricatalog

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

func TestParseEveJSONOnlyTLS(t *testing.T) {
	// Golden fixture has 3 TLS events, 1 alert, 1 http, 1 dns.
	recs, err := readEveJSON(context.Background(), "testdata/eve_mixed.json")
	if err != nil {
		t.Fatalf("readEveJSON: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("got %d records, want 3 (only TLS events should be parsed)", len(recs))
	}
}

func TestParseEveJSONDeduplication(t *testing.T) {
	// Two identical TLS events → only one unique record.
	const data = `{"event_type":"tls","dest_ip":"1.2.3.4","dest_port":443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_AES_128_GCM_SHA256","sni":"dup.example.com"}}
{"event_type":"tls","dest_ip":"1.2.3.4","dest_port":443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_AES_128_GCM_SHA256","sni":"dup.example.com"}}
`
	recs, err := parseEveJSON(context.Background(), strings.NewReader(data))
	if err != nil {
		t.Fatalf("parseEveJSON: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d records after dedup, want 1", len(recs))
	}
}

func TestParseEveJSONSkipNonTLS(t *testing.T) {
	const data = `{"event_type":"alert","alert":{"severity":1}}
{"event_type":"flow","flow":{"pkts_toserver":1}}
{"event_type":"dns","dns":{"type":"query"}}
`
	recs, err := parseEveJSON(context.Background(), strings.NewReader(data))
	if err != nil {
		t.Fatalf("parseEveJSON: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("got %d records for non-TLS events, want 0", len(recs))
	}
}

func TestParseEveJSONFieldMapping(t *testing.T) {
	const data = `{"event_type":"tls","dest_ip":"192.0.2.1","dest_port":8443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_CHACHA20_POLY1305_SHA256","sni":"test.example.com","subject":"CN=test.example.com","ja3s":{"hash":"deadbeefdeadbeefdeadbeefdeadbeef","string":""}}}
`
	recs, err := parseEveJSON(context.Background(), strings.NewReader(data))
	if err != nil {
		t.Fatalf("parseEveJSON: %v", err)
	}
	if len(recs) != 1 {
		t.Fatalf("got %d records, want 1", len(recs))
	}
	r := recs[0]
	if r.DestIP != "192.0.2.1" {
		t.Errorf("DestIP = %q, want %q", r.DestIP, "192.0.2.1")
	}
	if r.DestPort != "8443" {
		t.Errorf("DestPort = %q, want %q", r.DestPort, "8443")
	}
	if r.CipherSuite != "TLS_CHACHA20_POLY1305_SHA256" {
		t.Errorf("CipherSuite = %q, want %q", r.CipherSuite, "TLS_CHACHA20_POLY1305_SHA256")
	}
	if r.SNI != "test.example.com" {
		t.Errorf("SNI = %q, want %q", r.SNI, "test.example.com")
	}
	if r.JA3SHash != "deadbeefdeadbeefdeadbeefdeadbeef" {
		t.Errorf("JA3SHash = %q, want %q", r.JA3SHash, "deadbeefdeadbeefdeadbeefdeadbeef")
	}
}

func TestParseEveJSONMalformedLines(t *testing.T) {
	// Malformed lines should be skipped, not abort parsing.
	const data = `{"event_type":"tls","dest_ip":"1.2.3.4","dest_port":443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_AES_128_GCM_SHA256"}}
{not valid json
{"event_type":"tls","dest_ip":"5.6.7.8","dest_port":443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_AES_256_GCM_SHA384"}}
`
	recs, err := parseEveJSON(context.Background(), strings.NewReader(data))
	if err != nil {
		t.Fatalf("parseEveJSON: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records (malformed line should be skipped), want 2", len(recs))
	}
}

func TestParseEveJSONContextCancel(t *testing.T) {
	// Build 20 TLS lines so the scanner has something to process before cancellation.
	var sb strings.Builder
	for i := 0; i < 20; i++ {
		sb.WriteString(`{"event_type":"tls","dest_ip":"1.1.1.` + strings.Repeat("1", 1) + `","dest_port":` + fmt.Sprintf("%d", 10000+i) + `,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_AES_128_GCM_SHA256"}}` + "\n")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancelled

	recs, err := parseEveJSON(ctx, strings.NewReader(sb.String()))
	// A pre-cancelled context must return context.Canceled and fewer records than total.
	if err != context.Canceled {
		t.Errorf("expected context.Canceled error, got: %v", err)
	}
	if len(recs) >= 20 {
		t.Errorf("expected fewer than 20 records on cancelled context, got %d", len(recs))
	}
}

// TestParseChainDeepNestingNoPanic verifies that an eve.json event carrying a
// deeply nested "chain" array (which oqs-scanner drops) does not panic.
// Locks in A4/B4: chain was removed from YAML and the parser silently ignores it
// via encoding/json's unknown-field drop behaviour.
func TestParseChainDeepNestingNoPanic(t *testing.T) {
	// 100-level deep array nesting in the chain field.
	chainVal := strings.Repeat("[", 100) + strings.Repeat("]", 100)
	line := `{"event_type":"tls","dest_ip":"1.2.3.4","dest_port":443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_AES_128_GCM_SHA256","chain":` + chainVal + `}}` + "\n"

	recs, err := parseEveJSON(context.Background(), strings.NewReader(line))
	// Must not panic. The result (0 or 1 records) depends on whether json.Unmarshal
	// accepts the deeply nested value; what matters is no panic and no error from us.
	if err != nil {
		t.Errorf("unexpected error for chain-bearing event: %v", err)
	}
	// The TLS record itself must be parseable even if chain nesting confuses json.
	_ = recs
}
