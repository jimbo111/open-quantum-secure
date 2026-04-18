package suricatalog

import (
	"context"
	"strings"
	"testing"
)

// TestEventTypeDispatch_AllTypes verifies that interleaved Suricata event types
// produce findings only for event_type="tls" entries.
func TestEventTypeDispatch_AllTypes(t *testing.T) {
	const data = `{"event_type":"alert","alert":{"category":"A","severity":1}}
{"event_type":"flow","flow":{"pkts_toserver":10,"pkts_toclient":5}}
{"event_type":"tls","dest_ip":"1.2.3.4","dest_port":443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_AES_128_GCM_SHA256","sni":"first.example.com"}}
{"event_type":"dns","dns":{"type":"query","rrname":"example.com","rcode":"NOERROR"}}
{"event_type":"http","http":{"hostname":"example.com","url":"/path","status":200}}
{"event_type":"tls","dest_ip":"5.6.7.8","dest_port":443,"tls":{"version":"TLSv1.2","cipher_suite":"ECDHE-RSA-AES256-GCM-SHA384","sni":"second.example.com"}}
{"event_type":"fileinfo","fileinfo":{"filename":"/tmp/foo","magic":"text/plain","size":1024}}
{"event_type":"anomaly","anomaly":{"type":"applayer","event":"INVALID_RECORD_LENGTH"}}
{"event_type":"stats","stats":{"uptime":100,"capture":{"kernel_packets":1000}}}
{"event_type":"tls","dest_ip":"9.10.11.12","dest_port":8443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_CHACHA20_POLY1305_SHA256","sni":"third.example.com"}}
`
	recs, err := parseEveJSON(context.Background(), strings.NewReader(data))
	if err != nil {
		t.Fatalf("parseEveJSON: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("expected 3 TLS records from mixed input, got %d", len(recs))
	}

	sniSet := map[string]bool{
		"first.example.com":  false,
		"second.example.com": false,
		"third.example.com":  false,
	}
	for _, r := range recs {
		if _, known := sniSet[r.SNI]; !known {
			t.Errorf("unexpected SNI in result: %q", r.SNI)
		}
		sniSet[r.SNI] = true
	}
	for sni, seen := range sniSet {
		if !seen {
			t.Errorf("expected SNI %q not found in results", sni)
		}
	}
}

// TestEventTypeDispatch_TLSFakeNoMatch verifies that event_type="tls-fake" is not matched.
func TestEventTypeDispatch_TLSFakeNoMatch(t *testing.T) {
	const line = `{"event_type":"tls-fake","dest_ip":"1.2.3.4","dest_port":443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_AES_128_GCM_SHA256"}}` + "\n"
	recs, err := parseEveJSON(context.Background(), strings.NewReader(line))
	if err != nil {
		t.Fatalf("parseEveJSON: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("event_type=tls-fake must produce 0 records, got %d", len(recs))
	}
}

// TestEventTypeDispatch_UppercaseNoMatch verifies that event_type="TLS" is not matched
// (dispatch is case-sensitive).
func TestEventTypeDispatch_UppercaseNoMatch(t *testing.T) {
	const line = `{"event_type":"TLS","dest_ip":"1.2.3.4","dest_port":443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_AES_128_GCM_SHA256"}}` + "\n"
	recs, err := parseEveJSON(context.Background(), strings.NewReader(line))
	if err != nil {
		t.Fatalf("parseEveJSON: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("event_type=TLS (uppercase) must produce 0 records, got %d", len(recs))
	}
}

// TestEventTypeDispatch_TrailingWhitespaceNoMatch verifies that "tls " (trailing space)
// does not match.
func TestEventTypeDispatch_TrailingWhitespaceNoMatch(t *testing.T) {
	const line = `{"event_type":"tls ","dest_ip":"1.2.3.4","dest_port":443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_AES_128_GCM_SHA256"}}` + "\n"
	recs, err := parseEveJSON(context.Background(), strings.NewReader(line))
	if err != nil {
		t.Fatalf("parseEveJSON: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("event_type='tls ' (trailing space) must produce 0 records, got %d", len(recs))
	}
}

// TestEventTypeDispatch_TLSMissingSubObject verifies that event_type="tls" with no
// tls sub-object present produces 0 records (guard against nil dereference).
func TestEventTypeDispatch_TLSMissingSubObject(t *testing.T) {
	const line = `{"event_type":"tls","dest_ip":"1.2.3.4","dest_port":443}` + "\n"
	recs, err := parseEveJSON(context.Background(), strings.NewReader(line))
	if err != nil {
		t.Fatalf("parseEveJSON: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("event_type=tls with no tls sub-object must produce 0 records, got %d", len(recs))
	}
}

// TestEventTypeDispatch_UnicodeWhitespaceNoMatch verifies that event_type with unicode
// whitespace (e.g. non-breaking space \u00a0) does not match "tls".
func TestEventTypeDispatch_UnicodeWhitespaceNoMatch(t *testing.T) {
	// "tls\u00a0" — "tls" + unicode non-breaking space
	line := "{\"event_type\":\"tls\u00a0\",\"dest_ip\":\"1.2.3.4\",\"dest_port\":443,\"tls\":{\"version\":\"TLSv1.3\",\"cipher_suite\":\"TLS_AES_128_GCM_SHA256\"}}\n"
	recs, err := parseEveJSON(context.Background(), strings.NewReader(line))
	if err != nil {
		t.Fatalf("parseEveJSON: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("event_type with unicode whitespace must produce 0 records, got %d", len(recs))
	}
}
