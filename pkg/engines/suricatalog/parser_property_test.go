package suricatalog

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// TestDedupeOrderIndependence verifies that the set of deduplicated records
// is the same regardless of the order events appear in the input.
func TestDedupeOrderIndependence(t *testing.T) {
	type rec struct{ ip, cipher, version, sni string }
	inputs := []rec{
		{"1.1.1.1", "TLS_AES_128_GCM_SHA256", "TLSv1.3", "a.example.com"},
		{"2.2.2.2", "ECDHE-RSA-AES256-GCM-SHA384", "TLSv1.2", "b.example.com"},
		{"3.3.3.3", "TLS_CHACHA20_POLY1305_SHA256", "TLSv1.3", "c.example.com"},
	}

	build := func(order []int) string {
		var sb strings.Builder
		for _, i := range order {
			r := inputs[i]
			fmt.Fprintf(&sb,
				"{\"event_type\":\"tls\",\"dest_ip\":%q,\"dest_port\":443,\"tls\":{\"version\":%q,\"cipher_suite\":%q,\"sni\":%q}}\n",
				r.ip, r.version, r.cipher, r.sni)
		}
		return sb.String()
	}

	orders := [][]int{
		{0, 1, 2},
		{2, 1, 0},
		{1, 0, 2},
		{2, 0, 1},
	}

	var baseline map[string]bool
	for _, order := range orders {
		recs, err := parseEveJSON(context.Background(), strings.NewReader(build(order)))
		if err != nil {
			t.Fatalf("parseEveJSON order %v: %v", order, err)
		}
		keys := make(map[string]bool, len(recs))
		for _, r := range recs {
			keys[r.dedupeKey()] = true
		}
		if baseline == nil {
			baseline = keys
			continue
		}
		if len(keys) != len(baseline) {
			t.Errorf("order %v: got %d records, want %d (dedup is order-dependent)", order, len(keys), len(baseline))
		}
		for k := range baseline {
			if !keys[k] {
				t.Errorf("order %v: key %q present in baseline but missing", order, k)
			}
		}
	}
}

// TestDedupeKeyDeterminism verifies that TLSRecord.dedupeKey is pure and stable.
func TestDedupeKeyDeterminism(t *testing.T) {
	r := TLSRecord{
		DestIP:      "192.0.2.1",
		DestPort:    "8443",
		CipherSuite: "TLS_AES_128_GCM_SHA256",
		Version:     "TLSv1.3",
		SNI:         "deterministic.example.com",
	}
	k1 := r.dedupeKey()
	k2 := r.dedupeKey()
	k3 := r.dedupeKey()
	if k1 != k2 || k2 != k3 {
		t.Errorf("dedupeKey not deterministic: %q / %q / %q", k1, k2, k3)
	}
	if k1 == "" {
		t.Error("dedupeKey returned empty string")
	}
}

// TestRoundTripSyntheticRecord verifies that marshalling an eveEvent to JSON and
// parsing it back produces a TLSRecord with the same field values.
func TestRoundTripSyntheticRecord(t *testing.T) {
	cases := []struct {
		name      string
		destIP    string
		destPort  int
		cipher    string
		version   string
		sni       string
		subject   string
		issuerdn  string
		ja3sHash  string
	}{
		{
			name:     "TLS1.3 classical",
			destIP:   "10.0.0.1", destPort: 443,
			cipher: "TLS_AES_128_GCM_SHA256", version: "TLSv1.3",
			sni: "rt.example.com", subject: "CN=rt.example.com",
			issuerdn: "CN=Root CA", ja3sHash: "a0b1c2d3e4f5a0b1c2d3e4f5a0b1c2d3",
		},
		{
			name:     "TLS1.2 ECDHE IPv6",
			destIP:   "::1", destPort: 8443,
			cipher: "ECDHE-RSA-AES256-GCM-SHA384", version: "TLSv1.2",
			sni: "ipv6.rt.example.com",
		},
		{
			name:     "empty cipher and version",
			destIP:   "0.0.0.0", destPort: 0,
			cipher: "", version: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := eveEvent{
				EventType: "tls",
				DestIP:    tc.destIP,
				DestPort:  tc.destPort,
				TLS: &eveTLS{
					Version:     tc.version,
					CipherSuite: tc.cipher,
					SNI:         tc.sni,
					Subject:     tc.subject,
					Issuerdn:    tc.issuerdn,
				},
			}
			if tc.ja3sHash != "" {
				ev.TLS.JA3S = &eveJA3{Hash: tc.ja3sHash, String: "dummy"}
			}

			b, err := json.Marshal(ev)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}

			recs, err := parseEveJSON(context.Background(), strings.NewReader(string(b)+"\n"))
			if err != nil {
				t.Fatalf("parseEveJSON: %v", err)
			}
			if len(recs) != 1 {
				t.Fatalf("expected 1 record, got %d", len(recs))
			}
			got := recs[0]

			if got.DestIP != tc.destIP {
				t.Errorf("DestIP: got %q want %q", got.DestIP, tc.destIP)
			}
			wantPort := fmt.Sprintf("%d", tc.destPort)
			if got.DestPort != wantPort {
				t.Errorf("DestPort: got %q want %q", got.DestPort, wantPort)
			}
			if got.CipherSuite != tc.cipher {
				t.Errorf("CipherSuite: got %q want %q", got.CipherSuite, tc.cipher)
			}
			if got.SNI != tc.sni {
				t.Errorf("SNI: got %q want %q", got.SNI, tc.sni)
			}
			if got.JA3SHash != tc.ja3sHash {
				t.Errorf("JA3SHash: got %q want %q", got.JA3SHash, tc.ja3sHash)
			}
		})
	}
}

// TestEventTypeFilterCorrectness verifies that ONLY the exact string "tls" matches —
// not "tls-foo", "TLS", "tls " (trailing space), "tls\x00", or other variants.
func TestEventTypeFilterCorrectness(t *testing.T) {
	cases := []struct {
		name      string
		eventType string
		wantCount int
	}{
		{"exact lowercase tls", "tls", 1},
		{"prefix tls-foo", "tls-foo", 0},
		{"uppercase TLS", "TLS", 0},
		{"mixed case Tls", "Tls", 0},
		{"trailing space", "tls ", 0},
		{"empty string", "", 0},
		{"alert", "alert", 0},
		{"flow", "flow", 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line := fmt.Sprintf(
				`{"event_type":%q,"dest_ip":"1.2.3.4","dest_port":443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_AES_128_GCM_SHA256"}}`,
				tc.eventType,
			) + "\n"
			recs, err := parseEveJSON(context.Background(), strings.NewReader(line))
			if err != nil {
				t.Fatalf("parseEveJSON: %v", err)
			}
			if len(recs) != tc.wantCount {
				t.Errorf("event_type=%q → %d records, want %d", tc.eventType, len(recs), tc.wantCount)
			}
		})
	}
}
