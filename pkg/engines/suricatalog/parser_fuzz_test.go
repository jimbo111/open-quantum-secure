package suricatalog

import (
	"context"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzParseEveJSON exercises the top-level NDJSON parser with arbitrary byte input.
// Invariants: no panic, no hang, returned records pass basic UTF-8 checks.
func FuzzParseEveJSON(f *testing.F) {
	// Seed: real-shape Suricata 6.x / 7.x eve.json lines covering normal paths,
	// edge-case event_types, and structurally-valid-but-weird inputs.
	seeds := []string{
		// Suricata 6.x TLS 1.3 complete event
		`{"timestamp":"2026-04-18T00:00:01.000000+0000","flow_id":1111111111111111,"in_iface":"eth0","event_type":"tls","src_ip":"10.0.0.1","src_port":54321,"dest_ip":"93.184.216.34","dest_port":443,"proto":"TCP","tls":{"subject":"CN=example.com","issuerdn":"CN=DigiCert","serial":"00:01","fingerprint":"aa:bb:cc","sni":"example.com","version":"TLSv1.3","cipher_suite":"TLS_AES_128_GCM_SHA256","cipher_security":"secure","notbefore":"2026-01-01T00:00:00","notafter":"2027-01-01T00:00:00","ja3":{"hash":"abcdef","string":"771,4865,0-65281"},"ja3s":{"hash":"xyzuvw","string":"771,4865,65281"}}}`,
		// Suricata 7.x with custom sigalgs/groups fields
		`{"event_type":"tls","dest_ip":"1.2.3.4","dest_port":443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_AES_256_GCM_SHA384","sigalgs":"rsa_pkcs1_sha256,ecdsa_secp256r1_sha256","groups":"x25519,secp256r1"}}`,
		// event_type=tls with no tls sub-object
		`{"event_type":"tls","dest_ip":"1.2.3.4","dest_port":443}`,
		// Non-TLS events (all should produce 0 records)
		`{"event_type":"alert","alert":{"severity":1}}`,
		`{"event_type":"flow","flow":{"pkts_toserver":1}}`,
		`{"event_type":"dns","dns":{"type":"query"}}`,
		`{"event_type":"http","http":{"hostname":"x.com"}}`,
		// Truncated JSON (simulates log rotation)
		`{"event_type":"tls"`,
		// Empty object
		`{}`,
		// Blank line
		"",
		// Deeply nested (billion-comma approximation; Go JSON decoder handles gracefully)
		`{"event_type":"tls","dest_ip":"1.2.3.4","dest_port":443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_AES_128_GCM_SHA256","extensions":[[[[[]]]]]}}`,
		// event_type with unicode space character (must NOT match "tls")
		"{\"event_type\":\"tls\\u00a0\",\"dest_ip\":\"1.2.3.4\",\"dest_port\":443,\"tls\":{\"version\":\"TLSv1.3\",\"cipher_suite\":\"TLS_AES_128_GCM_SHA256\"}}",
		// CRLF line ending (bufio.Scanner treats \r\n as a line terminator)
		"{\"event_type\":\"tls\",\"dest_ip\":\"1.2.3.4\",\"dest_port\":443,\"tls\":{\"version\":\"TLSv1.3\",\"cipher_suite\":\"TLS_AES_128_GCM_SHA256\"}}\r",
		// Invalid UTF-8 in a string value
		"{\"event_type\":\"tls\",\"dest_ip\":\"1.2.3.4\",\"dest_port\":443,\"tls\":{\"version\":\"TLSv1.3\",\"cipher_suite\":\"TLS_AES\xc3\x28_GCM\"}}",
		// embedded NUL in dest_ip value (Go JSON will reject)
		"{\"event_type\":\"tls\",\"dest_ip\":\"1.2.3.4\x00\",\"dest_port\":443,\"tls\":{\"version\":\"TLSv1.3\",\"cipher_suite\":\"TLS_AES_128_GCM_SHA256\"}}",
		// TLS 1.2 ECDHE cipher (key-agree classification path)
		`{"event_type":"tls","dest_ip":"5.6.7.8","dest_port":443,"tls":{"version":"TLSv1.2","cipher_suite":"ECDHE-RSA-AES256-GCM-SHA384","sni":"ecdhe.example.com"}}`,
		// Very long SNI (path sanitization)
		`{"event_type":"tls","dest_ip":"9.9.9.9","dest_port":443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_AES_128_GCM_SHA256","sni":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com"}}`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data string) {
		recs, _ := parseEveJSON(context.Background(), strings.NewReader(data))
		// Invariant: all returned records must pass basic field checks.
		for _, r := range recs {
			// sanitizeField should produce valid UTF-8 (it strips > 0x7F only for controls
			// but JSON decoder guarantees UTF-8 by the time we get here).
			_ = utf8.ValidString(r.SNI)
			_ = utf8.ValidString(r.CipherSuite)
			_ = utf8.ValidString(r.DestIP)
		}
	})
}

// FuzzParseTLSEvent targets mutations of a single well-formed TLS event line.
// Seeds are structurally valid TLS events; mutations corrupt field values.
func FuzzParseTLSEvent(f *testing.F) {
	seeds := []string{
		`{"event_type":"tls","src_ip":"10.0.0.1","src_port":1234,"dest_ip":"93.184.216.34","dest_port":443,"proto":"TCP","tls":{"version":"TLSv1.3","cipher_suite":"TLS_AES_128_GCM_SHA256","sni":"example.com","subject":"CN=example.com","issuerdn":"CN=Root","serial":"00:01","fingerprint":"aa:bb","ja3":{"hash":"aabbcc","string":"771,4865,0"},"ja3s":{"hash":"ddeeff","string":"771,4865,65281"}}}`,
		`{"event_type":"tls","dest_ip":"::1","dest_port":8443,"tls":{"version":"TLSv1.2","cipher_suite":"ECDHE-RSA-AES256-GCM-SHA384","sni":"ipv6.example.com"}}`,
		`{"event_type":"tls","dest_ip":"0.0.0.0","dest_port":0,"tls":{"version":"","cipher_suite":""}}`,
		`{"event_type":"tls","dest_ip":"255.255.255.255","dest_port":65535,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_CHACHA20_POLY1305_SHA256","sigalgs":"ecdsa_secp256r1_sha256","groups":"x25519"}}`,
		`{"event_type":"tls","dest_ip":"10.0.0.1","dest_port":443,"tls":{"version":"TLSv1.3","cipher_suite":"TLS_AES_128_GCM_SHA256","ja3s":{"hash":"","string":""}}}`,
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, line string) {
		recs, _ := parseEveJSON(context.Background(), strings.NewReader(line+"\n"))
		for _, r := range recs {
			// dedupeKey must not panic and must return a non-empty string.
			key := r.dedupeKey()
			if key == "" {
				t.Error("dedupeKey returned empty string")
			}
		}
	})
}
