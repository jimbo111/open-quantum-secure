package protocols

import (
	"sort"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/impact"
)

// sortHits provides a stable ordering for comparison in tests.
func sortHits(h []impact.BoundaryHit) {
	sort.Slice(h, func(i, j int) bool {
		if h[i].Protocol != h[j].Protocol {
			return h[i].Protocol < h[j].Protocol
		}
		if h[i].File != h[j].File {
			return h[i].File < h[j].File
		}
		return h[i].Line < h[j].Line
	})
}

func TestDetectFromPath_SingleProtocol(t *testing.T) {
	tests := []struct {
		name     string
		message  string
		wantProt string
	}{
		{"jwt.Sign", "calling jwt.Sign(claims)", "JWT"},
		{"jwt.Encode", "jwt.Encode(header, payload)", "JWT"},
		{"Set-Cookie", "Set-Cookie: jwt=...", "JWT"},
		{"JWSHeader", "JWSHeader{alg: RS256}", "JWT"},

		{"tls.Config", "cfg := tls.Config{}", "TLS"},
		{"tls.Listen", "tls.Listen(\"tcp\", addr, cfg)", "TLS"},
		{"tls.Dial", "tls.Dial(\"tcp\", addr, nil)", "TLS"},
		{"TLSClientConfig", "&http.Transport{TLSClientConfig: cfg}", "TLS"},

		{"metadata.Pairs", "md := metadata.Pairs(\"key\", val)", "gRPC"},
		{"grpc.SetHeader", "grpc.SetHeader(ctx, md)", "gRPC"},
		{"metadata.New", "metadata.New(map)", "gRPC"},

		{"x509.CreateCertificate", "x509.CreateCertificate(rand, tmpl, parent, pub, priv)", "X.509"},
		{"ParseCertificate", "cert, _ := x509.ParseCertificate(der)", "X.509"},
		{"CertPool", "pool := x509.NewCertPool()", "X.509"},

		{"dtls.Config", "dtls.Config{}", "DTLS"},
		{"dtls.Listen", "dtls.Listen(\"udp\", addr, cfg)", "DTLS"},
		{"dtls.Dial", "dtls.Dial(\"udp\", addr, cfg)", "DTLS"},

		{"ssh.PublicKey", "var pub ssh.PublicKey", "SSH"},
		{"ssh.NewSignerFromKey", "ssh.NewSignerFromKey(priv)", "SSH"},
		{"authorized_keys", "authorized_keys file", "SSH"},

		{"ocsp.CreateRequest", "ocsp.CreateRequest(cert, issuer, opts)", "OCSP"},
		{"ocsp.CreateResponse", "ocsp.CreateResponse(issuer, resp, tmpl, key)", "OCSP"},

		{"smime.Encrypt", "smime.Encrypt(msg, certs)", "S/MIME"},
		{"smime.Sign", "smime.Sign(msg, chain, key)", "S/MIME"},
		{"pkcs7.Sign", "pkcs7.Sign(msg, cert, key)", "S/MIME"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := []findings.FlowStep{{File: "file.go", Line: 1, Message: tc.message}}
			hits := DetectFromPath(path)
			if len(hits) == 0 {
				t.Fatalf("DetectFromPath() returned no hits, expected protocol=%q", tc.wantProt)
			}
			found := false
			for _, h := range hits {
				if h.Protocol == tc.wantProt {
					found = true
					if h.File != "file.go" || h.Line != 1 {
						t.Errorf("hit file/line mismatch: got %s:%d", h.File, h.Line)
					}
				}
			}
			if !found {
				t.Errorf("protocol %q not found in hits %+v", tc.wantProt, hits)
			}
		})
	}
}

func TestDetectFromPath_MultipleSteps(t *testing.T) {
	path := []findings.FlowStep{
		{File: "svc.go", Line: 10, Message: "cfg := tls.Config{MinVersion: tls.VersionTLS13}"},
		{File: "auth.go", Line: 55, Message: "jwt.Sign(claims, key)"},
		{File: "grpc.go", Line: 22, Message: "metadata.Pairs(\"authorization\", token)"},
	}

	hits := DetectFromPath(path)
	if len(hits) < 3 {
		t.Fatalf("expected at least 3 hits, got %d: %+v", len(hits), hits)
	}

	protocols := map[string]bool{}
	for _, h := range hits {
		protocols[h.Protocol] = true
	}
	for _, want := range []string{"TLS", "JWT", "gRPC"} {
		if !protocols[want] {
			t.Errorf("protocol %q not detected", want)
		}
	}
}

func TestDetectFromPath_Empty(t *testing.T) {
	hits := DetectFromPath(nil)
	if hits != nil {
		t.Errorf("expected nil, got %+v", hits)
	}
}

func TestDetectFromPath_NoMatch(t *testing.T) {
	path := []findings.FlowStep{
		{File: "main.go", Line: 1, Message: "fmt.Println(\"hello world\")"},
	}
	hits := DetectFromPath(path)
	if len(hits) != 0 {
		t.Errorf("expected no hits, got %+v", hits)
	}
}

func TestDetectFromPath_NoDuplicateProtocolPerStep(t *testing.T) {
	// Message that contains two JWT patterns — should produce only 1 JWT hit
	path := []findings.FlowStep{
		{File: "auth.go", Line: 5, Message: "jwt.Sign and jwt.Encode both called"},
	}
	hits := DetectFromPath(path)
	jwtCount := 0
	for _, h := range hits {
		if h.Protocol == "JWT" {
			jwtCount++
		}
	}
	if jwtCount != 1 {
		t.Errorf("expected 1 JWT hit per step, got %d", jwtCount)
	}
}

// TestDetectFromPath_OrderStable verifies that DetectFromPath produces a
// consistent hit order across repeated calls when a message matches multiple
// protocols. This guards against the previously non-deterministic map iteration.
func TestDetectFromPath_OrderStable(t *testing.T) {
	// Craft a message that matches both TLS and JWT patterns.
	path := []findings.FlowStep{
		{File: "handler.go", Line: 42, Message: "tls.Config used with jwt.Sign for auth"},
	}

	var first []impact.BoundaryHit
	for i := 0; i < 100; i++ {
		hits := DetectFromPath(path)
		if i == 0 {
			first = make([]impact.BoundaryHit, len(hits))
			copy(first, hits)
			continue
		}
		if len(hits) != len(first) {
			t.Fatalf("iteration %d: got %d hits, want %d", i, len(hits), len(first))
		}
		for j := range hits {
			if hits[j] != first[j] {
				t.Fatalf("iteration %d: hit[%d] = %+v, want %+v (non-deterministic order)", i, j, hits[j], first[j])
			}
		}
	}
}

// sortHits is used in TestDetectFromPath_MultipleSteps for stable comparison.
var _ = sortHits
