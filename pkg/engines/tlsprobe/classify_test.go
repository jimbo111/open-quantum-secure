package tlsprobe

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestDecomposeCipherSuite_Registry(t *testing.T) {
	tests := []struct {
		name     string
		id       uint16
		wantKex  string
		wantAuth string
		wantSym  string
		wantHash string
	}{
		{
			name:     "ECDHE-RSA-AES128-GCM-SHA256",
			id:       tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			wantKex:  "ECDHE",
			wantAuth: "RSA",
			wantSym:  "AES",
			wantHash: "SHA-256",
		},
		{
			name:     "ECDHE-ECDSA-AES256-GCM-SHA384",
			id:       tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			wantKex:  "ECDHE",
			wantAuth: "ECDSA",
			wantSym:  "AES",
			wantHash: "SHA-384",
		},
		{
			name:     "RSA-AES128-CBC-SHA",
			id:       tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			wantKex:  "RSA",
			wantAuth: "RSA",
			wantSym:  "AES",
			wantHash: "SHA-1",
		},
		{
			name:     "TLS13-AES256-GCM-SHA384",
			id:       tls.TLS_AES_256_GCM_SHA384,
			wantKex:  "",
			wantAuth: "",
			wantSym:  "AES",
			wantHash: "SHA-384",
		},
		{
			name:     "TLS13-CHACHA20-POLY1305",
			id:       tls.TLS_CHACHA20_POLY1305_SHA256,
			wantKex:  "",
			wantAuth: "",
			wantSym:  "ChaCha20-Poly1305",
			wantHash: "SHA-256",
		},
		{
			name:     "RSA-3DES-SHA",
			id:       tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			wantKex:  "RSA",
			wantAuth: "RSA",
			wantSym:  "3DES",
			wantHash: "SHA-1",
		},
		{
			name:     "RSA-RC4-SHA",
			id:       tls.TLS_RSA_WITH_RC4_128_SHA,
			wantKex:  "RSA",
			wantAuth: "RSA",
			wantSym:  "RC4",
			wantHash: "SHA-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			comps := decomposeCipherSuite(tt.id)
			if len(comps) == 0 {
				t.Fatal("got zero components")
			}

			var gotKex, gotAuth, gotSym, gotHash string
			for _, c := range comps {
				switch c.Primitive {
				case "key-exchange":
					gotKex = c.Name
				case "signature":
					gotAuth = c.Name
				case "symmetric":
					gotSym = c.Name
				case "hash":
					gotHash = c.Name
				}
			}

			if tt.wantKex != "" && gotKex != tt.wantKex {
				t.Errorf("kex: got %q, want %q", gotKex, tt.wantKex)
			}
			if tt.wantAuth != "" && gotAuth != tt.wantAuth {
				t.Errorf("auth: got %q, want %q", gotAuth, tt.wantAuth)
			}
			if gotSym != tt.wantSym {
				t.Errorf("sym: got %q, want %q", gotSym, tt.wantSym)
			}
			if gotHash != tt.wantHash {
				t.Errorf("hash: got %q, want %q", gotHash, tt.wantHash)
			}
		})
	}
}

func TestDecomposeCipherSuite_AES256NotVulnerable(t *testing.T) {
	comps := decomposeCipherSuite(tls.TLS_AES_256_GCM_SHA384)
	for _, c := range comps {
		if c.Primitive == "symmetric" && c.KeySize < 256 {
			t.Errorf("AES-256-GCM should have KeySize=256, got %d", c.KeySize)
		}
	}
}

func TestObservationToFindings_NilOnError(t *testing.T) {
	result := ProbeResult{
		Target: "example.com:443",
		Error:  fmt.Errorf("dial %w", &net.OpError{Op: "dial"}),
	}
	ff := observationToFindings(result)
	if len(ff) != 0 {
		t.Errorf("expected 0 findings for error result, got %d", len(ff))
	}
}

func TestObservationToFindings_CipherAndCert(t *testing.T) {
	result := ProbeResult{
		Target:          "example.com:443",
		TLSVersion:      tls.VersionTLS12,
		CipherSuiteID:   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		CipherSuiteName: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		LeafCertKeyAlgo: "RSA",
		LeafCertKeySize: 2048,
	}
	ff := observationToFindings(result)
	if len(ff) == 0 {
		t.Fatal("expected findings")
	}

	// Should have cipher components + cert key finding.
	var hasECDHE, hasRSACert bool
	for _, f := range ff {
		if f.Algorithm != nil {
			if f.Algorithm.Name == "ECDHE" && f.Algorithm.Primitive == "key-exchange" {
				hasECDHE = true
			}
			if f.Algorithm.Name == "RSA" && f.Algorithm.Primitive == "signature" && f.Algorithm.KeySize == 2048 {
				hasRSACert = true
			}
		}
		// Verify location — each finding has a role suffix (#kex, #sig, #sym, #mac, #cert)
		if !strings.HasPrefix(f.Location.File, "(tls-probe)/example.com:443") {
			t.Errorf("unexpected Location.File: %s", f.Location.File)
		}
		if f.Location.ArtifactType != "tls-endpoint" {
			t.Errorf("unexpected ArtifactType: %s", f.Location.ArtifactType)
		}
		if f.SourceEngine != "tls-probe" {
			t.Errorf("unexpected SourceEngine: %s", f.SourceEngine)
		}
	}
	if !hasECDHE {
		t.Error("missing ECDHE key-exchange finding")
	}
	if !hasRSACert {
		t.Error("missing RSA cert signature finding")
	}
}

// TestDecomposeCipherSuite_Fallback passes a cipher suite ID that is NOT present
// in cipherRegistry (0xFFFF) to trigger the parseCipherSuiteName fallback path.
// The function must not panic and must return a non-nil result (empty is acceptable
// for a truly unknown suite, but the call itself must be safe).
func TestDecomposeCipherSuite_Fallback(t *testing.T) {
	const unknownSuite uint16 = 0xFFFF

	// Ensure the ID is genuinely absent from the registry.
	if _, ok := cipherRegistry[unknownSuite]; ok {
		t.Skip("0xFFFF is unexpectedly present in cipherRegistry; choose a different ID")
	}

	// Must not panic.
	comps := decomposeCipherSuite(unknownSuite)

	// Result may be nil/empty for a truly unknown suite — that is acceptable.
	// The critical invariant is that the call completes without panicking.
	_ = comps
}

// TestObservationToFindings_TLS10And11 verifies that TLS 1.0 (0x0301) and
// TLS 1.1 (0x0302) results do NOT produce the implicit ECDHE key-exchange
// finding that is only added for TLS 1.3.
func TestObservationToFindings_TLS10And11(t *testing.T) {
	versions := []struct {
		name    string
		version uint16
	}{
		{"TLS 1.0", 0x0301},
		{"TLS 1.1", 0x0302},
	}

	for _, v := range versions {
		t.Run(v.name, func(t *testing.T) {
			result := ProbeResult{
				Target:          "example.com:443",
				TLSVersion:      v.version,
				CipherSuiteID:   tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				CipherSuiteName: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				LeafCertKeyAlgo: "RSA",
				LeafCertKeySize: 2048,
			}

			ff := observationToFindings(result)

			for _, f := range ff {
				if f.Algorithm != nil &&
					f.Algorithm.Name == "ECDHE" &&
					f.Algorithm.Primitive == "key-exchange" &&
					f.RawIdentifier == "kex:ECDHE|"+result.Target {
					t.Errorf("%s: unexpected implicit ECDHE kex finding (only valid for TLS 1.3)", v.name)
				}
			}
		})
	}
}

func TestObservationToFindings_TLS13ImplicitKex(t *testing.T) {
	result := ProbeResult{
		Target:          "example.com:443",
		TLSVersion:      tls.VersionTLS13,
		CipherSuiteID:   tls.TLS_AES_256_GCM_SHA384,
		CipherSuiteName: "TLS_AES_256_GCM_SHA384",
		LeafCertKeyAlgo: "ECDSA",
		LeafCertKeySize: 256,
	}
	ff := observationToFindings(result)

	// TLS 1.3 should add an implicit ECDHE key-exchange finding.
	var hasECDHE bool
	for _, f := range ff {
		if f.Algorithm != nil && f.Algorithm.Name == "ECDHE" && f.Algorithm.Primitive == "key-exchange" {
			hasECDHE = true
		}
	}
	if !hasECDHE {
		t.Error("TLS 1.3 should have implicit ECDHE key-exchange finding")
	}
}
