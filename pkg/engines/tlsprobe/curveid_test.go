package tlsprobe

import (
	"crypto/tls"
	"testing"
)

// TestObservationToFindings_PQCGroup verifies that when NegotiatedGroupID is a
// known PQC hybrid (X25519MLKEM768), all emitted findings carry PQCPresent=true
// and NegotiatedGroupName is populated, and the TLS 1.3 kex finding uses the
// group name rather than the generic "ECDHE" label.
func TestObservationToFindings_PQCGroup(t *testing.T) {
	const x25519mlkem768 = uint16(0x11EC)

	result := ProbeResult{
		Target:            "pqc-server.example.com:443",
		TLSVersion:        tls.VersionTLS13,
		CipherSuiteID:     tls.TLS_AES_256_GCM_SHA384,
		CipherSuiteName:   "TLS_AES_256_GCM_SHA384",
		NegotiatedGroupID: x25519mlkem768,
		LeafCertKeyAlgo:   "RSA",
		LeafCertKeySize:   2048,
	}

	ff := observationToFindings(result)
	if len(ff) == 0 {
		t.Fatal("expected findings, got none")
	}

	var kexAlgoName string
	for _, f := range ff {
		// Every finding must carry the session-level PQC metadata.
		if f.NegotiatedGroup != x25519mlkem768 {
			t.Errorf("finding %q: NegotiatedGroup=0x%04x, want 0x%04x",
				f.RawIdentifier, f.NegotiatedGroup, x25519mlkem768)
		}
		if f.NegotiatedGroupName != "X25519MLKEM768" {
			t.Errorf("finding %q: NegotiatedGroupName=%q, want X25519MLKEM768",
				f.RawIdentifier, f.NegotiatedGroupName)
		}
		if !f.PQCPresent {
			t.Errorf("finding %q: PQCPresent=false, want true", f.RawIdentifier)
		}
		if f.PQCMaturity != "final" {
			t.Errorf("finding %q: PQCMaturity=%q, want final", f.RawIdentifier, f.PQCMaturity)
		}

		// Track kex finding algorithm name.
		if f.Algorithm != nil && f.Algorithm.Primitive == "key-exchange" {
			kexAlgoName = f.Algorithm.Name
		}
	}

	// TLS 1.3 kex finding should use the group name, not the generic "ECDHE".
	if kexAlgoName != "X25519MLKEM768" {
		t.Errorf("TLS 1.3 kex finding Algorithm.Name=%q, want X25519MLKEM768", kexAlgoName)
	}
}

// TestObservationToFindings_ClassicalGroup verifies that a classical CurveID
// (X25519, 0x001d) keeps PQCPresent=false and the kex finding stays "ECDHE".
func TestObservationToFindings_ClassicalGroup(t *testing.T) {
	const x25519 = uint16(0x001d)

	result := ProbeResult{
		Target:            "classical-server.example.com:443",
		TLSVersion:        tls.VersionTLS13,
		CipherSuiteID:     tls.TLS_AES_128_GCM_SHA256,
		CipherSuiteName:   "TLS_AES_128_GCM_SHA256",
		NegotiatedGroupID: x25519,
		LeafCertKeyAlgo:   "ECDSA",
		LeafCertKeySize:   256,
	}

	ff := observationToFindings(result)
	if len(ff) == 0 {
		t.Fatal("expected findings, got none")
	}

	for _, f := range ff {
		if f.PQCPresent {
			t.Errorf("finding %q: PQCPresent=true for classical group X25519", f.RawIdentifier)
		}
		if f.NegotiatedGroup != x25519 {
			t.Errorf("finding %q: NegotiatedGroup=0x%04x, want 0x%04x",
				f.RawIdentifier, f.NegotiatedGroup, x25519)
		}
		if f.NegotiatedGroupName != "X25519" {
			t.Errorf("finding %q: NegotiatedGroupName=%q, want X25519", f.RawIdentifier, f.NegotiatedGroupName)
		}

		// kex finding should remain "ECDHE" for classical groups.
		if f.Algorithm != nil && f.Algorithm.Primitive == "key-exchange" {
			if f.Algorithm.Name != "ECDHE" {
				t.Errorf("classical kex finding Name=%q, want ECDHE", f.Algorithm.Name)
			}
		}
	}
}

// TestObservationToFindings_ZeroCurveID verifies that CurveID=0 (TLS 1.2 RSA KEM,
// no named group) results in PQCPresent=false and NegotiatedGroupName="".
func TestObservationToFindings_ZeroCurveID(t *testing.T) {
	result := ProbeResult{
		Target:            "rsa-server.example.com:443",
		TLSVersion:        tls.VersionTLS12,
		CipherSuiteID:     tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		CipherSuiteName:   "TLS_RSA_WITH_AES_256_GCM_SHA384",
		NegotiatedGroupID: 0, // no named group
		LeafCertKeyAlgo:   "RSA",
		LeafCertKeySize:   2048,
	}

	ff := observationToFindings(result)
	if len(ff) == 0 {
		t.Fatal("expected findings, got none")
	}

	for _, f := range ff {
		if f.PQCPresent {
			t.Errorf("finding %q: PQCPresent=true with zero CurveID", f.RawIdentifier)
		}
		if f.NegotiatedGroupName != "" {
			t.Errorf("finding %q: NegotiatedGroupName=%q, want empty", f.RawIdentifier, f.NegotiatedGroupName)
		}
		if f.NegotiatedGroup != 0 {
			t.Errorf("finding %q: NegotiatedGroup=0x%04x, want 0", f.RawIdentifier, f.NegotiatedGroup)
		}
	}
}

// TestObservationToFindings_DraftKyber verifies that draft Kyber codepoints
// (0x6399) set PQCPresent=true but PQCMaturity="draft".
func TestObservationToFindings_DraftKyber(t *testing.T) {
	const kyberDraft = uint16(0x6399)

	result := ProbeResult{
		Target:            "draft-kyber.example.com:443",
		TLSVersion:        tls.VersionTLS13,
		CipherSuiteID:     tls.TLS_AES_256_GCM_SHA384,
		CipherSuiteName:   "TLS_AES_256_GCM_SHA384",
		NegotiatedGroupID: kyberDraft,
		LeafCertKeyAlgo:   "ECDSA",
		LeafCertKeySize:   256,
	}

	ff := observationToFindings(result)
	if len(ff) == 0 {
		t.Fatal("expected findings, got none")
	}

	for _, f := range ff {
		if !f.PQCPresent {
			t.Errorf("finding %q: PQCPresent=false for draft Kyber", f.RawIdentifier)
		}
		if f.PQCMaturity != "draft" {
			t.Errorf("finding %q: PQCMaturity=%q, want draft", f.RawIdentifier, f.PQCMaturity)
		}
	}
}

// TestProbeResult_NegotiatedGroupIDField verifies that the field exists and
// can be set/read with a round-trip through the struct (compile-time check).
func TestProbeResult_NegotiatedGroupIDField(t *testing.T) {
	r := ProbeResult{NegotiatedGroupID: 0x11EC}
	if r.NegotiatedGroupID != 0x11EC {
		t.Fatalf("NegotiatedGroupID round-trip failed: got 0x%04x", r.NegotiatedGroupID)
	}
}
