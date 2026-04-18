package tlsprobe

// backcompat_test.go — Bucket 7: Sprint 0/1 integration backcompat tests.
//
// Verifies that Sprint 2 changes to observationToFindings do not break callers
// that pass Sprint-1-era ProbeResult shapes (ECH fields zero-valued).  Also
// verifies the Volume + PQC dual-signal path introduced in Sprint 2.

import (
	"crypto/tls"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// TestObservationToFindings_Sprint1Shape_NoPartialInventory verifies that a
// ProbeResult shaped exactly like Sprint 1 (ECHDetected=false, ECHSource="",
// no HandshakeVolumeClass field set) produces findings with PartialInventory=false
// and PartialInventoryReason="".
func TestObservationToFindings_Sprint1Shape_NoPartialInventory(t *testing.T) {
	t.Parallel()

	// Sprint 1 ProbeResult: no ECH fields, no HandshakeVolumeClass.
	result := ProbeResult{
		Target:          "classic.example.com:443",
		TLSVersion:      tls.VersionTLS13,
		CipherSuiteID:   tls.TLS_AES_256_GCM_SHA384,
		CipherSuiteName: "TLS_AES_256_GCM_SHA384",
		LeafCertKeyAlgo: "RSA",
		LeafCertKeySize: 2048,
		NegotiatedGroupID: 0x001d, // X25519
		// Sprint 2 fields left zero-valued.
		ECHDetected:          false,
		ECHSource:            "",
		HandshakeVolumeClass: "",
	}

	ff := observationToFindings(result)
	if len(ff) == 0 {
		t.Fatal("expected findings from Sprint-1-shape ProbeResult")
	}

	for _, f := range ff {
		if f.PartialInventory {
			t.Errorf("Sprint-1-shape finding must not have PartialInventory=true; got true for %q",
				f.RawIdentifier)
		}
		if f.PartialInventoryReason != "" {
			t.Errorf("Sprint-1-shape finding must not have PartialInventoryReason set; got %q",
				f.PartialInventoryReason)
		}
	}
}

// TestObservationToFindings_Sprint1Shape_NegotiatedGroupFields verifies that
// the Sprint-1 NegotiatedGroup / NegotiatedGroupName / PQCPresent / PQCMaturity
// fields are still populated correctly for a known classical group (X25519).
func TestObservationToFindings_Sprint1Shape_NegotiatedGroupFields(t *testing.T) {
	t.Parallel()

	result := ProbeResult{
		Target:            "x25519.example.com:443",
		TLSVersion:        tls.VersionTLS13,
		CipherSuiteID:     tls.TLS_AES_256_GCM_SHA384,
		NegotiatedGroupID: 0x001d, // X25519
		LeafCertKeyAlgo:   "ECDSA",
		LeafCertKeySize:   256,
	}

	ff := observationToFindings(result)
	if len(ff) == 0 {
		t.Fatal("expected findings")
	}

	for _, f := range ff {
		if f.NegotiatedGroup != 0x001d {
			t.Errorf("NegotiatedGroup=0x%04x, want 0x001d", f.NegotiatedGroup)
		}
		if f.NegotiatedGroupName != "X25519" {
			t.Errorf("NegotiatedGroupName=%q, want X25519", f.NegotiatedGroupName)
		}
		if f.PQCPresent {
			t.Error("PQCPresent must be false for X25519 (classical)")
		}
		if f.PQCMaturity != "" {
			t.Errorf("PQCMaturity=%q, want empty for classical group", f.PQCMaturity)
		}
	}
}

// TestObservationToFindings_FullPQCAndECH_NoDedupeCollision verifies that a
// ProbeResult with HandshakeVolumeClass="full-pqc", PQCPresent=true (via
// X25519MLKEM768 group), and ECHDetected=true produces findings that:
//   1. All carry PartialInventory=true.
//   2. PQCPresent=true and PQCMaturity="final" are set.
//   3. No two findings share the same RawIdentifier (no dedupe collision).
func TestObservationToFindings_FullPQCAndECH_NoDedupeCollision(t *testing.T) {
	t.Parallel()

	result := ProbeResult{
		Target:               "pqcech.example.com:443",
		TLSVersion:           tls.VersionTLS13,
		CipherSuiteID:        tls.TLS_AES_256_GCM_SHA384,
		CipherSuiteName:      "TLS_AES_256_GCM_SHA384",
		NegotiatedGroupID:    0x11EC, // X25519MLKEM768
		LeafCertKeyAlgo:      "RSA",
		LeafCertKeySize:      2048,
		HandshakeVolumeClass: "full-pqc",
		ECHDetected:          true,
		ECHSource:            "dns-https-rr",
	}

	ff := observationToFindings(result)
	if len(ff) == 0 {
		t.Fatal("expected findings")
	}

	// All findings must carry PartialInventory annotation (ECH detected).
	for _, f := range ff {
		if !f.PartialInventory {
			t.Errorf("finding %q must have PartialInventory=true (ECH detected)", f.RawIdentifier)
		}
		if f.PartialInventoryReason != "ECH_ENABLED" {
			t.Errorf("finding %q: PartialInventoryReason=%q, want ECH_ENABLED", f.RawIdentifier, f.PartialInventoryReason)
		}
	}

	// At least one finding must carry PQCPresent=true (from X25519MLKEM768).
	var hasPQC bool
	for _, f := range ff {
		if f.PQCPresent {
			hasPQC = true
			if f.PQCMaturity != "final" {
				t.Errorf("PQCMaturity=%q, want final for X25519MLKEM768", f.PQCMaturity)
			}
		}
	}
	if !hasPQC {
		t.Error("expected at least one finding with PQCPresent=true for X25519MLKEM768")
	}

	// All RawIdentifiers must be unique.
	seen := make(map[string]bool)
	for _, f := range ff {
		if seen[f.RawIdentifier] {
			t.Errorf("duplicate RawIdentifier=%q (dedupe collision)", f.RawIdentifier)
		}
		seen[f.RawIdentifier] = true
	}
}

// TestObservationToFindings_Sprint1_PQCHybridKex verifies the TLS 1.3 implicit
// kex finding uses the group name (X25519MLKEM768) not "ECDHE" when PQCPresent=true,
// ensuring Sprint 1 classification works correctly after Sprint 2 changes.
func TestObservationToFindings_Sprint1_PQCHybridKex(t *testing.T) {
	t.Parallel()

	result := ProbeResult{
		Target:            "hybrid.example.com:443",
		TLSVersion:        tls.VersionTLS13,
		CipherSuiteID:     tls.TLS_AES_128_GCM_SHA256,
		CipherSuiteName:   "TLS_AES_128_GCM_SHA256",
		NegotiatedGroupID: 0x11EC, // X25519MLKEM768
		// No ECH, no volume class — Sprint 1 shape.
	}

	ff := observationToFindings(result)

	var kexFinding *findings.UnifiedFinding
	for i := range ff {
		f := &ff[i]
		if f.Algorithm != nil && f.Algorithm.Primitive == "key-exchange" &&
			f.RawIdentifier == "kex:X25519MLKEM768|"+result.Target {
			kexFinding = f
			break
		}
	}
	if kexFinding == nil {
		t.Fatal("expected a kex finding with Algorithm.Name=X25519MLKEM768 for TLS 1.3 PQC hybrid")
	}
	if kexFinding.Algorithm.Name != "X25519MLKEM768" {
		t.Errorf("kex finding Algorithm.Name=%q, want X25519MLKEM768", kexFinding.Algorithm.Name)
	}
}

// TestObservationToFindings_NoECH_FieldsAbsent verifies that when ECHDetected=false
// (the normal Sprint 0/1 path) the PartialInventory fields are absent (false/"").
func TestObservationToFindings_NoECH_FieldsAbsent(t *testing.T) {
	t.Parallel()

	result := ProbeResult{
		Target:          "noech.example.com:443",
		TLSVersion:      tls.VersionTLS12,
		CipherSuiteID:   tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		CipherSuiteName: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		LeafCertKeyAlgo: "RSA",
		LeafCertKeySize: 4096,
		ECHDetected:     false,
	}

	ff := observationToFindings(result)
	if len(ff) == 0 {
		t.Fatal("expected findings")
	}

	for _, f := range ff {
		if f.PartialInventory {
			t.Errorf("ECHDetected=false: PartialInventory must be false, got true for %q", f.RawIdentifier)
		}
	}
}
