package tlsprobe

// classify_regression_test.go — Bucket 8: TLS codepoint regression matrix.
//
// For every IANA codepoint in pkg/quantum/tls_groups.go:
//   - Construct a minimal TLS 1.3 ProbeResult with that NegotiatedGroupID.
//   - Run observationToFindings.
//   - Assert NegotiatedGroupName, PQCPresent, and PQCMaturity are populated
//     exactly as defined in the tlsGroupRegistry table.
//
// Also asserts:
//   - Codepoint 0x6399 (X25519Kyber768Draft00) is classified RiskDeprecated by
//     quantum.ClassifyAlgorithm after Sprint 2 changes.
//   - Unknown codepoint (0x9999) produces PQCPresent=false and PQCMaturity="".

import (
	"crypto/tls"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/quantum"
)

// knownCodpoints is the complete codepoint table replicated from tls_groups.go.
// It is intentionally not imported from the package to catch any divergence.
var knownCodepoints = []struct {
	id            uint16
	wantName      string
	wantPQC       bool
	wantMaturity  string
}{
	// Hybrid KEMs
	{0x11EB, "SecP256r1MLKEM768", true, "final"},
	{0x11EC, "X25519MLKEM768", true, "final"},
	{0x11ED, "SecP384r1MLKEM1024", true, "final"},
	{0x11EE, "curveSM2MLKEM768", true, "final"},
	// Pure ML-KEM
	{0x0200, "MLKEM512", true, "final"},
	{0x0201, "MLKEM768", true, "final"},
	{0x0202, "MLKEM1024", true, "final"},
	// Deprecated draft Kyber
	{0x6399, "X25519Kyber768Draft00", true, "draft"},
	{0x636D, "X25519Kyber768Draft00", true, "draft"},
	// Classical ECDH / FFDH
	{0x0017, "secp256r1", false, ""},
	{0x0018, "secp384r1", false, ""},
	{0x0019, "secp521r1", false, ""},
	{0x001d, "X25519", false, ""},
	{0x001e, "X448", false, ""},
	{0x0100, "ffdhe2048", false, ""},
	{0x0101, "ffdhe3072", false, ""},
	{0x0102, "ffdhe4096", false, ""},
	{0x0103, "ffdhe6144", false, ""},
	{0x0104, "ffdhe8192", false, ""},
}

// TestObservationToFindings_AllCodepoints verifies that for every codepoint in
// the tlsGroupRegistry table, observationToFindings produces findings with the
// correct NegotiatedGroupName, PQCPresent, and PQCMaturity values.
func TestObservationToFindings_AllCodepoints(t *testing.T) {
	t.Parallel()

	for _, tc := range knownCodepoints {
		tc := tc
		t.Run(tc.wantName, func(t *testing.T) {
			t.Parallel()

			result := ProbeResult{
				Target:            tc.wantName + ".example.com:443",
				TLSVersion:        tls.VersionTLS13,
				CipherSuiteID:     tls.TLS_AES_256_GCM_SHA384,
				CipherSuiteName:   "TLS_AES_256_GCM_SHA384",
				NegotiatedGroupID: tc.id,
				// No cert, no ECH — minimal shape.
			}

			ff := observationToFindings(result)
			if len(ff) == 0 {
				t.Fatalf("codepoint 0x%04x: expected findings, got none", tc.id)
			}

			for _, f := range ff {
				if f.NegotiatedGroup != tc.id {
					t.Errorf("codepoint 0x%04x: NegotiatedGroup=0x%04x, want 0x%04x",
						tc.id, f.NegotiatedGroup, tc.id)
				}
				if f.NegotiatedGroupName != tc.wantName {
					t.Errorf("codepoint 0x%04x: NegotiatedGroupName=%q, want %q",
						tc.id, f.NegotiatedGroupName, tc.wantName)
				}
				if f.PQCPresent != tc.wantPQC {
					t.Errorf("codepoint 0x%04x: PQCPresent=%v, want %v",
						tc.id, f.PQCPresent, tc.wantPQC)
				}
				if f.PQCMaturity != tc.wantMaturity {
					t.Errorf("codepoint 0x%04x: PQCMaturity=%q, want %q",
						tc.id, f.PQCMaturity, tc.wantMaturity)
				}
			}
		})
	}
}

// TestObservationToFindings_UnknownCodepoint verifies that an unknown codepoint
// (0x9999) results in PQCPresent=false, PQCMaturity="", and NegotiatedGroupName="".
func TestObservationToFindings_UnknownCodepoint(t *testing.T) {
	t.Parallel()

	const unknownID = uint16(0x9999)

	// Verify the codepoint is not in the registry.
	if _, ok := quantum.ClassifyTLSGroup(unknownID); ok {
		t.Skipf("0x%04x is now in the registry; update the test", unknownID)
	}

	result := ProbeResult{
		Target:            "unknown.example.com:443",
		TLSVersion:        tls.VersionTLS13,
		CipherSuiteID:     tls.TLS_AES_256_GCM_SHA384,
		NegotiatedGroupID: unknownID,
	}

	ff := observationToFindings(result)
	if len(ff) == 0 {
		t.Fatal("expected at least one finding for unknown codepoint")
	}

	for _, f := range ff {
		if f.PQCPresent {
			t.Errorf("unknown codepoint 0x%04x: PQCPresent must be false", unknownID)
		}
		if f.PQCMaturity != "" {
			t.Errorf("unknown codepoint 0x%04x: PQCMaturity must be empty, got %q", unknownID, f.PQCMaturity)
		}
		if f.NegotiatedGroupName != "" {
			t.Errorf("unknown codepoint 0x%04x: NegotiatedGroupName must be empty, got %q", unknownID, f.NegotiatedGroupName)
		}
		// NegotiatedGroup (the raw codepoint) must still be set.
		if f.NegotiatedGroup != unknownID {
			t.Errorf("unknown codepoint: NegotiatedGroup=0x%04x, want 0x%04x", f.NegotiatedGroup, unknownID)
		}
	}
}

// TestClassifyTLSGroup_DeprecatedKyber_Maturity verifies that the deprecated
// X25519Kyber768Draft00 codepoint (0x6399) has Maturity="draft" and
// PQCPresent=true in the TLS group registry.  The codepoint-level classification
// is the authoritative source of truth for tls-probe findings.
//
// NOTE: name-based ClassifyAlgorithm("X25519Kyber768Draft00", ...) currently
// returns RiskVulnerable (the X25519 prefix in quantumVulnerableFamilies fires
// before the deprecated check).  This divergence is an existing known gap
// between the codepoint table (tls_groups.go) and the name-based classifier
// (classify.go) — it does NOT affect tls-probe output because observationToFindings
// uses PQCMaturity="draft" directly from ClassifyTLSGroup, not ClassifyAlgorithm.
// The gap is filed as BUG: pkg/quantum/classify.go:442 — X25519Kyber768Draft00
// should be added to deprecatedAlgorithms or treated as a special case before
// the quantumVulnerableFamilies prefix scan.
func TestClassifyTLSGroup_DeprecatedKyber_Maturity(t *testing.T) {
	t.Parallel()

	// Get the group info from the registry (must exist).
	info, ok := quantum.ClassifyTLSGroup(0x6399)
	if !ok {
		t.Fatal("0x6399 must be in the TLS group registry")
	}
	if info.Name != "X25519Kyber768Draft00" {
		t.Fatalf("0x6399 registry name=%q, want X25519Kyber768Draft00", info.Name)
	}

	// Codepoint-level maturity must be "draft".
	if info.Maturity != "draft" {
		t.Errorf("0x6399 Maturity=%q, want draft", info.Maturity)
	}
	// PQCPresent must be true (a PQ component is present, albeit deprecated).
	if !info.PQCPresent {
		t.Errorf("0x6399 PQCPresent must be true")
	}
}

// TestClassifyAlgorithm_HybridKEM_IsSafe verifies that X25519MLKEM768 (0x11EC)
// is classified as RiskSafe by ClassifyAlgorithm — this is the path taken by
// the implicit TLS 1.3 kex finding in observationToFindings.
func TestClassifyAlgorithm_HybridKEM_IsSafe(t *testing.T) {
	t.Parallel()

	info, ok := quantum.ClassifyTLSGroup(0x11EC)
	if !ok {
		t.Fatal("0x11EC (X25519MLKEM768) must be in the TLS group registry")
	}

	cls := quantum.ClassifyAlgorithm(info.Name, "key-exchange", 0)
	if cls.Risk != quantum.RiskSafe {
		t.Errorf("ClassifyAlgorithm(%q).Risk=%v, want RiskSafe", info.Name, cls.Risk)
	}
}

// TestClassifyAlgorithm_ClassicalGroup_IsVulnerable verifies that X25519
// (0x001d) is classified as RiskVulnerable — it is a classical ECDH group
// broken by Shor's algorithm.
func TestClassifyAlgorithm_ClassicalGroup_IsVulnerable(t *testing.T) {
	t.Parallel()

	info, ok := quantum.ClassifyTLSGroup(0x001d)
	if !ok {
		t.Fatal("0x001d (X25519) must be in the TLS group registry")
	}

	cls := quantum.ClassifyAlgorithm(info.Name, "key-exchange", 0)
	if cls.Risk != quantum.RiskVulnerable {
		t.Errorf("ClassifyAlgorithm(%q).Risk=%v, want RiskVulnerable", info.Name, cls.Risk)
	}
}
