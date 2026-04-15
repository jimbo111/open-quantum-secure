package findings

import (
	"strings"
	"testing"
)

// dedup_pqc_test.go — verifies that the asymmetric Algorithm.Name design
// used by the tls-probe engine (S1.1) does not cause unintended DedupeKey
// collisions or double-counting.
//
// Design recap (from classify.go):
//   - TLS 1.3 + PQC hybrid group  → kex finding Algorithm.Name = group name
//     (e.g., "X25519MLKEM768")
//   - TLS 1.3 + classical/unknown → kex finding Algorithm.Name = "ECDHE"
//
// Assertions:
//   1. PQC kex ("X25519MLKEM768") and classical kex ("ECDHE") from the same
//      target do NOT share a DedupeKey — they describe different sessions.
//   2. Two PQC kex findings from the same target DO share a DedupeKey —
//      they represent the same session observed by two engines (corroboration).
//   3. PQC kex findings from different targets do NOT share a DedupeKey —
//      different endpoints are always distinct.
//   4. DedupeKey includes Algorithm.Name — confirms that asymmetric naming
//      doesn't produce accidental merges.

// tlsKexFinding constructs a synthetic TLS-probe kex finding using the same
// path convention as tlsprobe/classify.go:
//
//	basePath = "(tls-probe)/" + target
//	kexPath  = basePath + "#kex"
func tlsKexFinding(target, algorithmName string) *UnifiedFinding {
	return &UnifiedFinding{
		Location: Location{
			File:         "(tls-probe)/" + target + "#kex",
			Line:         0,
			ArtifactType: "tls-endpoint",
		},
		Algorithm: &Algorithm{
			Name:      algorithmName,
			Primitive: "key-exchange",
		},
		SourceEngine: "tls-probe",
		Confidence:   ConfidenceHigh,
		Reachable:    ReachableYes,
	}
}

// TestDedupPQC_PQCAndClassicalKex_NoCollision verifies that a PQC kex finding
// ("X25519MLKEM768") and a classical kex finding ("ECDHE") from the same target
// produce DIFFERENT DedupeKeys. They represent different TLS sessions
// (PQC-negotiated vs classical) and must not be merged.
func TestDedupPQC_PQCAndClassicalKex_NoCollision(t *testing.T) {
	target := "example.com:443"
	pqcKex := tlsKexFinding(target, "X25519MLKEM768")
	classicalKex := tlsKexFinding(target, "ECDHE")

	kPQC := pqcKex.DedupeKey()
	kClassical := classicalKex.DedupeKey()

	if kPQC == kClassical {
		t.Errorf("PQC kex and classical kex for same target must not share a DedupeKey: %q", kPQC)
	}

	// Both keys must be non-empty and contain the algorithm name, confirming
	// that Algorithm.Name is part of the key (not elided).
	if !strings.Contains(kPQC, "X25519MLKEM768") {
		t.Errorf("PQC kex DedupeKey %q does not contain algorithm name 'X25519MLKEM768'", kPQC)
	}
	if !strings.Contains(kClassical, "ECDHE") {
		t.Errorf("classical kex DedupeKey %q does not contain algorithm name 'ECDHE'", kClassical)
	}
}

// TestDedupPQC_SamePQCSession_SharedKey verifies that two kex findings for the
// same PQC hybrid group from the same target share a DedupeKey. This models
// the corroboration case: two engines observe the same TLS 1.3 handshake on
// the same host and both emit an "X25519MLKEM768" kex finding.
func TestDedupPQC_SamePQCSession_SharedKey(t *testing.T) {
	target := "hybrid.example.com:443"
	f1 := tlsKexFinding(target, "X25519MLKEM768")
	f2 := tlsKexFinding(target, "X25519MLKEM768")
	// Different source engine simulates corroboration.
	f2.SourceEngine = "tls-probe-corroborator"

	if f1.DedupeKey() != f2.DedupeKey() {
		t.Errorf("same PQC session (same target + name) must share DedupeKey: %q vs %q",
			f1.DedupeKey(), f2.DedupeKey())
	}
}

// TestDedupPQC_DifferentTargets_NoCollision verifies that the same PQC group
// negotiated on two different hosts produces different DedupeKeys, preventing
// false-positive deduplication across endpoints.
func TestDedupPQC_DifferentTargets_NoCollision(t *testing.T) {
	f1 := tlsKexFinding("host-a.example.com:443", "X25519MLKEM768")
	f2 := tlsKexFinding("host-b.example.com:443", "X25519MLKEM768")

	if f1.DedupeKey() == f2.DedupeKey() {
		t.Errorf("same PQC group on different targets must NOT share a DedupeKey: %q", f1.DedupeKey())
	}
}

// TestDedupPQC_DraftVsFinalKex_NoCollision verifies that deprecated draft Kyber
// ("X25519Kyber768Draft00") and the final standardised hybrid ("X25519MLKEM768")
// produce distinct DedupeKeys even on the same target. They are different
// algorithm names and must not be merged.
func TestDedupPQC_DraftVsFinalKex_NoCollision(t *testing.T) {
	target := "transitioning.example.com:443"
	final := tlsKexFinding(target, "X25519MLKEM768")
	draft := tlsKexFinding(target, "X25519Kyber768Draft00")

	if final.DedupeKey() == draft.DedupeKey() {
		t.Errorf("final hybrid and deprecated draft on same target must not share DedupeKey: %q",
			final.DedupeKey())
	}
}

// TestDedupPQC_PrimitiveSuffix_KexVsSig verifies that the #kex vs #sig path
// suffix (set by tlsprobe/classify.go's primitiveToSuffix map) prevents
// collisions between RSA-as-kex and RSA-as-sig for the same target. This is
// orthogonal to PQC but validates that the suffix encoding still works when
// PQC fields are present.
func TestDedupPQC_PrimitiveSuffix_KexVsSig(t *testing.T) {
	target := "rsa.example.com:443"
	kexFinding := &UnifiedFinding{
		Location:    Location{File: "(tls-probe)/" + target + "#kex"},
		Algorithm:   &Algorithm{Name: "RSA", Primitive: "key-exchange"},
		SourceEngine: "tls-probe",
		PQCPresent:  false,
	}
	sigFinding := &UnifiedFinding{
		Location:    Location{File: "(tls-probe)/" + target + "#sig"},
		Algorithm:   &Algorithm{Name: "RSA", Primitive: "signature"},
		SourceEngine: "tls-probe",
		PQCPresent:  false,
	}

	if kexFinding.DedupeKey() == sigFinding.DedupeKey() {
		t.Errorf("RSA-kex and RSA-sig for same target must have different DedupeKeys: %q",
			kexFinding.DedupeKey())
	}
}

// TestDedupPQC_AsymmetricNaming_NoCrossEngineDoubleCount is the main design
// regression test. It constructs findings as the tls-probe engine would emit
// them from a single PQC-negotiated session:
//
//   - Cipher-suite component kex: "ECDHE" at #kex (from cipher suite decomp)
//     NOTE: for TLS 1.3 cipher suites, no kex component is emitted by the
//     cipher suite decomposition. But for TLS 1.2 ECDHE suites it would be.
//   - TLS-1.3 synthetic kex: "X25519MLKEM768" at #kex (group name)
//
// For TLS 1.3 there is only ONE kex finding (the synthetic one). This test
// verifies that if two findings with different algorithm names were somehow
// emitted for the same #kex path, they would NOT accidentally share a key.
func TestDedupPQC_AsymmetricNaming_NoCrossEngineDoubleCount(t *testing.T) {
	target := "pqc-host.example.com:443"

	// Hypothetical "ECDHE" finding at the same path as the PQC kex finding.
	ecdheFinding := &UnifiedFinding{
		Location:    Location{File: "(tls-probe)/" + target + "#kex"},
		Algorithm:   &Algorithm{Name: "ECDHE", Primitive: "key-exchange"},
		SourceEngine: "tls-probe",
	}
	// Actual PQC hybrid kex finding.
	pqcFinding := &UnifiedFinding{
		Location:    Location{File: "(tls-probe)/" + target + "#kex"},
		Algorithm:   &Algorithm{Name: "X25519MLKEM768", Primitive: "key-exchange"},
		SourceEngine: "tls-probe",
		PQCPresent:  true,
		PQCMaturity: "final",
	}

	kECDHE := ecdheFinding.DedupeKey()
	kPQC := pqcFinding.DedupeKey()

	// Different algorithm names → different keys → no accidental merge.
	if kECDHE == kPQC {
		t.Errorf("ECDHE and X25519MLKEM768 at the same path must not share a DedupeKey: %q", kECDHE)
	}
	t.Logf("ECDHE key: %s", kECDHE)
	t.Logf("PQC key:   %s", kPQC)
}
