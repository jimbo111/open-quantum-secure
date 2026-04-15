package compliance

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// ---------------------------------------------------------------------------
// SHA-2 family boundary disambiguation
// ---------------------------------------------------------------------------

// TestEvaluate_SHA384_NotMistakenForSHA3 is a regression guard for the
// SHA-3/SHA-2 prefix collision: "SHA-384" starts with "SHA-3" so the
// isSHA3 detection must check for "SHA-3-" (with trailing dash) or "SHA3-",
// not just "SHA-3" prefix.
// GAP: if this test fails, the SHA-3 detection regex is too broad and will
// incorrectly flag SHA-384 as SHA-3 (unapproved), causing false positives.
func TestEvaluate_SHA384_NotMistakenForSHA3(t *testing.T) {
	f := algFinding("SHA-384", "hash", 0, findings.QRResistant, "")
	violations := Evaluate([]findings.UnifiedFinding{f})
	if len(violations) != 0 {
		t.Errorf("SHA-384 should not be flagged — it's SHA-2 (384-bit), not SHA-3; got violations: %+v", violations)
	}
}

// TestEvaluate_SHA3_256_IsUnapproved verifies that SHA3-256 (SHA-3 family)
// is correctly flagged as unapproved.
func TestEvaluate_SHA3_256_IsUnapproved(t *testing.T) {
	f := algFinding("SHA3-256", "hash", 256, findings.QRResistant, "")
	violations := Evaluate([]findings.UnifiedFinding{f})
	if len(violations) == 0 {
		t.Error("SHA3-256 should be flagged as unapproved for CNSA 2.0 (not SHA-2 family)")
	}
	if len(violations) > 0 && violations[0].Rule != "cnsa2-hash-unapproved" {
		t.Errorf("expected cnsa2-hash-unapproved, got %q", violations[0].Rule)
	}
}

// TestEvaluate_SHA3_512_IsUnapproved verifies that even the 512-bit SHA-3
// variant is flagged — it's a different family from SHA-512.
func TestEvaluate_SHA3_512_IsUnapproved(t *testing.T) {
	f := algFinding("SHA3-512", "hash", 512, findings.QRResistant, "")
	violations := Evaluate([]findings.UnifiedFinding{f})
	if len(violations) == 0 {
		t.Error("SHA3-512 (SHA-3 family) should be flagged — CNSA 2.0 only approves SHA-2")
	}
}

// TestEvaluate_SHA256_Flagged verifies that SHA-256 (insufficient output size)
// produces exactly one cnsa2-hash-output-size violation.
func TestEvaluate_SHA256_Flagged(t *testing.T) {
	f := algFinding("SHA-256", "hash", 256, findings.QRResistant, "")
	violations := Evaluate([]findings.UnifiedFinding{f})
	if len(violations) != 1 {
		t.Fatalf("SHA-256 should have 1 violation, got %d: %+v", len(violations), violations)
	}
	if violations[0].Rule != "cnsa2-hash-output-size" {
		t.Errorf("rule = %q, want cnsa2-hash-output-size", violations[0].Rule)
	}
}

// ---------------------------------------------------------------------------
// AES key-size inference exhaustion
// ---------------------------------------------------------------------------

// TestEvaluate_AES128_Flagged ensures AES-128 produces a key-size violation.
func TestEvaluate_AES128_Flagged(t *testing.T) {
	f := algFinding("AES-128", "symmetric", 128, findings.QRWeakened, "")
	violations := Evaluate([]findings.UnifiedFinding{f})
	if len(violations) != 1 {
		t.Fatalf("AES-128 should have 1 violation, got %d: %+v", len(violations), violations)
	}
	if violations[0].Rule != "cnsa2-symmetric-key-size" {
		t.Errorf("rule = %q, want cnsa2-symmetric-key-size", violations[0].Rule)
	}
	if violations[0].Deadline != deadlineFull {
		t.Errorf("deadline = %q, want %q", violations[0].Deadline, deadlineFull)
	}
}

// TestEvaluate_AES256_Passes verifies AES-256 does not produce a violation.
func TestEvaluate_AES256_Passes(t *testing.T) {
	f := algFinding("AES-256", "symmetric", 256, findings.QRResistant, "")
	violations := Evaluate([]findings.UnifiedFinding{f})
	if len(violations) != 0 {
		t.Errorf("AES-256 should not be flagged; got: %+v", violations)
	}
}

// ---------------------------------------------------------------------------
// ML-KEM parameter set edge cases
// ---------------------------------------------------------------------------

// TestEvaluate_MLKEM768_Flagged verifies ML-KEM-768 (sub-1024) is flagged.
func TestEvaluate_MLKEM768_Flagged(t *testing.T) {
	f := algFinding("ML-KEM-768", "kem", 0, findings.QRSafe, "immediate")
	violations := Evaluate([]findings.UnifiedFinding{f})
	if len(violations) != 1 {
		t.Fatalf("ML-KEM-768 should have 1 violation, got %d: %+v", len(violations), violations)
	}
	if violations[0].Rule != "cnsa2-ml-kem-key-size" {
		t.Errorf("rule = %q, want cnsa2-ml-kem-key-size", violations[0].Rule)
	}
}

// TestEvaluate_MLKEM1024_Passes verifies ML-KEM-1024 passes with no violation.
func TestEvaluate_MLKEM1024_Passes(t *testing.T) {
	f := algFinding("ML-KEM-1024", "kem", 0, findings.QRSafe, "immediate")
	violations := Evaluate([]findings.UnifiedFinding{f})
	if len(violations) != 0 {
		t.Errorf("ML-KEM-1024 should not be flagged; got: %+v", violations)
	}
}

// ---------------------------------------------------------------------------
// ML-DSA parameter set edge cases
// ---------------------------------------------------------------------------

// TestEvaluate_MLDSA65_Flagged verifies ML-DSA-65 (sub-87) is flagged.
func TestEvaluate_MLDSA65_Flagged(t *testing.T) {
	f := algFinding("ML-DSA-65", "signature", 0, findings.QRSafe, "deferred")
	violations := Evaluate([]findings.UnifiedFinding{f})
	if len(violations) != 1 {
		t.Fatalf("ML-DSA-65 should have 1 violation, got %d: %+v", len(violations), violations)
	}
	if violations[0].Rule != "cnsa2-ml-dsa-param-set" {
		t.Errorf("rule = %q, want cnsa2-ml-dsa-param-set", violations[0].Rule)
	}
}

// TestEvaluate_MLDSA87_Passes verifies ML-DSA-87 passes.
func TestEvaluate_MLDSA87_Passes(t *testing.T) {
	f := algFinding("ML-DSA-87", "signature", 0, findings.QRSafe, "deferred")
	violations := Evaluate([]findings.UnifiedFinding{f})
	if len(violations) != 0 {
		t.Errorf("ML-DSA-87 should not be flagged; got: %+v", violations)
	}
}

// ---------------------------------------------------------------------------
// SLH-DSA excluded despite NIST approval
// ---------------------------------------------------------------------------

// TestEvaluate_SLHDSAExcluded_HasCorrectDeadline verifies the deadline for
// SLH-DSA violations is the full transition deadline, not key exchange deadline.
func TestEvaluate_SLHDSAExcluded_HasCorrectDeadline(t *testing.T) {
	f := algFinding("SLH-DSA-128f", "signature", 0, findings.QRSafe, "deferred")
	violations := Evaluate([]findings.UnifiedFinding{f})
	if len(violations) != 1 {
		t.Fatalf("SLH-DSA should have 1 violation, got %d", len(violations))
	}
	if violations[0].Deadline != deadlineFull {
		t.Errorf("SLH-DSA deadline = %q, want %q (full transition)", violations[0].Deadline, deadlineFull)
	}
}

// ---------------------------------------------------------------------------
// HQC not yet approved
// ---------------------------------------------------------------------------

// TestEvaluate_HQC_HasKeyExchangeDeadline verifies the HQC deadline is the
// key-exchange deadline (not the full transition deadline).
func TestEvaluate_HQC_HasKeyExchangeDeadline(t *testing.T) {
	f := algFinding("HQC-256", "kem", 0, findings.QRSafe, "immediate")
	violations := Evaluate([]findings.UnifiedFinding{f})
	if len(violations) != 1 {
		t.Fatalf("HQC-256 should have 1 violation, got %d", len(violations))
	}
	if violations[0].Deadline != deadlineKeyExchange {
		t.Errorf("HQC deadline = %q, want %q (key exchange)", violations[0].Deadline, deadlineKeyExchange)
	}
}

// ---------------------------------------------------------------------------
// Non-AES symmetric ciphers
// ---------------------------------------------------------------------------

// TestEvaluate_ChaCha20_Unapproved verifies ChaCha20 is flagged as not CNSA
// 2.0 approved (only AES-256 is approved for symmetric).
func TestEvaluate_ChaCha20_Unapproved(t *testing.T) {
	f := algFinding("ChaCha20-Poly1305", "ae", 256, findings.QRResistant, "")
	violations := Evaluate([]findings.UnifiedFinding{f})
	if len(violations) != 1 {
		t.Fatalf("ChaCha20 should have 1 violation, got %d: %+v", len(violations), violations)
	}
	if violations[0].Rule != "cnsa2-symmetric-unapproved" {
		t.Errorf("rule = %q, want cnsa2-symmetric-unapproved", violations[0].Rule)
	}
}

// TestEvaluate_Camellia_Unapproved verifies Camellia is flagged as unapproved.
func TestEvaluate_Camellia_Unapproved(t *testing.T) {
	f := algFinding("Camellia-256", "symmetric", 256, findings.QRResistant, "")
	violations := Evaluate([]findings.UnifiedFinding{f})
	if len(violations) != 1 {
		t.Fatalf("Camellia should have 1 violation, got %d: %+v", len(violations), violations)
	}
	if violations[0].Rule != "cnsa2-symmetric-unapproved" {
		t.Errorf("rule = %q, want cnsa2-symmetric-unapproved", violations[0].Rule)
	}
}

// ---------------------------------------------------------------------------
// Quantum-vulnerable dependency
// ---------------------------------------------------------------------------

// TestEvaluate_QuantumVulnerableDependency_FlaggedWithAlgorithmEmpty verifies
// that a dependency finding (no Algorithm field) with QRVulnerable risk is
// flagged, and the Violation.Algorithm is set from RawIdentifier.
func TestEvaluate_QuantumVulnerableDependency_AlgorithmFromRawIdentifier(t *testing.T) {
	f := depFinding("openssl-1.0.2k", findings.QRVulnerable, "immediate")
	violations := Evaluate([]findings.UnifiedFinding{f})
	if len(violations) != 1 {
		t.Fatalf("quantum-vulnerable dependency should have 1 violation, got %d: %+v", len(violations), violations)
	}
	if violations[0].Algorithm != "openssl-1.0.2k" {
		t.Errorf("violation.Algorithm = %q, want openssl-1.0.2k (from RawIdentifier)", violations[0].Algorithm)
	}
}

// TestEvaluate_QuantumSafeDependency_NotFlagged verifies that a quantum-safe
// dependency produces no violation (the nil-algorithm path should be no-op
// for safe findings).
func TestEvaluate_QuantumSafeDependency_NotFlagged(t *testing.T) {
	f := depFinding("liboqs", findings.QRSafe, "")
	violations := Evaluate([]findings.UnifiedFinding{f})
	if len(violations) != 0 {
		t.Errorf("quantum-safe dependency should not be flagged; got: %+v", violations)
	}
}

// ---------------------------------------------------------------------------
// DeadlineForHNDL helper
// ---------------------------------------------------------------------------

// TestDeadlineForHNDL_ImmediateGetsKeyExchangeDeadline verifies "immediate"
// HNDL risk maps to the earlier 2030 key exchange deadline.
func TestDeadlineForHNDL_ImmediateGetsKeyExchangeDeadline(t *testing.T) {
	got := deadlineForHNDL("immediate")
	if got != deadlineKeyExchange {
		t.Errorf("deadlineForHNDL(immediate) = %q, want %q", got, deadlineKeyExchange)
	}
}

// TestDeadlineForHNDL_EmptyGetsFull verifies empty or "deferred" HNDL risk
// maps to the full transition deadline.
func TestDeadlineForHNDL_OtherGetsFull(t *testing.T) {
	for _, hndl := range []string{"", "deferred", "unknown-value"} {
		got := deadlineForHNDL(hndl)
		if got != deadlineFull {
			t.Errorf("deadlineForHNDL(%q) = %q, want %q", hndl, got, deadlineFull)
		}
	}
}

// ---------------------------------------------------------------------------
// Nil and empty input guards
// ---------------------------------------------------------------------------

// TestEvaluate_NilInput_ReturnsNilViolations verifies nil input returns nil
// (not an empty slice) to satisfy existing callers.
func TestEvaluate_NilInput_ReturnsNil(t *testing.T) {
	v := Evaluate(nil)
	if v != nil {
		t.Errorf("nil input should return nil violations, got %v", v)
	}
}

// TestEvaluate_AllApproved_NilReturn verifies that all-approved input returns
// nil (not empty slice) as documented.
func TestEvaluate_AllApproved_ReturnsNil(t *testing.T) {
	ff := []findings.UnifiedFinding{
		algFinding("ML-KEM-1024", "kem", 0, findings.QRSafe, "immediate"),
		algFinding("ML-DSA-87", "signature", 0, findings.QRSafe, "deferred"),
		algFinding("AES-256-GCM", "symmetric", 256, findings.QRResistant, ""),
		algFinding("SHA-384", "hash", 384, findings.QRResistant, ""),
	}
	v := Evaluate(ff)
	if v != nil {
		t.Errorf("all-approved findings should return nil violations; got %v", v)
	}
}
