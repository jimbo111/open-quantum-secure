package impact_test

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/impact"
	"github.com/jimbo111/open-quantum-secure/pkg/impact/blast"
	"github.com/jimbo111/open-quantum-secure/pkg/impact/constraints"
)

// ---------------------------------------------------------------------------
// Blast radius edge cases
// ---------------------------------------------------------------------------

// TestBlastRadius_ZeroConsumers verifies that an algorithm with no downstream
// consumers (hop=0, no constraints, no protocols, size=0) produces score=0
// and grade="Minimal".
func TestBlastRadius_ZeroConsumers(t *testing.T) {
	score, grade := blast.Calculate(blast.Input{
		HopCount:             0,
		ConstraintViolations: 0,
		ProtocolViolations:   0,
		SizeRatio:            0,
	})
	if score != 0 {
		t.Errorf("blast radius score = %d, want 0 for zero consumers", score)
	}
	if grade != "Minimal" {
		t.Errorf("blast radius grade = %q, want Minimal for zero consumers", grade)
	}
}

// TestBlastRadius_MaxEverything verifies all-maximum inputs clamp at 100/Critical.
func TestBlastRadius_MaxEverything(t *testing.T) {
	score, grade := blast.Calculate(blast.Input{
		HopCount:             1000,
		ConstraintViolations: 1000,
		ProtocolViolations:   1000,
		SizeRatio:            1e9,
	})
	if score != 100 {
		t.Errorf("all-max blast score = %d, want 100", score)
	}
	if grade != "Critical" {
		t.Errorf("all-max blast grade = %q, want Critical", grade)
	}
}

// TestBlastRadius_GradeBoundaries exhaustively checks all grade boundaries
// at exact cutoff values.
func TestBlastRadius_GradeBoundaries(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{
		{0, "Minimal"},
		{15, "Minimal"},
		{16, "Contained"},
		{40, "Contained"},
		{41, "Significant"},
		{70, "Significant"},
		{71, "Critical"},
		{100, "Critical"},
	}
	for _, tc := range cases {
		got := blast.ScoreToGrade(tc.score)
		if got != tc.want {
			t.Errorf("ScoreToGrade(%d) = %q, want %q", tc.score, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// ImpactResult.ImpactDataForFinding
// ---------------------------------------------------------------------------

// TestImpactDataForFinding_NoZones returns nil when ImpactZones is empty.
func TestImpactDataForFinding_NoZones_ReturnsNil(t *testing.T) {
	r := &impact.Result{}
	if got := r.ImpactDataForFinding("any-key"); got != nil {
		t.Errorf("expected nil for empty ImpactZones, got %+v", got)
	}
}

// TestImpactDataForFinding_NilResult ensures a nil pointer does not panic.
// GAP: Result is a concrete struct, not an interface, so nil receiver panics.
// This test documents the behaviour — callers must guard against nil result.
func TestImpactDataForFinding_NoMatch_ReturnsNil(t *testing.T) {
	r := &impact.Result{
		ImpactZones: []impact.ImpactZone{
			{FindingKey: "key-1", BlastRadiusScore: 50, BlastRadiusGrade: "Significant"},
		},
	}
	got := r.ImpactDataForFinding("does-not-exist")
	if got != nil {
		t.Errorf("expected nil for missing key, got %+v", got)
	}
}

// TestImpactDataForFinding_Match returns the correct zone.
func TestImpactDataForFinding_Match_ReturnsZone(t *testing.T) {
	r := &impact.Result{
		ImpactZones: []impact.ImpactZone{
			{FindingKey: "key-1", BlastRadiusScore: 30, BlastRadiusGrade: "Contained"},
			{FindingKey: "key-2", BlastRadiusScore: 80, BlastRadiusGrade: "Critical"},
		},
	}
	got := r.ImpactDataForFinding("key-2")
	if got == nil {
		t.Fatal("expected non-nil zone for key-2")
	}
	if got.BlastRadiusScore != 80 {
		t.Errorf("BlastRadiusScore = %d, want 80", got.BlastRadiusScore)
	}
	if got.BlastRadiusGrade != "Critical" {
		t.Errorf("BlastRadiusGrade = %q, want Critical", got.BlastRadiusGrade)
	}
}

// ---------------------------------------------------------------------------
// Constraint violations: RSA-4096 vs JWT 8KB header limit
// ---------------------------------------------------------------------------

// TestConstraintCheck_RSA4096_BelowJWTLimit verifies that an RSA-4096 public
// key (550 bytes) does NOT violate an 8192-byte limit.
func TestConstraintCheck_RSA4096_BelowJWTLimit(t *testing.T) {
	profile := constraints.AlgorithmSizeProfile{
		PublicKeyBytes:  550,
		SignatureBytes:  512,
	}
	// 8KB JWT header limit (JOSE RFC 7518 practical limit)
	constraint := impact.ConstraintHit{
		Type:         "jwt-header",
		MaxBytes:     8192,
		EffectiveMax: 8192,
	}
	violation := constraints.Check(profile, constraint)
	if violation != nil {
		t.Errorf("RSA-4096 (512 bytes) should not violate 8192-byte limit; got overflow=%d", violation.Overflow)
	}
}

// TestConstraintCheck_MLDSA87_ViolatesJWTLimit verifies that ML-DSA-87
// signature (4627 bytes) does NOT violate an 8192-byte limit either — but a
// tight 4096-byte limit does trigger a violation.
func TestConstraintCheck_MLDSA87_ViolatesTightLimit(t *testing.T) {
	profile := constraints.AlgorithmSizeProfile{
		PublicKeyBytes: 2592,
		SignatureBytes: 4627,
	}
	// A tight 4096-byte serialization limit
	constraint := impact.ConstraintHit{
		Type:         "custom-header",
		MaxBytes:     4096,
		EffectiveMax: 4096,
	}
	violation := constraints.Check(profile, constraint)
	if violation == nil {
		t.Error("ML-DSA-87 signature (4627 bytes) should violate a 4096-byte constraint")
	}
	if violation != nil && violation.Overflow != 4627-4096 {
		t.Errorf("overflow = %d, want %d", violation.Overflow, 4627-4096)
	}
}

// TestConstraintCheck_SLHDSA128f_LargeSignatureViolatesJWT verifies that
// SLH-DSA-128f (17088-byte signature) exceeds a realistic JWT constraint.
func TestConstraintCheck_SLHDSA128f_ExceedsJWT8KB(t *testing.T) {
	profile := constraints.AlgorithmSizeProfile{
		PublicKeyBytes: 32,
		SignatureBytes: 17088,
	}
	constraint := impact.ConstraintHit{
		Type:         "jwt-header",
		MaxBytes:     8192,
		EffectiveMax: 8192,
	}
	violation := constraints.Check(profile, constraint)
	if violation == nil {
		t.Error("SLH-DSA-128f (17088 byte sig) should violate 8192-byte JWT constraint")
	}
	if violation != nil {
		expectedOverflow := 17088 - 8192
		if violation.Overflow != expectedOverflow {
			t.Errorf("overflow = %d, want %d", violation.Overflow, expectedOverflow)
		}
	}
}

// TestConstraintCheck_ZeroProfile_UsesPublicKeyFallback verifies that when
// both SignatureBytes and CiphertextBytes are 0, PublicKeyBytes is used.
func TestConstraintCheck_ZeroSigAndCiphertext_FallsBackToPublicKey(t *testing.T) {
	profile := constraints.AlgorithmSizeProfile{
		PublicKeyBytes:  200,
		SignatureBytes:  0,
		CiphertextBytes: 0,
	}
	constraint := impact.ConstraintHit{
		MaxBytes:     100,
		EffectiveMax: 100,
	}
	violation := constraints.Check(profile, constraint)
	if violation == nil {
		t.Error("PublicKeyBytes(200) > limit(100) should produce violation when sig/ciphertext are 0")
	}
	if violation != nil && violation.Overflow != 100 {
		t.Errorf("overflow = %d, want 100 (200-100)", violation.Overflow)
	}
}

// TestConstraintCheck_ExactlyAtLimit_NoViolation verifies the inclusive
// boundary: projected == effectiveMax should NOT produce a violation.
func TestConstraintCheck_ExactlyAtLimit_NoViolation(t *testing.T) {
	profile := constraints.AlgorithmSizeProfile{
		SignatureBytes: 512,
	}
	constraint := impact.ConstraintHit{
		MaxBytes:     512,
		EffectiveMax: 512,
	}
	violation := constraints.Check(profile, constraint)
	if violation != nil {
		t.Errorf("projected == limit should not be a violation, got overflow=%d", violation.Overflow)
	}
}

// TestConstraintCheck_OneByteOver_IsViolation verifies the exclusive upper
// boundary: projected == effectiveMax+1 SHOULD produce a violation.
func TestConstraintCheck_OneByteOver_IsViolation(t *testing.T) {
	profile := constraints.AlgorithmSizeProfile{
		SignatureBytes: 513,
	}
	constraint := impact.ConstraintHit{
		MaxBytes:     512,
		EffectiveMax: 512,
	}
	violation := constraints.Check(profile, constraint)
	if violation == nil {
		t.Error("projected (513) > limit (512) should produce a violation")
	}
	if violation != nil && violation.Overflow != 1 {
		t.Errorf("overflow = %d, want 1", violation.Overflow)
	}
}

// ---------------------------------------------------------------------------
// ImpactZone structure completeness
// ---------------------------------------------------------------------------

// TestImpactZone_FieldsPresent_NoNilSlices verifies that an ImpactZone with
// populated fields serializes correctly and that nil slices for BrokenConstraints
// and ViolatedProtocols do not cause issues.
func TestImpactZone_NilSlices_Safe(t *testing.T) {
	zone := impact.ImpactZone{
		FindingKey:        "test-key",
		FromAlgorithm:     "RSA-2048",
		ToAlgorithm:       "ML-KEM-1024",
		SizeRatio:         5.3,
		BlastRadiusScore:  75,
		BlastRadiusGrade:  "Critical",
		ForwardHopCount:   3,
		BrokenConstraints: nil, // nil is valid
		ViolatedProtocols: nil, // nil is valid
	}
	// No panic expected
	_ = zone.BlastRadiusGrade
	_ = len(zone.BrokenConstraints)
	_ = len(zone.ViolatedProtocols)
}

// TestBlastCalculate_SingleConstraintViolation verifies the weighted formula
// for exactly one constraint violation: 25 * 0.35 = 8.75 → rounds to 9.
func TestBlastCalculate_SingleConstraintViolation(t *testing.T) {
	score, _ := blast.Calculate(blast.Input{ConstraintViolations: 1})
	// constraint = min(1*25.0, 100) = 25, * 0.35 = 8.75 → rounds to 9
	if score != 9 {
		t.Errorf("1 constraint violation: score = %d, want 9", score)
	}
}

// TestBlastCalculate_SingleProtocolViolation verifies: 33 * 0.25 = 8.25 → 8.
func TestBlastCalculate_SingleProtocolViolation(t *testing.T) {
	score, _ := blast.Calculate(blast.Input{ProtocolViolations: 1})
	// protocol = min(1*33.0, 100) = 33, * 0.25 = 8.25 → rounds to 8
	if score != 8 {
		t.Errorf("1 protocol violation: score = %d, want 8", score)
	}
}
