// Package impact_test — sophisticated tests covering blast radius grading,
// protocol boundary detection, and size constraints.
// Uses external test package to avoid import cycles (impact/constraints imports impact).
package impact_test

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/impact/blast"
	"github.com/jimbo111/open-quantum-secure/pkg/impact/constraints"
	"github.com/jimbo111/open-quantum-secure/pkg/impact/protocols"
)

// ---------------------------------------------------------------------------
// Blast radius grading: score boundaries
// ---------------------------------------------------------------------------

func TestBlastRadius_Grades(t *testing.T) {
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

	for _, c := range cases {
		got := blast.ScoreToGrade(c.score)
		if got != c.want {
			t.Errorf("ScoreToGrade(%d) = %q; want %q", c.score, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Blast radius calculator: zero input → score 0 + Minimal
// ---------------------------------------------------------------------------

func TestBlastRadius_ZeroInput(t *testing.T) {
	score, grade := blast.Calculate(blast.Input{})
	if score != 0 {
		t.Errorf("Calculate(zero) score = %d; want 0", score)
	}
	if grade != "Minimal" {
		t.Errorf("Calculate(zero) grade = %q; want Minimal", grade)
	}
}

// ---------------------------------------------------------------------------
// Blast radius calculator: max input → score 100 + Critical
// ---------------------------------------------------------------------------

func TestBlastRadius_MaxInput(t *testing.T) {
	score, grade := blast.Calculate(blast.Input{
		HopCount:             100,
		ConstraintViolations: 100,
		ProtocolViolations:   100,
		SizeRatio:            10000,
	})
	if score != 100 {
		t.Errorf("Calculate(max) score = %d; want 100", score)
	}
	if grade != "Critical" {
		t.Errorf("Calculate(max) grade = %q; want Critical", grade)
	}
}

// ---------------------------------------------------------------------------
// Blast radius calculator: score clamped to [0, 100]
// ---------------------------------------------------------------------------

func TestBlastRadius_ScoreClamped(t *testing.T) {
	score, _ := blast.Calculate(blast.Input{
		HopCount:             999999,
		ConstraintViolations: 999999,
		ProtocolViolations:   999999,
		SizeRatio:            999999,
	})
	if score < 0 || score > 100 {
		t.Errorf("score = %d; must be in [0, 100]", score)
	}
}

// ---------------------------------------------------------------------------
// Blast radius calculator: hop-count-only produces expected contribution
// ---------------------------------------------------------------------------

func TestBlastRadius_HopCountOnly(t *testing.T) {
	// 10 hops → hop component = 1.0 × weight 20% → 20 raw points.
	score, _ := blast.Calculate(blast.Input{HopCount: 10})
	if score != 20 {
		t.Errorf("Calculate(hops=10) = %d; want 20", score)
	}
}

// ---------------------------------------------------------------------------
// Blast radius calculator: high inputs push into Critical
// ---------------------------------------------------------------------------

func TestBlastRadius_MultipleFactors_Critical(t *testing.T) {
	// constraint=4 (100×0.35=35) + protocol=3 (99×0.25≈25) + hops=10 (20) ≈ 80
	score, grade := blast.Calculate(blast.Input{
		ConstraintViolations: 4,
		ProtocolViolations:   3,
		HopCount:             10,
	})
	if score < 71 {
		t.Errorf("expected Critical score (>70); got %d (%s)", score, grade)
	}
	if grade != "Critical" {
		t.Errorf("expected Critical grade; got %q (score=%d)", grade, score)
	}
}

// ---------------------------------------------------------------------------
// Blast radius: size ratio contribution (SizeRatio=50 → 20 points)
// ---------------------------------------------------------------------------

func TestBlastRadius_SizeRatioContribution(t *testing.T) {
	// SizeRatio=50 → (50/50=1.0) × 100 × 0.20 = 20
	score, _ := blast.Calculate(blast.Input{SizeRatio: 50})
	if score != 20 {
		t.Errorf("Calculate(SizeRatio=50) = %d; want 20", score)
	}
}

// ---------------------------------------------------------------------------
// Protocol registry: TLS, SSH, JWT all present in default registry
// ---------------------------------------------------------------------------

func TestProtocols_KnownProtocolsPresent(t *testing.T) {
	for _, name := range []string{"TLS", "SSH", "JWT", "DTLS"} {
		proto, ok := protocols.Lookup(name)
		if !ok {
			t.Errorf("expected protocol %q in registry; not found", name)
			continue
		}
		if proto.MaxBytes <= 0 {
			t.Errorf("protocol %q has non-positive MaxBytes: %d", name, proto.MaxBytes)
		}
	}
}

// ---------------------------------------------------------------------------
// Protocol registry: TLS max 16384 bytes (hard limit)
// ---------------------------------------------------------------------------

func TestProtocols_TLS_HardLimit16384(t *testing.T) {
	p, ok := protocols.Lookup("TLS")
	if !ok {
		t.Fatal("TLS not found in protocol registry")
	}
	if p.MaxBytes != 16384 {
		t.Errorf("TLS MaxBytes = %d; want 16384", p.MaxBytes)
	}
	if !p.HardLimit {
		t.Error("TLS constraint must be a hard limit")
	}
}

// ---------------------------------------------------------------------------
// Constraints: ML-KEM-768 public key is larger than RSA-2048
// ---------------------------------------------------------------------------

func TestConstraints_MLKEM768_LargerThanRSA2048(t *testing.T) {
	mlkem, ok1 := constraints.Lookup("ML-KEM-768")
	rsa, ok2 := constraints.Lookup("RSA-2048")
	if !ok1 {
		t.Skip("ML-KEM-768 not in constraints table")
	}
	if !ok2 {
		t.Skip("RSA-2048 not in constraints table")
	}
	if mlkem.PublicKeyBytes <= rsa.PublicKeyBytes {
		t.Errorf("ML-KEM-768 public key (%d B) should be larger than RSA-2048 (%d B)",
			mlkem.PublicKeyBytes, rsa.PublicKeyBytes)
	}
}

// ---------------------------------------------------------------------------
// Constraints: ML-DSA-87 signature is larger than ECDSA-P256
// ---------------------------------------------------------------------------

func TestConstraints_MLDSA87_SigLargerThanECDSA(t *testing.T) {
	mldsa, ok1 := constraints.Lookup("ML-DSA-87")
	ecdsa, ok2 := constraints.Lookup("ECDSA-P256")
	if !ok1 || !ok2 {
		t.Skip("ML-DSA-87 or ECDSA-P256 not in constraints table")
	}
	if mldsa.SignatureBytes <= ecdsa.SignatureBytes {
		t.Errorf("ML-DSA-87 signature (%d B) should be larger than ECDSA-P256 (%d B)",
			mldsa.SignatureBytes, ecdsa.SignatureBytes)
	}
}

// ---------------------------------------------------------------------------
// Constraints: Lookup unknown algorithm returns false
// ---------------------------------------------------------------------------

func TestConstraints_UnknownAlgorithm(t *testing.T) {
	_, ok := constraints.Lookup("NOTREAL-9999")
	if ok {
		t.Error("Lookup of unknown algorithm should return false")
	}
}

// ---------------------------------------------------------------------------
// Protocol: unknown protocol returns false
// ---------------------------------------------------------------------------

func TestProtocols_UnknownProtocol(t *testing.T) {
	_, ok := protocols.Lookup("NOTAPROTOCOL")
	if ok {
		t.Error("Lookup of unknown protocol should return false")
	}
}

// ---------------------------------------------------------------------------
// Protocol: All() returns the full list (at least 5 protocols)
// ---------------------------------------------------------------------------

func TestProtocols_All_NonEmpty(t *testing.T) {
	all := protocols.All()
	if len(all) < 5 {
		t.Errorf("protocols.All() returned %d entries; expected at least 5", len(all))
	}
}
