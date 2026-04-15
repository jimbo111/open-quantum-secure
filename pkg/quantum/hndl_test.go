package quantum

import (
	"fmt"
	"strings"
	"testing"
)

func TestHNDL_KeyExchangeIsImmediate(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		primitive string
	}{
		{"ECDH", "ECDH", "key-exchange"},
		{"ECDHE", "ECDHE", "key-agree"},
		{"X25519", "X25519", "key-exchange"},
		{"X448", "X448", "key-exchange"},
		{"DH", "DH", "key-exchange"},
		{"FFDH", "FFDH", "key-agree"},
		{"RSA-KEM", "RSA", "kem"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := ClassifyAlgorithm(tt.algorithm, tt.primitive, 0)
			if c.HNDLRisk != HNDLImmediate {
				t.Errorf("ClassifyAlgorithm(%q, %q) HNDLRisk = %q, want %q",
					tt.algorithm, tt.primitive, c.HNDLRisk, HNDLImmediate)
			}
			if c.Severity != SeverityCritical {
				t.Errorf("key exchange should be SeverityCritical, got %s", c.Severity)
			}
		})
	}
}

func TestHNDL_SignatureIsDeferred(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		primitive string
	}{
		{"ECDSA", "ECDSA", "signature"},
		{"Ed25519-sig", "Ed25519", "signature"},
		{"RSA-sign", "RSA", "signature"},
		{"DSA", "DSA", "signature"},
		{"KCDSA", "KCDSA", "signature"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := ClassifyAlgorithm(tt.algorithm, tt.primitive, 0)
			if c.HNDLRisk != HNDLDeferred {
				t.Errorf("ClassifyAlgorithm(%q, %q) HNDLRisk = %q, want %q",
					tt.algorithm, tt.primitive, c.HNDLRisk, HNDLDeferred)
			}
			if c.Severity != SeverityHigh {
				t.Errorf("signature should be SeverityHigh, got %s", c.Severity)
			}
		})
	}
}

func TestHNDL_SymmetricHasNoHNDL(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		primitive string
		keySize   int
	}{
		{"AES-256", "AES-256-GCM", "symmetric", 256},
		{"AES-128", "AES-128", "symmetric", 128},
		{"ChaCha20", "ChaCha20-Poly1305", "ae", 0},
		{"SHA-256", "SHA-256", "hash", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := ClassifyAlgorithm(tt.algorithm, tt.primitive, tt.keySize)
			if c.HNDLRisk != "" {
				t.Errorf("symmetric/hash should have empty HNDLRisk, got %q", c.HNDLRisk)
			}
		})
	}
}

func TestHNDL_PQCSafeHasNoHNDL(t *testing.T) {
	tests := []struct {
		algorithm string
		primitive string
	}{
		{"ML-KEM-768", "kem"},
		{"ML-DSA-65", "signature"},
		{"SLH-DSA-128s", "signature"},
		{"SMAUG-T-128", "kem"},
		{"HAETAE-3", "signature"},
	}

	for _, tt := range tests {
		t.Run(tt.algorithm, func(t *testing.T) {
			c := ClassifyAlgorithm(tt.algorithm, tt.primitive, 0)
			if c.HNDLRisk != "" {
				t.Errorf("PQC-safe %q should have empty HNDLRisk, got %q", tt.algorithm, c.HNDLRisk)
			}
			if c.Risk != RiskSafe {
				t.Errorf("PQC-safe %q should be RiskSafe, got %s", tt.algorithm, c.Risk)
			}
		})
	}
}

func TestHNDL_DeprecatedHasNoHNDL(t *testing.T) {
	// Deprecated algorithms are classically broken — HNDL is irrelevant
	c := ClassifyAlgorithm("MD5", "hash", 0)
	if c.HNDLRisk != "" {
		t.Errorf("deprecated MD5 should have empty HNDLRisk, got %q", c.HNDLRisk)
	}

	c = ClassifyAlgorithm("DES", "symmetric", 0)
	if c.HNDLRisk != "" {
		t.Errorf("deprecated DES should have empty HNDLRisk, got %q", c.HNDLRisk)
	}
}

func TestHNDL_UnrecognizedAsymmetricAlgorithm(t *testing.T) {
	// Unrecognized KEM should get immediate HNDL
	c := ClassifyAlgorithm("FooKEM", "kem", 0)
	if c.HNDLRisk != HNDLImmediate {
		t.Errorf("unrecognized KEM should be immediate, got %q", c.HNDLRisk)
	}

	// Unrecognized signature should get deferred HNDL
	c = ClassifyAlgorithm("FooSign", "signature", 0)
	if c.HNDLRisk != HNDLDeferred {
		t.Errorf("unrecognized signature should be deferred, got %q", c.HNDLRisk)
	}

	// Unrecognized key-agree should get immediate HNDL
	c = ClassifyAlgorithm("FooDH", "key-exchange", 0)
	if c.HNDLRisk != HNDLImmediate {
		t.Errorf("unrecognized key-exchange should be immediate, got %q", c.HNDLRisk)
	}
}

func TestHNDL_UnknownPrimitiveVulnerableIsImmediate(t *testing.T) {
	// Vulnerable algorithm with unknown primitive should be conservative (immediate)
	c := ClassifyAlgorithm("RSA-2048", "", 0)
	if c.HNDLRisk != HNDLImmediate {
		t.Errorf("RSA with unknown primitive should default to immediate, got %q", c.HNDLRisk)
	}
}

func TestHNDL_RecommendationContainsHNDLTerminology(t *testing.T) {
	// Key exchange recommendation should mention HNDL
	c := ClassifyAlgorithm("ECDH", "key-exchange", 0)
	if c.Recommendation == "" {
		t.Fatal("expected non-empty recommendation")
	}
	if !containsIgnoreCase(c.Recommendation, "HNDL") {
		t.Errorf("key exchange recommendation should mention HNDL, got: %s", c.Recommendation)
	}
	if !containsIgnoreCase(c.Recommendation, "2030") {
		t.Errorf("key exchange recommendation should mention 2030 deadline, got: %s", c.Recommendation)
	}

	// Signature recommendation should mention HNDL
	c = ClassifyAlgorithm("ECDSA", "signature", 0)
	if !containsIgnoreCase(c.Recommendation, "HNDL") {
		t.Errorf("signature recommendation should mention HNDL, got: %s", c.Recommendation)
	}
	if !containsIgnoreCase(c.Recommendation, "2035") {
		t.Errorf("signature recommendation should mention 2035 deadline, got: %s", c.Recommendation)
	}
}

func containsIgnoreCase(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}

// ─── Mosca inequality: ComputeHNDLSurplus ──────────────────────────────────

func TestComputeHNDLSurplus_ExplicitValues(t *testing.T) {
	tests := []struct {
		name         string
		shelfLife    int
		migLag       int
		timeToCRQC   int
		wantSurplus  int
	}{
		// surplus = (shelf + lag) - crqc
		{"zero shelf, explicit lag+crqc", 0, 5, 5, 0},
		{"standard 10y shelf", 10, 5, 5, 10},
		{"medical 30y shelf", 30, 5, 5, 30},
		{"finance 7y shelf", 7, 5, 5, 7},
		{"state 50y shelf", 50, 5, 5, 50},
		{"code 5y shelf, crqc=10", 5, 5, 10, 0},
		{"code 5y shelf, crqc=15", 5, 5, 15, -5},
		{"negative surplus (data expires before CRQC)", 1, 3, 10, -6},
		{"negative shelf treated as-is", -1, 5, 5, -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ComputeHNDLSurplus(tt.shelfLife, tt.migLag, tt.timeToCRQC)
			if got != tt.wantSurplus {
				t.Errorf("ComputeHNDLSurplus(%d, %d, %d) = %d, want %d",
					tt.shelfLife, tt.migLag, tt.timeToCRQC, got, tt.wantSurplus)
			}
		})
	}
}

func TestComputeHNDLSurplus_DefaultMigrationLag(t *testing.T) {
	// Passing migrationLagYears=0 should use DefaultMigrationLagYears (5).
	explicit := ComputeHNDLSurplus(10, DefaultMigrationLagYears, 5)
	defaulted := ComputeHNDLSurplus(10, 0, 5)
	if explicit != defaulted {
		t.Errorf("migLag=0 should use default (%d): explicit=%d, defaulted=%d",
			DefaultMigrationLagYears, explicit, defaulted)
	}
}

func TestComputeHNDLSurplus_DefaultTimeToCRQC(t *testing.T) {
	// Passing timeToCRQCYears=0 should use the dynamic default (≥ 0).
	// We can't pin the exact value across years, but the result must be
	// arithmetically consistent with a non-negative CRQC window.
	surplus := ComputeHNDLSurplus(10, 5, 0)
	// timeToCRQC is always ≥ 0, so surplus ≤ (10 + 5) = 15.
	if surplus > 15 {
		t.Errorf("ComputeHNDLSurplus(10, 5, 0) = %d, want ≤ 15 (CRQC must be ≥ 0)", surplus)
	}
	// With shelf=10 and default lag=5, surplus should always map to HIGH for any
	// year ≤ 2031 (surplus = 15 - crqc ≥ 15 - 5 = 10 when crqc≥0 today) or remain
	// elevated when CRQC arrives (surplus = 15 - 0 = 15 in year 2031+).
	level := HNDLLevelFromSurplus(surplus)
	if level != HNDLLevelHigh {
		t.Errorf("10y shelf with defaults should be HNDLLevelHigh, got %s (surplus=%d)", level, surplus)
	}
}

func TestComputeHNDLSurplus_EdgeCases(t *testing.T) {
	// Zero shelf life with explicit values — near-zero surplus.
	s := ComputeHNDLSurplus(0, 5, 5)
	if s != 0 {
		t.Errorf("ComputeHNDLSurplus(0, 5, 5) = %d, want 0", s)
	}

	// Zero shelf, zero lag (→default 5), zero crqc (→dynamic ≥ 0): surplus = 5 - crqc.
	// We just verify it doesn't panic and returns an int.
	_ = ComputeHNDLSurplus(0, 0, 0)

	// Negative shelf is passed through unchanged.
	s = ComputeHNDLSurplus(-5, 5, 5)
	if s != -5 {
		t.Errorf("ComputeHNDLSurplus(-5, 5, 5) = %d, want -5", s)
	}
}

// ─── HNDLLevelFromSurplus ─────────────────────────────────────────────────

func TestHNDLLevelFromSurplus(t *testing.T) {
	tests := []struct {
		surplus int
		want    HNDLLevel
	}{
		{-10, HNDLLevelLow},
		{-1, HNDLLevelLow},
		{0, HNDLLevelMedium},
		{1, HNDLLevelMedium},
		{2, HNDLLevelMedium},
		{3, HNDLLevelHigh},
		{10, HNDLLevelHigh},
		{50, HNDLLevelHigh},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("surplus_%+d", tt.surplus), func(t *testing.T) {
			got := HNDLLevelFromSurplus(tt.surplus)
			if got != tt.want {
				t.Errorf("HNDLLevelFromSurplus(%d) = %q, want %q", tt.surplus, got, tt.want)
			}
		})
	}
}
