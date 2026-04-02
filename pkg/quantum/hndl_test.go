package quantum

import (
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
