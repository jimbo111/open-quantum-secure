package quantum

import (
	"strings"
	"testing"
)

// Regression tests for the 2026-08-23 detection-gap batch: bare "ECC",
// ambiguous "asymmetric" primitives, JWS tokens, bare curve names, SRP/HPKE,
// and the AES-192 recommendation text.

func TestClassifyECC(t *testing.T) {
	tests := []struct {
		name      string
		primitive string
		wantRisk  Risk
		wantSev   Severity
		wantTgt   string
	}{
		// cryptoscan emits "ECC" with primitive "asymmetric" for createECDH,
		// crypto/ecdsa imports, and ssl_ecdh_curve. Previously RiskUnknown/P4.
		{"ECC", "asymmetric", RiskVulnerable, SeverityCritical, "ML-KEM-768"},
		{"ECC", "", RiskVulnerable, SeverityHigh, "ML-KEM-768"},
		{"ECC", "key-exchange", RiskVulnerable, SeverityCritical, "ML-KEM-768"},
		{"ECC", "signature", RiskVulnerable, SeverityHigh, "ML-KEM-768"},
	}
	for _, tt := range tests {
		c := ClassifyAlgorithm(tt.name, tt.primitive, 0)
		if c.Risk != tt.wantRisk || c.Severity != tt.wantSev {
			t.Errorf("ClassifyAlgorithm(%q, %q): got risk=%s sev=%s, want risk=%s sev=%s",
				tt.name, tt.primitive, c.Risk, c.Severity, tt.wantRisk, tt.wantSev)
		}
		if c.TargetAlgorithm != tt.wantTgt {
			t.Errorf("ClassifyAlgorithm(%q, %q): target=%q, want %q",
				tt.name, tt.primitive, c.TargetAlgorithm, tt.wantTgt)
		}
		if c.Recommendation == "" {
			t.Errorf("ClassifyAlgorithm(%q, %q): empty recommendation", tt.name, tt.primitive)
		}
	}
}

func TestECBNotSwallowedByECC(t *testing.T) {
	// Guard: "ECC" must not prefix-match cipher-mode identifiers. ECB is a
	// mode string, typically arriving with a symmetric primitive.
	c := ClassifyAlgorithm("ECB", "symmetric", 0)
	if c.Risk == RiskVulnerable && strings.Contains(c.Recommendation, "Elliptic") {
		t.Fatalf("ECB misclassified as elliptic-curve: %+v", c)
	}
}

func TestAsymmetricPrimitiveRouting(t *testing.T) {
	// ECDH tagged "asymmetric" is kex-only → Critical/immediate, ML-KEM.
	c := ClassifyAlgorithm("ECDH", "asymmetric", 0)
	if c.Severity != SeverityCritical || c.HNDLRisk != HNDLImmediate {
		t.Errorf("ECDH/asymmetric: got sev=%s hndl=%s, want critical/immediate", c.Severity, c.HNDLRisk)
	}
	if c.TargetAlgorithm != "ML-KEM-768" {
		t.Errorf("ECDH/asymmetric: target=%q, want ML-KEM-768", c.TargetAlgorithm)
	}
	// ECDSA tagged "asymmetric" is signature-only → High/deferred, ML-DSA.
	c = ClassifyAlgorithm("ECDSA", "asymmetric", 0)
	if c.Severity != SeverityHigh || c.HNDLRisk != HNDLDeferred {
		t.Errorf("ECDSA/asymmetric: got sev=%s hndl=%s, want high/deferred", c.Severity, c.HNDLRisk)
	}
	if c.TargetAlgorithm != "ML-DSA-65" {
		t.Errorf("ECDSA/asymmetric: target=%q, want ML-DSA-65", c.TargetAlgorithm)
	}
	// RSA tagged "asymmetric" is ambiguous → worst-case Critical, immediate.
	c = ClassifyAlgorithm("RSA", "asymmetric", 2048)
	if c.Severity != SeverityCritical || c.HNDLRisk != HNDLImmediate {
		t.Errorf("RSA/asymmetric: got sev=%s hndl=%s, want critical/immediate", c.Severity, c.HNDLRisk)
	}
}

func TestJWSTokens(t *testing.T) {
	tests := []struct {
		token    string
		wantRisk Risk
		wantTgt  string
	}{
		{"RS256", RiskVulnerable, "ML-DSA-65"},
		{"PS512", RiskVulnerable, "ML-DSA-65"},
		{"ES256", RiskVulnerable, "ML-DSA-65"},
		{"ES256K", RiskVulnerable, "ML-DSA-65"},
		{"ECDH-ES", RiskVulnerable, "ML-KEM-768"},
		{"ECDH-ES+A256KW", RiskVulnerable, "ML-KEM-768"},
	}
	for _, tt := range tests {
		c := ClassifyAlgorithm(tt.token, "", 0)
		if c.Risk != tt.wantRisk {
			t.Errorf("ClassifyAlgorithm(%q): risk=%s, want %s", tt.token, c.Risk, tt.wantRisk)
		}
		if c.TargetAlgorithm != tt.wantTgt {
			t.Errorf("ClassifyAlgorithm(%q): target=%q, want %q", tt.token, c.TargetAlgorithm, tt.wantTgt)
		}
	}
	// HMAC JWS tokens follow the inner hash: HS256 is quantum-safe practice.
	c := ClassifyAlgorithm("HS256", "", 0)
	if c.Risk == RiskVulnerable {
		t.Errorf("HS256 must not classify quantum-vulnerable, got %s", c.Risk)
	}
}

func TestBareCurveNames(t *testing.T) {
	// Key-agreement (or unknown) usage → ECDH family with curve bits.
	c := ClassifyAlgorithm("secp256r1", "key-exchange", 0)
	if c.Risk != RiskVulnerable || c.TargetAlgorithm != "ML-KEM-768" {
		t.Errorf("secp256r1/kex: got risk=%s target=%q", c.Risk, c.TargetAlgorithm)
	}
	// >=384-bit curves step up the KEM tier.
	c = ClassifyAlgorithm("secp521r1", "key-exchange", 0)
	if c.TargetAlgorithm != "ML-KEM-1024" {
		t.Errorf("secp521r1/kex: target=%q, want ML-KEM-1024", c.TargetAlgorithm)
	}
	// Signature usage → ECDSA family; P-521 steps up to ML-DSA-87.
	c = ClassifyAlgorithm("P-521", "signature", 0)
	if c.TargetAlgorithm != "ML-DSA-87" {
		t.Errorf("P-521/signature: target=%q, want ML-DSA-87", c.TargetAlgorithm)
	}
	// libsodium symbol scanner emits the literal "Curve25519" (kex-only).
	c = ClassifyAlgorithm("Curve25519", "", 0)
	if c.Risk != RiskVulnerable || c.TargetAlgorithm != "ML-KEM-768" {
		t.Errorf("Curve25519: got risk=%s target=%q, want vulnerable/ML-KEM-768", c.Risk, c.TargetAlgorithm)
	}
	// Curve25519 must resolve to X25519 even with a signature tag (kex-only curve).
	c = ClassifyAlgorithm("Curve25519", "signature", 0)
	if c.TargetAlgorithm != "ML-KEM-768" {
		t.Errorf("Curve25519/signature: target=%q, want ML-KEM-768", c.TargetAlgorithm)
	}
	// An explicit caller-provided key size wins over the catalog's bits.
	c = ClassifyAlgorithm("brainpoolP384r1", "key-exchange", 0)
	if c.TargetAlgorithm != "ML-KEM-1024" {
		t.Errorf("brainpoolP384r1: target=%q, want ML-KEM-1024", c.TargetAlgorithm)
	}
}

func TestSRPAndHPKE(t *testing.T) {
	for _, name := range []string{"SRP", "HPKE"} {
		c := ClassifyAlgorithm(name, "", 0)
		if c.Risk != RiskVulnerable {
			t.Errorf("%s: risk=%s, want vulnerable", name, c.Risk)
		}
		if c.HNDLRisk != HNDLImmediate {
			t.Errorf("%s: hndl=%s, want immediate", name, c.HNDLRisk)
		}
		// The asymmetric tag routes kex-only families to the Critical branch.
		c = ClassifyAlgorithm(name, "asymmetric", 0)
		if c.Severity != SeverityCritical {
			t.Errorf("%s/asymmetric: sev=%s, want critical (kex-only family)", name, c.Severity)
		}
	}
	// Hybrid/PQ names must stay safe — HPKE's blanket entry must not shadow them.
	c := ClassifyAlgorithm("X25519MLKEM768", "kem", 0)
	if c.Risk != RiskSafe {
		t.Errorf("X25519MLKEM768: risk=%s, want safe", c.Risk)
	}
}

func TestOpenSSHHybridKEXNames(t *testing.T) {
	// SSH wire names for OpenSSH's hybrid PQC key exchange, with and without
	// hash/vendor suffixes, must classify safe.
	for _, name := range []string{
		"sntrup761x25519-sha512@openssh.com",
		"sntrup761x25519",
		"mlkem768x25519-sha256",
	} {
		c := ClassifyAlgorithm(name, "kem", 0)
		if c.Risk != RiskSafe {
			t.Errorf("ClassifyAlgorithm(%q): risk=%s, want safe", name, c.Risk)
		}
	}
}

func TestAES192RecommendationText(t *testing.T) {
	c := ClassifyAlgorithm("AES", "symmetric", 192)
	if !strings.Contains(c.Recommendation, "192-bit") || !strings.Contains(c.Recommendation, "96-bit") {
		t.Errorf("AES-192 recommendation should state 192-bit/96-bit effective, got: %q", c.Recommendation)
	}
	c = ClassifyAlgorithm("AES", "symmetric", 128)
	if !strings.Contains(c.Recommendation, "128-bit") || !strings.Contains(c.Recommendation, "64-bit") {
		t.Errorf("AES-128 recommendation should state 128-bit/64-bit effective, got: %q", c.Recommendation)
	}
}
