package compliance

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

func algFinding(name, primitive string, keySize int, qr findings.QuantumRisk, hndl string) findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Algorithm:   &findings.Algorithm{Name: name, Primitive: primitive, KeySize: keySize},
		QuantumRisk: qr,
		HNDLRisk:    hndl,
	}
}

func depFinding(library string, qr findings.QuantumRisk, hndl string) findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Dependency:    &findings.Dependency{Library: library},
		RawIdentifier: library,
		QuantumRisk:   qr,
		HNDLRisk:      hndl,
	}
}

func TestEvaluate_NoViolations(t *testing.T) {
	tests := []struct {
		name    string
		finding findings.UnifiedFinding
	}{
		{
			name:    "ML-KEM-1024 approved",
			finding: algFinding("ML-KEM-1024", "kem", 1024, findings.QRSafe, "immediate"),
		},
		{
			name:    "ML-DSA-87 approved",
			finding: algFinding("ML-DSA-87", "signature", 0, findings.QRSafe, "deferred"),
		},
		{
			name:    "LMS approved",
			finding: algFinding("LMS", "signature", 0, findings.QRSafe, "deferred"),
		},
		{
			name:    "XMSS approved",
			finding: algFinding("XMSS", "signature", 0, findings.QRSafe, "deferred"),
		},
		{
			name:    "AES-256-GCM approved",
			finding: algFinding("AES-256-GCM", "symmetric", 256, findings.QRResistant, ""),
		},
		{
			name:    "AES-256 inferred from name",
			finding: algFinding("AES-256", "symmetric", 0, findings.QRResistant, ""),
		},
		{
			name:    "SHA-384 approved",
			finding: algFinding("SHA-384", "hash", 384, findings.QRResistant, ""),
		},
		{
			name:    "SHA-512 approved",
			finding: algFinding("SHA-512", "hash", 512, findings.QRResistant, ""),
		},
		{
			name:    "SHA-384 inferred from name",
			finding: algFinding("SHA-384", "hash", 0, findings.QRResistant, ""),
		},
		{
			name:    "SHA-512/256 sufficient output inferred",
			finding: algFinding("SHA-512", "hash", 0, findings.QRResistant, ""),
		},
		// Removed 2026-04-20: "quantum-safe unknown algorithm no violation" encoded
		// the bug fixed in the CNSA 2.0 signature default-deny. An unknown signature
		// scheme (e.g. SomeNewPQC) MUST now produce a cnsa2-signature-not-approved
		// violation — that's the whole point of default-deny. The new behaviour is
		// covered by TestAudit_CNSA2_Falcon_FalseApproval.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violations := Evaluate([]findings.UnifiedFinding{tt.finding})
			if len(violations) != 0 {
				t.Errorf("expected no violations, got %d: %+v", len(violations), violations)
			}
		})
	}
}

func TestEvaluate_SLHDSAExcluded(t *testing.T) {
	tests := []struct {
		name      string
		algName   string
		wantRule  string
	}{
		{"SLH-DSA bare", "SLH-DSA", "cnsa2-slh-dsa-excluded"},
		{"SLH-DSA-128f", "SLH-DSA-128f", "cnsa2-slh-dsa-excluded"},
		{"SLH-DSA-256s", "SLH-DSA-256s", "cnsa2-slh-dsa-excluded"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := algFinding(tt.algName, "signature", 0, findings.QRSafe, "deferred")
			violations := Evaluate([]findings.UnifiedFinding{f})
			if len(violations) != 1 {
				t.Fatalf("expected 1 violation, got %d", len(violations))
			}
			if violations[0].Rule != tt.wantRule {
				t.Errorf("rule: got %q, want %q", violations[0].Rule, tt.wantRule)
			}
			if violations[0].Algorithm != tt.algName {
				t.Errorf("algorithm: got %q, want %q", violations[0].Algorithm, tt.algName)
			}
		})
	}
}

func TestEvaluate_HashMLDSAExcluded(t *testing.T) {
	tests := []struct {
		name    string
		algName string
	}{
		{"HashML-DSA exact", "HashML-DSA"},
		{"HashML-DSA-87 variant", "HashML-DSA-87"},
		{"Hash-ML-DSA alternate form", "Hash-ML-DSA"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := algFinding(tt.algName, "signature", 0, findings.QRSafe, "deferred")
			violations := Evaluate([]findings.UnifiedFinding{f})
			if len(violations) != 1 {
				t.Fatalf("expected 1 violation, got %d", len(violations))
			}
			if violations[0].Rule != "cnsa2-hashml-dsa-excluded" {
				t.Errorf("rule: got %q, want %q", violations[0].Rule, "cnsa2-hashml-dsa-excluded")
			}
		})
	}
}

func TestEvaluate_HQCNotApproved(t *testing.T) {
	tests := []struct {
		name    string
		algName string
	}{
		{"HQC bare", "HQC"},
		{"HQC-128", "HQC-128"},
		{"HQC-192", "HQC-192"},
		{"HQC-256", "HQC-256"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := algFinding(tt.algName, "kem", 0, findings.QRSafe, "immediate")
			violations := Evaluate([]findings.UnifiedFinding{f})
			if len(violations) != 1 {
				t.Fatalf("expected 1 violation, got %d: %+v", len(violations), violations)
			}
			if violations[0].Rule != "cnsa2-hqc-not-approved" {
				t.Errorf("rule: got %q, want %q", violations[0].Rule, "cnsa2-hqc-not-approved")
			}
			if violations[0].Algorithm != tt.algName {
				t.Errorf("algorithm: got %q, want %q", violations[0].Algorithm, tt.algName)
			}
			if violations[0].Deadline != deadlineKeyExchange {
				t.Errorf("deadline: got %q, want %q", violations[0].Deadline, deadlineKeyExchange)
			}
		})
	}
}

func TestEvaluate_MLKEMKeySize(t *testing.T) {
	tests := []struct {
		name        string
		algName     string
		wantViolate bool
	}{
		{"ML-KEM-512 insufficient", "ML-KEM-512", true},
		{"ML-KEM-768 insufficient", "ML-KEM-768", true},
		{"ML-KEM-1024 approved", "ML-KEM-1024", false},
		{"ML-KEM bare no variant no violation", "ML-KEM", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := algFinding(tt.algName, "kem", 0, findings.QRSafe, "immediate")
			violations := Evaluate([]findings.UnifiedFinding{f})
			if tt.wantViolate {
				if len(violations) != 1 {
					t.Fatalf("expected 1 violation, got %d", len(violations))
				}
				if violations[0].Rule != "cnsa2-ml-kem-key-size" {
					t.Errorf("rule: got %q, want %q", violations[0].Rule, "cnsa2-ml-kem-key-size")
				}
				if violations[0].Deadline != deadlineKeyExchange {
					t.Errorf("deadline: got %q, want %q", violations[0].Deadline, deadlineKeyExchange)
				}
			} else {
				if len(violations) != 0 {
					t.Errorf("expected no violations, got %d: %+v", len(violations), violations)
				}
			}
		})
	}
}

func TestEvaluate_MLDSAParamSet(t *testing.T) {
	tests := []struct {
		name        string
		algName     string
		wantViolate bool
	}{
		{"ML-DSA-44 insufficient", "ML-DSA-44", true},
		{"ML-DSA-65 insufficient", "ML-DSA-65", true},
		{"ML-DSA-87 approved", "ML-DSA-87", false},
		{"ML-DSA bare no variant no violation", "ML-DSA", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := algFinding(tt.algName, "signature", 0, findings.QRSafe, "deferred")
			violations := Evaluate([]findings.UnifiedFinding{f})
			if tt.wantViolate {
				if len(violations) != 1 {
					t.Fatalf("expected 1 violation, got %d", len(violations))
				}
				if violations[0].Rule != "cnsa2-ml-dsa-param-set" {
					t.Errorf("rule: got %q, want %q", violations[0].Rule, "cnsa2-ml-dsa-param-set")
				}
				if violations[0].Deadline != deadlineFull {
					t.Errorf("deadline: got %q, want %q", violations[0].Deadline, deadlineFull)
				}
			} else {
				if len(violations) != 0 {
					t.Errorf("expected no violations, got %d: %+v", len(violations), violations)
				}
			}
		})
	}
}

func TestEvaluate_HashBasedSigExclusions(t *testing.T) {
	tests := []struct {
		name        string
		algName     string
		wantViolate bool
		wantRule    string
	}{
		{"LMS approved", "LMS", false, ""},
		{"XMSS approved", "XMSS", false, ""},
		{"HSS approved per SP 800-208", "HSS", false, ""},
		{"XMSSMT approved per SP 800-208", "XMSSMT", false, ""},
		{"XMSS-MT approved per SP 800-208", "XMSS-MT", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := algFinding(tt.algName, "signature", 0, findings.QRSafe, "deferred")
			violations := Evaluate([]findings.UnifiedFinding{f})
			if tt.wantViolate {
				if len(violations) != 1 {
					t.Fatalf("expected 1 violation, got %d", len(violations))
				}
				if violations[0].Rule != tt.wantRule {
					t.Errorf("rule: got %q, want %q", violations[0].Rule, tt.wantRule)
				}
			} else {
				if len(violations) != 0 {
					t.Errorf("expected no violations, got %d: %+v", len(violations), violations)
				}
			}
		})
	}
}

func TestEvaluate_SymmetricKeySize(t *testing.T) {
	tests := []struct {
		name        string
		algName     string
		keySize     int
		wantViolate bool
	}{
		{"AES-128 explicit key size", "AES-128", 128, true},
		{"AES-128-GCM inferred from name", "AES-128-GCM", 0, true},
		{"AES-192 insufficient", "AES-192", 192, true},
		{"AES-256 approved explicit", "AES-256", 256, false},
		{"AES-256-GCM approved inferred", "AES-256-GCM", 0, false},
		{"ARIA-128 unapproved non-AES", "ARIA-128-CBC", 128, true},
		{"ARIA-256 unapproved non-AES", "ARIA-256-GCM", 256, true},
		{"AES no size no violation", "AES", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := algFinding(tt.algName, "symmetric", tt.keySize, findings.QRWeakened, "")
			if tt.keySize >= 256 || (!tt.wantViolate && tt.keySize == 0) {
				f.QuantumRisk = findings.QRResistant
			}
			violations := Evaluate([]findings.UnifiedFinding{f})
			if tt.wantViolate {
				if len(violations) != 1 {
					t.Fatalf("%s: expected 1 violation, got %d: %+v", tt.name, len(violations), violations)
				}
				rule := violations[0].Rule
				if rule != "cnsa2-symmetric-key-size" && rule != "cnsa2-symmetric-unapproved" {
					t.Errorf("rule: got %q, want cnsa2-symmetric-key-size or cnsa2-symmetric-unapproved", rule)
				}
			} else {
				if len(violations) != 0 {
					t.Errorf("expected no violations, got %d: %+v", len(violations), violations)
				}
			}
		})
	}
}

func TestEvaluate_HashOutputSize(t *testing.T) {
	tests := []struct {
		name        string
		algName     string
		keySize     int
		wantViolate bool
	}{
		{"SHA-256 insufficient", "SHA-256", 256, true},
		{"SHA-256 inferred from name", "SHA-256", 0, true},
		{"SHA-224 insufficient", "SHA-224", 224, true},
		{"SHA-384 approved", "SHA-384", 384, false},
		{"SHA-512 approved", "SHA-512", 512, false},
		{"SHA-384 inferred from name", "SHA-384", 0, false},
		{"SHA-512 inferred from name", "SHA-512", 0, false},
		{"HMAC-SHA-256 insufficient", "HMAC-SHA-256", 256, true},
		{"HMAC-SHA-384 approved", "HMAC-SHA-384", 384, false},
		{"SHA3-256 unapproved non-SHA2", "SHA3-256", 256, true},
		{"SHA3-512 unapproved non-SHA2", "SHA3-512", 512, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := algFinding(tt.algName, "hash", tt.keySize, findings.QRResistant, "")
			violations := Evaluate([]findings.UnifiedFinding{f})
			if tt.wantViolate {
				if len(violations) != 1 {
					t.Fatalf("%s: expected 1 violation, got %d: %+v", tt.name, len(violations), violations)
				}
				rule := violations[0].Rule
				if rule != "cnsa2-hash-output-size" && rule != "cnsa2-hash-unapproved" {
					t.Errorf("rule: got %q, want cnsa2-hash-output-size or cnsa2-hash-unapproved", rule)
				}
			} else {
				if len(violations) != 0 {
					t.Errorf("expected no violations, got %d: %+v", len(violations), violations)
				}
			}
		})
	}
}

func TestEvaluate_QuantumVulnerable(t *testing.T) {
	tests := []struct {
		name     string
		f        findings.UnifiedFinding
		wantRule string
		deadline string
	}{
		{
			name:     "RSA key exchange immediate deadline",
			f:        algFinding("RSA-2048", "kem", 2048, findings.QRVulnerable, "immediate"),
			wantRule: "cnsa2-quantum-vulnerable",
			deadline: deadlineKeyExchange,
		},
		{
			name:     "ECDSA signature deferred deadline",
			f:        algFinding("ECDSA", "signature", 0, findings.QRVulnerable, "deferred"),
			wantRule: "cnsa2-quantum-vulnerable",
			deadline: deadlineFull,
		},
		{
			name:     "deprecated MD5",
			f:        algFinding("MD5", "hash", 0, findings.QRDeprecated, ""),
			wantRule: "cnsa2-quantum-vulnerable",
			deadline: deadlineFull,
		},
		{
			name:     "quantum-vulnerable dependency",
			f:        depFinding("openssl-1.0.2", findings.QRVulnerable, "immediate"),
			wantRule: "cnsa2-quantum-vulnerable",
			deadline: deadlineKeyExchange,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violations := Evaluate([]findings.UnifiedFinding{tt.f})
			if len(violations) != 1 {
				t.Fatalf("expected 1 violation, got %d", len(violations))
			}
			if violations[0].Rule != tt.wantRule {
				t.Errorf("rule: got %q, want %q", violations[0].Rule, tt.wantRule)
			}
			if violations[0].Deadline != tt.deadline {
				t.Errorf("deadline: got %q, want %q", violations[0].Deadline, tt.deadline)
			}
		})
	}
}

func TestEvaluate_EmptyInput(t *testing.T) {
	violations := Evaluate(nil)
	if violations != nil {
		t.Errorf("expected nil violations for nil input, got %v", violations)
	}
	violations = Evaluate([]findings.UnifiedFinding{})
	if violations != nil {
		t.Errorf("expected nil violations for empty input, got %v", violations)
	}
}

func TestEvaluate_MultipleFindings(t *testing.T) {
	ff := []findings.UnifiedFinding{
		algFinding("ML-KEM-1024", "kem", 1024, findings.QRSafe, "immediate"),   // OK
		algFinding("SLH-DSA-128f", "signature", 0, findings.QRSafe, "deferred"), // violation
		algFinding("ML-DSA-65", "signature", 0, findings.QRSafe, "deferred"),   // violation
		algFinding("SHA-256", "hash", 256, findings.QRResistant, ""),           // violation
		algFinding("AES-256-GCM", "symmetric", 256, findings.QRResistant, ""), // OK
	}

	violations := Evaluate(ff)
	if len(violations) != 3 {
		t.Fatalf("expected 3 violations, got %d: %+v", len(violations), violations)
	}

	rules := make(map[string]bool)
	for _, v := range violations {
		rules[v.Rule] = true
	}
	for _, want := range []string{"cnsa2-slh-dsa-excluded", "cnsa2-ml-dsa-param-set", "cnsa2-hash-output-size"} {
		if !rules[want] {
			t.Errorf("expected violation rule %q not found in %v", want, violations)
		}
	}
}

func TestMlVariantLevel(t *testing.T) {
	tests := []struct {
		name string
		want int
	}{
		// hyphenated forms
		{"ML-KEM-512", 512},
		{"ML-KEM-768", 768},
		{"ML-KEM-1024", 1024},
		{"ML-KEM", 0},
		{"ML-DSA-44", 44},
		{"ML-DSA-65", 65},
		{"ML-DSA-87", 87},
		{"ML-DSA", 0},
		{"SLH-DSA-128f", 0}, // suffix is "128f" — not purely numeric
		// hyphen-less forms (TLS probe emits these)
		{"MLKEM512", 512},
		{"MLKEM768", 768},
		{"MLKEM1024", 1024},
		{"MLKEM", 0},
		{"MLDSA44", 44},
		{"MLDSA65", 65},
		{"MLDSA87", 87},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mlVariantLevel(tt.name)
			if got != tt.want {
				t.Errorf("mlVariantLevel(%q) = %d, want %d", tt.name, got, tt.want)
			}
		})
	}
}

// TestCNSA2_HyphenlessMLKEM verifies that hyphen-less ML-KEM names (emitted by
// the TLS probe) are correctly caught by the grade check (C1 reproducer).
func TestCNSA2_HyphenlessMLKEM(t *testing.T) {
	tests := []struct {
		algName     string
		wantViolate bool
		wantRule    string
	}{
		{"MLKEM512", true, "cnsa2-ml-kem-key-size"},
		{"MLKEM768", true, "cnsa2-ml-kem-key-size"},
		{"MLKEM1024", false, ""},
		{"MLKEM", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.algName, func(t *testing.T) {
			f := algFinding(tt.algName, "kem", 0, findings.QRSafe, "immediate")
			v := Evaluate([]findings.UnifiedFinding{f})
			if tt.wantViolate {
				if len(v) != 1 {
					t.Fatalf("expected 1 violation, got %d: %+v", len(v), v)
				}
				if v[0].Rule != tt.wantRule {
					t.Errorf("rule = %q, want %q", v[0].Rule, tt.wantRule)
				}
				if v[0].Deadline != deadlineKeyExchange {
					t.Errorf("deadline = %q, want %q", v[0].Deadline, deadlineKeyExchange)
				}
			} else {
				if len(v) != 0 {
					t.Errorf("expected no violations, got: %+v", v)
				}
			}
		})
	}
}

// TestCNSA2_HyphenlessMLDSA verifies that hyphen-less ML-DSA names are correctly
// caught by the param-set check (C1 reproducer).
func TestCNSA2_HyphenlessMLDSA(t *testing.T) {
	tests := []struct {
		algName     string
		wantViolate bool
	}{
		{"MLDSA44", true},
		{"MLDSA65", true},
		{"MLDSA87", false},
		{"MLDSA", false},
	}
	for _, tt := range tests {
		t.Run(tt.algName, func(t *testing.T) {
			f := algFinding(tt.algName, "signature", 0, findings.QRSafe, "deferred")
			v := Evaluate([]findings.UnifiedFinding{f})
			if tt.wantViolate {
				if len(v) != 1 {
					t.Fatalf("expected 1 violation, got %d: %+v", len(v), v)
				}
				if v[0].Rule != "cnsa2-ml-dsa-param-set" {
					t.Errorf("rule = %q, want cnsa2-ml-dsa-param-set", v[0].Rule)
				}
			} else {
				if len(v) != 0 {
					t.Errorf("expected no violations, got: %+v", v)
				}
			}
		})
	}
}

// TestCNSA2_HybridSubGrade verifies that hybrid KEMs using a sub-1024 ML-KEM
// variant produce a cnsa2-hybrid-sub-1024 violation (C3 reproducer).
func TestCNSA2_HybridSubGrade(t *testing.T) {
	tests := []struct {
		algName     string
		wantViolate bool
		wantRule    string
	}{
		{"X25519MLKEM768", true, "cnsa2-hybrid-sub-1024"},
		{"X25519MLKEM512", true, "cnsa2-hybrid-sub-1024"},
		{"X25519MLKEM1024", false, ""},
		{"SecP256r1MLKEM768", true, "cnsa2-hybrid-sub-1024"},
		{"SecP384r1MLKEM1024", false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.algName, func(t *testing.T) {
			f := algFinding(tt.algName, "kem", 0, findings.QRSafe, "immediate")
			v := Evaluate([]findings.UnifiedFinding{f})
			if tt.wantViolate {
				if len(v) != 1 {
					t.Fatalf("expected 1 violation, got %d: %+v", len(v), v)
				}
				if v[0].Rule != tt.wantRule {
					t.Errorf("rule = %q, want %q", v[0].Rule, tt.wantRule)
				}
				if v[0].Deadline != deadlineKeyExchange {
					t.Errorf("deadline = %q, want %q", v[0].Deadline, deadlineKeyExchange)
				}
			} else {
				if len(v) != 0 {
					t.Errorf("expected no violations, got: %+v", v)
				}
			}
		})
	}
}

// TestCNSA2_UnknownKEMDefaultDeny is the regression test for GAP-A surfaced by
// the sophisticated test run: CNSA 2.0 silently PASSED FrodoKEM-976-AES and
// other non-ML-KEM quantum-safe KEMs because no explicit rule matched. NSA
// CNSA 2.0 approves only ML-KEM-1024 for key establishment. Every other
// quantum-safe KEM — FrodoKEM (NIST Round 4 alternate), Classic McEliece, BIKE,
// HQC variants, future alternates — must fail via the default-deny rule.
//
// HQC is still caught by the earlier explicit cnsa2-hqc-not-approved rule
// (that name was already known); we assert that rule continues to fire
// instead of the more generic kem-not-approved.
func TestCNSA2_UnknownKEMDefaultDeny(t *testing.T) {
	tests := []struct {
		algName     string
		wantRule    string
		description string
	}{
		{"FrodoKEM-976-AES", "cnsa2-kem-not-approved", "BSI-approved lattice KEM, not on CNSA 2.0 list"},
		{"FrodoKEM-1344-SHAKE", "cnsa2-kem-not-approved", "BSI-approved Frodo variant"},
		{"Classic-McEliece-6960", "cnsa2-kem-not-approved", "BSI-approved code-based KEM"},
		{"Classic-McEliece-8192", "cnsa2-kem-not-approved", "Classic McEliece large variant"},
		{"BIKE-L1", "cnsa2-kem-not-approved", "NIST Round 4 alternate code-based KEM"},
		{"BIKE-L3", "cnsa2-kem-not-approved", "BIKE security level 3"},
		{"NTRU-Prime-761", "cnsa2-kem-not-approved", "sntrup761 variant"},
		// HQC is caught by the EARLIER explicit rule, not the default-deny.
		{"HQC-256", "cnsa2-hqc-not-approved", "explicit rule fires before default-deny"},
		{"HQC-128", "cnsa2-hqc-not-approved", "explicit HQC rule"},
	}
	for _, tt := range tests {
		t.Run(tt.algName, func(t *testing.T) {
			f := algFinding(tt.algName, "kem", 0, findings.QRSafe, "immediate")
			v := Evaluate([]findings.UnifiedFinding{f})
			if len(v) != 1 {
				t.Fatalf("%s (%s): expected 1 violation, got %d: %+v",
					tt.algName, tt.description, len(v), v)
			}
			if v[0].Rule != tt.wantRule {
				t.Errorf("%s: rule = %q, want %q", tt.algName, v[0].Rule, tt.wantRule)
			}
		})
	}
}

// TestCNSA2_ApprovedKEMsNotFlagged verifies that the default-deny rule does NOT
// fire for the two algorithms CNSA 2.0 actually approves: pure ML-KEM-1024
// and the approved hybrid X25519MLKEM1024 / SecP*MLKEM1024. This is the dual
// of TestCNSA2_UnknownKEMDefaultDeny — regression protection that the rule
// doesn't over-reject known-good algorithms.
func TestCNSA2_ApprovedKEMsNotFlagged(t *testing.T) {
	approved := []string{
		"ML-KEM-1024",
		"MLKEM1024", // hyphen-less form
		"X25519MLKEM1024",
		"SecP384r1MLKEM1024",
	}
	for _, name := range approved {
		t.Run(name, func(t *testing.T) {
			f := algFinding(name, "kem", 0, findings.QRSafe, "immediate")
			v := Evaluate([]findings.UnifiedFinding{f})
			if len(v) != 0 {
				t.Errorf("%s: approved CNSA 2.0 KEM produced violation(s): %+v", name, v)
			}
		})
	}
}
