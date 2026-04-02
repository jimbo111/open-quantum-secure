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
		{
			name:    "quantum-safe unknown algorithm no violation",
			finding: algFinding("SomeNewPQC", "signature", 0, findings.QRSafe, ""),
		},
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
		{"ML-KEM-512", 512},
		{"ML-KEM-768", 768},
		{"ML-KEM-1024", 1024},
		{"ML-KEM", 0},
		{"ML-DSA-44", 44},
		{"ML-DSA-65", 65},
		{"ML-DSA-87", 87},
		{"ML-DSA", 0},
		{"SLH-DSA-128f", 0}, // suffix is "128f" — not purely numeric
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
