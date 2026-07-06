package compliance

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/quantum"
)

var asd = asdISMFramework{}

func asdFinding(name, prim string, keySize int, qr findings.QuantumRisk) findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Algorithm:   &findings.Algorithm{Name: name, Primitive: prim, KeySize: keySize},
		QuantumRisk: qr,
	}
}

func TestASD_QuantumVulnerable(t *testing.T) {
	for _, alg := range []string{"RSA-2048", "ECDH", "ECDSA"} {
		t.Run(alg, func(t *testing.T) {
			f := asdFinding(alg, "kem", 0, findings.QRVulnerable)
			v := asd.Evaluate([]findings.UnifiedFinding{f})
			if len(v) != 1 {
				t.Fatalf("expected 1 violation, got %d", len(v))
			}
			if v[0].Rule != "asd-quantum-vulnerable" {
				t.Errorf("rule = %q, want asd-quantum-vulnerable", v[0].Rule)
			}
		})
	}
}

// TestASD_MLKEMGrade verifies only ML-KEM-1024 passes ASD ISM.
func TestASD_MLKEMGrade(t *testing.T) {
	tests := []struct {
		name        string
		wantViolate bool
	}{
		{"ML-KEM-512", true},
		{"ML-KEM-768", true},
		{"ML-KEM-1024", false},
		{"ML-KEM", false}, // no numeric suffix → no grade check
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := asdFinding(tt.name, "kem", 0, findings.QRSafe)
			v := asd.Evaluate([]findings.UnifiedFinding{f})
			if tt.wantViolate {
				if len(v) != 1 {
					t.Fatalf("expected 1 violation, got %d", len(v))
				}
				if v[0].Rule != "asd-ml-kem-grade" {
					t.Errorf("rule = %q, want asd-ml-kem-grade", v[0].Rule)
				}
			} else {
				if len(v) != 0 {
					t.Errorf("expected no violations, got: %+v", v)
				}
			}
		})
	}
}

// TestASD_MLDSAGrade verifies only ML-DSA-87 passes ASD ISM.
func TestASD_MLDSAGrade(t *testing.T) {
	tests := []struct {
		name        string
		wantViolate bool
	}{
		{"ML-DSA-44", true},
		{"ML-DSA-65", true},
		{"ML-DSA-87", false},
		{"ML-DSA", false}, // no numeric suffix → no grade check
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := asdFinding(tt.name, "signature", 0, findings.QRSafe)
			v := asd.Evaluate([]findings.UnifiedFinding{f})
			if tt.wantViolate {
				if len(v) != 1 {
					t.Fatalf("expected 1 violation, got %d", len(v))
				}
				if v[0].Rule != "asd-ml-dsa-grade" {
					t.Errorf("rule = %q, want asd-ml-dsa-grade", v[0].Rule)
				}
			} else {
				if len(v) != 0 {
					t.Errorf("expected no violations, got: %+v", v)
				}
			}
		})
	}
}

// TestASD_SLHDSAPasses verifies SLH-DSA passes ASD ISM (unlike CNSA 2.0).
func TestASD_SLHDSAPasses(t *testing.T) {
	for _, name := range []string{"SLH-DSA", "SLH-DSA-128f", "SLH-DSA-256s"} {
		t.Run(name, func(t *testing.T) {
			f := asdFinding(name, "signature", 0, findings.QRSafe)
			v := asd.Evaluate([]findings.UnifiedFinding{f})
			if len(v) != 0 {
				t.Errorf("SLH-DSA should pass ASD ISM; got: %+v", v)
			}
		})
	}
}

// TestASD_AESKeySize verifies ASD ISM requires AES-256.
func TestASD_AESKeySize(t *testing.T) {
	tests := []struct {
		name        string
		keySize     int
		wantViolate bool
	}{
		{"AES-128-GCM", 0, true},
		{"AES-192-GCM", 0, true},
		{"AES-256-GCM", 0, false},
		{"AES-256", 256, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := asdFinding(tt.name, "symmetric", tt.keySize, findings.QRResistant)
			v := asd.Evaluate([]findings.UnifiedFinding{f})
			if tt.wantViolate {
				if len(v) != 1 {
					t.Fatalf("expected 1 violation, got %d: %+v", len(v), v)
				}
				if v[0].Rule != "asd-aes-key-size" {
					t.Errorf("rule = %q, want asd-aes-key-size", v[0].Rule)
				}
			} else {
				if len(v) != 0 {
					t.Errorf("expected no violations, got: %+v", v)
				}
			}
		})
	}
}

// TestASD_HashOutputSize verifies ASD ISM requires SHA-384/512.
func TestASD_HashOutputSize(t *testing.T) {
	tests := []struct {
		name        string
		keySize     int
		wantViolate bool
	}{
		{"SHA-256", 256, true},
		{"SHA-384", 384, false},
		{"SHA-512", 512, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := asdFinding(tt.name, "hash", tt.keySize, findings.QRResistant)
			v := asd.Evaluate([]findings.UnifiedFinding{f})
			if tt.wantViolate {
				if len(v) != 1 {
					t.Fatalf("expected 1 violation, got %d", len(v))
				}
				if v[0].Rule != "asd-hash-output-size" {
					t.Errorf("rule = %q, want asd-hash-output-size", v[0].Rule)
				}
			} else {
				if len(v) != 0 {
					t.Errorf("expected no violations, got: %+v", v)
				}
			}
		})
	}
}

// TestASD_HyphenlessMLKEM verifies that hyphen-less ML-KEM names are caught by
// the grade check (C2 reproducer — same root cause as CNSA 2.0 C1).
func TestASD_HyphenlessMLKEM(t *testing.T) {
	tests := []struct {
		algName     string
		wantViolate bool
	}{
		{"MLKEM512", true},
		{"MLKEM768", true},
		{"MLKEM1024", false},
		{"MLKEM", false},
	}
	for _, tt := range tests {
		t.Run(tt.algName, func(t *testing.T) {
			f := asdFinding(tt.algName, "kem", 0, findings.QRSafe)
			v := asd.Evaluate([]findings.UnifiedFinding{f})
			if tt.wantViolate {
				if len(v) != 1 {
					t.Fatalf("expected 1 violation, got %d: %+v", len(v), v)
				}
				if v[0].Rule != "asd-ml-kem-grade" {
					t.Errorf("rule = %q, want asd-ml-kem-grade", v[0].Rule)
				}
			} else {
				if len(v) != 0 {
					t.Errorf("expected no violations, got: %+v", v)
				}
			}
		})
	}
}

// TestASD_HyphenlessMLDSA verifies that hyphen-less ML-DSA names are caught by
// the grade check (C2 reproducer).
func TestASD_HyphenlessMLDSA(t *testing.T) {
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
			f := asdFinding(tt.algName, "signature", 0, findings.QRSafe)
			v := asd.Evaluate([]findings.UnifiedFinding{f})
			if tt.wantViolate {
				if len(v) != 1 {
					t.Fatalf("expected 1 violation, got %d: %+v", len(v), v)
				}
				if v[0].Rule != "asd-ml-dsa-grade" {
					t.Errorf("rule = %q, want asd-ml-dsa-grade", v[0].Rule)
				}
			} else {
				if len(v) != 0 {
					t.Errorf("expected no violations, got: %+v", v)
				}
			}
		})
	}
}

func TestASD_EmptyInput(t *testing.T) {
	if v := asd.Evaluate(nil); v != nil {
		t.Errorf("expected nil for nil input, got %v", v)
	}
}

// TestASD_HybridSubGrade is the regression test for ultrareview merged_bug_006
// gap 1: ASD ISM was silently passing hybrid KEMs like X25519MLKEM768 even
// though the framework mandates ML-KEM-1024 grade (this is the most common
// production PQC TLS hybrid — Cloudflare/Chrome default).
func TestASD_HybridSubGrade(t *testing.T) {
	tests := []struct {
		algName     string
		wantViolate bool
		wantRule    string
	}{
		{"X25519MLKEM768", true, "asd-hybrid-sub-1024"},
		{"X25519MLKEM512", true, "asd-hybrid-sub-1024"},
		{"X25519MLKEM1024", false, ""},
		{"SecP256r1MLKEM768", true, "asd-hybrid-sub-1024"},
		{"SecP384r1MLKEM1024", false, ""},
		{"curveSM2MLKEM768", true, "asd-hybrid-sub-1024"},
	}
	for _, tt := range tests {
		t.Run(tt.algName, func(t *testing.T) {
			f := asdFinding(tt.algName, "kem", 0, findings.QRSafe)
			v := asd.Evaluate([]findings.UnifiedFinding{f})
			if tt.wantViolate {
				if len(v) != 1 {
					t.Fatalf("expected 1 violation, got %d: %+v", len(v), v)
				}
				if v[0].Rule != tt.wantRule {
					t.Errorf("rule = %q, want %q", v[0].Rule, tt.wantRule)
				}
			} else {
				if len(v) != 0 {
					t.Errorf("expected no violations, got: %+v", v)
				}
			}
		})
	}
}

// TestASD_SymmetricUnapproved is the regression test for ultrareview
// merged_bug_006 gap 2: ASD ISM's stated "AES-256 only" policy was silently
// passing ChaCha20-Poly1305, Camellia, ARIA, etc. because the symmetric branch
// only checked AES key size and had no catch-all for non-AES ciphers.
func TestASD_SymmetricUnapproved(t *testing.T) {
	for _, alg := range []string{
		"ChaCha20-Poly1305",
		"ChaCha20",
		"Camellia-256",
		"ARIA-256",
		"SEED",
		"Serpent-256",
		"Twofish-256",
		"3DES",
		"RC4",
	} {
		t.Run(alg, func(t *testing.T) {
			f := asdFinding(alg, "symmetric", 256, findings.QRSafe)
			v := asd.Evaluate([]findings.UnifiedFinding{f})
			if len(v) != 1 {
				t.Fatalf("expected 1 violation for %s, got %d: %+v", alg, len(v), v)
			}
			if v[0].Rule != "asd-symmetric-unapproved" {
				t.Errorf("%s: rule = %q, want asd-symmetric-unapproved", alg, v[0].Rule)
			}
		})
	}
}

// TestASD_SymmetricApprovedStillPasses guards against the new
// symmetric-unapproved rule over-rejecting valid AES-256 findings.
func TestASD_SymmetricApprovedStillPasses(t *testing.T) {
	for _, alg := range []string{"AES-256-GCM", "AES-256-CBC", "AES-256"} {
		t.Run(alg, func(t *testing.T) {
			f := asdFinding(alg, "symmetric", 256, findings.QRSafe)
			v := asd.Evaluate([]findings.UnifiedFinding{f})
			if len(v) != 0 {
				t.Errorf("%s: expected no violations, got: %+v", alg, v)
			}
		})
	}
}

// TestASD_HashUnapproved is the regression test for ultrareview
// merged_bug_006 gap 3: ASD ISM's stated "SHA-2 only" policy was silently
// passing SHA-3-384/512 and BLAKE2-384/512 because the size check didn't
// distinguish SHA-2 from other SHA families.
func TestASD_HashUnapproved(t *testing.T) {
	tests := []struct {
		algName  string
		keySize  int
		wantRule string
	}{
		{"SHA3-384", 384, "asd-hash-unapproved"},
		{"SHA3-512", 512, "asd-hash-unapproved"},
		{"SHA-3-256", 256, "asd-hash-unapproved"},
		{"BLAKE2b-512", 512, "asd-hash-unapproved"},
		{"BLAKE3-384", 384, "asd-hash-unapproved"},
		{"SHA-256", 256, "asd-hash-output-size"},   // SHA-2 but too small
		{"SHA-384", 384, ""},                        // SHA-2 approved
		{"SHA-512", 512, ""},                        // SHA-2 approved
		{"HMAC-SHA-256", 256, "asd-hash-output-size"},
		{"HMAC-SHA-384", 384, ""},
	}
	for _, tt := range tests {
		t.Run(tt.algName, func(t *testing.T) {
			f := asdFinding(tt.algName, "hash", tt.keySize, findings.QRSafe)
			v := asd.Evaluate([]findings.UnifiedFinding{f})
			if tt.wantRule == "" {
				if len(v) != 0 {
					t.Errorf("%s: expected no violations, got: %+v", tt.algName, v)
				}
				return
			}
			if len(v) != 1 {
				t.Fatalf("%s: expected 1 violation, got %d: %+v", tt.algName, len(v), v)
			}
			if v[0].Rule != tt.wantRule {
				t.Errorf("%s: rule = %q, want %q", tt.algName, v[0].Rule, tt.wantRule)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// B3 fix: ASD ISM default-deny for KEM/signature primitives ASD ISM's own
// ApprovedAlgos() table doesn't list. Mirrors CNSA 2.0's
// cnsa2-kem-not-approved / cnsa2-signature-not-approved default-deny
// (cnsa2.go:208-244). Before the fix, FrodoKEM/HQC/McEliece/Falcon fell
// through Evaluate() with zero violations despite ASD ISM restricting Key
// Exchange to ML-KEM-1024 and Digital Signatures to ML-DSA-87/SLH-DSA only.
// ---------------------------------------------------------------------------

func TestASD_KEMDefaultDeny(t *testing.T) {
	tests := []struct {
		algName     string
		description string
	}{
		{"FrodoKEM-976-AES", "BSI-approved lattice KEM, not on ASD ISM's ML-KEM-1024-only list"},
		{"FrodoKEM-1344-SHAKE", "BSI-approved Frodo variant"},
		{"HQC-256", "NIST-selected 5th PQC KEM, not on ASD ISM's approved list"},
		{"HQC-128", "HQC smaller variant"},
		{"Classic-McEliece-6960", "BSI-approved code-based KEM"},
		{"Classic-McEliece-8192", "Classic McEliece large variant"},
	}
	for _, tt := range tests {
		t.Run(tt.algName, func(t *testing.T) {
			f := asdFinding(tt.algName, "kem", 0, findings.QRSafe)
			v := asd.Evaluate([]findings.UnifiedFinding{f})
			if len(v) != 1 {
				t.Fatalf("%s (%s): expected 1 violation, got %d: %+v", tt.algName, tt.description, len(v), v)
			}
			if v[0].Rule != "asd-kem-not-approved" {
				t.Errorf("%s: rule = %q, want asd-kem-not-approved", tt.algName, v[0].Rule)
			}
		})
	}
}

func TestASD_SignatureDefaultDeny(t *testing.T) {
	// Falcon/FN-DSA: pkg/quantum classifies these RiskSafe (standard-pending,
	// see G2 fix) but ASD ISM's own ApprovedAlgos() restricts Digital
	// Signatures to ML-DSA-87 and SLH-DSA only — Falcon is not on that list.
	names := []string{"Falcon-512", "Falcon-1024", "FALCON-512", "FN-DSA-512", "FNDSA512", "Falcon"}
	for _, n := range names {
		t.Run(n, func(t *testing.T) {
			f := asdFinding(n, "signature", 0, findings.QRSafe)
			v := asd.Evaluate([]findings.UnifiedFinding{f})
			if len(v) != 1 {
				t.Fatalf("expected 1 violation, got %d: %+v", len(v), v)
			}
			if v[0].Rule != "asd-signature-not-approved" {
				t.Errorf("rule = %q, want asd-signature-not-approved", v[0].Rule)
			}
		})
	}
}

// TestASD_SLHDSA_StillApproved is the regression guard: the new KEM/signature
// default-deny must not swallow SLH-DSA, which ASD ISM's own ApprovedAlgos()
// explicitly approves for all parameter sets.
func TestASD_SLHDSA_StillApproved(t *testing.T) {
	for _, n := range []string{"SLH-DSA", "SLH-DSA-128f", "SLH-DSA-256s"} {
		t.Run(n, func(t *testing.T) {
			f := asdFinding(n, "signature", 0, findings.QRSafe)
			v := asd.Evaluate([]findings.UnifiedFinding{f})
			if len(v) != 0 {
				t.Errorf("SLH-DSA must remain approved under ASD ISM, got violations: %+v", v)
			}
		})
	}
}

// TestASD_ApprovedKEMsSignaturesNotFlagged is the dual of the default-deny
// tests: ML-KEM-1024 and ML-DSA-87 (ASD ISM's actual approved algorithms)
// must not be caught by the new catch-all rules.
func TestASD_ApprovedKEMsSignaturesNotFlagged(t *testing.T) {
	f1 := asdFinding("ML-KEM-1024", "kem", 0, findings.QRSafe)
	if v := asd.Evaluate([]findings.UnifiedFinding{f1}); len(v) != 0 {
		t.Errorf("ML-KEM-1024 should not be flagged, got: %+v", v)
	}
	f2 := asdFinding("ML-DSA-87", "signature", 0, findings.QRSafe)
	if v := asd.Evaluate([]findings.UnifiedFinding{f2}); len(v) != 0 {
		t.Errorf("ML-DSA-87 should not be flagged, got: %+v", v)
	}
}

// TestASD_Falcon_ClassifierVsFramework_LayerSeparation pins the distinction
// between pkg/quantum's classifier view (Falcon is RiskSafe, standard-pending
// — see the G2 fix) and ASD ISM's independent approved-list enforcement
// (Falcon is NOT on ASD ISM's approved signature list, which is ML-DSA-87 +
// SLH-DSA only). A quantum-safe algorithm per the classifier can still be
// non-compliant with a specific framework's approved list — these are two
// independent layers, and the fix for B3 must not conflate them.
func TestASD_Falcon_ClassifierVsFramework_LayerSeparation(t *testing.T) {
	c := quantum.ClassifyAlgorithm("Falcon-512", "signature", 0)
	if c.Risk != quantum.RiskSafe {
		t.Fatalf("pkg/quantum classifier: Falcon-512 Risk = %q, want RiskSafe (pre-req for this test's premise)", c.Risk)
	}

	f := asdFinding("Falcon-512", "signature", 0, findings.QRSafe)
	v := asd.Evaluate([]findings.UnifiedFinding{f})
	if len(v) != 1 {
		t.Fatalf("ASD ISM must flag Falcon-512 as not-approved despite classifier RiskSafe; got %d violations: %+v", len(v), v)
	}
	if v[0].Rule != "asd-signature-not-approved" {
		t.Errorf("rule = %q, want asd-signature-not-approved", v[0].Rule)
	}
}

func TestASD_RegistrationAndID(t *testing.T) {
	fw, ok := Get("asd-ism")
	if !ok {
		t.Fatal("asd-ism not found in registry")
	}
	if fw.ID() != "asd-ism" {
		t.Errorf("ID = %q, want asd-ism", fw.ID())
	}
	if fw.Name() != "ASD ISM" {
		t.Errorf("Name = %q, want ASD ISM", fw.Name())
	}
}

// Wave-2 review V16-V18: the signature default-deny must not flag
// algorithms ASD ISM itself approves — OID-derived hyphen-less SLH-DSA
// names from the TLS probe ("slhdsa-sha2-128s"), and SP 800-208 stateful
// hash signatures (XMSS/LMS), which the mirrored CNSA 2.0 rule exempts.
func TestASD_ApprovedSignatureShapesNotDenied(t *testing.T) {
	fw := asdISMFramework{}
	for _, tc := range []struct{ name, primitive string }{
		{"slhdsa-sha2-128s", "digital-signature"},
		{"slhdsa-shake-256f", "digital-signature"},
		{"SLH-DSA-SHA2-128s", "signature"},
		{"XMSS", "signature"},
		{"LMS", "signature"},
		{"XMSSMT", "signature"},
	} {
		ff := []findings.UnifiedFinding{{
			Algorithm:   &findings.Algorithm{Name: tc.name, Primitive: tc.primitive},
			QuantumRisk: findings.QRSafe,
		}}
		vs := fw.Evaluate(ff)
		for _, v := range vs {
			if v.Rule == "asd-signature-not-approved" {
				t.Errorf("%s: asd-signature-not-approved fired on an ASD-approved signature shape: %s", tc.name, v.Message)
			}
		}
	}
	// Default-deny still catches genuinely unapproved signatures.
	ff := []findings.UnifiedFinding{{
		Algorithm:   &findings.Algorithm{Name: "Falcon-512", Primitive: "signature"},
		QuantumRisk: findings.QRSafe,
	}}
	found := false
	for _, v := range fw.Evaluate(ff) {
		if v.Rule == "asd-signature-not-approved" {
			found = true
		}
	}
	if !found {
		t.Error("Falcon-512 must still trip asd-signature-not-approved")
	}
}
