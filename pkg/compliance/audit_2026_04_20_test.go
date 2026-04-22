package compliance

// Audit 2026-04-20 — Compliance framework adversarial + property tests.
// Report: docs/audits/2026-04-20-scanner-layer-audit/09-policy-compliance.md.
//
// Each test documents observed behaviour. A failing test = behaviour regressed
// since the audit or a bug was fixed (in which case update the expectation).

import (
	"fmt"
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// ---------------------------------------------------------------------------
// Table-driven: CNSA 2.0 compliance over NIST PQC finalists + classical algs.
// Covers the audit "Focus Area 4" matrix. Each row asserts expected CNSA 2.0
// status AND flags known gaps inline.
// ---------------------------------------------------------------------------
func TestAudit_CNSA2_AlgorithmMatrix(t *testing.T) {
	type row struct {
		name       string
		primitive  string
		keySize    int
		qr         findings.QuantumRisk
		wantPass   bool   // wantPass=true → Evaluate returns zero violations
		wantRule   string // when wantPass=false, the expected rule ID
		annotation string
	}
	cases := []row{
		// --- PQC KEMs ---
		{"ML-KEM-512", "kem", 0, findings.QRSafe, false, "cnsa2-ml-kem-key-size", "sub-1024 grade"},
		{"ML-KEM-768", "kem", 0, findings.QRSafe, false, "cnsa2-ml-kem-key-size", "sub-1024 grade"},
		{"ML-KEM-1024", "kem", 0, findings.QRSafe, true, "", "CNSA 2.0 sole approved KEM"},
		{"MLKEM1024", "kem", 0, findings.QRSafe, true, "", "hyphenless form"},

		// --- PQC Signatures ---
		{"ML-DSA-44", "signature", 0, findings.QRSafe, false, "cnsa2-ml-dsa-param-set", "sub-87"},
		{"ML-DSA-65", "signature", 0, findings.QRSafe, false, "cnsa2-ml-dsa-param-set", "sub-87"},
		{"ML-DSA-87", "signature", 0, findings.QRSafe, true, "", "CNSA 2.0 approved"},
		{"SLH-DSA-128f", "signature", 0, findings.QRSafe, false, "cnsa2-slh-dsa-excluded", "FIPS 205 but excluded from CNSA 2.0"},
		{"SLH-DSA-256s", "signature", 0, findings.QRSafe, false, "cnsa2-slh-dsa-excluded", ""},
		// Caught by the 2026-04-20 signature default-deny (cnsa2-signature-not-approved).
		{"Falcon-512", "signature", 0, findings.QRSafe, false, "cnsa2-signature-not-approved", "Falcon/FN-DSA not on CNSA 2.0 list"},
		{"FN-DSA-512", "signature", 0, findings.QRSafe, false, "cnsa2-signature-not-approved", "Falcon/FN-DSA not on CNSA 2.0 list"},

		// --- Stateful hash signatures ---
		{"LMS", "signature", 0, findings.QRSafe, true, "", "SP 800-208 approved"},
		{"XMSS", "signature", 0, findings.QRSafe, true, "", "SP 800-208 approved"},
		{"HSS", "signature", 0, findings.QRSafe, true, "", "SP 800-208 multi-tree LMS"},

		// --- Classical / Quantum-vulnerable ---
		{"RSA-2048", "kem", 2048, findings.QRVulnerable, false, "cnsa2-quantum-vulnerable", "classical"},
		{"RSA-3072", "kem", 3072, findings.QRVulnerable, false, "cnsa2-quantum-vulnerable", "classical"},
		{"ECDH-P256", "kem", 0, findings.QRVulnerable, false, "cnsa2-quantum-vulnerable", "classical ECDH"},
		{"ECDH-P384", "kem", 0, findings.QRVulnerable, false, "cnsa2-quantum-vulnerable", "classical ECDH"},
		{"ECDSA", "signature", 0, findings.QRVulnerable, false, "cnsa2-quantum-vulnerable", "classical sig"},
		{"DH", "kem", 0, findings.QRVulnerable, false, "cnsa2-quantum-vulnerable", "classical DH"},

		// --- Symmetric ---
		{"AES-128", "symmetric", 128, findings.QRWeakened, false, "cnsa2-symmetric-key-size", "sub-256"},
		{"AES-192", "symmetric", 192, findings.QRWeakened, false, "cnsa2-symmetric-key-size", ""},
		{"AES-256", "symmetric", 256, findings.QRResistant, true, "", "approved"},

		// --- Hash ---
		{"SHA-256", "hash", 256, findings.QRResistant, false, "cnsa2-hash-output-size", "sub-384"},
		{"SHA-384", "hash", 384, findings.QRResistant, true, "", "approved"},
		{"SHA-512", "hash", 512, findings.QRResistant, true, "", "approved"},
		{"SHA3-256", "hash", 256, findings.QRResistant, false, "cnsa2-hash-unapproved", "SHA-3 excluded"},
		{"SHA3-512", "hash", 512, findings.QRResistant, false, "cnsa2-hash-unapproved", "SHA-3 excluded"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := algFinding(c.name, c.primitive, c.keySize, c.qr, "deferred")
			v := Evaluate([]findings.UnifiedFinding{f})
			if c.wantPass {
				if len(v) != 0 {
					t.Errorf("[%s] expected PASS (%s), got violations: %+v", c.name, c.annotation, v)
				}
			} else {
				if len(v) == 0 {
					t.Errorf("[%s] expected FAIL with rule %q (%s), got PASS (silent approval)",
						c.name, c.wantRule, c.annotation)
				} else if v[0].Rule != c.wantRule {
					t.Errorf("[%s] expected rule %q, got %q (%s)", c.name, c.wantRule, v[0].Rule, c.annotation)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// F-C1 (Adversarial): CNSA 2.0 silently approves Falcon / FN-DSA
//
// SEVERITY: CRITICAL — CNSA 2.0 false-approval of a non-approved PQC alg.
//
// NSA CNSA 2.0 approves ONLY ML-DSA-87 for digital signatures (with SLH-DSA
// explicitly excluded). Falcon (NIST FIPS 206 FN-DSA, still draft) is not on
// the CNSA 2.0 approved list. A QRSafe finding named "Falcon-512" or
// "FN-DSA-512" with primitive="signature" is emitted by some engines today
// (e.g. liboqs-based detectors). The CNSA 2.0 evaluator has no rule that
// matches Falcon/FN-DSA: it falls through every check and produces zero
// violations — i.e. silently approves a non-approved signature algorithm.
//
// This is the dual of the `cnsa2-kem-not-approved` default-deny rule that
// correctly catches unknown KEMs; no equivalent default-deny exists on the
// signature side.
// ---------------------------------------------------------------------------
func TestAudit_CNSA2_Falcon_FalseApproval(t *testing.T) {
	// 2026-04-20: flipped from t.Logf to t.Errorf as part of fixing F-C1.
	// NSA CNSA 2.0 approves only ML-DSA-87 for signatures (and LMS/HSS/XMSS
	// for firmware signing). Falcon/FN-DSA are NOT approved and must produce
	// a violation.
	names := []string{"Falcon-512", "Falcon-1024", "FALCON-512", "FN-DSA-512", "FNDSA512", "Falcon"}
	for _, n := range names {
		t.Run(n, func(t *testing.T) {
			f := algFinding(n, "signature", 0, findings.QRSafe, "deferred")
			v := Evaluate([]findings.UnifiedFinding{f})
			if len(v) == 0 {
				t.Errorf("CNSA 2.0 must reject %s (signature, QRSafe) — got 0 violations", n)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// F-C2 (Adversarial): CNSA 2.0 KEM default-deny SKIPS QRWeakened / QRUnknown
//
// SEVERITY: HIGH — potential policy-bypass.
//
// The default-deny rule fires only when the finding is NEITHER QRVulnerable
// NOR QRDeprecated (cnsa2.go:189). That means QRWeakened or QRUnknown (or
// QRResistant) KEMs fall through every earlier rule and DO hit the default
// deny. But wait — let's assert behaviour concretely: a future/misclassified
// KEM name with QR=Unknown should still be caught OR there must be conscious
// handling. Code analysis: the condition excludes only QRVulnerable /
// QRDeprecated. QRUnknown / QRSafe / QRResistant / QRWeakened all trigger.
// This test pins the current behaviour so regressions are detected.
// ---------------------------------------------------------------------------
func TestAudit_CNSA2_DefaultDeny_QRBranches(t *testing.T) {
	type row struct {
		qr        findings.QuantumRisk
		wantFires bool
	}
	// Unknown KEM "BIKE-L1" with each possible QR value:
	cases := []row{
		{findings.QRSafe, true},
		{findings.QRResistant, true},
		{findings.QRWeakened, true},
		{findings.QRUnknown, true},
		{findings.QRVulnerable, false}, // caught by earlier quantum-vulnerable rule
		{findings.QRDeprecated, false}, // caught by earlier quantum-vulnerable rule
	}
	for _, c := range cases {
		t.Run(string(c.qr), func(t *testing.T) {
			f := algFinding("BIKE-L1", "kem", 0, c.qr, "immediate")
			v := Evaluate([]findings.UnifiedFinding{f})
			fired := false
			for _, vi := range v {
				if vi.Rule == "cnsa2-kem-not-approved" {
					fired = true
				}
			}
			if fired != c.wantFires {
				t.Errorf("QR=%s BIKE-L1: kem-not-approved fired=%v, want %v; got violations=%+v",
					c.qr, fired, c.wantFires, v)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// F-C3 (Adversarial): CNSA 2.0 approves SHA-512/256 (truncated SHA-512)
//
// Observation: "SHA-512/256" has 256-bit output. The current resolveHashOutputSize
// uses substring matching, so "SHA-512/256" will match "512" FIRST (since
// the switch checks 512 before 256). Then the check `size < 384` is false
// (size=512), so no violation fires. But SHA-512/256 is a truncated variant
// with 256-bit security — it should NOT meet CNSA 2.0's 384-bit minimum.
// ---------------------------------------------------------------------------
func TestAudit_CNSA2_SHA512_256_Truncated_IncorrectlyApproved(t *testing.T) {
	// 2026-04-21: flipped after fix. SHA-512/256 is the truncated variant
	// (256-bit output) per NIST FIPS 180-4; CNSA 2.0 requires 384-bit
	// minimum so this must produce a violation.
	f := algFinding("SHA-512/256", "hash", 0, findings.QRResistant, "")
	v := Evaluate([]findings.UnifiedFinding{f})
	if len(v) == 0 {
		t.Errorf("SHA-512/256 must be rejected by CNSA 2.0 (256-bit output < 384-bit minimum); got 0 violations")
	} else if v[0].Rule != "cnsa2-hash-output-size" {
		t.Errorf("SHA-512/256: expected rule cnsa2-hash-output-size, got %q", v[0].Rule)
	}
}

// ---------------------------------------------------------------------------
// F-C4 (Adversarial): CNSA 2.0 AES with ambiguous key size inference
//
// "AES-GCM-128" contains "128" — will be detected by the substring scan as
// 128-bit. But ordering in resolveSymmetricKeySize is 256 → 192 → 128 on
// Contains(). An alg name like "AES-128-256-WRAP" (hypothetical) would match
// 256 first, silently approving a 128-bit key. This is an exploitable pattern
// if a name contains "256" incidentally.
// ---------------------------------------------------------------------------
func TestAudit_CNSA2_AES_SubstringKeySizeConfusion(t *testing.T) {
	// 2026-04-21: flipped after fix. These 128-bit ciphers contain "256"
	// in their cipher suite name (SHA256 MAC) but the AES key is 128-bit
	// so CNSA 2.0 must reject them with a key-size violation.
	confusing := []string{
		"AES-128-SHA256",
		"AES-128-HMAC-SHA256",
	}
	for _, name := range confusing {
		t.Run(name, func(t *testing.T) {
			f := algFinding(name, "symmetric", 0, findings.QRWeakened, "")
			v := Evaluate([]findings.UnifiedFinding{f})
			if len(v) == 0 {
				t.Errorf("CNSA 2.0 must reject %q (128-bit AES key): got 0 violations", name)
			} else if v[0].Rule != "cnsa2-symmetric-key-size" {
				t.Errorf("%q: expected rule cnsa2-symmetric-key-size, got %q", name, v[0].Rule)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// F-C5 (Adversarial): CNSA 2.0 leaves ECDSA with extremely high quantum
// safety classification intact. If the finding is mis-classified as QRSafe
// (bug upstream), CNSA 2.0 doesn't have a name-based ECDSA rejection.
// ---------------------------------------------------------------------------
func TestAudit_CNSA2_MisclassifiedECDSA_FallsThroughToNoViolation(t *testing.T) {
	// 2026-04-21: flipped after fix. Defence-in-depth: even if an engine
	// misclassifies ECDSA as QRSafe, CNSA 2.0 must still reject by name.
	cases := []struct {
		name      string
		primitive string
	}{
		{"ECDSA", "signature"},
		{"RSA-2048", "kem"},
		{"ECDH-P256", "kem"},
		{"DH", "kem"},
		{"DSA", "signature"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := algFinding(c.name, c.primitive, 0, findings.QRSafe, "deferred")
			v := Evaluate([]findings.UnifiedFinding{f})
			if len(v) == 0 {
				t.Errorf("%s tagged QRSafe must still be rejected by CNSA 2.0 name-based defence, got 0 violations", c.name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// F-C6 (Adversarial): Per-framework classical-vulnerability coverage matrix.
//
// For each framework, assert that classical quantum-vulnerable algorithms are
// rejected AND PQC-safe algorithms (the framework's own approved set) pass.
// This is the "framework-specific rules" audit focus #5.
// ---------------------------------------------------------------------------
func TestAudit_AllFrameworks_ClassicalVulnerableRejected(t *testing.T) {
	classicalFindings := []findings.UnifiedFinding{
		algFinding("RSA-2048", "kem", 2048, findings.QRVulnerable, "immediate"),
		algFinding("ECDSA", "signature", 0, findings.QRVulnerable, "deferred"),
		algFinding("ECDH-P256", "kem", 0, findings.QRVulnerable, "immediate"),
		algFinding("DH", "kem", 0, findings.QRVulnerable, "immediate"),
	}

	// Frameworks whose Evaluate MUST produce at least one violation for a
	// classical quantum-vulnerable input.
	enforcingFrameworks := []string{
		"cnsa-2.0", "asd-ism", "bsi-tr-02102", "ncsc-uk",
		"nist-ir-8547", "anssi-guide-pqc",
	}
	for _, id := range enforcingFrameworks {
		t.Run(id, func(t *testing.T) {
			fw, ok := Get(id)
			if !ok {
				t.Fatalf("framework %q not registered", id)
			}
			for _, f := range classicalFindings {
				v := fw.Evaluate([]findings.UnifiedFinding{f})
				if len(v) == 0 {
					t.Errorf("framework %q accepted classical quantum-vulnerable %s (expected violation)",
						id, f.Algorithm.Name)
				}
			}
		})
	}
	// PCI DSS 4.0 is the inventory-only framework — it PASSES QRVulnerable
	// findings (they ARE inventory evidence). Documented per pci_dss_4_0.go.
	t.Run("pci-dss-4.0-inventory-only", func(t *testing.T) {
		fw, ok := Get("pci-dss-4.0")
		if !ok {
			t.Fatal("pci-dss-4.0 not registered")
		}
		v := fw.Evaluate(classicalFindings)
		if len(v) != 0 {
			t.Errorf("PCI DSS 4.0 expects PASS on classified findings (inventory evidence); got %v", v)
		}
	})
}

// ---------------------------------------------------------------------------
// F-C7 (Adversarial): Per-framework PQC approval — ML-KEM-1024 + ML-DSA-87
// must pass EVERY framework (they are the universal PQC approvals).
// ---------------------------------------------------------------------------
func TestAudit_AllFrameworks_ML_KEM_1024_And_ML_DSA_87_Pass(t *testing.T) {
	mlkem := algFinding("ML-KEM-1024", "kem", 0, findings.QRSafe, "immediate")
	mldsa := algFinding("ML-DSA-87", "signature", 0, findings.QRSafe, "deferred")

	// ANSSI flags pure ML-KEM-KEX as "warn" via anssi-hybrid-kem-required —
	// it's a recommendation (severity=warn), not a hard failure. BSI likewise.
	// These frameworks are in the "hybrid-required" set.
	advisoryFrameworks := map[string]bool{"anssi-guide-pqc": true, "bsi-tr-02102": true}

	for _, fw := range All() {
		t.Run(fw.ID()+"/ML-KEM-1024", func(t *testing.T) {
			v := fw.Evaluate([]findings.UnifiedFinding{mlkem})
			if fw.ID() == "pci-dss-4.0" {
				// Passes because QRSafe is classified evidence.
				if len(v) != 0 {
					t.Errorf("%s: expected PCI PASS on classified finding, got %v", fw.ID(), v)
				}
				return
			}
			if advisoryFrameworks[fw.ID()] {
				// Permitted: exactly one warn on the hybrid recommendation.
				if len(v) == 1 && v[0].Severity == "warn" {
					return
				}
				if len(v) == 0 {
					return // also fine (PQC is safe; no errors)
				}
				t.Errorf("%s: pure ML-KEM-1024 expected 0 or 1 warn violation, got %+v", fw.ID(), v)
				return
			}
			if len(v) != 0 {
				t.Errorf("%s: ML-KEM-1024 should PASS, got %+v", fw.ID(), v)
			}
		})
		t.Run(fw.ID()+"/ML-DSA-87", func(t *testing.T) {
			v := fw.Evaluate([]findings.UnifiedFinding{mldsa})
			if fw.ID() == "pci-dss-4.0" {
				if len(v) != 0 {
					t.Errorf("%s: expected PCI PASS, got %v", fw.ID(), v)
				}
				return
			}
			if len(v) != 0 {
				t.Errorf("%s: ML-DSA-87 should PASS, got %+v", fw.ID(), v)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// F-C8 (Adversarial): BSI / ANSSI hybrid-required rule only fires when
// primitive is explicitly "kem"/"key-exchange"/etc. Empty primitive → no fire.
// That's potentially a gap: the ANSSI/BSI guidance targets key exchange
// independent of primitive tagging quality.
// ---------------------------------------------------------------------------
func TestAudit_ANSSI_BSI_HybridRule_EmptyPrimitive_DoesNotFire(t *testing.T) {
	// Pure ML-KEM-768 finding with NO primitive tag — engine didn't set it.
	f := findings.UnifiedFinding{
		Algorithm:   &findings.Algorithm{Name: "ML-KEM-768"}, // primitive=""
		QuantumRisk: findings.QRSafe,
	}
	for _, id := range []string{"anssi-guide-pqc", "bsi-tr-02102"} {
		t.Run(id, func(t *testing.T) {
			fw, _ := Get(id)
			v := fw.Evaluate([]findings.UnifiedFinding{f})
			// Hybrid-required rule should have fired but won't (empty primitive).
			if len(v) == 0 {
				t.Logf("AUDIT CONFIRMED (low): %s skips hybrid-required check when primitive is empty. "+
					"Engines that forget to set primitive cause silent approval of pure PQC KEMs that "+
					"should emit a warn-severity advisory.", id)
			} else {
				t.Logf("AUDIT NOTE: %s now fires on empty-primitive finding", id)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// F-C9 (Property-based): every Framework.Evaluate returns nil (not empty
// slice) when there are no violations.
// ---------------------------------------------------------------------------
func TestAudit_AllFrameworks_Property_NilSliceOnNoViolations(t *testing.T) {
	// For each framework, feed a benign approved finding (AES-256) and assert nil.
	bench := algFinding("AES-256", "symmetric", 256, findings.QRResistant, "")
	for _, fw := range All() {
		t.Run(fw.ID(), func(t *testing.T) {
			v := fw.Evaluate([]findings.UnifiedFinding{bench})
			if fw.ID() == "pci-dss-4.0" {
				// PCI passes when classification exists — v should be nil.
				if v != nil {
					t.Errorf("%s: classified input should return nil, got %v", fw.ID(), v)
				}
				return
			}
			if len(v) == 0 && v != nil {
				t.Errorf("%s: returned empty-but-non-nil slice; contract requires nil", fw.ID())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// F-C10 (Property-based): finding order invariance
// Running Evaluate on shuffled input must produce the same violation count.
// ---------------------------------------------------------------------------
func TestAudit_AllFrameworks_Property_OrderInvariant(t *testing.T) {
	base := []findings.UnifiedFinding{
		algFinding("RSA-2048", "kem", 2048, findings.QRVulnerable, "immediate"),
		algFinding("ML-KEM-1024", "kem", 0, findings.QRSafe, "immediate"),
		algFinding("SHA-256", "hash", 256, findings.QRResistant, ""),
		algFinding("AES-128", "symmetric", 128, findings.QRWeakened, ""),
	}
	reverse := make([]findings.UnifiedFinding, len(base))
	for i, f := range base {
		reverse[len(base)-1-i] = f
	}
	for _, fw := range All() {
		t.Run(fw.ID(), func(t *testing.T) {
			v1 := fw.Evaluate(base)
			v2 := fw.Evaluate(reverse)
			if len(v1) != len(v2) {
				t.Errorf("%s: count changed with input order: %d vs %d", fw.ID(), len(v1), len(v2))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// F-C11 (Property-based): every per-finding violation references an Algorithm
// name equal to the finding's Algorithm.Name (when the finding had one).
// ---------------------------------------------------------------------------
func TestAudit_AllFrameworks_Property_ViolationAlgorithmMatches(t *testing.T) {
	ff := []findings.UnifiedFinding{
		algFinding("RSA-2048", "kem", 2048, findings.QRVulnerable, "immediate"),
	}
	for _, fw := range All() {
		t.Run(fw.ID(), func(t *testing.T) {
			v := fw.Evaluate(ff)
			for _, vi := range v {
				// PCI-DSS violations are aggregate (Algorithm="") by design.
				if fw.ID() == "pci-dss-4.0" {
					continue
				}
				if vi.Algorithm == "" {
					continue // aggregate violation
				}
				if !strings.EqualFold(vi.Algorithm, "RSA-2048") {
					t.Errorf("%s: violation.Algorithm=%q, expected RSA-2048", fw.ID(), vi.Algorithm)
				}
			}
		})
	}
}

// ---------------------------------------------------------------------------
// F-C12 (Adversarial): CNSA 2.0 HMAC-MD5 with QRDeprecated
//
// Documents interaction of isHashFamily + quantum-vulnerable-first rule:
// HMAC-MD5 has QRDeprecated upstream → cnsa2-quantum-vulnerable fires first
// via the QRVulnerable/QRDeprecated branch. The hash-unapproved rule never
// executes because of `continue`.
// ---------------------------------------------------------------------------
func TestAudit_CNSA2_HMAC_MD5_CaughtByQuantumVulnerableRule(t *testing.T) {
	f := algFinding("HMAC-MD5", "hash", 0, findings.QRDeprecated, "")
	v := Evaluate([]findings.UnifiedFinding{f})
	if len(v) != 1 {
		t.Fatalf("expected 1 violation, got %d: %+v", len(v), v)
	}
	if v[0].Rule != "cnsa2-quantum-vulnerable" {
		t.Errorf("rule=%q, want cnsa2-quantum-vulnerable (QRDeprecated branch fires before hash-unapproved)",
			v[0].Rule)
	}
}

// ---------------------------------------------------------------------------
// F-C13 (Adversarial): CNSA 2.0 BLAKE2 / BLAKE3 handling — isHashFamily
// matches "BLAKE" prefix and forwards to the SHA-2 detection which fails,
// then hash-unapproved fires. Verify.
// ---------------------------------------------------------------------------
func TestAudit_CNSA2_BLAKE_Flagged(t *testing.T) {
	for _, name := range []string{"BLAKE2b", "BLAKE2s", "BLAKE3"} {
		t.Run(name, func(t *testing.T) {
			f := algFinding(name, "hash", 0, findings.QRResistant, "")
			v := Evaluate([]findings.UnifiedFinding{f})
			if len(v) != 1 {
				t.Fatalf("expected 1 violation for %s, got %d: %+v", name, len(v), v)
			}
			if v[0].Rule != "cnsa2-hash-unapproved" {
				t.Errorf("%s: rule=%q, want cnsa2-hash-unapproved", name, v[0].Rule)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// F-C14 (Adversarial): NIST IR 8547 AES-128 handling
//
// NIST IR 8547 explicitly permits AES-128/192/256 for federal civilian systems
// per the comment block. A QRWeakened AES-128 finding should NOT produce a
// nist8547-* violation — verify no accidental rejection.
// ---------------------------------------------------------------------------
func TestAudit_NISTIR8547_AES128_Permitted(t *testing.T) {
	fw, _ := Get("nist-ir-8547")
	f := algFinding("AES-128", "symmetric", 128, findings.QRWeakened, "")
	v := fw.Evaluate([]findings.UnifiedFinding{f})
	if len(v) != 0 {
		t.Errorf("AUDIT: NIST IR 8547 should permit AES-128 per its stated policy; got %+v", v)
	}
}

// ---------------------------------------------------------------------------
// F-C15 (Adversarial): NCSC UK accepts SHA-256, SHA-384, SHA-512 AND SHA-3 —
// verify no false-rejection of these.
// ---------------------------------------------------------------------------
func TestAudit_NCSC_Hash_AllApprovedPass(t *testing.T) {
	fw, _ := Get("ncsc-uk")
	for _, h := range []string{"SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-512"} {
		t.Run(h, func(t *testing.T) {
			f := algFinding(h, "hash", 0, findings.QRResistant, "")
			v := fw.Evaluate([]findings.UnifiedFinding{f})
			if len(v) != 0 {
				t.Errorf("NCSC UK should accept %s; got %+v", h, v)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// F-C16 (Adversarial): framework registry ID uniqueness
// ---------------------------------------------------------------------------
func TestAudit_Registry_IDUnique(t *testing.T) {
	ids := SupportedIDs()
	seen := make(map[string]bool)
	for _, id := range ids {
		if seen[id] {
			t.Errorf("duplicate framework ID: %q", id)
		}
		seen[id] = true
	}
	if len(ids) < 7 {
		t.Errorf("expected at least 7 frameworks (per audit brief), got %d: %v", len(ids), ids)
	}
}

// ---------------------------------------------------------------------------
// F-C17 (Adversarial): CNSA 2.0 "SHA-512/256" collision with SHA-512 check.
// See F-C3. This test also verifies the underlying resolveHashOutputSize
// behaviour in isolation.
// ---------------------------------------------------------------------------
func TestAudit_ResolveHashOutputSize_SubstringOrdering(t *testing.T) {
	cases := []struct {
		upper string
		want  int
	}{
		{"SHA-256", 256},
		{"SHA-384", 384},
		{"SHA-512", 512},
		// 2026-04-21: truncated form must report its real 256-bit output.
		{"SHA-512/256", 256},
		{"HMAC-SHA-384", 384},
	}
	for _, c := range cases {
		t.Run(c.upper, func(t *testing.T) {
			got := resolveHashOutputSize(c.upper, 0)
			if got != c.want {
				t.Errorf("resolveHashOutputSize(%q)=%d, want %d", c.upper, got, c.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// F-C18 (Adversarial): Re-entrant safety of Register — framework.go warns
// "Register must only be called from init()". Double-registering should
// silently overwrite (current behaviour). Verify and document.
// ---------------------------------------------------------------------------
func TestAudit_Registry_DoubleRegisterOverwrites(t *testing.T) {
	// Use a stub framework that overlays an existing ID.
	stub := stubFramework{id: "cnsa-2.0"}
	saved, _ := Get("cnsa-2.0")
	defer Register(saved) // restore
	Register(stub)
	got, _ := Get("cnsa-2.0")
	if _, isStub := got.(stubFramework); !isStub {
		t.Errorf("Register did not overwrite — Get returned %T", got)
	}
	// No error returned → documented as silent overwrite.
}

type stubFramework struct{ id string }

func (s stubFramework) ID() string                                      { return s.id }
func (s stubFramework) Name() string                                    { return "stub" }
func (s stubFramework) Description() string                             { return "stub" }
func (s stubFramework) Evaluate([]findings.UnifiedFinding) []Violation  { return nil }
func (s stubFramework) ApprovedAlgos() []ApprovedAlgoRef                { return nil }
func (s stubFramework) Deadlines() []DeadlineRef                        { return nil }

// ---------------------------------------------------------------------------
// F-C19 (Adversarial): EvaluateByID unknown framework returns error
// ---------------------------------------------------------------------------
func TestAudit_EvaluateByID_UnknownID(t *testing.T) {
	_, err := EvaluateByID("nonexistent-framework-v99", nil)
	if err == nil {
		t.Error("EvaluateByID with unknown ID should return error")
	}
	if err != nil && !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("error message should mention 'unsupported'; got %q", err.Error())
	}
}

// ---------------------------------------------------------------------------
// F-C20 (Property-based): Large-input sanity — 1000 findings doesn't blow up
// or produce wildly inconsistent counts.
// ---------------------------------------------------------------------------
func TestAudit_CNSA2_Property_LargeInput(t *testing.T) {
	n := 1000
	ff := make([]findings.UnifiedFinding, 0, n)
	for i := 0; i < n; i++ {
		if i%2 == 0 {
			ff = append(ff, algFinding(fmt.Sprintf("RSA-2048-%d", i), "kem", 2048, findings.QRVulnerable, "immediate"))
		} else {
			ff = append(ff, algFinding("ML-KEM-1024", "kem", 0, findings.QRSafe, "immediate"))
		}
	}
	v := Evaluate(ff)
	// Half of n should produce quantum-vulnerable violations; the other half passes.
	if len(v) != n/2 {
		t.Errorf("expected %d violations, got %d", n/2, len(v))
	}
}
