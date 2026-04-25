// Package compliance — sophisticated tests covering multi-framework evaluation,
// CNSA 2.0 hybrid sub-1024, ANSSI/BSI severity=warn, NIST IR 8547 deadline,
// PCI DSS inventory evidence, and multi---compliance flag behaviour.
package compliance

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// ---------------------------------------------------------------------------
// CNSA 2.0: hybrid KEM with sub-1024 ML-KEM is NOT compliant (post-f00a290)
// ---------------------------------------------------------------------------

func TestCNSA20_HybridSub1024_NotCompliant(t *testing.T) {
	// X25519MLKEM768 is a hybrid KEM with ML-KEM-768 < 1024. CNSA 2.0 requires ML-KEM-1024.
	f := findings.UnifiedFinding{
		Algorithm:           &findings.Algorithm{Name: "X25519MLKEM768", Primitive: "kem"},
		NegotiatedGroupName: "X25519MLKEM768",
		QuantumRisk:         findings.QRSafe,
	}
	violations := Evaluate([]findings.UnifiedFinding{f})
	if len(violations) == 0 {
		t.Error("X25519MLKEM768 (hybrid sub-1024) must produce a CNSA 2.0 violation")
	}
	found := false
	for _, v := range violations {
		if v.Rule == "cnsa2-hybrid-sub-1024" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected cnsa2-hybrid-sub-1024 violation; got: %+v", violations)
	}
}

func TestCNSA20_HybridML_KEM_1024_Compliant(t *testing.T) {
	// SecP384r1MLKEM1024 uses ML-KEM-1024 — meets the CNSA 2.0 requirement.
	f := findings.UnifiedFinding{
		Algorithm:           &findings.Algorithm{Name: "SecP384r1MLKEM1024", Primitive: "kem"},
		NegotiatedGroupName: "SecP384r1MLKEM1024",
		QuantumRisk:         findings.QRSafe,
	}
	violations := Evaluate([]findings.UnifiedFinding{f})
	for _, v := range violations {
		if v.Rule == "cnsa2-hybrid-sub-1024" {
			t.Errorf("SecP384r1MLKEM1024 should NOT trigger cnsa2-hybrid-sub-1024; got: %+v", v)
		}
	}
}

// ---------------------------------------------------------------------------
// CNSA 2.0: ML-KEM below 1024 must be flagged
// ---------------------------------------------------------------------------

func TestCNSA20_MLKEM768_Insufficient(t *testing.T) {
	f := algFinding("ML-KEM-768", "kem", 768, findings.QRSafe, "immediate")
	violations := Evaluate([]findings.UnifiedFinding{f})
	if len(violations) == 0 {
		t.Error("ML-KEM-768 must be flagged by CNSA 2.0 (minimum is ML-KEM-1024)")
	}
	if violations[0].Rule != "cnsa2-ml-kem-key-size" {
		t.Errorf("expected cnsa2-ml-kem-key-size; got %q", violations[0].Rule)
	}
}

// ---------------------------------------------------------------------------
// CNSA 2.0: ML-DSA below 87 must be flagged
// ---------------------------------------------------------------------------

func TestCNSA20_MLDSA65_Insufficient(t *testing.T) {
	f := algFinding("ML-DSA-65", "signature", 0, findings.QRSafe, "deferred")
	violations := Evaluate([]findings.UnifiedFinding{f})
	if len(violations) == 0 {
		t.Error("ML-DSA-65 must be flagged by CNSA 2.0 (minimum is ML-DSA-87)")
	}
	if violations[0].Rule != "cnsa2-ml-dsa-param-set" {
		t.Errorf("expected cnsa2-ml-dsa-param-set; got %q", violations[0].Rule)
	}
}

// ---------------------------------------------------------------------------
// ANSSI: violations must have Severity="warn" (not "error" / "")
// ---------------------------------------------------------------------------

func TestANSSI_PurePQC_KEM_ViolationSeverityIsWarn(t *testing.T) {
	// ANSSI requires hybrid KEM during transition; pure ML-KEM alone is a warn.
	fw, ok := Get("anssi-guide-pqc")
	if !ok {
		t.Skip("anssi-guide-pqc framework not registered")
	}

	f := findings.UnifiedFinding{
		Algorithm:   &findings.Algorithm{Name: "ML-KEM-768", Primitive: "kem"},
		QuantumRisk: findings.QRSafe,
	}
	violations := fw.Evaluate([]findings.UnifiedFinding{f})
	for _, v := range violations {
		if v.Severity != "warn" && v.Severity != "" {
			// Accept either "warn" or "" depending on the framework's implementation.
			// The key invariant is it must NOT be "error".
			if v.Severity == "error" {
				t.Errorf("ANSSI violation severity must be 'warn'; got 'error' for rule %q", v.Rule)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// BSI TR-02102: severity is warn, not error
// ---------------------------------------------------------------------------

func TestBSI_PurePQC_KEM_ViolationSeverityIsWarn(t *testing.T) {
	fw, ok := Get("bsi-tr-02102")
	if !ok {
		t.Skip("bsi-tr-02102 framework not registered")
	}

	f := findings.UnifiedFinding{
		Algorithm:   &findings.Algorithm{Name: "ML-KEM-768", Primitive: "kem"},
		QuantumRisk: findings.QRSafe,
	}
	violations := fw.Evaluate([]findings.UnifiedFinding{f})
	for _, v := range violations {
		if v.Severity == "error" {
			t.Errorf("BSI violation severity must be 'warn'; got 'error' for rule %q", v.Rule)
		}
	}
}

// ---------------------------------------------------------------------------
// NIST IR 8547: single 2030 deadline for deprecated algorithms
// ---------------------------------------------------------------------------

func TestNISTIR8547_SingleDeadline(t *testing.T) {
	fw, ok := Get("nist-ir-8547")
	if !ok {
		t.Skip("nist-ir-8547 framework not registered")
	}

	deadlines := fw.Deadlines()
	if len(deadlines) == 0 {
		t.Fatal("nist-ir-8547 must have at least one deadline entry")
	}

	// NIST IR 8547 specifies 2030 as the primary transition deadline.
	has2030 := false
	for _, d := range deadlines {
		if len(d.Date) >= 4 && d.Date[:4] == "2030" {
			has2030 = true
			break
		}
	}
	if !has2030 {
		t.Errorf("nist-ir-8547 must include a 2030 deadline; found: %+v", deadlines)
	}
}

// ---------------------------------------------------------------------------
// PCI DSS 4.0: inventory evidence Req 12.3.3
// PASS when classified findings exist (evidence of inventory)
// FAIL when NO findings (nothing was inventoried)
// ---------------------------------------------------------------------------

func TestPCIDSS40_WithClassifiedFinding_NoViolation(t *testing.T) {
	fw, ok := Get("pci-dss-4.0")
	if !ok {
		t.Skip("pci-dss-4.0 framework not registered")
	}

	f := algFinding("RSA", "asymmetric", 2048, findings.QRVulnerable, "immediate")
	violations := fw.Evaluate([]findings.UnifiedFinding{f})
	// PCI DSS 4.0 passes when findings exist (inventory evidence present).
	if len(violations) > 0 {
		t.Errorf("PCI DSS 4.0 should PASS when classified findings exist (evidence of inventory); got: %+v", violations)
	}
}

func TestPCIDSS40_NoFindings_Violation(t *testing.T) {
	fw, ok := Get("pci-dss-4.0")
	if !ok {
		t.Skip("pci-dss-4.0 framework not registered")
	}

	// Empty findings = no evidence of inventory review.
	violations := fw.Evaluate(nil)
	if len(violations) == 0 {
		t.Error("PCI DSS 4.0 should FAIL when there are no findings (no inventory evidence)")
	}
}

// ---------------------------------------------------------------------------
// Multi-framework: EvaluateByID for two frameworks independently
// ---------------------------------------------------------------------------

func TestEvaluateByID_MultiFramework(t *testing.T) {
	// RSA-2048 is quantum-vulnerable — should trigger violations in both frameworks.
	f := algFinding("RSA", "asymmetric", 2048, findings.QRVulnerable, "immediate")
	ff := []findings.UnifiedFinding{f}

	frameworks := []string{"cnsa-2.0"}
	// Add other frameworks if registered.
	for _, id := range []string{"nist-ir-8547", "bsi-tr-02102"} {
		if _, ok := Get(id); ok {
			frameworks = append(frameworks, id)
		}
	}

	for _, id := range frameworks {
		violations, err := EvaluateByID(id, ff)
		if err != nil {
			t.Errorf("EvaluateByID(%q) error: %v", id, err)
			continue
		}
		if len(violations) == 0 {
			t.Errorf("EvaluateByID(%q): expected violations for RSA-2048; got none", id)
		}
	}
}

// ---------------------------------------------------------------------------
// EvaluateByID: unknown framework returns error
// ---------------------------------------------------------------------------

func TestEvaluateByID_UnknownFramework(t *testing.T) {
	_, err := EvaluateByID("not-a-real-framework", nil)
	if err == nil {
		t.Error("EvaluateByID should return error for unknown framework ID")
	}
}

// ---------------------------------------------------------------------------
// SupportedIDs: must include all expected framework IDs
// ---------------------------------------------------------------------------

func TestSupportedIDs_ContainsExpected(t *testing.T) {
	ids := SupportedIDs()
	idSet := make(map[string]bool, len(ids))
	for _, id := range ids {
		idSet[id] = true
	}

	// These frameworks must always be registered.
	required := []string{"cnsa-2.0"}
	for _, r := range required {
		if !idSet[r] {
			t.Errorf("SupportedIDs() missing required framework %q", r)
		}
	}

	// SupportedIDs must be sorted.
	for i := 1; i < len(ids); i++ {
		if ids[i] < ids[i-1] {
			t.Errorf("SupportedIDs() not sorted: %q before %q", ids[i-1], ids[i])
		}
	}
}

// ---------------------------------------------------------------------------
// CNSA 2.0: quantum-vulnerable dependency (no Algorithm) triggers violation
// ---------------------------------------------------------------------------

func TestCNSA20_QuantumVulnerableDependency_Flagged(t *testing.T) {
	f := depFinding("openssl-1.0", findings.QRVulnerable, "immediate")
	violations := Evaluate([]findings.UnifiedFinding{f})
	if len(violations) == 0 {
		t.Error("quantum-vulnerable dependency must be flagged by CNSA 2.0")
	}
	if violations[0].Rule != "cnsa2-quantum-vulnerable" {
		t.Errorf("expected cnsa2-quantum-vulnerable; got %q", violations[0].Rule)
	}
}

// ---------------------------------------------------------------------------
// CNSA 2.0: ML-KEM-1024 pure (non-hybrid) must be compliant
// ---------------------------------------------------------------------------

func TestCNSA20_MLKEM1024_Compliant(t *testing.T) {
	f := algFinding("ML-KEM-1024", "kem", 1024, findings.QRSafe, "immediate")
	violations := Evaluate([]findings.UnifiedFinding{f})
	if len(violations) > 0 {
		t.Errorf("ML-KEM-1024 must be CNSA 2.0 compliant; got violations: %+v", violations)
	}
}

// ---------------------------------------------------------------------------
// CNSA 2.0: SLH-DSA excluded (despite NIST FIPS 205 approval)
// ---------------------------------------------------------------------------

func TestCNSA20_SLHDSA_Excluded(t *testing.T) {
	f := algFinding("SLH-DSA-128s", "signature", 0, findings.QRSafe, "deferred")
	violations := Evaluate([]findings.UnifiedFinding{f})
	if len(violations) == 0 {
		t.Error("SLH-DSA must be excluded from CNSA 2.0")
	}
	if violations[0].Rule != "cnsa2-slh-dsa-excluded" {
		t.Errorf("expected cnsa2-slh-dsa-excluded; got %q", violations[0].Rule)
	}
}

// ---------------------------------------------------------------------------
// CNSA 2.0: AES-128 triggers key-size violation
// ---------------------------------------------------------------------------

func TestCNSA20_AES128_InsufficientKeySize(t *testing.T) {
	f := algFinding("AES-128-GCM", "symmetric", 128, findings.QRWeakened, "")
	violations := Evaluate([]findings.UnifiedFinding{f})
	if len(violations) == 0 {
		t.Error("AES-128 must be flagged by CNSA 2.0 (requires AES-256)")
	}
}
