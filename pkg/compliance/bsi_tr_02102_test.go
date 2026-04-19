package compliance

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

var bsi = bsiTR02102Framework{}

func bsiKEMFinding(name string, qr findings.QuantumRisk) findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Algorithm:   &findings.Algorithm{Name: name, Primitive: "kem"},
		QuantumRisk: qr,
	}
}

func bsiTLSFinding(groupName string, qr findings.QuantumRisk) findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Algorithm:           &findings.Algorithm{Name: groupName, Primitive: "kem"},
		NegotiatedGroupName: groupName,
		QuantumRisk:         qr,
	}
}

func bsiSigFinding(name string, qr findings.QuantumRisk) findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Algorithm:   &findings.Algorithm{Name: name, Primitive: "signature"},
		QuantumRisk: qr,
	}
}

// TestBSI_QuantumVulnerable verifies RSA/ECDH trigger a quantum-vulnerable violation.
func TestBSI_QuantumVulnerable(t *testing.T) {
	tests := []struct {
		name string
		alg  string
	}{
		{"RSA-2048", "RSA-2048"},
		{"ECDH", "ECDH"},
		{"DH-2048", "DH-2048"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := bsiKEMFinding(tt.alg, findings.QRVulnerable)
			v := bsi.Evaluate([]findings.UnifiedFinding{f})
			if len(v) != 1 {
				t.Fatalf("expected 1 violation, got %d", len(v))
			}
			if v[0].Rule != "bsi-quantum-vulnerable" {
				t.Errorf("rule = %q, want bsi-quantum-vulnerable", v[0].Rule)
			}
		})
	}
}

// TestBSI_HybridKEMPasses verifies that hybrid KEM names are NOT flagged.
func TestBSI_HybridKEMPasses(t *testing.T) {
	hybrids := []string{
		"X25519MLKEM768",
		"SecP256r1MLKEM768",
		"SecP384r1MLKEM1024",
	}
	for _, h := range hybrids {
		t.Run(h, func(t *testing.T) {
			f := bsiTLSFinding(h, findings.QRSafe)
			v := bsi.Evaluate([]findings.UnifiedFinding{f})
			if len(v) != 0 {
				t.Errorf("hybrid KEM %q should pass BSI; got violations: %+v", h, v)
			}
		})
	}
}

// TestBSI_PureMLKEMKEX_Flagged verifies that pure (non-hybrid) ML-KEM used as KEM
// is flagged with bsi-hybrid-kem-required.
func TestBSI_PureMLKEMKEX_Flagged(t *testing.T) {
	pures := []string{"MLKEM512", "MLKEM768", "MLKEM1024", "ML-KEM-768", "ML-KEM-1024"}
	for _, p := range pures {
		t.Run(p, func(t *testing.T) {
			f := bsiKEMFinding(p, findings.QRSafe)
			v := bsi.Evaluate([]findings.UnifiedFinding{f})
			if len(v) != 1 {
				t.Fatalf("pure ML-KEM KEM %q should have 1 BSI violation, got %d", p, len(v))
			}
			if v[0].Rule != "bsi-hybrid-kem-required" {
				t.Errorf("rule = %q, want bsi-hybrid-kem-required", v[0].Rule)
			}
			if v[0].Deadline != bsiDeadlineKEX {
				t.Errorf("deadline = %q, want %q", v[0].Deadline, bsiDeadlineKEX)
			}
		})
	}
}

// TestBSI_PureMLKEMTLS_Flagged verifies TLS probe findings with pure MLKEM groups are flagged.
func TestBSI_PureMLKEMTLS_Flagged(t *testing.T) {
	f := bsiTLSFinding("MLKEM768", findings.QRSafe)
	v := bsi.Evaluate([]findings.UnifiedFinding{f})
	if len(v) != 1 {
		t.Fatalf("expected 1 violation for pure TLS MLKEM768, got %d", len(v))
	}
	if v[0].Rule != "bsi-hybrid-kem-required" {
		t.Errorf("rule = %q, want bsi-hybrid-kem-required", v[0].Rule)
	}
}

// TestBSI_SLHDSAPasses verifies SLH-DSA passes BSI (unlike CNSA 2.0).
func TestBSI_SLHDSAPasses(t *testing.T) {
	for _, name := range []string{"SLH-DSA", "SLH-DSA-128f", "SLH-DSA-256s"} {
		t.Run(name, func(t *testing.T) {
			f := bsiSigFinding(name, findings.QRSafe)
			v := bsi.Evaluate([]findings.UnifiedFinding{f})
			if len(v) != 0 {
				t.Errorf("SLH-DSA should be BSI-approved; got: %+v", v)
			}
		})
	}
}

// TestBSI_MLDSAAllLevelsPasses verifies ML-DSA-44/65/87 all pass BSI.
func TestBSI_MLDSAAllLevelsPasses(t *testing.T) {
	for _, name := range []string{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"} {
		t.Run(name, func(t *testing.T) {
			f := bsiSigFinding(name, findings.QRSafe)
			v := bsi.Evaluate([]findings.UnifiedFinding{f})
			if len(v) != 0 {
				t.Errorf("%q should pass BSI; got: %+v", name, v)
			}
		})
	}
}

// TestBSI_HQCApproved verifies HQC is approved by BSI (unlike CNSA 2.0).
func TestBSI_HQCApproved(t *testing.T) {
	for _, name := range []string{"HQC", "HQC-128", "HQC-256"} {
		t.Run(name, func(t *testing.T) {
			f := bsiKEMFinding(name, findings.QRSafe)
			// HQC has KEM primitive but is not ML-KEM — no hybrid-required rule.
			v := bsi.Evaluate([]findings.UnifiedFinding{f})
			if len(v) != 0 {
				t.Errorf("HQC should be BSI-approved; got: %+v", v)
			}
		})
	}
}

// TestBSI_HybridSeverityIsWarn verifies the hybrid-kem-required rule has
// Severity "warn" (strong recommendation, not a hard normative requirement).
func TestBSI_HybridSeverityIsWarn(t *testing.T) {
	f := bsiKEMFinding("ML-KEM-768", findings.QRSafe)
	v := bsi.Evaluate([]findings.UnifiedFinding{f})
	if len(v) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(v))
	}
	if v[0].Rule != "bsi-hybrid-kem-required" {
		t.Errorf("rule = %q, want bsi-hybrid-kem-required", v[0].Rule)
	}
	if v[0].Severity != "warn" {
		t.Errorf("severity = %q, want warn", v[0].Severity)
	}
}

// TestBSI_EmptyInput returns nil.
func TestBSI_EmptyInput(t *testing.T) {
	if v := bsi.Evaluate(nil); v != nil {
		t.Errorf("expected nil for nil input, got %v", v)
	}
	if v := bsi.Evaluate([]findings.UnifiedFinding{}); v != nil {
		t.Errorf("expected nil for empty input, got %v", v)
	}
}

// TestBSI_RegistrationAndID verifies framework is registered and returns correct IDs.
func TestBSI_RegistrationAndID(t *testing.T) {
	fw, ok := Get("bsi-tr-02102")
	if !ok {
		t.Fatal("bsi-tr-02102 not found in registry")
	}
	if fw.ID() != "bsi-tr-02102" {
		t.Errorf("ID = %q, want bsi-tr-02102", fw.ID())
	}
	if fw.Name() != "BSI TR-02102" {
		t.Errorf("Name = %q, want BSI TR-02102", fw.Name())
	}
}
