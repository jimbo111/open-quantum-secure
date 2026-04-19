package compliance

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

var anssi = anssiFramework{}

func TestANSSI_QuantumVulnerable(t *testing.T) {
	tests := []string{"RSA-2048", "ECDH", "DH-2048", "ECDSA"}
	for _, alg := range tests {
		t.Run(alg, func(t *testing.T) {
			f := findings.UnifiedFinding{
				Algorithm:   &findings.Algorithm{Name: alg, Primitive: "kem"},
				QuantumRisk: findings.QRVulnerable,
			}
			v := anssi.Evaluate([]findings.UnifiedFinding{f})
			if len(v) != 1 {
				t.Fatalf("expected 1 violation, got %d", len(v))
			}
			if v[0].Rule != "anssi-quantum-vulnerable" {
				t.Errorf("rule = %q, want anssi-quantum-vulnerable", v[0].Rule)
			}
		})
	}
}

func TestANSSI_HybridKEMPasses(t *testing.T) {
	hybrids := []string{"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024"}
	for _, h := range hybrids {
		t.Run(h, func(t *testing.T) {
			f := findings.UnifiedFinding{
				Algorithm:           &findings.Algorithm{Name: h, Primitive: "kem"},
				NegotiatedGroupName: h,
				QuantumRisk:         findings.QRSafe,
			}
			v := anssi.Evaluate([]findings.UnifiedFinding{f})
			if len(v) != 0 {
				t.Errorf("hybrid KEM %q should pass ANSSI; got: %+v", h, v)
			}
		})
	}
}

func TestANSSI_PureMLKEMKEX_Flagged(t *testing.T) {
	for _, name := range []string{"ML-KEM-768", "MLKEM1024", "ML-KEM-512"} {
		t.Run(name, func(t *testing.T) {
			f := findings.UnifiedFinding{
				Algorithm:   &findings.Algorithm{Name: name, Primitive: "kem"},
				QuantumRisk: findings.QRSafe,
			}
			v := anssi.Evaluate([]findings.UnifiedFinding{f})
			if len(v) != 1 {
				t.Fatalf("pure ML-KEM KEM %q should have 1 ANSSI violation, got %d", name, len(v))
			}
			if v[0].Rule != "anssi-hybrid-kem-required" {
				t.Errorf("rule = %q, want anssi-hybrid-kem-required", v[0].Rule)
			}
		})
	}
}

func TestANSSI_SLHDSAPasses(t *testing.T) {
	for _, name := range []string{"SLH-DSA", "SLH-DSA-128f", "SLH-DSA-256s"} {
		t.Run(name, func(t *testing.T) {
			f := findings.UnifiedFinding{
				Algorithm:   &findings.Algorithm{Name: name, Primitive: "signature"},
				QuantumRisk: findings.QRSafe,
			}
			v := anssi.Evaluate([]findings.UnifiedFinding{f})
			if len(v) != 0 {
				t.Errorf("SLH-DSA should be ANSSI-approved; got: %+v", v)
			}
		})
	}
}

func TestANSSI_MLDSAAllLevelsPasses(t *testing.T) {
	for _, name := range []string{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"} {
		t.Run(name, func(t *testing.T) {
			f := findings.UnifiedFinding{
				Algorithm:   &findings.Algorithm{Name: name, Primitive: "signature"},
				QuantumRisk: findings.QRSafe,
			}
			v := anssi.Evaluate([]findings.UnifiedFinding{f})
			if len(v) != 0 {
				t.Errorf("%q should pass ANSSI; got: %+v", name, v)
			}
		})
	}
}

// TestANSSI_HybridSeverityIsWarn verifies the hybrid-kem-required rule has
// Severity "warn" (recommendation, not normative requirement per ANSSI §1.1-§1.2).
func TestANSSI_HybridSeverityIsWarn(t *testing.T) {
	f := findings.UnifiedFinding{
		Algorithm:   &findings.Algorithm{Name: "ML-KEM-768", Primitive: "kem"},
		QuantumRisk: findings.QRSafe,
	}
	v := anssi.Evaluate([]findings.UnifiedFinding{f})
	if len(v) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(v))
	}
	if v[0].Rule != "anssi-hybrid-kem-required" {
		t.Errorf("rule = %q, want anssi-hybrid-kem-required", v[0].Rule)
	}
	if v[0].Severity != "warn" {
		t.Errorf("severity = %q, want warn", v[0].Severity)
	}
}

func TestANSSI_EmptyInput(t *testing.T) {
	if v := anssi.Evaluate(nil); v != nil {
		t.Errorf("expected nil for nil input, got %v", v)
	}
}

func TestANSSI_RegistrationAndID(t *testing.T) {
	fw, ok := Get("anssi-guide-pqc")
	if !ok {
		t.Fatal("anssi-guide-pqc not found in registry")
	}
	if fw.ID() != "anssi-guide-pqc" {
		t.Errorf("ID = %q, want anssi-guide-pqc", fw.ID())
	}
	if fw.Name() != "ANSSI Guide PQC" {
		t.Errorf("Name = %q, want ANSSI Guide PQC", fw.Name())
	}
}
