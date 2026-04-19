package compliance

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

var nist8547 = nistIR8547Framework{}

func nist8547Finding(name, prim string, qr findings.QuantumRisk) findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Algorithm:   &findings.Algorithm{Name: name, Primitive: prim},
		QuantumRisk: qr,
	}
}

func TestNIST8547_QuantumVulnerable(t *testing.T) {
	for _, alg := range []string{"RSA-2048", "ECDH", "ECDSA", "DH-2048"} {
		t.Run(alg, func(t *testing.T) {
			f := nist8547Finding(alg, "kem", findings.QRVulnerable)
			v := nist8547.Evaluate([]findings.UnifiedFinding{f})
			if len(v) != 1 {
				t.Fatalf("expected 1 violation, got %d", len(v))
			}
			if v[0].Rule != "nist8547-quantum-vulnerable" {
				t.Errorf("rule = %q, want nist8547-quantum-vulnerable", v[0].Rule)
			}
		})
	}
}

// TestNIST8547_DeprecationDeadlines verifies the correct deadlines per IR 8547 §3.1 Table 1.
// All quantum-vulnerable algorithms (RSA, ECDSA, DH, MD5, etc.) use the 2030-12-31 deprecation
// deadline. The 2035 disallow date is referenced in remediation text only.
func TestNIST8547_DeprecationDeadlines(t *testing.T) {
	tests := []struct {
		name string
		prim string
		qr   findings.QuantumRisk
	}{
		{"RSA-2048", "kem", findings.QRVulnerable},
		{"ECDSA", "signature", findings.QRVulnerable},
		{"DH-2048", "kem", findings.QRVulnerable},
		{"MD5", "hash", findings.QRDeprecated},
	}
	for _, tt := range tests {
		t.Run(tt.name+" gets 2030 deadline", func(t *testing.T) {
			f := nist8547Finding(tt.name, tt.prim, tt.qr)
			v := nist8547.Evaluate([]findings.UnifiedFinding{f})
			if len(v) != 1 {
				t.Fatalf("expected 1 violation, got %d", len(v))
			}
			if v[0].Deadline != nist8547DeprecateDate {
				t.Errorf("deadline = %q, want %q (nist8547DeprecateDate)", v[0].Deadline, nist8547DeprecateDate)
			}
		})
	}
}

// TestNIST8547_SLHDSAPasses verifies SLH-DSA is approved (unlike CNSA 2.0).
func TestNIST8547_SLHDSAPasses(t *testing.T) {
	for _, name := range []string{"SLH-DSA", "SLH-DSA-128f", "SLH-DSA-256s"} {
		t.Run(name, func(t *testing.T) {
			f := nist8547Finding(name, "signature", findings.QRSafe)
			v := nist8547.Evaluate([]findings.UnifiedFinding{f})
			if len(v) != 0 {
				t.Errorf("SLH-DSA should pass NIST IR 8547; got: %+v", v)
			}
		})
	}
}

// TestNIST8547_AllMLKEMPasses verifies all ML-KEM parameter sets pass.
func TestNIST8547_AllMLKEMPasses(t *testing.T) {
	for _, name := range []string{"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"} {
		t.Run(name, func(t *testing.T) {
			f := nist8547Finding(name, "kem", findings.QRSafe)
			v := nist8547.Evaluate([]findings.UnifiedFinding{f})
			if len(v) != 0 {
				t.Errorf("%q should pass NIST IR 8547; got: %+v", name, v)
			}
		})
	}
}

// TestNIST8547_AllMLDSAPasses verifies all ML-DSA parameter sets pass.
func TestNIST8547_AllMLDSAPasses(t *testing.T) {
	for _, name := range []string{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"} {
		t.Run(name, func(t *testing.T) {
			f := nist8547Finding(name, "signature", findings.QRSafe)
			v := nist8547.Evaluate([]findings.UnifiedFinding{f})
			if len(v) != 0 {
				t.Errorf("%q should pass NIST IR 8547; got: %+v", name, v)
			}
		})
	}
}

func TestNIST8547_EmptyInput(t *testing.T) {
	if v := nist8547.Evaluate(nil); v != nil {
		t.Errorf("expected nil for nil input, got %v", v)
	}
}

func TestNIST8547_RegistrationAndID(t *testing.T) {
	fw, ok := Get("nist-ir-8547")
	if !ok {
		t.Fatal("nist-ir-8547 not found in registry")
	}
	if fw.ID() != "nist-ir-8547" {
		t.Errorf("ID = %q, want nist-ir-8547", fw.ID())
	}
	if fw.Name() != "NIST IR 8547" {
		t.Errorf("Name = %q, want NIST IR 8547", fw.Name())
	}
}
