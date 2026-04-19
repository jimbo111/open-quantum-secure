package compliance

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

var ncsc = ncscUKFramework{}

func ncscAlgFinding(name, prim string, qr findings.QuantumRisk) findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Algorithm:   &findings.Algorithm{Name: name, Primitive: prim},
		QuantumRisk: qr,
	}
}

func TestNCSC_QuantumVulnerable(t *testing.T) {
	for _, alg := range []string{"RSA-2048", "ECDH", "ECDSA", "DH-2048"} {
		t.Run(alg, func(t *testing.T) {
			f := ncscAlgFinding(alg, "kem", findings.QRVulnerable)
			v := ncsc.Evaluate([]findings.UnifiedFinding{f})
			if len(v) != 1 {
				t.Fatalf("expected 1 violation, got %d", len(v))
			}
			if v[0].Rule != "ncsc-quantum-vulnerable" {
				t.Errorf("rule = %q, want ncsc-quantum-vulnerable", v[0].Rule)
			}
		})
	}
}

// TestNCSC_SLHDSAPasses verifies SLH-DSA passes NCSC UK (unlike CNSA 2.0).
func TestNCSC_SLHDSAPasses(t *testing.T) {
	for _, name := range []string{"SLH-DSA", "SLH-DSA-128f", "SLH-DSA-256s"} {
		t.Run(name, func(t *testing.T) {
			f := ncscAlgFinding(name, "signature", findings.QRSafe)
			v := ncsc.Evaluate([]findings.UnifiedFinding{f})
			if len(v) != 0 {
				t.Errorf("SLH-DSA should pass NCSC UK; got: %+v", v)
			}
		})
	}
}

// TestNCSC_AllMLKEMPasses verifies ML-KEM-512/768/1024 all pass (no grade minimum).
func TestNCSC_AllMLKEMPasses(t *testing.T) {
	for _, name := range []string{"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"} {
		t.Run(name, func(t *testing.T) {
			f := ncscAlgFinding(name, "kem", findings.QRSafe)
			v := ncsc.Evaluate([]findings.UnifiedFinding{f})
			if len(v) != 0 {
				t.Errorf("%q should pass NCSC UK; got: %+v", name, v)
			}
		})
	}
}

// TestNCSC_AllMLDSAPasses verifies ML-DSA-44/65/87 all pass.
func TestNCSC_AllMLDSAPasses(t *testing.T) {
	for _, name := range []string{"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"} {
		t.Run(name, func(t *testing.T) {
			f := ncscAlgFinding(name, "signature", findings.QRSafe)
			v := ncsc.Evaluate([]findings.UnifiedFinding{f})
			if len(v) != 0 {
				t.Errorf("%q should pass NCSC UK; got: %+v", name, v)
			}
		})
	}
}

// TestNCSC_PureMLKEMNotFlagged verifies NCSC UK does NOT require hybrid
// (unlike BSI/ANSSI). Pure ML-KEM should pass.
func TestNCSC_PureMLKEMNotFlagged(t *testing.T) {
	f := ncscAlgFinding("ML-KEM-768", "kem", findings.QRSafe)
	v := ncsc.Evaluate([]findings.UnifiedFinding{f})
	if len(v) != 0 {
		t.Errorf("NCSC UK does not require hybrid; pure ML-KEM-768 should pass, got: %+v", v)
	}
}

func TestNCSC_EmptyInput(t *testing.T) {
	if v := ncsc.Evaluate(nil); v != nil {
		t.Errorf("expected nil for nil input, got %v", v)
	}
}

func TestNCSC_RegistrationAndID(t *testing.T) {
	fw, ok := Get("ncsc-uk")
	if !ok {
		t.Fatal("ncsc-uk not found in registry")
	}
	if fw.ID() != "ncsc-uk" {
		t.Errorf("ID = %q, want ncsc-uk", fw.ID())
	}
	if fw.Name() != "NCSC UK" {
		t.Errorf("Name = %q, want NCSC UK", fw.Name())
	}
}

// TestNCSC_RSAGetEarlierDeadline verifies RSA (KEM usage) gets the 2030 deadline.
func TestNCSC_RSAGetEarlierDeadline(t *testing.T) {
	f := ncscAlgFinding("RSA-2048", "kem", findings.QRVulnerable)
	v := ncsc.Evaluate([]findings.UnifiedFinding{f})
	if len(v) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(v))
	}
	if v[0].Deadline != ncscDeadlineKEX {
		t.Errorf("deadline = %q, want %q (key exchange deadline)", v[0].Deadline, ncscDeadlineKEX)
	}
}
