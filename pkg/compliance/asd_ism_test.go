package compliance

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
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

func TestASD_EmptyInput(t *testing.T) {
	if v := asd.Evaluate(nil); v != nil {
		t.Errorf("expected nil for nil input, got %v", v)
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
