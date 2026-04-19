package compliance

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

var pci = pciDSS40Framework{}

// TestPCI_NoFindings_Fails verifies that an empty scan fails PCI DSS inventory check.
func TestPCI_NoFindings_Fails(t *testing.T) {
	v := pci.Evaluate(nil)
	if len(v) != 1 {
		t.Fatalf("empty findings should produce 1 inventory-evidence violation, got %d", len(v))
	}
	if v[0].Rule != "pci-no-inventory-evidence" {
		t.Errorf("rule = %q, want pci-no-inventory-evidence", v[0].Rule)
	}
}

// TestPCI_EmptySlice_Fails verifies that an empty (non-nil) slice also fails.
func TestPCI_EmptySlice_Fails(t *testing.T) {
	v := pci.Evaluate([]findings.UnifiedFinding{})
	if len(v) != 1 {
		t.Fatalf("expected 1 violation for empty findings, got %d", len(v))
	}
	if v[0].Rule != "pci-no-inventory-evidence" {
		t.Errorf("rule = %q, want pci-no-inventory-evidence", v[0].Rule)
	}
}

// TestPCI_UnclassifiedFindings_Fails verifies that findings with no risk
// classification do not satisfy the Req 12.3.3 inventory evidence requirement.
func TestPCI_UnclassifiedFindings_Fails(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Algorithm:   &findings.Algorithm{Name: "AES-256", Primitive: "symmetric"},
			QuantumRisk: "", // unclassified
		},
		{
			Algorithm:   &findings.Algorithm{Name: "SHA-256", Primitive: "hash"},
			QuantumRisk: findings.QRUnknown,
		},
	}
	v := pci.Evaluate(ff)
	if len(v) != 1 {
		t.Fatalf("expected 1 violation for unclassified findings, got %d", len(v))
	}
	if v[0].Rule != "pci-no-inventory-evidence" {
		t.Errorf("rule = %q, want pci-no-inventory-evidence", v[0].Rule)
	}
}

// TestPCI_ClassifiedFindings_Pass verifies that at least one risk-classified
// finding produces a PASS (no violations) — regardless of the specific risk level.
func TestPCI_ClassifiedFindings_Pass(t *testing.T) {
	tests := []struct {
		name string
		qr   findings.QuantumRisk
	}{
		{"vulnerable finding", findings.QRVulnerable},
		{"safe finding", findings.QRSafe},
		{"resistant finding", findings.QRResistant},
		{"weakened finding", findings.QRWeakened},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ff := []findings.UnifiedFinding{
				{
					Algorithm:   &findings.Algorithm{Name: "RSA-2048", Primitive: "kem"},
					QuantumRisk: tt.qr,
				},
			}
			v := pci.Evaluate(ff)
			if len(v) != 0 {
				t.Errorf("classified finding (%s) should PASS PCI DSS inventory check; got: %+v", tt.qr, v)
			}
		})
	}
}

// TestPCI_MixedClassified_Pass verifies that a mix of classified and unclassified
// findings passes as long as at least one is classified.
func TestPCI_MixedClassified_Pass(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Algorithm:   &findings.Algorithm{Name: "RSA-2048"},
			QuantumRisk: findings.QRVulnerable, // classified
		},
		{
			Algorithm:   &findings.Algorithm{Name: "AES-256"},
			QuantumRisk: "", // unclassified
		},
	}
	v := pci.Evaluate(ff)
	if len(v) != 0 {
		t.Errorf("mixed findings with at least one classified should PASS; got: %+v", v)
	}
}

// TestPCI_ViolationDeadline verifies the deadline is the annual review date.
func TestPCI_ViolationDeadline(t *testing.T) {
	v := pci.Evaluate(nil)
	if len(v) != 1 {
		t.Fatalf("expected 1 violation")
	}
	if v[0].Deadline != pciDSS40RequirementDate {
		t.Errorf("deadline = %q, want %q", v[0].Deadline, pciDSS40RequirementDate)
	}
}

func TestPCI_RegistrationAndID(t *testing.T) {
	fw, ok := Get("pci-dss-4.0")
	if !ok {
		t.Fatal("pci-dss-4.0 not found in registry")
	}
	if fw.ID() != "pci-dss-4.0" {
		t.Errorf("ID = %q, want pci-dss-4.0", fw.ID())
	}
	if fw.Name() != "PCI DSS 4.0" {
		t.Errorf("Name = %q, want PCI DSS 4.0", fw.Name())
	}
}

// TestPCI_QuantumVulnerableAlgoPassesCheck verifies that even quantum-vulnerable
// findings pass PCI DSS 4.0 (they provide inventory evidence; PCI doesn't block
// specific algorithms, it requires them to be inventoried and planned for migration).
func TestPCI_QuantumVulnerableAlgoPassesCheck(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Algorithm:   &findings.Algorithm{Name: "RSA-2048", Primitive: "kem"},
			QuantumRisk: findings.QRVulnerable,
		},
	}
	v := pci.Evaluate(ff)
	if len(v) != 0 {
		t.Errorf("quantum-vulnerable algorithm should provide inventory evidence and pass PCI check; got: %+v", v)
	}
}
