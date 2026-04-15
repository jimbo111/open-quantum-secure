package findings

import "testing"

// pqc_clone_test.go — deep-copy safety checks for the Sprint 1 PQC fields on
// UnifiedFinding.Clone().
//
// The four PQC fields are value types (uint16, string, bool, string), so Clone
// provides trivial copy safety. These tests act as a golden assertion: if a
// future refactor changes any field to a reference type (e.g., *string for
// interning, []byte for a group ID array), the tests will catch shallow-copy
// regressions before they reach production.
//
// Tests also verify that the clone is equal to the original immediately after
// cloning, and that mutations in EITHER direction (clone→doesn't affect original,
// original→doesn't affect clone) are independent.

// TestPQCClone_AllFieldsPopulated verifies that Clone copies all four PQC
// fields with their non-zero values intact.
func TestPQCClone_AllFieldsPopulated(t *testing.T) {
	orig := UnifiedFinding{
		SourceEngine:        "tls-probe",
		NegotiatedGroup:     0x11EC,
		NegotiatedGroupName: "X25519MLKEM768",
		PQCPresent:          true,
		PQCMaturity:         "final",
	}

	clone := orig.Clone()

	if clone.NegotiatedGroup != orig.NegotiatedGroup {
		t.Errorf("NegotiatedGroup: clone=0x%04x, orig=0x%04x", clone.NegotiatedGroup, orig.NegotiatedGroup)
	}
	if clone.NegotiatedGroupName != orig.NegotiatedGroupName {
		t.Errorf("NegotiatedGroupName: clone=%q, orig=%q", clone.NegotiatedGroupName, orig.NegotiatedGroupName)
	}
	if clone.PQCPresent != orig.PQCPresent {
		t.Errorf("PQCPresent: clone=%v, orig=%v", clone.PQCPresent, orig.PQCPresent)
	}
	if clone.PQCMaturity != orig.PQCMaturity {
		t.Errorf("PQCMaturity: clone=%q, orig=%q", clone.PQCMaturity, orig.PQCMaturity)
	}
}

// TestPQCClone_MutateClone_DoesNotAffectOriginal mutates all four PQC fields on
// the clone and verifies the original is unchanged. This is the shallow-copy-safety
// check for the forward direction (clone modification leaking to original).
func TestPQCClone_MutateClone_DoesNotAffectOriginal(t *testing.T) {
	orig := UnifiedFinding{
		NegotiatedGroup:     0x11EC,
		NegotiatedGroupName: "X25519MLKEM768",
		PQCPresent:          true,
		PQCMaturity:         "final",
	}

	clone := orig.Clone()

	// Mutate every PQC field on the clone.
	clone.NegotiatedGroup = 0x001d
	clone.NegotiatedGroupName = "X25519"
	clone.PQCPresent = false
	clone.PQCMaturity = ""

	// Original must be unchanged.
	if orig.NegotiatedGroup != 0x11EC {
		t.Errorf("orig.NegotiatedGroup mutated to 0x%04x after clone mutation", orig.NegotiatedGroup)
	}
	if orig.NegotiatedGroupName != "X25519MLKEM768" {
		t.Errorf("orig.NegotiatedGroupName mutated to %q after clone mutation", orig.NegotiatedGroupName)
	}
	if !orig.PQCPresent {
		t.Error("orig.PQCPresent mutated to false after clone mutation")
	}
	if orig.PQCMaturity != "final" {
		t.Errorf("orig.PQCMaturity mutated to %q after clone mutation", orig.PQCMaturity)
	}
}

// TestPQCClone_MutateOriginal_DoesNotAffectClone mutates the original after
// cloning and verifies the clone is unchanged. This is the reverse direction
// safety check that complements TestPQCClone_MutateClone_DoesNotAffectOriginal.
func TestPQCClone_MutateOriginal_DoesNotAffectClone(t *testing.T) {
	orig := UnifiedFinding{
		NegotiatedGroup:     0x6399,
		NegotiatedGroupName: "X25519Kyber768Draft00",
		PQCPresent:          true,
		PQCMaturity:         "draft",
	}

	clone := orig.Clone()

	// Mutate every PQC field on the original.
	orig.NegotiatedGroup = 0
	orig.NegotiatedGroupName = ""
	orig.PQCPresent = false
	orig.PQCMaturity = ""

	// Clone must retain the values it had at Clone() time.
	if clone.NegotiatedGroup != 0x6399 {
		t.Errorf("clone.NegotiatedGroup mutated to 0x%04x after original mutation", clone.NegotiatedGroup)
	}
	if clone.NegotiatedGroupName != "X25519Kyber768Draft00" {
		t.Errorf("clone.NegotiatedGroupName mutated to %q after original mutation", clone.NegotiatedGroupName)
	}
	if !clone.PQCPresent {
		t.Error("clone.PQCPresent mutated to false after original mutation")
	}
	if clone.PQCMaturity != "draft" {
		t.Errorf("clone.PQCMaturity mutated to %q after original mutation", clone.PQCMaturity)
	}
}

// TestPQCClone_DraftAndFinalVariants exercises both draft and final maturity
// variants in a single clone cycle to ensure no interning or aliasing occurs
// between distinct maturity strings.
func TestPQCClone_DraftAndFinalVariants(t *testing.T) {
	cases := []struct {
		name    string
		finding UnifiedFinding
	}{
		{
			"final-hybrid",
			UnifiedFinding{
				NegotiatedGroup:     0x11EC,
				NegotiatedGroupName: "X25519MLKEM768",
				PQCPresent:          true,
				PQCMaturity:         "final",
			},
		},
		{
			"draft-kyber-primary",
			UnifiedFinding{
				NegotiatedGroup:     0x6399,
				NegotiatedGroupName: "X25519Kyber768Draft00",
				PQCPresent:          true,
				PQCMaturity:         "draft",
			},
		},
		{
			"draft-kyber-alt",
			UnifiedFinding{
				NegotiatedGroup:     0x636D,
				NegotiatedGroupName: "X25519Kyber768Draft00",
				PQCPresent:          true,
				PQCMaturity:         "draft",
			},
		},
		{
			"classical-no-pqc",
			UnifiedFinding{
				NegotiatedGroup:     0x001d,
				NegotiatedGroupName: "X25519",
				PQCPresent:          false,
				PQCMaturity:         "",
			},
		},
		{
			"zero-fields",
			UnifiedFinding{
				// All PQC fields at zero value — clone must also be zero.
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			clone := tc.finding.Clone()

			if clone.NegotiatedGroup != tc.finding.NegotiatedGroup {
				t.Errorf("NegotiatedGroup mismatch: clone=0x%04x orig=0x%04x",
					clone.NegotiatedGroup, tc.finding.NegotiatedGroup)
			}
			if clone.NegotiatedGroupName != tc.finding.NegotiatedGroupName {
				t.Errorf("NegotiatedGroupName mismatch: clone=%q orig=%q",
					clone.NegotiatedGroupName, tc.finding.NegotiatedGroupName)
			}
			if clone.PQCPresent != tc.finding.PQCPresent {
				t.Errorf("PQCPresent mismatch: clone=%v orig=%v",
					clone.PQCPresent, tc.finding.PQCPresent)
			}
			if clone.PQCMaturity != tc.finding.PQCMaturity {
				t.Errorf("PQCMaturity mismatch: clone=%q orig=%q",
					clone.PQCMaturity, tc.finding.PQCMaturity)
			}
		})
	}
}
