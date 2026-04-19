package orchestrator

import (
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// TestJA3SFindingReclassificationNotInverted is a regression test for the A3 bug:
// tlsRecordToFindings previously set Algorithm.Name = "PQC-Server-Stack" for JA3S
// matches, which caused classifyFindings (orchestrator) to re-classify the finding
// as RiskVulnerable/Critical because "PQC-Server-Stack" fell through to the
// key-agree default path instead of the pqcSafeFamilies path.
//
// Fix: Algorithm.Name is now set to the actual KEM name (e.g. "MLKEM768") so
// both the initial classify call and this re-classify call agree.
//
// The bug is dormant while ja3sDB is empty but activates the moment any entry is
// added. This test locks in the correct behaviour for future DB population.
func TestJA3SFindingReclassificationNotInverted(t *testing.T) {
	// Simulate the finding produced by the fixed tlsRecordToFindings JA3S path.
	f := findings.UnifiedFinding{
		Location:      findings.Location{File: "(suricata-log)/target.example.com#MLKEM768"},
		Algorithm:     &findings.Algorithm{Name: "MLKEM768", Primitive: "key-agree"},
		PQCPresent:    true,
		PQCMaturity:   "final",
		RawIdentifier: "suricata-ja3s:deadbeefdeadbeefdeadbeefdeadbeef",
	}
	ff := []findings.UnifiedFinding{f}

	classifyFindings(ff)

	if ff[0].QuantumRisk != findings.QRSafe {
		t.Errorf("JA3S MLKEM768 finding: QuantumRisk = %q, want %q (classifyFindings must not invert safe PQC to vulnerable)", ff[0].QuantumRisk, findings.QRSafe)
	}
}
