// backcompat_test.go — backward-compatibility tests across Sprint 0–4.
//
// Purpose: verify that adding Sprint 4 ssh-probe findings to a ScanResult does
// not break serialization of Sprint 0/1/2/3 fields. Specifically:
//   - Sprint 0: HNDLRisk, Severity, QuantumRisk (Mosca/QRS fields)
//   - Sprint 1: PQCPresent, PQCMaturity, NegotiatedGroup, NegotiatedGroupName (TLS probe)
//   - Sprint 2: PartialInventory, PartialInventoryReason, HandshakeVolumeClass,
//               HandshakeBytes (ECH + volume classification)
//   - Sprint 3: no new UnifiedFinding fields (CT lookup output is findings too)
//   - Sprint 4: PQCPresent, PQCMaturity (SSH probe reuses Sprint 1 fields — no
//               new fields added, pure additive via SourceEngine="ssh-probe")
//
// These tests ensure the json struct tags and omitempty annotations on
// UnifiedFinding have not regressed as Sprint 4 code landed.
package sshprobe

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// TestBackcompat_Sprint0_HNDLAndSeverityFields verifies that HNDLRisk, Severity,
// and QuantumRisk (Sprint 0 scoring fields) round-trip correctly through JSON.
func TestBackcompat_Sprint0_HNDLAndSeverityFields(t *testing.T) {
	f := findings.UnifiedFinding{
		Location:    findings.Location{File: "/src/rsa.go", Line: 10},
		Algorithm:   &findings.Algorithm{Name: "RSA-2048", Primitive: "asymmetric", KeySize: 2048},
		SourceEngine: "cipherscope",
		Confidence:  findings.ConfidenceHigh,
		Reachable:   findings.ReachableYes,
		QuantumRisk: findings.QRVulnerable,
		Severity:    findings.SevCritical,
		HNDLRisk:    "immediate",
	}

	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal Sprint 0 finding: %v", err)
	}

	var got findings.UnifiedFinding
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("json.Unmarshal Sprint 0 finding: %v", err)
	}

	if got.QuantumRisk != findings.QRVulnerable {
		t.Errorf("Sprint 0 QuantumRisk=%q, want %q", got.QuantumRisk, findings.QRVulnerable)
	}
	if got.Severity != findings.SevCritical {
		t.Errorf("Sprint 0 Severity=%q, want %q", got.Severity, findings.SevCritical)
	}
	if got.HNDLRisk != "immediate" {
		t.Errorf("Sprint 0 HNDLRisk=%q, want immediate", got.HNDLRisk)
	}
}

// TestBackcompat_Sprint1_TLSProbeFields verifies that Sprint 1 TLS probe fields
// (NegotiatedGroup, NegotiatedGroupName, PQCPresent, PQCMaturity) survive JSON
// round-trip when co-located with Sprint 4 SSH probe findings in the same output.
func TestBackcompat_Sprint1_TLSProbeFields(t *testing.T) {
	tlsFinding := findings.UnifiedFinding{
		Location:            findings.Location{File: "(tls-probe)/example.com:443#kex", ArtifactType: "tls-endpoint"},
		Algorithm:           &findings.Algorithm{Name: "X25519MLKEM768", Primitive: "key-exchange"},
		SourceEngine:        "tls-probe",
		Confidence:          findings.ConfidenceHigh,
		Reachable:           findings.ReachableYes,
		QuantumRisk:         findings.QRSafe,
		NegotiatedGroup:     0x11EC,
		NegotiatedGroupName: "X25519MLKEM768",
		PQCPresent:          true,
		PQCMaturity:         "final",
	}
	sshFinding := findings.UnifiedFinding{
		Location:    findings.Location{File: "(ssh-probe)/example.com:22#kex", ArtifactType: "ssh-endpoint"},
		Algorithm:   &findings.Algorithm{Name: "mlkem768x25519-sha256", Primitive: "kex"},
		SourceEngine: "ssh-probe",
		Confidence:  findings.ConfidenceHigh,
		Reachable:   findings.ReachableYes,
		QuantumRisk: findings.QRSafe,
		PQCPresent:  true,
		PQCMaturity: "final",
		// NegotiatedGroup intentionally 0 — SSH probe does not populate this field.
	}

	pair := []findings.UnifiedFinding{tlsFinding, sshFinding}
	b, err := json.Marshal(pair)
	if err != nil {
		t.Fatalf("json.Marshal Sprint 1+4 findings: %v", err)
	}

	var got []findings.UnifiedFinding
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("json.Unmarshal Sprint 1+4 findings: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(got))
	}

	// TLS finding: NegotiatedGroup must still be set.
	if got[0].NegotiatedGroup != 0x11EC {
		t.Errorf("Sprint 1 NegotiatedGroup=0x%04x, want 0x11EC", got[0].NegotiatedGroup)
	}
	if got[0].NegotiatedGroupName != "X25519MLKEM768" {
		t.Errorf("Sprint 1 NegotiatedGroupName=%q, want X25519MLKEM768", got[0].NegotiatedGroupName)
	}
	if !got[0].PQCPresent {
		t.Error("Sprint 1 PQCPresent=false after round-trip, want true")
	}
	if got[0].PQCMaturity != "final" {
		t.Errorf("Sprint 1 PQCMaturity=%q, want final", got[0].PQCMaturity)
	}

	// SSH finding: NegotiatedGroup must remain 0 (not set by SSH probe).
	if got[1].NegotiatedGroup != 0 {
		t.Errorf("Sprint 4 SSH finding NegotiatedGroup=0x%04x, want 0", got[1].NegotiatedGroup)
	}
	if !got[1].PQCPresent {
		t.Error("Sprint 4 SSH finding PQCPresent=false after round-trip, want true")
	}
}

// TestBackcompat_Sprint2_ECHAndVolumeFields verifies that Sprint 2 partial-inventory
// and handshake-volume fields survive JSON round-trip.
func TestBackcompat_Sprint2_ECHAndVolumeFields(t *testing.T) {
	f := findings.UnifiedFinding{
		Location:               findings.Location{File: "(tls-probe)/ech.example.com:443#kex", ArtifactType: "tls-endpoint"},
		Algorithm:              &findings.Algorithm{Name: "ECDHE", Primitive: "key-exchange"},
		SourceEngine:           "tls-probe",
		Confidence:             findings.ConfidenceMedium,
		Reachable:              findings.ReachableYes,
		QuantumRisk:            findings.QRVulnerable,
		PartialInventory:       true,
		PartialInventoryReason: "ECH_ENABLED",
		HandshakeVolumeClass:   "hybrid-kem",
		HandshakeBytes:         8500,
	}

	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal Sprint 2 finding: %v", err)
	}

	var got findings.UnifiedFinding
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("json.Unmarshal Sprint 2 finding: %v", err)
	}

	if !got.PartialInventory {
		t.Error("Sprint 2 PartialInventory=false after round-trip, want true")
	}
	if got.PartialInventoryReason != "ECH_ENABLED" {
		t.Errorf("Sprint 2 PartialInventoryReason=%q, want ECH_ENABLED", got.PartialInventoryReason)
	}
	if got.HandshakeVolumeClass != "hybrid-kem" {
		t.Errorf("Sprint 2 HandshakeVolumeClass=%q, want hybrid-kem", got.HandshakeVolumeClass)
	}
	if got.HandshakeBytes != 8500 {
		t.Errorf("Sprint 2 HandshakeBytes=%d, want 8500", got.HandshakeBytes)
	}
}

// TestBackcompat_Sprint4_AdditiveOnly verifies that Sprint 4 ssh-probe findings
// use no new JSON fields beyond what was already defined in Sprints 0–3.
// Concretely: marshal a Sprint 4 SSH finding and assert the raw JSON keys are a
// strict subset of the known UnifiedFinding schema.
func TestBackcompat_Sprint4_AdditiveOnly(t *testing.T) {
	sshFinding := findings.UnifiedFinding{
		Location:    findings.Location{File: "(ssh-probe)/203.0.113.1:22#kex", ArtifactType: "ssh-endpoint"},
		Algorithm:   &findings.Algorithm{Name: "mlkem768x25519-sha256", Primitive: "kex"},
		SourceEngine: "ssh-probe",
		Confidence:  findings.ConfidenceHigh,
		Reachable:   findings.ReachableYes,
		QuantumRisk: findings.QRSafe,
		Severity:    findings.SevInfo,
		PQCPresent:  true,
		PQCMaturity: "final",
		Recommendation: "PQC-capable KEX method advertised. No migration required.",
		RawIdentifier:  "ssh-kex:mlkem768x25519-sha256|203.0.113.1:22",
	}

	b, err := json.Marshal(sshFinding)
	if err != nil {
		t.Fatalf("json.Marshal Sprint 4 finding: %v", err)
	}

	// Unmarshal into a raw map to inspect keys.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatalf("json.Unmarshal to map: %v", err)
	}

	// All field names must match the documented UnifiedFinding schema.
	// Sprint 4 must not introduce any new top-level JSON keys.
	knownKeys := map[string]bool{
		"location":               true,
		"algorithm":              true,
		"dependency":             true,
		"confidence":             true,
		"sourceEngine":           true,
		"corroboratedBy":         true,
		"reachable":              true,
		"rawIdentifier":          true,
		"quantumRisk":            true,
		"severity":               true,
		"recommendation":         true,
		"dataFlowPath":           true,
		"hndlRisk":               true,
		"priority":               true,
		"blastRadius":            true,
		"testFile":               true,
		"generatedFile":          true,
		"migrationEffort":        true,
		"targetAlgorithm":        true,
		"targetStandard":         true,
		"migrationSnippet":       true,
		"negotiatedGroup":        true, // Sprint 1 TLS
		"negotiatedGroupName":    true, // Sprint 1 TLS
		"pqcPresent":             true, // Sprint 1 TLS; reused by Sprint 4 SSH
		"pqcMaturity":            true, // Sprint 1 TLS; reused by Sprint 4 SSH
		"partialInventory":       true, // Sprint 2
		"partialInventoryReason": true, // Sprint 2
		"handshakeVolumeClass":   true, // Sprint 2
		"handshakeBytes":         true, // Sprint 2
	}

	for key := range raw {
		if !knownKeys[key] {
			t.Errorf("Sprint 4 SSH finding introduces unknown JSON key %q — "+
				"Sprint 4 must be purely additive with no new top-level fields", key)
		}
	}
}

// TestBackcompat_AllSprints_FullRoundTrip performs a joint round-trip across
// all sprint fields in a single JSON array, asserting no cross-sprint interference.
func TestBackcompat_AllSprints_FullRoundTrip(t *testing.T) {
	all := []findings.UnifiedFinding{
		// Sprint 0: classical vulnerable with HNDL risk
		{
			Location:    findings.Location{File: "/src/rsa.go", Line: 5},
			Algorithm:   &findings.Algorithm{Name: "RSA-2048", Primitive: "asymmetric", KeySize: 2048},
			SourceEngine: "cipherscope",
			Confidence:  findings.ConfidenceHigh,
			Reachable:   findings.ReachableYes,
			QuantumRisk: findings.QRVulnerable,
			Severity:    findings.SevCritical,
			HNDLRisk:    "immediate",
		},
		// Sprint 1: TLS hybrid KEX
		{
			Location:            findings.Location{File: "(tls-probe)/example.com:443#kex", ArtifactType: "tls-endpoint"},
			Algorithm:           &findings.Algorithm{Name: "X25519MLKEM768", Primitive: "key-exchange"},
			SourceEngine:        "tls-probe",
			Confidence:          findings.ConfidenceHigh,
			Reachable:           findings.ReachableYes,
			QuantumRisk:         findings.QRSafe,
			NegotiatedGroup:     0x11EC,
			NegotiatedGroupName: "X25519MLKEM768",
			PQCPresent:          true,
			PQCMaturity:         "final",
		},
		// Sprint 2: ECH partial inventory
		{
			Location:               findings.Location{File: "(tls-probe)/ech.example.com:443#kex", ArtifactType: "tls-endpoint"},
			Algorithm:              &findings.Algorithm{Name: "ECDHE", Primitive: "key-exchange"},
			SourceEngine:           "tls-probe",
			Confidence:             findings.ConfidenceMedium,
			Reachable:              findings.ReachableYes,
			QuantumRisk:            findings.QRVulnerable,
			PartialInventory:       true,
			PartialInventoryReason: "ECH_ENABLED",
			HandshakeVolumeClass:   "classical",
			HandshakeBytes:         6200,
		},
		// Sprint 4: SSH PQC KEX
		{
			Location:    findings.Location{File: "(ssh-probe)/203.0.113.1:22#kex", ArtifactType: "ssh-endpoint"},
			Algorithm:   &findings.Algorithm{Name: "mlkem768x25519-sha256", Primitive: "kex"},
			SourceEngine: "ssh-probe",
			Confidence:  findings.ConfidenceHigh,
			Reachable:   findings.ReachableYes,
			QuantumRisk: findings.QRSafe,
			PQCPresent:  true,
			PQCMaturity: "final",
		},
		// Sprint 4: SSH classical KEX
		{
			Location:    findings.Location{File: "(ssh-probe)/203.0.113.1:22#kex", ArtifactType: "ssh-endpoint"},
			Algorithm:   &findings.Algorithm{Name: "diffie-hellman-group14-sha256", Primitive: "kex"},
			SourceEngine: "ssh-probe",
			Confidence:  findings.ConfidenceHigh,
			Reachable:   findings.ReachableYes,
			QuantumRisk: findings.QRVulnerable,
			Severity:    findings.SevHigh,
			PQCPresent:  false,
		},
	}

	b, err := json.Marshal(all)
	if err != nil {
		t.Fatalf("json.Marshal all-sprint findings: %v", err)
	}
	var got []findings.UnifiedFinding
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("json.Unmarshal all-sprint findings: %v", err)
	}
	if len(got) != len(all) {
		t.Fatalf("expected %d findings, got %d", len(all), len(got))
	}

	// Sprint 0 — HNDL risk preserved.
	if got[0].HNDLRisk != "immediate" {
		t.Errorf("Sprint 0 HNDLRisk=%q, want immediate", got[0].HNDLRisk)
	}

	// Sprint 1 — TLS group preserved.
	if got[1].NegotiatedGroup != 0x11EC {
		t.Errorf("Sprint 1 NegotiatedGroup=0x%04x, want 0x11EC", got[1].NegotiatedGroup)
	}
	if got[1].NegotiatedGroupName != "X25519MLKEM768" {
		t.Errorf("Sprint 1 NegotiatedGroupName=%q, want X25519MLKEM768", got[1].NegotiatedGroupName)
	}

	// Sprint 2 — ECH fields preserved.
	if !got[2].PartialInventory {
		t.Error("Sprint 2 PartialInventory=false after round-trip")
	}
	if got[2].HandshakeBytes != 6200 {
		t.Errorf("Sprint 2 HandshakeBytes=%d, want 6200", got[2].HandshakeBytes)
	}

	// Sprint 4 SSH PQC — reuses Sprint 1 PQC fields, NegotiatedGroup must be 0.
	if !got[3].PQCPresent {
		t.Error("Sprint 4 SSH PQCPresent=false after round-trip, want true")
	}
	if got[3].NegotiatedGroup != 0 {
		t.Errorf("Sprint 4 SSH NegotiatedGroup=0x%04x, want 0", got[3].NegotiatedGroup)
	}
	if got[3].SourceEngine != "ssh-probe" {
		t.Errorf("Sprint 4 SSH SourceEngine=%q, want ssh-probe", got[3].SourceEngine)
	}

	// Sprint 4 SSH classical — PQCPresent=false, no NegotiatedGroup.
	if got[4].PQCPresent {
		t.Error("Sprint 4 classical SSH PQCPresent=true after round-trip, want false")
	}
	if !strings.Contains(got[4].Algorithm.Name, "diffie-hellman") {
		t.Errorf("Sprint 4 classical method name=%q", got[4].Algorithm.Name)
	}
}
