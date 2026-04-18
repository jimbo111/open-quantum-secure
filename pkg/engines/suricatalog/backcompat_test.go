package suricatalog

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// TestBackcompat_Sprint0to5FieldsPresent verifies that UnifiedFinding fields introduced
// in Sprint 0-5 still serialize correctly when produced by the suricata-log engine.
// Sprint 6 adds SourceEngine="suricata-log" as a purely additive field.
func TestBackcompat_Sprint0to5FieldsPresent(t *testing.T) {
	// Construct a finding that exercises Sprint 1/2 TLS probe fields to confirm the
	// UnifiedFinding struct still carries them alongside Sprint 6 suricata-log fields.
	f := findings.UnifiedFinding{
		// Sprint 0: base UnifiedFinding fields
		Location:       findings.Location{File: "(suricata-log)/example.com#TLS_AES_128_GCM_SHA256"},
		Algorithm:      &findings.Algorithm{Name: "TLS_AES_128_GCM_SHA256", Primitive: "symmetric"},
		Confidence:     findings.ConfidenceMedium,
		Reachable:      findings.ReachableUnknown,
		QuantumRisk:    findings.QRResistant,
		Severity:       findings.SevInfo,
		Recommendation: "No migration required",
		HNDLRisk:       "",
		MigrationEffort: findings.EffortSimple,
		TargetAlgorithm: "AES-256-GCM",
		TargetStandard:  "NIST SP 800-38D",

		// Sprint 1: TLS probe PQC fields
		NegotiatedGroup:     0x0000,
		NegotiatedGroupName: "",
		PQCPresent:          false,
		PQCMaturity:         "",

		// Sprint 2: ECH partial-inventory + handshake volume fields
		PartialInventory:       false,
		PartialInventoryReason: "",
		HandshakeVolumeClass:   "",
		HandshakeBytes:         0,

		// Sprint 6: suricata-log engine identifier (additive)
		SourceEngine: "suricata-log",
	}

	b, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var got findings.UnifiedFinding
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	// Sprint 6 field must be preserved.
	if got.SourceEngine != "suricata-log" {
		t.Errorf("SourceEngine = %q, want suricata-log", got.SourceEngine)
	}

	// Sprint 0 fields must survive round-trip.
	if got.QuantumRisk != findings.QRResistant {
		t.Errorf("QuantumRisk = %q, want QRResistant", got.QuantumRisk)
	}
	if got.Algorithm == nil || got.Algorithm.Name != "TLS_AES_128_GCM_SHA256" {
		t.Errorf("Algorithm.Name = %v, want TLS_AES_128_GCM_SHA256", got.Algorithm)
	}

	// Sprint 1 fields must still be present in the struct (no removal).
	_ = got.NegotiatedGroup
	_ = got.NegotiatedGroupName
	_ = got.PQCPresent
	_ = got.PQCMaturity

	// Sprint 2 fields must still be present in the struct (no removal).
	_ = got.PartialInventory
	_ = got.PartialInventoryReason
	_ = got.HandshakeVolumeClass
	_ = got.HandshakeBytes
}

// TestBackcompat_Sprint6FieldsAdditive verifies that a Sprint 0-5 finding encoded
// before Sprint 6 (without SourceEngine) still deserializes without error.
func TestBackcompat_Sprint6FieldsAdditive(t *testing.T) {
	// JSON with no "sourceEngine" field (pre-Sprint 6 shape).
	const preSprint6JSON = `{
		"location": {"file": "(tls-probe)/example.com:443#kex", "line": 0, "column": 0},
		"algorithm": {"name": "X25519MLKEM768", "primitive": "key-exchange"},
		"confidence": "high",
		"reachable": "yes",
		"quantumRisk": "quantum-safe",
		"pqcPresent": true,
		"pqcMaturity": "final",
		"negotiatedGroup": 4588,
		"negotiatedGroupName": "X25519MLKEM768",
		"handshakeVolumeClass": "hybrid-kem",
		"handshakeBytes": 9500
	}`

	var f findings.UnifiedFinding
	if err := json.Unmarshal([]byte(preSprint6JSON), &f); err != nil {
		t.Fatalf("unmarshal pre-Sprint6 finding: %v", err)
	}

	// SourceEngine defaults to empty string (zero value) — additive, not breaking.
	if f.SourceEngine != "" {
		t.Errorf("pre-Sprint6 finding: SourceEngine=%q, want empty (field absent in old JSON)", f.SourceEngine)
	}

	// Sprint 1/2 fields must still deserialize correctly.
	if !f.PQCPresent {
		t.Error("PQCPresent not preserved")
	}
	if f.NegotiatedGroup != 4588 {
		t.Errorf("NegotiatedGroup=%d, want 4588", f.NegotiatedGroup)
	}
	if f.HandshakeVolumeClass != "hybrid-kem" {
		t.Errorf("HandshakeVolumeClass=%q, want hybrid-kem", f.HandshakeVolumeClass)
	}
}

// TestBackcompat_DedupeKeyStable verifies that DedupeKey output for a suricata-log
// finding has the same shape as for other engines (no regression in dedup format).
func TestBackcompat_DedupeKeyStable(t *testing.T) {
	f := findings.UnifiedFinding{
		Location:     findings.Location{File: "(suricata-log)/example.com#TLS_AES_128_GCM_SHA256", Line: 0},
		Algorithm:    &findings.Algorithm{Name: "TLS_AES_128_GCM_SHA256"},
		SourceEngine: "suricata-log",
	}
	key := f.DedupeKey()
	if key == "" {
		t.Fatal("DedupeKey returned empty string")
	}
	// Key must contain the file path component.
	if !strings.HasPrefix(key, "(suricata-log)/") {
		t.Errorf("DedupeKey does not start with (suricata-log)/: %q", key)
	}
}
