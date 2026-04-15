package findings

import (
	"encoding/json"
	"testing"
)

// TestUnifiedFinding_PQCFields verifies that the Sprint 1 TLS PQC fields
// serialize/deserialize correctly and that Clone copies them as value types.
func TestUnifiedFinding_PQCFields_JSONRoundTrip(t *testing.T) {
	orig := UnifiedFinding{
		SourceEngine:        "tls-probe",
		NegotiatedGroup:     0x11EC,
		NegotiatedGroupName: "X25519MLKEM768",
		PQCPresent:          true,
		PQCMaturity:         "final",
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var got UnifiedFinding
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if got.NegotiatedGroup != orig.NegotiatedGroup {
		t.Errorf("NegotiatedGroup: got 0x%04x, want 0x%04x", got.NegotiatedGroup, orig.NegotiatedGroup)
	}
	if got.NegotiatedGroupName != orig.NegotiatedGroupName {
		t.Errorf("NegotiatedGroupName: got %q, want %q", got.NegotiatedGroupName, orig.NegotiatedGroupName)
	}
	if got.PQCPresent != orig.PQCPresent {
		t.Errorf("PQCPresent: got %v, want %v", got.PQCPresent, orig.PQCPresent)
	}
	if got.PQCMaturity != orig.PQCMaturity {
		t.Errorf("PQCMaturity: got %q, want %q", got.PQCMaturity, orig.PQCMaturity)
	}
}

// TestUnifiedFinding_PQCFields_OmitEmpty verifies that zero-value PQC fields
// are omitted from JSON to keep output clean for non-TLS findings.
func TestUnifiedFinding_PQCFields_OmitEmpty(t *testing.T) {
	f := UnifiedFinding{
		SourceEngine: "semgrep",
		Algorithm:    &Algorithm{Name: "RSA"},
		// NegotiatedGroup=0, NegotiatedGroupName="", PQCPresent=false, PQCMaturity=""
	}

	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}

	for _, field := range []string{"negotiatedGroup", "negotiatedGroupName", "pqcPresent", "pqcMaturity"} {
		if _, present := raw[field]; present {
			t.Errorf("field %q should be omitted when zero, but it was present in JSON", field)
		}
	}
}

// TestUnifiedFinding_PQCFields_Clone verifies that Clone copies value-type PQC fields.
func TestUnifiedFinding_PQCFields_Clone(t *testing.T) {
	orig := UnifiedFinding{
		NegotiatedGroup:     0x11EC,
		NegotiatedGroupName: "X25519MLKEM768",
		PQCPresent:          true,
		PQCMaturity:         "final",
	}

	clone := orig.Clone()

	// Mutate original after clone — clone must not be affected.
	orig.NegotiatedGroup = 0x001d
	orig.NegotiatedGroupName = "X25519"
	orig.PQCPresent = false
	orig.PQCMaturity = ""

	if clone.NegotiatedGroup != 0x11EC {
		t.Errorf("Clone NegotiatedGroup mutated: got 0x%04x", clone.NegotiatedGroup)
	}
	if clone.NegotiatedGroupName != "X25519MLKEM768" {
		t.Errorf("Clone NegotiatedGroupName mutated: got %q", clone.NegotiatedGroupName)
	}
	if !clone.PQCPresent {
		t.Errorf("Clone PQCPresent mutated: got false")
	}
	if clone.PQCMaturity != "final" {
		t.Errorf("Clone PQCMaturity mutated: got %q", clone.PQCMaturity)
	}
}

// TestUnifiedFinding_PQCFields_DraftMaturity verifies draft-maturity round-trip.
func TestUnifiedFinding_PQCFields_DraftMaturity(t *testing.T) {
	orig := UnifiedFinding{
		NegotiatedGroup:     0x6399,
		NegotiatedGroupName: "X25519Kyber768Draft00",
		PQCPresent:          true,
		PQCMaturity:         "draft",
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var got UnifiedFinding
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if got.PQCMaturity != "draft" {
		t.Errorf("PQCMaturity: got %q, want draft", got.PQCMaturity)
	}
	if got.PQCPresent != true {
		t.Errorf("PQCPresent: got false for draft Kyber, want true")
	}
}
