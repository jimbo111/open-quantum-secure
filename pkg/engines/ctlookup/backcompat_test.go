// backcompat_test.go — Backward-compatibility regression test. Serialises a
// known-good Sprint 2 UnifiedFinding (tls-probe, ECH annotation, volume class)
// through JSON and verifies the round-trip is lossless. This guards against
// accidental field renames or omitempty changes introduced in Sprint 3.
package ctlookup

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// sprint2ECHFinding returns a representative Sprint 2 tls-probe finding with
// all fields that were added in Sprints 1 and 2. The ct-lookup engine (Sprint 3)
// must not rename, remove, or reorder these fields.
func sprint2ECHFinding() findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Location: findings.Location{
			File:         "(tls-probe)/ech.example.com:443#kex",
			Line:         0,
			ArtifactType: "tls-handshake",
		},
		Algorithm: &findings.Algorithm{
			Name:      "ECDHE",
			Primitive: "key-exchange",
			Curve:     "P-256",
		},
		Confidence:             findings.ConfidenceMedium,
		SourceEngine:           "tls-probe",
		Reachable:              findings.ReachableYes,
		NegotiatedGroup:        23,
		NegotiatedGroupName:    "secp256r1",
		PQCPresent:             false,
		PartialInventory:       true,
		PartialInventoryReason: "ECH_ENABLED",
		HandshakeVolumeClass:   "classical",
		HandshakeBytes:         5800,
	}
}

// TestBackcompat_Sprint2_JSON_RoundTrip marshals a Sprint 2 finding to JSON,
// unmarshals it back, re-marshals, and asserts the two JSON representations are
// byte-for-byte identical. Any field rename would produce a mismatch.
func TestBackcompat_Sprint2_JSON_RoundTrip(t *testing.T) {
	original := sprint2ECHFinding()

	first, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("first marshal: %v", err)
	}

	var decoded findings.UnifiedFinding
	if err := json.Unmarshal(first, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	second, err := json.Marshal(decoded)
	if err != nil {
		t.Fatalf("second marshal: %v", err)
	}

	if string(first) != string(second) {
		t.Errorf("JSON round-trip produced different output:\n  first:  %s\n  second: %s",
			first, second)
	}
}

// TestBackcompat_Sprint2_JSON_FieldNames verifies that specific Sprint 1/2 field
// names are present in the serialised JSON. A rename would cause the field to
// disappear or change name, triggering this test.
func TestBackcompat_Sprint2_JSON_FieldNames(t *testing.T) {
	f := sprint2ECHFinding()
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(data)

	for _, field := range []string{
		"negotiatedGroup",
		"negotiatedGroupName",
		"partialInventory",
		"partialInventoryReason",
		"handshakeVolumeClass",
		"handshakeBytes",
	} {
		if !strings.Contains(s, `"`+field+`"`) {
			t.Errorf("field %q missing from Sprint 2 JSON output:\n%s", field, s)
		}
	}
}

// TestBackcompat_Sprint2_NoCtlookupFields verifies that the Sprint 2 finding
// does NOT accidentally acquire Sprint 3 ct-lookup-specific fields (e.g.
// "ct-cert" prefix in location or partialInventory=false override).
func TestBackcompat_Sprint2_NoCtlookupFields(t *testing.T) {
	f := sprint2ECHFinding()
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	s := string(data)

	// Sprint 3 introduces "(ct-lookup)/" prefix in Location.File.
	if strings.Contains(s, "ct-lookup") {
		t.Errorf("Sprint 2 finding should not mention ct-lookup, but JSON contains it:\n%s", s)
	}
}

// TestBackcompat_PreSprint2_JSON_NoAnnotationFields verifies that a pre-Sprint-2
// JSON payload (no partialInventory or handshake fields) round-trips cleanly
// through UnifiedFinding without gaining any extra keys.
func TestBackcompat_PreSprint2_JSON_NoAnnotationFields(t *testing.T) {
	// Minimal Sprint-1-era finding as it would appear in a stored JSON report.
	preSprint2JSON := `{
		"location": {"file":"(tls-probe)/classic.host:443#kex","line":0},
		"algorithm": {"name":"ECDHE","primitive":"key-exchange"},
		"confidence": "high",
		"sourceEngine": "tls-probe",
		"reachable": "yes",
		"negotiatedGroup": 23,
		"negotiatedGroupName": "secp256r1"
	}`

	var f findings.UnifiedFinding
	if err := json.Unmarshal([]byte(preSprint2JSON), &f); err != nil {
		t.Fatalf("unmarshal Sprint-1 JSON: %v", err)
	}

	// Sprint 2/3 fields must be zero-valued.
	if f.PartialInventory {
		t.Error("PartialInventory should be false in Sprint-1 finding")
	}
	if f.PartialInventoryReason != "" {
		t.Errorf("PartialInventoryReason should be empty, got %q", f.PartialInventoryReason)
	}
	if f.HandshakeVolumeClass != "" {
		t.Errorf("HandshakeVolumeClass should be empty, got %q", f.HandshakeVolumeClass)
	}

	// Re-marshal must not introduce any partial-inventory or handshake keys.
	out, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	for _, key := range []string{"partialInventory", "handshakeVolumeClass", "handshakeBytes"} {
		if strings.Contains(string(out), `"`+key+`"`) {
			t.Errorf("re-marshalled Sprint-1 finding should not contain %q: %s", key, out)
		}
	}
}
