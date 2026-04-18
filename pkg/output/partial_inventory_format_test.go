package output

// partial_inventory_format_test.go — Bucket 6: PartialInventory surfacing across
// all three formats (JSON / SARIF / CBOM) plus backcompat unmarshalling.
//
// Focus: tests NOT already covered by pqc_fields_format_test.go.
// That file has the basic present/absent checks; this file adds:
//   - omitempty semantics verified via a zero-value UnifiedFinding (no fields set).
//   - backcompat: unmarshal a Sprint-1-era JSON (no partialInventory keys) and
//     verify the round-trip marshal equals the input (no spurious additions).
//   - Multi-finding mixed scan: only ECH finding carries the annotation;
//     classical finding is clean.
//   - CBOM: PartialInventory with empty Reason string is handled gracefully
//     (oqs:partialInventory=true present, oqs:partialInventoryReason absent).

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// ── helpers ───────────────────────────────────────────────────────────────────

func zeroValueFinding() findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Location:     findings.Location{File: "dummy.go", Line: 1},
		Algorithm:    &findings.Algorithm{Name: "AES", Primitive: "symmetric", KeySize: 256, Mode: "GCM"},
		SourceEngine: "semgrep",
		Confidence:   findings.ConfidenceHigh,
		Reachable:    findings.ReachableYes,
		// PartialInventory and PartialInventoryReason are zero-valued (false / "").
	}
}

func echAnnotatedFinding() findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Location:               findings.Location{File: "(tls-probe)/ech.host:443#kex"},
		Algorithm:              &findings.Algorithm{Name: "ECDHE", Primitive: "key-exchange"},
		SourceEngine:           "tls-probe",
		Confidence:             findings.ConfidenceMedium,
		Reachable:              findings.ReachableYes,
		PartialInventory:       true,
		PartialInventoryReason: "ECH_ENABLED",
	}
}

func echNoReasonFinding() findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Location:         findings.Location{File: "(tls-probe)/ech.host:443#kex"},
		Algorithm:        &findings.Algorithm{Name: "ECDHE", Primitive: "key-exchange"},
		SourceEngine:     "tls-probe",
		Confidence:       findings.ConfidenceMedium,
		Reachable:        findings.ReachableYes,
		PartialInventory: true,
		// PartialInventoryReason deliberately left empty.
	}
}

func makeResult(ff []findings.UnifiedFinding) ScanResult {
	return ScanResult{
		Version:  "0.0.0-test",
		Target:   "/test",
		Engines:  []string{"tls-probe"},
		Findings: ff,
	}
}

// ── JSON omitempty ─────────────────────────────────────────────────────────────

// TestPartialInventory_JSON_ZeroValue verifies that a completely zero-valued
// finding (not just RSA, but literally no fields set for PartialInventory)
// omits both fields.
func TestPartialInventory_JSON_ZeroValue(t *testing.T) {
	t.Parallel()
	result := makeResult([]findings.UnifiedFinding{zeroValueFinding()})
	var buf bytes.Buffer
	if err := WriteJSON(&buf, result); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var raw struct {
		Findings []map[string]json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(raw.Findings) == 0 {
		t.Fatal("expected at least one finding in output")
	}
	f := raw.Findings[0]
	for _, key := range []string{"partialInventory", "partialInventoryReason"} {
		if _, present := f[key]; present {
			t.Errorf("JSON zero-value: field %q must be omitted (omitempty), but was present", key)
		}
	}
}

// TestPartialInventory_JSON_TrueNoReason verifies that when PartialInventory=true
// but PartialInventoryReason="" the JSON contains partialInventory but omits
// partialInventoryReason (omitempty on reason).
func TestPartialInventory_JSON_TrueNoReason(t *testing.T) {
	t.Parallel()
	result := makeResult([]findings.UnifiedFinding{echNoReasonFinding()})
	var buf bytes.Buffer
	if err := WriteJSON(&buf, result); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var raw struct {
		Findings []map[string]json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	f := raw.Findings[0]
	if _, present := f["partialInventory"]; !present {
		t.Error("partialInventory=true must be present in JSON")
	}
	if _, present := f["partialInventoryReason"]; present {
		t.Error("partialInventoryReason=\"\" must be omitted (omitempty)")
	}
}

// ── Backcompat: pre-Sprint-2 JSON round-trip ──────────────────────────────────

// TestPartialInventory_Backcompat_Sprint1JSON unmarshals a synthetic Sprint 1
// JSON (no partialInventory or partialInventoryReason keys) into a
// UnifiedFinding and verifies the fields remain zero-valued, then re-marshals
// and asserts the output does NOT contain those keys.
func TestPartialInventory_Backcompat_Sprint1JSON(t *testing.T) {
	t.Parallel()
	// Minimal Sprint-1-era finding JSON without PartialInventory fields.
	sprint1JSON := `{
		"location": {"file":"(tls-probe)/old.host:443#kex","line":0},
		"algorithm": {"name":"ECDHE","primitive":"key-exchange"},
		"confidence": "high",
		"sourceEngine": "tls-probe",
		"reachable": "yes",
		"negotiatedGroup": 4588,
		"negotiatedGroupName": "X25519MLKEM768",
		"pqcPresent": true,
		"pqcMaturity": "final"
	}`

	var f findings.UnifiedFinding
	if err := json.Unmarshal([]byte(sprint1JSON), &f); err != nil {
		t.Fatalf("unmarshal Sprint-1 JSON: %v", err)
	}

	// PartialInventory fields must be zero-valued.
	if f.PartialInventory {
		t.Error("PartialInventory should be false after unmarshalling Sprint-1 JSON")
	}
	if f.PartialInventoryReason != "" {
		t.Errorf("PartialInventoryReason should be empty, got %q", f.PartialInventoryReason)
	}

	// Re-marshal and verify the output does not contain partialInventory keys.
	out, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	outStr := string(out)
	if strings.Contains(outStr, "partialInventory") {
		t.Errorf("re-marshaled Sprint-1 finding must not contain partialInventory, got: %s", outStr)
	}
}

// ── Multi-finding mixed scan ───────────────────────────────────────────────────

// TestPartialInventory_JSON_MixedFindings verifies that in a scan result with
// one classical finding and one ECH finding, only the ECH finding carries the
// annotation.
func TestPartialInventory_JSON_MixedFindings(t *testing.T) {
	t.Parallel()
	result := makeResult([]findings.UnifiedFinding{
		zeroValueFinding(),
		echAnnotatedFinding(),
	})
	var buf bytes.Buffer
	if err := WriteJSON(&buf, result); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var raw struct {
		Findings []map[string]json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(raw.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(raw.Findings))
	}

	// First finding (classical): must have no partialInventory.
	f0 := raw.Findings[0]
	if _, ok := f0["partialInventory"]; ok {
		t.Error("classical finding must not have partialInventory")
	}

	// Second finding (ECH): must have partialInventory=true and reason.
	f1 := raw.Findings[1]
	if _, ok := f1["partialInventory"]; !ok {
		t.Error("ECH finding must have partialInventory")
	}
	if _, ok := f1["partialInventoryReason"]; !ok {
		t.Error("ECH finding must have partialInventoryReason")
	}
}

// ── CBOM: PartialInventory=true with empty Reason ─────────────────────────────

// TestPartialInventory_CBOM_TrueNoReason verifies that when PartialInventory=true
// but PartialInventoryReason="" the CBOM includes oqs:partialInventory but
// omits oqs:partialInventoryReason.
func TestPartialInventory_CBOM_TrueNoReason(t *testing.T) {
	t.Parallel()
	result := makeResult([]findings.UnifiedFinding{echNoReasonFinding()})
	var buf bytes.Buffer
	if err := WriteCBOM(&buf, result); err != nil {
		t.Fatalf("WriteCBOM: %v", err)
	}
	var bom struct {
		Components []struct {
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"components"`
	}
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatalf("unmarshal CBOM: %v", err)
	}
	if len(bom.Components) == 0 {
		t.Fatal("expected at least one CBOM component")
	}

	findProp := func(name string) (string, bool) {
		for _, p := range bom.Components[0].Properties {
			if p.Name == name {
				return p.Value, true
			}
		}
		return "", false
	}

	if v, ok := findProp("oqs:partialInventory"); !ok || v != "true" {
		t.Errorf("oqs:partialInventory: got %q ok=%v, want \"true\" present", v, ok)
	}
	if _, ok := findProp("oqs:partialInventoryReason"); ok {
		t.Error("oqs:partialInventoryReason must be absent when Reason is empty")
	}
}

// ── SARIF: zero-value finding has no partialInventory property ────────────────

// TestPartialInventory_SARIF_ZeroValue verifies that a zero-value finding
// produces no partialInventory key in SARIF result.properties.
func TestPartialInventory_SARIF_ZeroValue(t *testing.T) {
	t.Parallel()
	result := makeResult([]findings.UnifiedFinding{zeroValueFinding()})
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, result); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	var sarifDoc struct {
		Runs []struct {
			Results []struct {
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &sarifDoc); err != nil {
		t.Fatalf("unmarshal SARIF: %v", err)
	}
	if len(sarifDoc.Runs[0].Results) == 0 {
		t.Fatal("expected at least one SARIF result")
	}
	props := sarifDoc.Runs[0].Results[0].Properties
	if _, ok := props["partialInventory"]; ok {
		t.Error("SARIF zero-value finding must not carry partialInventory property")
	}
}
