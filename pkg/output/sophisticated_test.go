// Package output — sophisticated tests for SARIF, JSON, CSV, CBOM, HTML.
package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func sophMakeResult(ff []findings.UnifiedFinding) ScanResult {
	return BuildResult("0.1.0", "/project", []string{"test-engine"}, ff)
}

func makePQCFinding() findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Location:            findings.Location{File: "/project/tls.go", Line: 10},
		Algorithm:           &findings.Algorithm{Name: "X25519MLKEM768", Primitive: "kem"},
		SourceEngine:        "tls-probe",
		Confidence:          findings.ConfidenceHigh,
		PQCPresent:          true,
		PQCMaturity:         "final",
		NegotiatedGroup:     0x11EC,
		NegotiatedGroupName: "X25519MLKEM768",
	}
}

func makeECHFinding() findings.UnifiedFinding {
	f := makePQCFinding()
	f.PartialInventory = true
	f.PartialInventoryReason = "ECH_ENABLED"
	f.HandshakeVolumeClass = "hybrid-kem"
	f.HandshakeBytes = 9500
	return f
}

// ---------------------------------------------------------------------------
// 1. SARIF: schema / version / run structure
// ---------------------------------------------------------------------------

func TestSARIF_StructuralInvariants(t *testing.T) {
	buf := writeSARIFFor(t, []findings.UnifiedFinding{makePQCFinding()}, "/project")

	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("SARIF is not valid JSON: %v", err)
	}

	// $schema must be present.
	if schema, ok := raw["$schema"].(string); !ok || schema == "" {
		t.Error("SARIF missing or empty $schema field")
	}
	// version must be 2.1.0.
	if ver, _ := raw["version"].(string); ver != "2.1.0" {
		t.Errorf("SARIF version = %q; want 2.1.0", ver)
	}
	// runs must be a non-empty array.
	runs, ok := raw["runs"].([]interface{})
	if !ok || len(runs) == 0 {
		t.Fatal("SARIF missing runs array")
	}
	run := runs[0].(map[string]interface{})
	if _, ok := run["tool"]; !ok {
		t.Error("SARIF run missing 'tool' field")
	}
	if _, ok := run["results"]; !ok {
		t.Error("SARIF run missing 'results' field")
	}
}

// ---------------------------------------------------------------------------
// 2. SARIF: partialInventory is bool, partialInventoryReason is string
// ---------------------------------------------------------------------------

func TestSARIF_PartialInventoryTypes(t *testing.T) {
	f := makeECHFinding()
	buf := writeSARIFFor(t, []findings.UnifiedFinding{f}, "/project")
	result := sarifResultFor(t, &buf)

	props, ok := result["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("SARIF result missing properties")
	}

	// partialInventory must be a JSON bool, not a string "true".
	if pi, exists := props["partialInventory"]; exists {
		if _, isBool := pi.(bool); !isBool {
			t.Errorf("partialInventory must be bool; got %T (%v)", pi, pi)
		}
	} else {
		t.Error("partialInventory property missing from SARIF result")
	}

	// partialInventoryReason must be a string.
	if pir, exists := props["partialInventoryReason"]; exists {
		if _, isStr := pir.(string); !isStr {
			t.Errorf("partialInventoryReason must be string; got %T (%v)", pir, pir)
		}
		if pir.(string) != "ECH_ENABLED" {
			t.Errorf("partialInventoryReason = %q; want ECH_ENABLED", pir)
		}
	} else {
		t.Error("partialInventoryReason missing from SARIF result when PartialInventory=true")
	}
}

// ---------------------------------------------------------------------------
// 3. SARIF: pqcPresent emitted as bool when true, absent when false
// ---------------------------------------------------------------------------

func TestSARIF_PQCPresent_OmittedWhenFalse(t *testing.T) {
	classical := findings.UnifiedFinding{
		Location:     findings.Location{File: "/project/main.go", Line: 1},
		Algorithm:    &findings.Algorithm{Name: "RSA", Primitive: "asymmetric", KeySize: 2048},
		SourceEngine: "cipherscope",
		PQCPresent:   false, // zero value
	}
	buf := writeSARIFFor(t, []findings.UnifiedFinding{classical}, "/project")
	result := sarifResultFor(t, &buf)

	props, ok := result["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("SARIF result missing properties")
	}
	if _, exists := props["pqcPresent"]; exists {
		t.Error("pqcPresent must be omitted from SARIF properties when false")
	}
}

func TestSARIF_PQCPresent_EmittedAsBool(t *testing.T) {
	buf := writeSARIFFor(t, []findings.UnifiedFinding{makePQCFinding()}, "/project")
	result := sarifResultFor(t, &buf)

	props, _ := result["properties"].(map[string]interface{})
	pi, exists := props["pqcPresent"]
	if !exists {
		t.Fatal("pqcPresent missing from SARIF properties when PQCPresent=true")
	}
	if _, isBool := pi.(bool); !isBool {
		t.Errorf("pqcPresent must be bool; got %T", pi)
	}
}

// ---------------------------------------------------------------------------
// 4. JSON: omitempty — NegotiatedGroup=0 must not appear in output
// ---------------------------------------------------------------------------

func TestJSON_OmitEmpty_ZeroCodpoint(t *testing.T) {
	f := findings.UnifiedFinding{
		Location:     findings.Location{File: "/main.go", Line: 1},
		Algorithm:    &findings.Algorithm{Name: "RSA", KeySize: 2048},
		SourceEngine: "cipherscope",
		// NegotiatedGroup is zero — must be omitted.
	}
	result := sophMakeResult([]findings.UnifiedFinding{f})
	var buf bytes.Buffer
	if err := WriteJSON(&buf, result); err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	findingsList, _ := parsed["findings"].([]interface{})
	if len(findingsList) == 0 {
		t.Fatal("no findings in JSON output")
	}
	fo := findingsList[0].(map[string]interface{})
	if _, exists := fo["negotiatedGroup"]; exists {
		t.Error("negotiatedGroup must be omitted when value is 0 (omitempty)")
	}
	if _, exists := fo["negotiatedGroupName"]; exists {
		t.Error("negotiatedGroupName must be omitted when empty (omitempty)")
	}
}

// ---------------------------------------------------------------------------
// 5. JSON: non-zero NegotiatedGroup is serialized
// ---------------------------------------------------------------------------

func TestJSON_NegotiatedGroupSerialized(t *testing.T) {
	f := makePQCFinding()
	result := sophMakeResult([]findings.UnifiedFinding{f})
	var buf bytes.Buffer
	if err := WriteJSON(&buf, result); err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}

	raw := buf.String()
	if !strings.Contains(raw, `"negotiatedGroup"`) {
		t.Error("negotiatedGroup missing from JSON when NegotiatedGroup != 0")
	}
	if !strings.Contains(raw, `"X25519MLKEM768"`) {
		t.Error("negotiatedGroupName value missing from JSON")
	}
}

// ---------------------------------------------------------------------------
// 6. CSV: expected header columns present
// ---------------------------------------------------------------------------

func TestCSV_HeaderColumns(t *testing.T) {
	result := sophMakeResult(nil)
	var buf bytes.Buffer
	if err := WriteCSV(&buf, result); err != nil {
		t.Fatalf("WriteCSV error: %v", err)
	}

	header := strings.SplitN(buf.String(), "\r\n", 2)[0]
	required := []string{
		"severity", "confidence", "algorithm", "primitive", "keySize", "risk",
		"pqcPresent", "pqcMaturity", "negotiatedGroupName",
		"handshakeVolumeClass", "handshakeBytes",
		"file", "line", "sourceEngine", "reachable",
		"partialInventory", "partialInventoryReason", "dedupeKey",
	}
	for _, col := range required {
		if !strings.Contains(header, col) {
			t.Errorf("CSV header missing column %q", col)
		}
	}
}

// ---------------------------------------------------------------------------
// 7. CBOM: bomFormat and specVersion invariants
// ---------------------------------------------------------------------------

func TestCBOM_BOMFormatInvariants(t *testing.T) {
	f := makePQCFinding()
	result := sophMakeResult([]findings.UnifiedFinding{f})
	var buf bytes.Buffer
	if err := WriteCBOM(&buf, result); err != nil {
		t.Fatalf("WriteCBOM error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("CBOM is not valid JSON: %v", err)
	}

	if bf, _ := parsed["bomFormat"].(string); bf != "CycloneDX" {
		t.Errorf("bomFormat = %q; want CycloneDX", bf)
	}
	if sv, _ := parsed["specVersion"].(string); sv != "1.7" {
		t.Errorf("specVersion = %q; want 1.7", sv)
	}
	if _, ok := parsed["serialNumber"]; !ok {
		t.Error("CBOM missing serialNumber")
	}
}

// ---------------------------------------------------------------------------
// 8. HTML: self-contained (no external links in src/href)
// ---------------------------------------------------------------------------

func TestHTML_SelfContained(t *testing.T) {
	f := makePQCFinding()
	result := sophMakeResult([]findings.UnifiedFinding{f})
	var buf bytes.Buffer
	if err := WriteHTML(&buf, result); err != nil {
		t.Fatalf("WriteHTML error: %v", err)
	}

	html := buf.String()
	// Must not reference any external script or stylesheet URLs
	// (anchor hrefs for informational links are acceptable).
	externalPrefixes := []string{
		`src="http`, `src='http`,
		`src="//`, `src='//`,
	}
	for _, prefix := range externalPrefixes {
		if strings.Contains(html, prefix) {
			t.Errorf("HTML report contains external script/style reference: %q", prefix)
		}
	}
	// Must contain basic structural elements.
	if !strings.Contains(html, "<html") {
		t.Error("HTML output missing <html> tag")
	}
	if !strings.Contains(html, "</html>") {
		t.Error("HTML output missing closing </html> tag")
	}
}

// ---------------------------------------------------------------------------
// 9. Table: PQC badge rendered for PQC findings, absent for classical
// ---------------------------------------------------------------------------

func TestTable_PQCBadge(t *testing.T) {
	classical := findings.UnifiedFinding{
		Location:     findings.Location{File: "/main.go", Line: 1},
		Algorithm:    &findings.Algorithm{Name: "RSA", KeySize: 2048},
		SourceEngine: "cipherscope",
		PQCPresent:   false,
	}
	pqc := makePQCFinding()

	var buf bytes.Buffer
	result := sophMakeResult([]findings.UnifiedFinding{classical, pqc})
	if err := WriteTable(&buf, result); err != nil {
		t.Fatalf("WriteTable error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "[PQC]") {
		t.Error("table output missing [PQC] badge for PQC finding")
	}
}

// ---------------------------------------------------------------------------
// 10. SARIF: handshakeVolumeClass and handshakeBytes in properties
// ---------------------------------------------------------------------------

func TestSARIF_HandshakeVolumeFields(t *testing.T) {
	f := makeECHFinding()
	buf := writeSARIFFor(t, []findings.UnifiedFinding{f}, "/project")
	result := sarifResultFor(t, &buf)

	props, _ := result["properties"].(map[string]interface{})
	if _, ok := props["handshakeVolumeClass"]; !ok {
		t.Error("SARIF properties missing handshakeVolumeClass")
	}
	if _, ok := props["handshakeBytes"]; !ok {
		t.Error("SARIF properties missing handshakeBytes")
	}
}

// ---------------------------------------------------------------------------
// 11. CBOM: negotiatedGroupName property name (Sprint 2 rename)
// ---------------------------------------------------------------------------

func TestCBOM_NegotiatedGroupNameProperty(t *testing.T) {
	f := makePQCFinding()
	result := sophMakeResult([]findings.UnifiedFinding{f})
	var buf bytes.Buffer
	if err := WriteCBOM(&buf, result); err != nil {
		t.Fatalf("WriteCBOM error: %v", err)
	}

	raw := buf.String()
	// Must use the Sprint-2 renamed property key.
	if !strings.Contains(raw, "oqs:negotiatedGroupName") {
		t.Error("CBOM missing oqs:negotiatedGroupName property (Sprint 2 rename from oqs:negotiatedGroup)")
	}
}

// ---------------------------------------------------------------------------
// 12. WriteJSON / WriteSARIF / WriteCBOM: no error on empty findings
// ---------------------------------------------------------------------------

func TestAllWriters_EmptyFindings_NoError(t *testing.T) {
	result := sophMakeResult(nil)

	writers := []struct {
		name string
		fn   func(*bytes.Buffer) error
	}{
		{"JSON", func(b *bytes.Buffer) error { return WriteJSON(b, result) }},
		{"SARIF", func(b *bytes.Buffer) error { return WriteSARIF(b, result) }},
		{"CBOM", func(b *bytes.Buffer) error { return WriteCBOM(b, result) }},
		{"CSV", func(b *bytes.Buffer) error { return WriteCSV(b, result) }},
		{"HTML", func(b *bytes.Buffer) error { return WriteHTML(b, result) }},
	}

	for _, w := range writers {
		var buf bytes.Buffer
		if err := w.fn(&buf); err != nil {
			t.Errorf("%s writer returned error on empty findings: %v", w.name, err)
		}
		if buf.Len() == 0 {
			t.Errorf("%s writer produced zero bytes for empty findings", w.name)
		}
	}
}
