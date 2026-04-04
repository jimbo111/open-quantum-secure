package output

// integration_test.go — end-to-end tests for the full scanner output pipeline.
//
// Each test drives findings through BuildResult and then through every output
// writer (JSON, Table, SARIF, CBOM), asserting structural correctness and
// value accuracy.  Tests are intentionally kept in the same package so that
// internal SARIF/CBOM types can be inspected directly after unmarshalling.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// ---------------------------------------------------------------------------
// Shared test fixture
// ---------------------------------------------------------------------------

// makeTestFindings returns a realistic, diverse set of findings that exercises
// every QuantumRisk category, both algorithm and dependency finding types, a
// corroborated finding, and a PQC-safe algorithm.
//
// Composition (7 findings):
//   - RSA-2048      algorithm  quantum-vulnerable  critical   (no corroboration)
//   - AES-256-GCM   algorithm  quantum-resistant   info
//   - ML-KEM-768    algorithm  quantum-safe        info
//   - openssl        dependency quantum-unknown     medium
//   - SHA-1         algorithm  deprecated          high
//   - AES-128-CBC   algorithm  quantum-weakened    low
//   - RSA-2048      algorithm  quantum-vulnerable  critical   corroborated by cryptoscan
func makeTestFindings() []findings.UnifiedFinding {
	return []findings.UnifiedFinding{
		{
			Location:     findings.Location{File: "/repo/src/auth/login.go", Line: 42, Column: 8},
			Algorithm:    &findings.Algorithm{Name: "RSA-2048", Primitive: "asymmetric", KeySize: 2048},
			Confidence:   findings.ConfidenceHigh,
			SourceEngine: "cipherscope",
			Reachable:    findings.ReachableYes,
			QuantumRisk:  findings.QRVulnerable,
			Severity:     findings.SevCritical,
			Recommendation: "Replace with ML-KEM-768 or X25519 for key exchange",
		},
		{
			Location:     findings.Location{File: "/repo/src/crypto/symmetric.go", Line: 17, Column: 4},
			Algorithm:    &findings.Algorithm{Name: "AES-256-GCM", Primitive: "ae", KeySize: 256, Mode: "GCM"},
			Confidence:   findings.ConfidenceMedium,
			SourceEngine: "cipherscope",
			Reachable:    findings.ReachableYes,
			QuantumRisk:  findings.QRResistant,
			Severity:     findings.SevInfo,
		},
		{
			Location:     findings.Location{File: "/repo/src/crypto/pqc.go", Line: 9, Column: 2},
			Algorithm:    &findings.Algorithm{Name: "ML-KEM-768", Primitive: "kem"},
			Confidence:   findings.ConfidenceHigh,
			SourceEngine: "cipherscope",
			Reachable:    findings.ReachableYes,
			QuantumRisk:  findings.QRSafe,
			Severity:     findings.SevInfo,
		},
		{
			Location:     findings.Location{File: "/repo/go.sum", Line: 1, Column: 0},
			Dependency:   &findings.Dependency{Library: "openssl"},
			Confidence:   findings.ConfidenceMedium,
			SourceEngine: "cipherscope",
			Reachable:    findings.ReachableUnknown,
			QuantumRisk:  findings.QRUnknown,
		},
		{
			Location:     findings.Location{File: "/repo/src/legacy/digest.go", Line: 88, Column: 12},
			Algorithm:    &findings.Algorithm{Name: "SHA-1", Primitive: "hash"},
			Confidence:   findings.ConfidenceHigh,
			SourceEngine: "cipherscope",
			Reachable:    findings.ReachableYes,
			QuantumRisk:  findings.QRDeprecated,
			Severity:     findings.SevHigh,
			Recommendation: "Migrate to SHA-256 or SHA-3",
		},
		{
			Location:     findings.Location{File: "/repo/src/legacy/cipher.go", Line: 33, Column: 6},
			Algorithm:    &findings.Algorithm{Name: "AES-128-CBC", Primitive: "symmetric", KeySize: 128, Mode: "CBC"},
			Confidence:   findings.ConfidenceMedium,
			SourceEngine: "cipherscope",
			Reachable:    findings.ReachableYes,
			QuantumRisk:  findings.QRWeakened,
			Severity:     findings.SevLow,
		},
		{
			Location:       findings.Location{File: "/repo/src/tls/handshake.go", Line: 210, Column: 16},
			Algorithm:      &findings.Algorithm{Name: "RSA-2048", Primitive: "asymmetric", KeySize: 2048},
			Confidence:     findings.ConfidenceHigh,
			SourceEngine:   "cipherscope",
			CorroboratedBy: []string{"cryptoscan"},
			Reachable:      findings.ReachableYes,
			QuantumRisk:    findings.QRVulnerable,
			Severity:       findings.SevCritical,
			Recommendation: "Replace with ML-KEM-768 or X25519 for key exchange",
		},
	}
}

// ---------------------------------------------------------------------------
// 1. BuildResult summary calculation
// ---------------------------------------------------------------------------

func TestIntegration_BuildResult_SummaryCalculation(t *testing.T) {
	ff := makeTestFindings()
	result := BuildResult("1.0.0", "/repo", []string{"cipherscope", "cryptoscan"}, ff)

	s := result.Summary

	// Total
	if s.TotalFindings != 7 {
		t.Errorf("TotalFindings = %d, want 7", s.TotalFindings)
	}

	// Type split: 6 algorithms + 1 dependency
	if s.Algorithms != 6 {
		t.Errorf("Algorithms = %d, want 6", s.Algorithms)
	}
	if s.Dependencies != 1 {
		t.Errorf("Dependencies = %d, want 1", s.Dependencies)
	}

	// QuantumRisk breakdown:
	//   quantum-vulnerable: RSA-2048 (uncorroborated) + RSA-2048 (corroborated) = 2
	if s.QuantumVulnerable != 2 {
		t.Errorf("QuantumVulnerable = %d, want 2", s.QuantumVulnerable)
	}
	//   quantum-weakened: AES-128-CBC = 1
	if s.QuantumWeakened != 1 {
		t.Errorf("QuantumWeakened = %d, want 1", s.QuantumWeakened)
	}
	//   quantum-safe: ML-KEM-768 = 1
	if s.QuantumSafe != 1 {
		t.Errorf("QuantumSafe = %d, want 1", s.QuantumSafe)
	}
	//   deprecated: SHA-1 = 1
	if s.Deprecated != 1 {
		t.Errorf("Deprecated = %d, want 1", s.Deprecated)
	}

	// Corroborated: only the second RSA-2048 has CorroboratedBy set
	if s.Corroborated != 1 {
		t.Errorf("Corroborated = %d, want 1", s.Corroborated)
	}

	// Version and target pass through
	if result.Version != "1.0.0" {
		t.Errorf("Version = %q, want 1.0.0", result.Version)
	}
	if result.Target != "/repo" {
		t.Errorf("Target = %q, want /repo", result.Target)
	}
}

// ---------------------------------------------------------------------------
// 2. BuildResult QRS calculation
// ---------------------------------------------------------------------------

func TestIntegration_BuildResult_QRSIsCalculated(t *testing.T) {
	ff := makeTestFindings()
	result := BuildResult("1.0.0", "/repo", []string{"cipherscope"}, ff)

	if result.QRS == nil {
		t.Fatal("QRS must not be nil for non-empty findings")
	}

	// The fixture has 2 vulnerable (one corroborated), 1 weakened, 1 deprecated, 1 safe.
	// Expected math:
	//   RSA-2048 uncorr: -2.0 * 1.0 = -2.0
	//   RSA-2048 corr:   -2.0 * 1.5 = -3.0
	//   SHA-1 deprecated: -1.5 * 1.0 = -1.5
	//   AES-128-CBC weakened: -0.5 * 1.0 = -0.5
	//   ML-KEM-768 safe: +0.5
	//   Total delta = -2.0 - 3.0 - 1.5 - 0.5 + 0.5 = -6.5 → raw 93.5
	//   math.Round(93.5) = 94 (Go rounds half away from zero) → Grade A
	if result.QRS.Score < 0 || result.QRS.Score > 100 {
		t.Errorf("QRS.Score = %d out of [0,100]", result.QRS.Score)
	}
	if result.QRS.Grade == "" {
		t.Error("QRS.Grade must not be empty")
	}
	validGrades := map[string]bool{"A+": true, "A": true, "B": true, "C": true, "D": true, "F": true}
	if !validGrades[result.QRS.Grade] {
		t.Errorf("QRS.Grade = %q is not a recognised grade", result.QRS.Grade)
	}

	// With our fixture the grade must be A (score 94; 93.5 rounds up)
	if result.QRS.Score != 94 {
		t.Errorf("QRS.Score = %d, want 94 for fixture findings", result.QRS.Score)
	}
	if result.QRS.Grade != "A" {
		t.Errorf("QRS.Grade = %q, want A", result.QRS.Grade)
	}
}

// ---------------------------------------------------------------------------
// 3a. All four formats from the same input — JSON
// ---------------------------------------------------------------------------

func TestIntegration_AllFormats_JSON(t *testing.T) {
	ff := makeTestFindings()
	result := BuildResult("1.0.0", "/repo", []string{"cipherscope", "cryptoscan"}, ff)

	var buf bytes.Buffer
	if err := WriteJSON(&buf, result); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	// Must be valid JSON
	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("JSON output is not valid JSON: %v", err)
	}

	// Top-level structural fields
	for _, key := range []string{"version", "target", "engines", "summary", "findings", "quantumReadinessScore"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("JSON missing top-level field %q", key)
		}
	}

	// Findings array length
	findingsArr, ok := raw["findings"].([]interface{})
	if !ok {
		t.Fatal("JSON 'findings' field is not an array")
	}
	if len(findingsArr) != 7 {
		t.Errorf("JSON findings count = %d, want 7", len(findingsArr))
	}

	// Summary sub-object
	summary, ok := raw["summary"].(map[string]interface{})
	if !ok {
		t.Fatal("JSON 'summary' is not an object")
	}
	assertJSONInt(t, summary, "totalFindings", 7)
	assertJSONInt(t, summary, "algorithms", 6)
	assertJSONInt(t, summary, "dependencies", 1)
	assertJSONInt(t, summary, "quantumVulnerable", 2)
	assertJSONInt(t, summary, "quantumSafe", 1)
	assertJSONInt(t, summary, "deprecated", 1)
	assertJSONInt(t, summary, "quantumWeakened", 1)
	assertJSONInt(t, summary, "corroborated", 1)

	// QRS is present with score and grade
	qrs, ok := raw["quantumReadinessScore"].(map[string]interface{})
	if !ok {
		t.Fatal("JSON 'quantumReadinessScore' is not an object")
	}
	if _, ok := qrs["score"]; !ok {
		t.Error("QRS missing 'score'")
	}
	if _, ok := qrs["grade"]; !ok {
		t.Error("QRS missing 'grade'")
	}

	// Round-trip: unmarshal into typed ScanResult
	var typed ScanResult
	if err := json.Unmarshal(buf.Bytes(), &typed); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	if typed.Summary.TotalFindings != 7 {
		t.Errorf("round-trip TotalFindings = %d, want 7", typed.Summary.TotalFindings)
	}
	if len(typed.Findings) != 7 {
		t.Errorf("round-trip Findings len = %d, want 7", len(typed.Findings))
	}
}

// ---------------------------------------------------------------------------
// 3b. All four formats from the same input — Table
// ---------------------------------------------------------------------------

func TestIntegration_AllFormats_Table(t *testing.T) {
	ff := makeTestFindings()
	result := BuildResult("1.0.0", "/repo", []string{"cipherscope", "cryptoscan"}, ff)

	var buf bytes.Buffer
	if err := WriteTable(&buf, result); err != nil {
		t.Fatalf("WriteTable: %v", err)
	}

	out := buf.String()

	// Header columns
	for _, col := range []string{"TYPE", "IDENTIFIER", "FILE", "LINE"} {
		if !strings.Contains(out, col) {
			t.Errorf("table missing column header %q", col)
		}
	}

	// Version and target in title line
	if !strings.Contains(out, "1.0.0") {
		t.Error("table missing version 1.0.0")
	}

	// Algorithm names from fixtures
	for _, name := range []string{"RSA-2048", "AES-256-GCM", "ML-KEM-768", "SHA-1", "AES-128-CBC"} {
		if !strings.Contains(out, name) {
			t.Errorf("table missing algorithm %q", name)
		}
	}

	// Dependency name
	if !strings.Contains(out, "openssl") {
		t.Error("table missing dependency openssl")
	}

	// Quantum risk badges
	if !strings.Contains(out, "[QV]") {
		t.Error("table missing quantum-vulnerable badge [QV]")
	}
	if !strings.Contains(out, "[QR]") {
		t.Error("table missing quantum-resistant badge [QR]")
	}
	if !strings.Contains(out, "[QS]") {
		t.Error("table missing quantum-safe badge [QS]")
	}
	if !strings.Contains(out, "[DEP]") {
		t.Error("table missing deprecated badge [DEP]")
	}
	if !strings.Contains(out, "[QW]") {
		t.Error("table missing quantum-weakened badge [QW]")
	}

	// Corroboration marker for the second RSA-2048 finding
	if !strings.Contains(out, "[+cryptoscan]") {
		t.Error("table missing corroboration marker [+cryptoscan]")
	}

	// Summary line with totals
	if !strings.Contains(out, "Total: 7 findings") {
		t.Errorf("table missing summary line, got:\n%s", out)
	}

	// QRS line
	if !strings.Contains(out, "Quantum Readiness Score:") {
		t.Error("table missing Quantum Readiness Score line")
	}
}

// ---------------------------------------------------------------------------
// 3c. All four formats from the same input — SARIF
// ---------------------------------------------------------------------------

func TestIntegration_AllFormats_SARIF(t *testing.T) {
	ff := makeTestFindings()
	result := BuildResult("1.0.0", "/repo", []string{"cipherscope", "cryptoscan"}, ff)

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, result); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	// Must be valid JSON
	if !json.Valid(buf.Bytes()) {
		t.Fatal("SARIF output is not valid JSON")
	}

	// Unmarshal into typed struct for deep inspection
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("unmarshal SARIF: %v", err)
	}

	// SARIF 2.1.0 envelope
	if log.Version != "2.1.0" {
		t.Errorf("SARIF version = %q, want 2.1.0", log.Version)
	}
	if !strings.Contains(log.Schema, "sarif") {
		t.Errorf("SARIF $schema = %q does not reference sarif", log.Schema)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("SARIF runs count = %d, want 1", len(log.Runs))
	}

	run := log.Runs[0]

	// Tool driver
	if run.Tool.Driver.Name != "oqs-scanner" {
		t.Errorf("driver.name = %q, want oqs-scanner", run.Tool.Driver.Name)
	}
	if run.Tool.Driver.Version != "1.0.0" {
		t.Errorf("driver.version = %q, want 1.0.0", run.Tool.Driver.Version)
	}

	// Unique rules: RSA-2048, AES-256-GCM, ML-KEM-768, openssl, SHA-1, AES-128-CBC → 6 distinct keys
	if len(run.Tool.Driver.Rules) != 6 {
		t.Errorf("SARIF rules count = %d, want 6 (one per unique algorithm/dep)", len(run.Tool.Driver.Rules))
	}

	// Results: one per finding (7 total)
	if len(run.Results) != 7 {
		t.Errorf("SARIF results count = %d, want 7", len(run.Results))
	}

	// Every result must have a ruleId, level, message, and at least one location
	for i, r := range run.Results {
		if r.RuleID == "" {
			t.Errorf("result[%d] has empty ruleId", i)
		}
		if r.Level == "" {
			t.Errorf("result[%d] has empty level", i)
		}
		if r.Message.Text == "" {
			t.Errorf("result[%d] has empty message.text", i)
		}
		if len(r.Locations) == 0 {
			t.Errorf("result[%d] has no locations", i)
		}
	}

	// Critical findings map to "error" level
	errorCount := 0
	for _, r := range run.Results {
		if r.Level == "error" {
			errorCount++
		}
	}
	// Two RSA-2048 findings are SevCritical → level "error"
	if errorCount != 2 {
		t.Errorf("SARIF error-level results = %d, want 2", errorCount)
	}
}

// ---------------------------------------------------------------------------
// 3d. All four formats from the same input — CBOM
// ---------------------------------------------------------------------------

func TestIntegration_AllFormats_CBOM(t *testing.T) {
	ff := makeTestFindings()
	result := BuildResult("1.0.0", "/repo", []string{"cipherscope", "cryptoscan"}, ff)

	var buf bytes.Buffer
	if err := WriteCBOM(&buf, result); err != nil {
		t.Fatalf("WriteCBOM: %v", err)
	}

	// Must be valid JSON
	if !json.Valid(buf.Bytes()) {
		t.Fatal("CBOM output is not valid JSON")
	}

	var bom cdxBOM
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatalf("unmarshal CBOM: %v", err)
	}

	// CycloneDX 1.7 envelope
	if bom.BOMFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q, want CycloneDX", bom.BOMFormat)
	}
	if bom.SpecVersion != "1.7" {
		t.Errorf("specVersion = %q, want 1.7", bom.SpecVersion)
	}
	if !strings.HasPrefix(bom.SerialNumber, "urn:uuid:") {
		t.Errorf("serialNumber = %q, want urn:uuid:... prefix", bom.SerialNumber)
	}
	if bom.Version != 1 {
		t.Errorf("version = %d, want 1", bom.Version)
	}

	// Tool metadata
	if bom.Metadata.Tools == nil || len(bom.Metadata.Tools.Components) == 0 {
		t.Error("CBOM metadata.tools must contain the oqs-scanner tool")
	} else {
		tool := bom.Metadata.Tools.Components[0]
		if tool.Name != "oqs-scanner" {
			t.Errorf("tool.name = %q, want oqs-scanner", tool.Name)
		}
		if tool.Version != "1.0.0" {
			t.Errorf("tool.version = %q, want 1.0.0", tool.Version)
		}
	}

	// Component count:
	// Algorithm findings are grouped by (name|keySize|mode|curve):
	//   RSA-2048|2048||  — two occurrences merged into ONE component
	//   AES-256-GCM|256|GCM|
	//   ML-KEM-768|0||
	//   SHA-1|0||
	//   AES-128-CBC|128|CBC|
	// Plus 1 dependency component (openssl) = 5 algo + 1 dep = 6 components
	if len(bom.Components) != 6 {
		t.Errorf("CBOM components = %d, want 6", len(bom.Components))
	}

	// Verify the RSA-2048 component has 2 occurrences (grouped)
	for _, c := range bom.Components {
		if c.Name == "RSA-2048" {
			if c.Evidence == nil {
				t.Error("RSA-2048 component missing evidence")
			} else if len(c.Evidence.Occurrences) != 2 {
				t.Errorf("RSA-2048 occurrences = %d, want 2", len(c.Evidence.Occurrences))
			}
		}
	}

	// Dependency graph: dependencies array should reference openssl
	if len(bom.Dependencies) == 0 {
		t.Error("CBOM dependencies should not be empty when a library finding is present")
	}

	// Metadata properties include QRS
	hasQRS := false
	for _, p := range bom.Metadata.Properties {
		if p.Name == "oqs:quantumReadinessScore" {
			hasQRS = true
			break
		}
	}
	if !hasQRS {
		t.Error("CBOM metadata missing oqs:quantumReadinessScore property")
	}
}

// ---------------------------------------------------------------------------
// 3e. All five formats from the same input — HTML
// ---------------------------------------------------------------------------

func TestIntegration_AllFormats_HTML(t *testing.T) {
	ff := makeTestFindings()
	result := BuildResult("1.0.0", "/repo", []string{"cipherscope", "cryptoscan"}, ff)

	var buf bytes.Buffer
	if err := WriteHTML(&buf, result); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}

	out := buf.String()

	// Must contain HTML structure
	if !strings.Contains(out, "<!DOCTYPE html>") {
		t.Error("HTML missing DOCTYPE")
	}
	if !strings.Contains(out, "OQS Scanner Report") {
		t.Error("HTML missing report title")
	}

	// Algorithm names from fixtures
	for _, name := range []string{"RSA-2048", "AES-256-GCM", "ML-KEM-768", "SHA-1", "AES-128-CBC"} {
		if !strings.Contains(out, name) {
			t.Errorf("HTML missing algorithm %q", name)
		}
	}

	// Dependency name
	if !strings.Contains(out, "openssl") {
		t.Error("HTML missing dependency openssl")
	}

	// QRS score must be displayed
	if !strings.Contains(out, "Quantum Readiness Score") {
		t.Error("HTML missing QRS section")
	}

	// Recommendation field rendered for RSA-2048
	if !strings.Contains(out, "ML-KEM-768") {
		t.Error("HTML missing recommendation text")
	}

	// Version displayed
	if !strings.Contains(out, "1.0.0") {
		t.Error("HTML missing version")
	}
}

// ---------------------------------------------------------------------------
// 3f. HTML with DataFlowPath — integration test for Tier 2 flow data
// ---------------------------------------------------------------------------

func TestIntegration_HTML_DataFlowPath(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:     findings.Location{File: "/src/crypto.go", Line: 10},
			Algorithm:    &findings.Algorithm{Name: "RSA-2048", Primitive: "asymmetric"},
			Confidence:   findings.ConfidenceHigh,
			SourceEngine: "semgrep",
			QuantumRisk:  findings.QRVulnerable,
			Severity:     findings.SevCritical,
			Reachable:    findings.ReachableYes,
			DataFlowPath: []findings.FlowStep{
				{File: "/src/crypto.go", Line: 5, Message: "key generated here"},
				{File: "/src/crypto.go", Line: 10, Message: "key used for signing"},
			},
		},
	}
	result := BuildResult("1.0.0", "/src", []string{"semgrep"}, ff)

	var buf bytes.Buffer
	if err := WriteHTML(&buf, result); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}

	out := buf.String()

	// DataFlowPath rendered as collapsible details
	if !strings.Contains(out, "data flow") {
		t.Error("HTML missing data flow section")
	}
	if !strings.Contains(out, "2 steps") {
		t.Error("HTML missing step count")
	}
	if !strings.Contains(out, "key generated here") {
		t.Error("HTML missing flow step message")
	}
}

// ---------------------------------------------------------------------------
// 4. Empty findings through all formats
// ---------------------------------------------------------------------------

func TestIntegration_EmptyFindings_AllFormats(t *testing.T) {
	result := BuildResult("1.0.0", "/repo", []string{"cipherscope"}, nil)

	// --- JSON ---
	var jsonBuf bytes.Buffer
	if err := WriteJSON(&jsonBuf, result); err != nil {
		t.Fatalf("WriteJSON(empty): %v", err)
	}
	if !json.Valid(jsonBuf.Bytes()) {
		t.Fatal("WriteJSON(empty): output is not valid JSON")
	}
	var jsonParsed map[string]interface{}
	if err := json.Unmarshal(jsonBuf.Bytes(), &jsonParsed); err != nil {
		t.Fatalf("WriteJSON(empty) unmarshal: %v", err)
	}
	// "findings" field must be present; it may be null or an empty array when
	// no findings were provided — both are valid representations of zero findings.
	findingsVal, ok := jsonParsed["findings"]
	if !ok {
		t.Error("WriteJSON(empty): missing 'findings' field")
	}
	switch v := findingsVal.(type) {
	case nil:
		// JSON null — acceptable for a nil slice
	case []interface{}:
		if len(v) != 0 {
			t.Errorf("WriteJSON(empty): findings length = %d, want 0", len(v))
		}
	default:
		t.Errorf("WriteJSON(empty): 'findings' has unexpected type %T", findingsVal)
	}
	// QRS must be A+ / 100 for empty input
	if qrs, ok := jsonParsed["quantumReadinessScore"].(map[string]interface{}); ok {
		if score, ok := qrs["score"].(float64); !ok || int(score) != 100 {
			t.Errorf("WriteJSON(empty): QRS score = %v, want 100", qrs["score"])
		}
		if grade, ok := qrs["grade"].(string); !ok || grade != "A+" {
			t.Errorf("WriteJSON(empty): QRS grade = %v, want A+", qrs["grade"])
		}
	} else {
		t.Error("WriteJSON(empty): missing quantumReadinessScore")
	}

	// --- Table ---
	var tableBuf bytes.Buffer
	if err := WriteTable(&tableBuf, result); err != nil {
		t.Fatalf("WriteTable(empty): %v", err)
	}
	tableOut := tableBuf.String()
	if tableOut == "" {
		t.Error("WriteTable(empty): output must not be empty")
	}
	if !strings.Contains(tableOut, "No findings") {
		t.Errorf("WriteTable(empty): expected 'No findings' message, got: %q", tableOut)
	}

	// --- SARIF ---
	var sarifBuf bytes.Buffer
	if err := WriteSARIF(&sarifBuf, result); err != nil {
		t.Fatalf("WriteSARIF(empty): %v", err)
	}
	if !json.Valid(sarifBuf.Bytes()) {
		t.Fatal("WriteSARIF(empty): not valid JSON")
	}
	var sarifParsed sarifLog
	if err := json.Unmarshal(sarifBuf.Bytes(), &sarifParsed); err != nil {
		t.Fatalf("WriteSARIF(empty) unmarshal: %v", err)
	}
	if sarifParsed.Version != "2.1.0" {
		t.Errorf("WriteSARIF(empty): version = %q, want 2.1.0", sarifParsed.Version)
	}
	if len(sarifParsed.Runs) != 1 {
		t.Errorf("WriteSARIF(empty): runs count = %d, want 1", len(sarifParsed.Runs))
	}
	// Results should be nil or empty — not an error
	if n := len(sarifParsed.Runs[0].Results); n != 0 {
		t.Errorf("WriteSARIF(empty): results count = %d, want 0", n)
	}

	// --- CBOM ---
	var cbomBuf bytes.Buffer
	if err := WriteCBOM(&cbomBuf, result); err != nil {
		t.Fatalf("WriteCBOM(empty): %v", err)
	}
	if !json.Valid(cbomBuf.Bytes()) {
		t.Fatal("WriteCBOM(empty): not valid JSON")
	}
	var bomParsed cdxBOM
	if err := json.Unmarshal(cbomBuf.Bytes(), &bomParsed); err != nil {
		t.Fatalf("WriteCBOM(empty) unmarshal: %v", err)
	}
	if bomParsed.BOMFormat != "CycloneDX" {
		t.Errorf("WriteCBOM(empty): bomFormat = %q", bomParsed.BOMFormat)
	}
	if len(bomParsed.Components) != 0 {
		t.Errorf("WriteCBOM(empty): components = %d, want 0", len(bomParsed.Components))
	}

	// --- HTML ---
	var htmlBuf bytes.Buffer
	if err := WriteHTML(&htmlBuf, result); err != nil {
		t.Fatalf("WriteHTML(empty): %v", err)
	}
	htmlOut := htmlBuf.String()
	if !strings.Contains(htmlOut, "<!DOCTYPE html>") {
		t.Error("WriteHTML(empty): missing DOCTYPE")
	}
	if !strings.Contains(htmlOut, "No findings detected") {
		t.Errorf("WriteHTML(empty): expected 'No findings detected' message")
	}
}

// ---------------------------------------------------------------------------
// 5. Corroborated findings through all formats
// ---------------------------------------------------------------------------

func TestIntegration_Corroborated_AllFormats(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:       findings.Location{File: "/src/tls.go", Line: 50, Column: 4},
			Algorithm:      &findings.Algorithm{Name: "RSA-2048", Primitive: "asymmetric", KeySize: 2048},
			Confidence:     findings.ConfidenceHigh,
			SourceEngine:   "cipherscope",
			CorroboratedBy: []string{"cryptoscan", "semgrep"},
			Reachable:      findings.ReachableYes,
			QuantumRisk:    findings.QRVulnerable,
			Severity:       findings.SevCritical,
		},
	}
	result := BuildResult("1.0.0", "/src", []string{"cipherscope", "cryptoscan", "semgrep"}, ff)

	if result.Summary.Corroborated != 1 {
		t.Fatalf("Corroborated = %d, want 1", result.Summary.Corroborated)
	}

	// JSON: corroboratedBy array must be present on the finding
	var jsonBuf bytes.Buffer
	if err := WriteJSON(&jsonBuf, result); err != nil {
		t.Fatalf("WriteJSON(corr): %v", err)
	}
	jsonStr := jsonBuf.String()
	if !strings.Contains(jsonStr, "corroboratedBy") {
		t.Error("JSON: missing 'corroboratedBy' field in corroborated finding")
	}
	if !strings.Contains(jsonStr, "cryptoscan") {
		t.Error("JSON: missing corroborating engine 'cryptoscan'")
	}
	if !strings.Contains(jsonStr, "semgrep") {
		t.Error("JSON: missing corroborating engine 'semgrep'")
	}

	// Table: corroboration marker must appear
	var tableBuf bytes.Buffer
	if err := WriteTable(&tableBuf, result); err != nil {
		t.Fatalf("WriteTable(corr): %v", err)
	}
	tableStr := tableBuf.String()
	if !strings.Contains(tableStr, "[+") {
		t.Error("Table: missing corroboration marker")
	}
	if !strings.Contains(tableStr, "cryptoscan") {
		t.Error("Table: missing engine name in corroboration marker")
	}

	// SARIF: message must mention confirming engines
	var sarifBuf bytes.Buffer
	if err := WriteSARIF(&sarifBuf, result); err != nil {
		t.Fatalf("WriteSARIF(corr): %v", err)
	}
	sarifStr := sarifBuf.String()
	if !strings.Contains(sarifStr, "confirmed by") {
		t.Error("SARIF: message should contain 'confirmed by' for corroborated finding")
	}
	if !strings.Contains(sarifStr, "cryptoscan") {
		t.Error("SARIF: message should contain corroborating engine 'cryptoscan'")
	}

	// CBOM: sources must include all engines
	var cbomBuf bytes.Buffer
	if err := WriteCBOM(&cbomBuf, result); err != nil {
		t.Fatalf("WriteCBOM(corr): %v", err)
	}
	cbomStr := cbomBuf.String()
	// The oqs:source property is set to "cipherscope+cryptoscan+semgrep" (joined with +)
	if !strings.Contains(cbomStr, "cipherscope") {
		t.Error("CBOM: source should contain 'cipherscope'")
	}
	if !strings.Contains(cbomStr, "cryptoscan") {
		t.Error("CBOM: source should contain 'cryptoscan'")
	}
}

// ---------------------------------------------------------------------------
// 6. QuantumRisk distribution
// ---------------------------------------------------------------------------

func TestIntegration_QuantumRisk_Distribution(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{Algorithm: &findings.Algorithm{Name: "RSA-2048"}, QuantumRisk: findings.QRVulnerable, Severity: findings.SevCritical},
		{Algorithm: &findings.Algorithm{Name: "RSA-4096"}, QuantumRisk: findings.QRVulnerable, Severity: findings.SevHigh},
		{Algorithm: &findings.Algorithm{Name: "RSA-8192"}, QuantumRisk: findings.QRVulnerable, Severity: findings.SevMedium},
		{Algorithm: &findings.Algorithm{Name: "AES-128"}, QuantumRisk: findings.QRWeakened, Severity: findings.SevLow},
		{Algorithm: &findings.Algorithm{Name: "AES-192"}, QuantumRisk: findings.QRWeakened, Severity: findings.SevLow},
		{Algorithm: &findings.Algorithm{Name: "ML-KEM-512"}, QuantumRisk: findings.QRSafe, Severity: findings.SevInfo},
		{Algorithm: &findings.Algorithm{Name: "ML-KEM-768"}, QuantumRisk: findings.QRSafe, Severity: findings.SevInfo},
		{Algorithm: &findings.Algorithm{Name: "ML-KEM-1024"}, QuantumRisk: findings.QRSafe, Severity: findings.SevInfo},
		{Algorithm: &findings.Algorithm{Name: "MD5"}, QuantumRisk: findings.QRDeprecated, Severity: findings.SevCritical},
		{Algorithm: &findings.Algorithm{Name: "SHA-1"}, QuantumRisk: findings.QRDeprecated, Severity: findings.SevHigh},
		{Dependency: &findings.Dependency{Library: "libcrypto"}, QuantumRisk: findings.QRUnknown},
	}

	result := BuildResult("1.0.0", "/target", []string{"cipherscope"}, ff)
	s := result.Summary

	if s.TotalFindings != 11 {
		t.Errorf("TotalFindings = %d, want 11", s.TotalFindings)
	}
	if s.QuantumVulnerable != 3 {
		t.Errorf("QuantumVulnerable = %d, want 3", s.QuantumVulnerable)
	}
	if s.QuantumWeakened != 2 {
		t.Errorf("QuantumWeakened = %d, want 2", s.QuantumWeakened)
	}
	if s.QuantumSafe != 3 {
		t.Errorf("QuantumSafe = %d, want 3", s.QuantumSafe)
	}
	if s.Deprecated != 2 {
		t.Errorf("Deprecated = %d, want 2", s.Deprecated)
	}
	// QRUnknown and QRResistant are not counted in any summary bucket;
	// verify the counts above add up correctly
	accounted := s.QuantumVulnerable + s.QuantumWeakened + s.QuantumSafe + s.Deprecated
	if accounted != 10 {
		t.Errorf("accounted risk categories = %d, want 10 (unknown/resistant excluded)", accounted)
	}

	// Verify JSON output reflects these counts
	var buf bytes.Buffer
	if err := WriteJSON(&buf, result); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var parsed struct {
		Summary Summary `json:"summary"`
	}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if parsed.Summary.QuantumVulnerable != 3 {
		t.Errorf("JSON summary.quantumVulnerable = %d, want 3", parsed.Summary.QuantumVulnerable)
	}
	if parsed.Summary.QuantumSafe != 3 {
		t.Errorf("JSON summary.quantumSafe = %d, want 3", parsed.Summary.QuantumSafe)
	}
	if parsed.Summary.Deprecated != 2 {
		t.Errorf("JSON summary.deprecated = %d, want 2", parsed.Summary.Deprecated)
	}
}

// ---------------------------------------------------------------------------
// 7. WithDuration option
// ---------------------------------------------------------------------------

func TestIntegration_WithDuration(t *testing.T) {
	d := 4*time.Minute + 30*time.Second + 250*time.Millisecond
	result := BuildResult("1.0.0", "/repo", []string{"cipherscope"}, makeTestFindings(), WithDuration(d))

	// ScanResult field
	if result.ScanDuration == "" {
		t.Fatal("ScanDuration must not be empty when WithDuration is used")
	}
	// Duration rounded to millisecond: "4m30.25s"
	if !strings.Contains(result.ScanDuration, "4m") {
		t.Errorf("ScanDuration = %q, want to contain '4m'", result.ScanDuration)
	}

	// JSON output must include scanDuration field
	var jsonBuf bytes.Buffer
	if err := WriteJSON(&jsonBuf, result); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(jsonBuf.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	dur, ok := raw["scanDuration"].(string)
	if !ok || dur == "" {
		t.Errorf("JSON scanDuration = %v, want non-empty string", raw["scanDuration"])
	}
	if !strings.Contains(dur, "4m") {
		t.Errorf("JSON scanDuration = %q, want to contain '4m'", dur)
	}

	// Table output should not break when duration is set
	var tableBuf bytes.Buffer
	if err := WriteTable(&tableBuf, result); err != nil {
		t.Fatalf("WriteTable with duration: %v", err)
	}

	// Millisecond rounding: 0ms duration
	zeroResult := BuildResult("1.0.0", "/repo", []string{"cs"}, nil, WithDuration(0))
	if zeroResult.ScanDuration != "0s" {
		t.Errorf("WithDuration(0) = %q, want 0s", zeroResult.ScanDuration)
	}

	// Sub-millisecond duration rounds to nearest ms
	subMsResult := BuildResult("1.0.0", "/repo", []string{"cs"}, nil, WithDuration(500*time.Microsecond))
	if subMsResult.ScanDuration != "1ms" {
		t.Errorf("WithDuration(500µs) = %q, want 1ms (rounded)", subMsResult.ScanDuration)
	}
}

// ---------------------------------------------------------------------------
// 8. Large finding set — no performance/memory issues
// ---------------------------------------------------------------------------

func TestIntegration_LargeFindingSet(t *testing.T) {
	const count = 120
	ff := make([]findings.UnifiedFinding, count)
	for i := 0; i < count; i++ {
		switch i % 4 {
		case 0:
			ff[i] = findings.UnifiedFinding{
				Location:     findings.Location{File: fmt.Sprintf("/src/file%d.go", i), Line: i + 1},
				Algorithm:    &findings.Algorithm{Name: fmt.Sprintf("RSA-%d", 1024+i*256), Primitive: "asymmetric", KeySize: 1024 + i*256},
				Confidence:   findings.ConfidenceHigh,
				SourceEngine: "cipherscope",
				QuantumRisk:  findings.QRVulnerable,
				Severity:     findings.SevHigh,
			}
		case 1:
			ff[i] = findings.UnifiedFinding{
				Location:     findings.Location{File: fmt.Sprintf("/src/file%d.go", i), Line: i + 1},
				Algorithm:    &findings.Algorithm{Name: "AES-256-GCM", Primitive: "ae", KeySize: 256, Mode: "GCM"},
				Confidence:   findings.ConfidenceMedium,
				SourceEngine: "cryptoscan",
				QuantumRisk:  findings.QRResistant,
				Severity:     findings.SevInfo,
			}
		case 2:
			ff[i] = findings.UnifiedFinding{
				Location:     findings.Location{File: fmt.Sprintf("/src/file%d.go", i), Line: i + 1},
				Algorithm:    &findings.Algorithm{Name: "ML-KEM-768", Primitive: "kem"},
				Confidence:   findings.ConfidenceHigh,
				SourceEngine: "cipherscope",
				QuantumRisk:  findings.QRSafe,
				Severity:     findings.SevInfo,
			}
		case 3:
			ff[i] = findings.UnifiedFinding{
				Location:     findings.Location{File: fmt.Sprintf("/src/file%d.go", i), Line: i + 1},
				Dependency:   &findings.Dependency{Library: fmt.Sprintf("lib%d", i)},
				Confidence:   findings.ConfidenceLow,
				SourceEngine: "cipherscope",
				QuantumRisk:  findings.QRUnknown,
			}
		}
	}

	result := BuildResult("1.0.0", "/src", []string{"cipherscope", "cryptoscan"}, ff)

	if result.Summary.TotalFindings != count {
		t.Errorf("TotalFindings = %d, want %d", result.Summary.TotalFindings, count)
	}

	// All five formats must succeed without error or panic
	var jsonBuf, tableBuf, sarifBuf, cbomBuf, htmlBuf bytes.Buffer

	if err := WriteJSON(&jsonBuf, result); err != nil {
		t.Errorf("WriteJSON(large): %v", err)
	}
	if !json.Valid(jsonBuf.Bytes()) {
		t.Error("WriteJSON(large): invalid JSON")
	}

	if err := WriteTable(&tableBuf, result); err != nil {
		t.Errorf("WriteTable(large): %v", err)
	}
	if tableBuf.Len() == 0 {
		t.Error("WriteTable(large): empty output")
	}

	if err := WriteSARIF(&sarifBuf, result); err != nil {
		t.Errorf("WriteSARIF(large): %v", err)
	}
	if !json.Valid(sarifBuf.Bytes()) {
		t.Error("WriteSARIF(large): invalid JSON")
	}

	if err := WriteCBOM(&cbomBuf, result); err != nil {
		t.Errorf("WriteCBOM(large): %v", err)
	}
	if !json.Valid(cbomBuf.Bytes()) {
		t.Error("WriteCBOM(large): invalid JSON")
	}

	if err := WriteHTML(&htmlBuf, result); err != nil {
		t.Errorf("WriteHTML(large): %v", err)
	}
	if htmlBuf.Len() == 0 {
		t.Error("WriteHTML(large): empty output")
	}

	// Spot-check SARIF: 120 results
	var sarifParsed sarifLog
	if err := json.Unmarshal(sarifBuf.Bytes(), &sarifParsed); err != nil {
		t.Fatalf("SARIF unmarshal(large): %v", err)
	}
	if len(sarifParsed.Runs[0].Results) != count {
		t.Errorf("SARIF results = %d, want %d", len(sarifParsed.Runs[0].Results), count)
	}
}

// ---------------------------------------------------------------------------
// 9. Special characters in algorithm names
// ---------------------------------------------------------------------------

func TestIntegration_SpecialCharacters_AlgorithmNames(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:     findings.Location{File: "/src/chacha.go", Line: 5},
			Algorithm:    &findings.Algorithm{Name: "ChaCha20-Poly1305", Primitive: "ae"},
			Confidence:   findings.ConfidenceHigh,
			SourceEngine: "cipherscope",
			QuantumRisk:  findings.QRResistant,
			Severity:     findings.SevInfo,
		},
		{
			Location:     findings.Location{File: "/src/ntru.go", Line: 12},
			Algorithm:    &findings.Algorithm{Name: "NTRU+", Primitive: "kem"},
			Confidence:   findings.ConfidenceMedium,
			SourceEngine: "cipherscope",
			QuantumRisk:  findings.QRSafe,
			Severity:     findings.SevInfo,
		},
		{
			Location:     findings.Location{File: "/src/falcon.go", Line: 22},
			Algorithm:    &findings.Algorithm{Name: "FALCON-512(padded)", Primitive: "signature"},
			Confidence:   findings.ConfidenceMedium,
			SourceEngine: "cipherscope",
			QuantumRisk:  findings.QRSafe,
			Severity:     findings.SevInfo,
		},
		{
			Location:     findings.Location{File: "/src/shake.go", Line: 3},
			Algorithm:    &findings.Algorithm{Name: "SHAKE128/256", Primitive: "xof"},
			Confidence:   findings.ConfidenceLow,
			SourceEngine: "cipherscope",
			QuantumRisk:  findings.QRSafe,
			Severity:     findings.SevInfo,
		},
	}

	result := BuildResult("1.0.0", "/src", []string{"cipherscope"}, ff)

	// JSON: all names must survive round-trip
	var jsonBuf bytes.Buffer
	if err := WriteJSON(&jsonBuf, result); err != nil {
		t.Fatalf("WriteJSON(special chars): %v", err)
	}
	if !json.Valid(jsonBuf.Bytes()) {
		t.Fatal("WriteJSON(special chars): invalid JSON")
	}
	jsonStr := jsonBuf.String()
	for _, name := range []string{"ChaCha20-Poly1305", "NTRU+", "FALCON-512(padded)", "SHAKE128/256"} {
		if !strings.Contains(jsonStr, name) {
			t.Errorf("JSON missing algorithm name %q", name)
		}
	}

	// Table: must not panic
	var tableBuf bytes.Buffer
	if err := WriteTable(&tableBuf, result); err != nil {
		t.Fatalf("WriteTable(special chars): %v", err)
	}

	// SARIF: sanitizeID must produce legal identifiers (no raw +, /, (, ))
	var sarifBuf bytes.Buffer
	if err := WriteSARIF(&sarifBuf, result); err != nil {
		t.Fatalf("WriteSARIF(special chars): %v", err)
	}
	if !json.Valid(sarifBuf.Bytes()) {
		t.Fatal("WriteSARIF(special chars): invalid JSON")
	}
	var sarifParsed sarifLog
	if err := json.Unmarshal(sarifBuf.Bytes(), &sarifParsed); err != nil {
		t.Fatalf("SARIF unmarshal(special chars): %v", err)
	}
	for _, rule := range sarifParsed.Runs[0].Tool.Driver.Rules {
		// IDs should not contain literal + or ( or )
		for _, ch := range []string{"(", ")"} {
			if strings.Contains(rule.ID, ch) {
				t.Errorf("SARIF rule ID %q contains illegal character %q", rule.ID, ch)
			}
		}
		// + should be replaced by PLUS
		if strings.Contains(rule.ID, "+") {
			t.Errorf("SARIF rule ID %q still contains literal '+'", rule.ID)
		}
	}

	// CBOM: must be valid JSON with all 4 distinct algorithm components
	var cbomBuf bytes.Buffer
	if err := WriteCBOM(&cbomBuf, result); err != nil {
		t.Fatalf("WriteCBOM(special chars): %v", err)
	}
	if !json.Valid(cbomBuf.Bytes()) {
		t.Fatal("WriteCBOM(special chars): invalid JSON")
	}
	var bom cdxBOM
	if err := json.Unmarshal(cbomBuf.Bytes(), &bom); err != nil {
		t.Fatalf("CBOM unmarshal(special chars): %v", err)
	}
	if len(bom.Components) != 4 {
		t.Errorf("CBOM components = %d, want 4", len(bom.Components))
	}
}

// ---------------------------------------------------------------------------
// 10. Unicode in file paths
// ---------------------------------------------------------------------------

func TestIntegration_UnicodePaths_AllFormats(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			// Korean characters in directory name
			Location:     findings.Location{File: "/repo/암호화/crypto.go", Line: 10, Column: 4},
			Algorithm:    &findings.Algorithm{Name: "AES-256-GCM", Primitive: "ae", KeySize: 256, Mode: "GCM"},
			Confidence:   findings.ConfidenceHigh,
			SourceEngine: "cipherscope",
			QuantumRisk:  findings.QRResistant,
			Severity:     findings.SevInfo,
		},
		{
			// Japanese characters
			Location:     findings.Location{File: "/repo/暗号/tls.go", Line: 77},
			Algorithm:    &findings.Algorithm{Name: "RSA-2048", Primitive: "asymmetric", KeySize: 2048},
			Confidence:   findings.ConfidenceHigh,
			SourceEngine: "cipherscope",
			QuantumRisk:  findings.QRVulnerable,
			Severity:     findings.SevCritical,
		},
		{
			// Emoji in path (edge case)
			Location:     findings.Location{File: "/repo/src-🔐/auth.go", Line: 5},
			Dependency:   &findings.Dependency{Library: "botan"},
			Confidence:   findings.ConfidenceMedium,
			SourceEngine: "cipherscope",
			QuantumRisk:  findings.QRUnknown,
		},
		{
			// Arabic characters
			Location:     findings.Location{File: "/repo/تشفير/hash.go", Line: 33},
			Algorithm:    &findings.Algorithm{Name: "SHA-256", Primitive: "hash"},
			Confidence:   findings.ConfidenceMedium,
			SourceEngine: "cipherscope",
			QuantumRisk:  findings.QRResistant,
			Severity:     findings.SevInfo,
		},
	}

	result := BuildResult("1.0.0", "/repo", []string{"cipherscope"}, ff)

	// JSON: unicode paths must survive encoding
	var jsonBuf bytes.Buffer
	if err := WriteJSON(&jsonBuf, result); err != nil {
		t.Fatalf("WriteJSON(unicode): %v", err)
	}
	if !json.Valid(jsonBuf.Bytes()) {
		t.Fatal("WriteJSON(unicode): invalid JSON")
	}
	// Go's json.Encoder uses unicode-safe escaping; the raw Korean/Japanese
	// characters may appear as \uXXXX escapes or literal UTF-8 — both valid.
	// Verify all four files appear after round-trip unmarshal.
	var typed ScanResult
	if err := json.Unmarshal(jsonBuf.Bytes(), &typed); err != nil {
		t.Fatalf("WriteJSON(unicode) unmarshal: %v", err)
	}
	unicodePaths := map[string]bool{
		"/repo/암호화/crypto.go": false,
		"/repo/暗号/tls.go":     false,
		"/repo/src-🔐/auth.go":  false,
		"/repo/تشفير/hash.go":   false,
	}
	for _, f := range typed.Findings {
		if _, ok := unicodePaths[f.Location.File]; ok {
			unicodePaths[f.Location.File] = true
		}
	}
	for path, found := range unicodePaths {
		if !found {
			t.Errorf("JSON round-trip lost unicode file path %q", path)
		}
	}

	// Table: must not panic on unicode paths
	var tableBuf bytes.Buffer
	if err := WriteTable(&tableBuf, result); err != nil {
		t.Fatalf("WriteTable(unicode): %v", err)
	}
	if tableBuf.Len() == 0 {
		t.Error("WriteTable(unicode): empty output")
	}

	// SARIF: must be valid JSON with 4 results
	var sarifBuf bytes.Buffer
	if err := WriteSARIF(&sarifBuf, result); err != nil {
		t.Fatalf("WriteSARIF(unicode): %v", err)
	}
	if !json.Valid(sarifBuf.Bytes()) {
		t.Fatal("WriteSARIF(unicode): invalid JSON")
	}
	var sarifParsed sarifLog
	if err := json.Unmarshal(sarifBuf.Bytes(), &sarifParsed); err != nil {
		t.Fatalf("WriteSARIF(unicode) unmarshal: %v", err)
	}
	if len(sarifParsed.Runs[0].Results) != 4 {
		t.Errorf("WriteSARIF(unicode): results = %d, want 4", len(sarifParsed.Runs[0].Results))
	}

	// CBOM: must be valid JSON with 4 components (3 algo + 1 dep)
	var cbomBuf bytes.Buffer
	if err := WriteCBOM(&cbomBuf, result); err != nil {
		t.Fatalf("WriteCBOM(unicode): %v", err)
	}
	if !json.Valid(cbomBuf.Bytes()) {
		t.Fatal("WriteCBOM(unicode): invalid JSON")
	}
	var bomParsed cdxBOM
	if err := json.Unmarshal(cbomBuf.Bytes(), &bomParsed); err != nil {
		t.Fatalf("WriteCBOM(unicode) unmarshal: %v", err)
	}
	if len(bomParsed.Components) != 4 {
		t.Errorf("WriteCBOM(unicode): components = %d, want 4", len(bomParsed.Components))
	}

	// Occurrences inside CBOM components must preserve unicode paths
	cbomStr := cbomBuf.String()
	// After json.Encoder processing the path may be escaped; unmarshal already
	// verified structure, so checking the parsed occurrences is the correct approach.
	foundUnicode := false
	for _, comp := range bomParsed.Components {
		if comp.Evidence != nil {
			for _, occ := range comp.Evidence.Occurrences {
				if strings.Contains(occ.Location, "암호화") ||
					strings.Contains(occ.Location, "暗号") ||
					strings.Contains(occ.Location, "تشفير") {
					foundUnicode = true
				}
			}
		}
	}
	if !foundUnicode {
		// Provide raw string for diagnosis
		t.Logf("CBOM output (excerpt):\n%s", cbomStr[:min(500, len(cbomStr))])
		t.Error("CBOM: unicode directory names not found in occurrence locations")
	}
}

// ---------------------------------------------------------------------------
// Helper utilities (integration test-specific)
// ---------------------------------------------------------------------------

// assertJSONInt checks that a JSON object key holds the expected integer value.
// JSON numbers decode as float64 in map[string]interface{}, so we cast accordingly.
func assertJSONInt(t *testing.T, obj map[string]interface{}, key string, want int) {
	t.Helper()
	v, ok := obj[key]
	if !ok {
		t.Errorf("JSON summary missing field %q", key)
		return
	}
	got, ok := v.(float64)
	if !ok {
		t.Errorf("JSON summary.%s is not a number (type %T, value %v)", key, v, v)
		return
	}
	if int(got) != want {
		t.Errorf("JSON summary.%s = %d, want %d", key, int(got), want)
	}
}

// min returns the smaller of two ints. Used only for safe log truncation.
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ---------------------------------------------------------------------------
// 8. PQC migration data across all output formats
// ---------------------------------------------------------------------------

// TestIntegration_MigrationAcrossFormats creates a single finding with full
// migration data (TargetAlgorithm, TargetStandard, MigrationSnippet) and
// verifies that each of JSON, SARIF, and HTML surfaces the migration fields.
func TestIntegration_MigrationAcrossFormats(t *testing.T) {
	snippet := &findings.MigrationSnippet{
		Language:    "go",
		Before:      `rsa.GenerateKey(rand.Reader, 2048)`,
		After:       `kemkem.GenerateKey()`,
		Explanation: "Replace RSA key exchange with ML-KEM-768",
	}
	ff := []findings.UnifiedFinding{
		{
			Location:        findings.Location{File: "/repo/src/auth/login.go", Line: 42, Column: 8},
			Algorithm:       &findings.Algorithm{Name: "RSA-2048", Primitive: "asymmetric", KeySize: 2048},
			Confidence:      findings.ConfidenceHigh,
			SourceEngine:    "cipherscope",
			QuantumRisk:     findings.QRVulnerable,
			Severity:        findings.SevCritical,
			TargetAlgorithm: "ML-KEM-768",
			TargetStandard:  "NIST FIPS 203",
			MigrationSnippet: snippet,
		},
	}
	result := BuildResult("1.0.0", "/repo", []string{"cipherscope"}, ff)

	// --- JSON ---
	var jsonBuf bytes.Buffer
	if err := WriteJSON(&jsonBuf, result); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if !json.Valid(jsonBuf.Bytes()) {
		t.Fatal("WriteJSON: output is not valid JSON")
	}
	var jsonParsed map[string]interface{}
	if err := json.Unmarshal(jsonBuf.Bytes(), &jsonParsed); err != nil {
		t.Fatalf("WriteJSON unmarshal: %v", err)
	}
	jsonFindings, ok := jsonParsed["findings"].([]interface{})
	if !ok || len(jsonFindings) == 0 {
		t.Fatal("JSON: findings array is missing or empty")
	}
	jf := jsonFindings[0].(map[string]interface{})
	if got, ok := jf["targetAlgorithm"].(string); !ok || got != "ML-KEM-768" {
		t.Errorf("JSON: findings[0].targetAlgorithm = %v, want ML-KEM-768", jf["targetAlgorithm"])
	}
	if got, ok := jf["targetStandard"].(string); !ok || got != "NIST FIPS 203" {
		t.Errorf("JSON: findings[0].targetStandard = %v, want NIST FIPS 203", jf["targetStandard"])
	}
	jSnippet, ok := jf["migrationSnippet"].(map[string]interface{})
	if !ok {
		t.Fatal("JSON: findings[0].migrationSnippet is missing or not an object")
	}
	if got, ok := jSnippet["language"].(string); !ok || got != "go" {
		t.Errorf("JSON: migrationSnippet.language = %v, want go", jSnippet["language"])
	}

	// --- SARIF ---
	var sarifBuf bytes.Buffer
	if err := WriteSARIF(&sarifBuf, result); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	if !json.Valid(sarifBuf.Bytes()) {
		t.Fatal("WriteSARIF: output is not valid JSON")
	}
	var sarifRaw map[string]interface{}
	if err := json.Unmarshal(sarifBuf.Bytes(), &sarifRaw); err != nil {
		t.Fatalf("WriteSARIF unmarshal: %v", err)
	}
	sarifRuns := sarifRaw["runs"].([]interface{})
	sarifRun := sarifRuns[0].(map[string]interface{})
	sarifResults := sarifRun["results"].([]interface{})
	if len(sarifResults) != 1 {
		t.Fatalf("SARIF: results count = %d, want 1", len(sarifResults))
	}
	sarifResult := sarifResults[0].(map[string]interface{})
	sarifProps, ok := sarifResult["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("SARIF: result.properties is missing or not an object")
	}
	if got, ok := sarifProps["targetAlgorithm"].(string); !ok || got != "ML-KEM-768" {
		t.Errorf("SARIF: properties.targetAlgorithm = %v, want ML-KEM-768", sarifProps["targetAlgorithm"])
	}
	if got, ok := sarifProps["targetStandard"].(string); !ok || got != "NIST FIPS 203" {
		t.Errorf("SARIF: properties.targetStandard = %v, want NIST FIPS 203", sarifProps["targetStandard"])
	}
	sarifSnippet, ok := sarifProps["migrationSnippet"].(map[string]interface{})
	if !ok {
		t.Fatal("SARIF: properties.migrationSnippet is missing or not an object")
	}
	if got, ok := sarifSnippet["language"].(string); !ok || got != "go" {
		t.Errorf("SARIF: migrationSnippet.language = %v, want go", sarifSnippet["language"])
	}

	// --- HTML ---
	var htmlBuf bytes.Buffer
	if err := WriteHTML(&htmlBuf, result); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	htmlOut := htmlBuf.String()

	// Migration column header
	if !strings.Contains(htmlOut, "Migration") {
		t.Error("HTML: missing Migration column header")
	}
	// Target algorithm visible in the report (appears via Recommendation or snippet summary)
	if !strings.Contains(htmlOut, "ML-KEM-768") {
		t.Error("HTML: missing target algorithm ML-KEM-768")
	}
	// Collapsible snippet block
	if !strings.Contains(htmlOut, "<details>") {
		t.Error("HTML: missing <details> element for migration snippet")
	}
	// Snippet language in the summary line
	if !strings.Contains(htmlOut, "go") {
		t.Error("HTML: missing snippet language 'go' in Migration column")
	}
}
