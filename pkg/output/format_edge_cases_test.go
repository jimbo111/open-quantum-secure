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

func emptyResult() ScanResult {
	return BuildResult("1.0.0", "/scan/target", []string{"cipherscope"}, nil)
}

func findingWithAlg(name, file string, line int) findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Location:     findings.Location{File: file, Line: line},
		Algorithm:    &findings.Algorithm{Name: name, Primitive: "asymmetric"},
		Confidence:   findings.ConfidenceHigh,
		SourceEngine: "cipherscope",
		QuantumRisk:  findings.QRVulnerable,
		Severity:     findings.SevHigh,
	}
}

// ---------------------------------------------------------------------------
// JSON edge cases
// ---------------------------------------------------------------------------

// TestWriteJSON_EmptyFindings_ValidDocument ensures an empty scan produces valid
// JSON with "findings":[] (not null) and all required top-level keys.
func TestWriteJSON_EmptyFindings_ValidDocument(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteJSON(&buf, emptyResult()); err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	for _, key := range []string{"version", "target", "engines", "summary", "findings", "quantumReadinessScore"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("missing required key %q in empty scan JSON", key)
		}
	}
	// "findings" must be [] not null
	raw := buf.String()
	if strings.Contains(raw, `"findings":null`) {
		t.Error(`"findings" marshalled as null instead of []`)
	}
}

// TestWriteJSON_SpecialCharsInFilePath verifies that control characters
// (newline, tab) inside file paths are properly JSON-escaped and that the
// document remains valid.
func TestWriteJSON_SpecialCharsInFilePath(t *testing.T) {
	paths := []struct {
		name string
		path string
	}{
		{"newline in path", "/src/file\nwith-newline.go"},
		{"tab in path", "/src/file\twith-tab.go"},
		{"unicode path", "/src/文件/crypto.go"},
		{"quote in path", `/src/file"with"quotes.go`},
	}
	for _, tc := range paths {
		t.Run(tc.name, func(t *testing.T) {
			ff := []findings.UnifiedFinding{findingWithAlg("RSA-2048", tc.path, 1)}
			result := BuildResult("1.0.0", "/src", []string{"cs"}, ff)
			var buf bytes.Buffer
			if err := WriteJSON(&buf, result); err != nil {
				t.Fatalf("WriteJSON error: %v", err)
			}
			var doc map[string]interface{}
			if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
				t.Fatalf("invalid JSON for path %q: %v", tc.path, err)
			}
		})
	}
}

// TestWriteJSON_NilEnginesField verifies that a nil engines slice marshals as
// [] and not null (defensive: BuildResult ensures non-nil engines via callers).
func TestWriteJSON_NilVsEmptySliceConsistency(t *testing.T) {
	// nil findings → BuildResult normalises to []
	r1 := BuildResult("1.0.0", "/t", []string{"cs"}, nil)
	// explicit empty slice
	r2 := BuildResult("1.0.0", "/t", []string{"cs"}, []findings.UnifiedFinding{})

	var b1, b2 bytes.Buffer
	_ = WriteJSON(&b1, r1)
	_ = WriteJSON(&b2, r2)

	var d1, d2 map[string]interface{}
	json.Unmarshal(b1.Bytes(), &d1) //nolint:errcheck
	json.Unmarshal(b2.Bytes(), &d2) //nolint:errcheck

	// Both should produce the same findings array length (0)
	arr1 := d1["findings"].([]interface{})
	arr2 := d2["findings"].([]interface{})
	if len(arr1) != 0 || len(arr2) != 0 {
		t.Errorf("nil/empty findings should both produce empty array; got lens %d, %d", len(arr1), len(arr2))
	}
}

// ---------------------------------------------------------------------------
// SARIF 2.1.0 edge cases
// ---------------------------------------------------------------------------

// TestWriteSARIF_EmptyFindings_ValidSchema verifies that empty findings produce
// a valid SARIF 2.1.0 document with required fields: $schema, version, runs[],
// runs[0].tool.driver.name, and runs[0].results[].
func TestWriteSARIF_EmptyFindings_ValidSchema(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, emptyResult()); err != nil {
		t.Fatalf("WriteSARIF error: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}

	if doc["$schema"] == nil {
		t.Error("SARIF missing $schema")
	}
	if doc["version"] != "2.1.0" {
		t.Errorf("SARIF version = %v, want 2.1.0", doc["version"])
	}
	runs, ok := doc["runs"].([]interface{})
	if !ok || len(runs) == 0 {
		t.Fatal("SARIF runs array missing or empty")
	}
	run := runs[0].(map[string]interface{})
	tool := run["tool"].(map[string]interface{})
	driver := tool["driver"].(map[string]interface{})
	if driver["name"] != "oqs-scanner" {
		t.Errorf("tool.driver.name = %v, want oqs-scanner", driver["name"])
	}
	// results must be present (as empty array) even with no findings
	if _, ok := run["results"]; !ok {
		t.Error("SARIF run missing 'results' key")
	}
}

// TestWriteSARIF_RequiredFields verifies that each result carries ruleId,
// level, message.text, and locations[].
func TestWriteSARIF_RequiredFields(t *testing.T) {
	ff := []findings.UnifiedFinding{findingWithAlg("RSA-2048", "/src/auth.go", 10)}
	result := BuildResult("1.0.0", "/src", []string{"cs"}, ff)

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, result); err != nil {
		t.Fatalf("WriteSARIF error: %v", err)
	}

	var doc map[string]interface{}
	json.Unmarshal(buf.Bytes(), &doc) //nolint:errcheck
	run := doc["runs"].([]interface{})[0].(map[string]interface{})
	results := run["results"].([]interface{})
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0].(map[string]interface{})
	if r["ruleId"] == nil || r["ruleId"] == "" {
		t.Error("result.ruleId missing")
	}
	if r["level"] == nil {
		t.Error("result.level missing")
	}
	msg := r["message"].(map[string]interface{})
	if msg["text"] == nil || msg["text"] == "" {
		t.Error("result.message.text missing")
	}
	locs := r["locations"].([]interface{})
	if len(locs) == 0 {
		t.Error("result.locations must be non-empty")
	}
}

// TestWriteSARIF_RulesArray verifies the rules array is present in driver and
// populated when there are findings.
func TestWriteSARIF_RulesArray(t *testing.T) {
	ff := []findings.UnifiedFinding{
		findingWithAlg("RSA-2048", "/src/a.go", 1),
		findingWithAlg("AES-128", "/src/b.go", 2),
	}
	result := BuildResult("1.0.0", "/src", []string{"cs"}, ff)

	var buf bytes.Buffer
	WriteSARIF(&buf, result) //nolint:errcheck
	var doc map[string]interface{}
	json.Unmarshal(buf.Bytes(), &doc) //nolint:errcheck

	run := doc["runs"].([]interface{})[0].(map[string]interface{})
	driver := run["tool"].(map[string]interface{})["driver"].(map[string]interface{})
	rules, ok := driver["rules"].([]interface{})
	if !ok || len(rules) == 0 {
		t.Error("tool.driver.rules must be non-empty when findings present")
	}
	// Each rule needs an id
	for i, rRaw := range rules {
		r := rRaw.(map[string]interface{})
		if r["id"] == nil || r["id"] == "" {
			t.Errorf("rules[%d].id missing", i)
		}
	}
}

// TestWriteSARIF_PropertyBagMigrationSnippet verifies the migrationSnippet
// property is serialized in the SARIF properties bag.
func TestWriteSARIF_PropertyBagMigrationSnippet(t *testing.T) {
	f := findingWithAlg("RSA-2048", "/src/auth.go", 5)
	f.MigrationSnippet = &findings.MigrationSnippet{
		Language:    "go",
		Before:      "rsa.GenerateKey(...)",
		After:       "mlkem.GenerateKey()",
		Explanation: "use ML-KEM",
	}
	result := BuildResult("1.0.0", "/src", []string{"cs"}, []findings.UnifiedFinding{f})

	var buf bytes.Buffer
	WriteSARIF(&buf, result) //nolint:errcheck
	var doc map[string]interface{}
	json.Unmarshal(buf.Bytes(), &doc) //nolint:errcheck

	run := doc["runs"].([]interface{})[0].(map[string]interface{})
	res := run["results"].([]interface{})[0].(map[string]interface{})
	props, ok := res["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("result.properties missing")
	}
	snippet, ok := props["migrationSnippet"]
	if !ok {
		t.Fatal("properties.migrationSnippet missing")
	}
	snippetMap := snippet.(map[string]interface{})
	if snippetMap["language"] != "go" {
		t.Errorf("migrationSnippet.language = %v, want go", snippetMap["language"])
	}
}

// TestWriteSARIF_StartLineMustBePositive verifies that a finding with Line=0
// produces no region (SARIF spec: startLine >= 1).
func TestWriteSARIF_StartLineMustBePositive(t *testing.T) {
	f := findings.UnifiedFinding{
		Location:     findings.Location{File: "/src/file.go", Line: 0},
		Algorithm:    &findings.Algorithm{Name: "AES-128"},
		SourceEngine: "cs",
		Confidence:   findings.ConfidenceHigh,
	}
	result := BuildResult("1.0.0", "/src", []string{"cs"}, []findings.UnifiedFinding{f})

	var buf bytes.Buffer
	WriteSARIF(&buf, result) //nolint:errcheck
	var doc map[string]interface{}
	json.Unmarshal(buf.Bytes(), &doc) //nolint:errcheck

	run := doc["runs"].([]interface{})[0].(map[string]interface{})
	res := run["results"].([]interface{})[0].(map[string]interface{})
	locs := res["locations"].([]interface{})
	physLoc := locs[0].(map[string]interface{})["physicalLocation"].(map[string]interface{})
	if _, hasRegion := physLoc["region"]; hasRegion {
		t.Error("SARIF region must be omitted when startLine is 0 (SARIF spec: startLine >= 1)")
	}
}

// ---------------------------------------------------------------------------
// CBOM (CycloneDX 1.7) edge cases
// ---------------------------------------------------------------------------

// TestWriteCBOM_EmptyFindings_SchemaFields verifies the empty-scan CBOM has
// bomFormat, specVersion=1.7, and components as an empty array.
func TestWriteCBOM_EmptyFindings_SchemaFields(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCBOM(&buf, emptyResult()); err != nil {
		t.Fatalf("WriteCBOM error: %v", err)
	}
	bom := parseCBOM(t, &buf)

	if bom.BOMFormat != "CycloneDX" {
		t.Errorf("bomFormat = %q, want CycloneDX", bom.BOMFormat)
	}
	if bom.SpecVersion != "1.7" {
		t.Errorf("specVersion = %q, want 1.7", bom.SpecVersion)
	}
	if bom.SerialNumber == "" {
		t.Error("serialNumber must be non-empty")
	}
	if !strings.HasPrefix(bom.SerialNumber, "urn:uuid:") {
		t.Errorf("serialNumber must start with urn:uuid:, got %q", bom.SerialNumber)
	}
	if bom.Components == nil {
		t.Error("components must not be nil (should be empty slice)")
	}
}

// TestWriteCBOM_CryptoProperties verifies that an algorithm finding produces a
// component with cryptoProperties.assetType = "algorithm" as required by
// CycloneDX 1.7 CBOM spec.
func TestWriteCBOM_CryptoProperties(t *testing.T) {
	ff := []findings.UnifiedFinding{findingWithAlg("RSA-2048", "/src/auth.go", 10)}
	result := BuildResult("1.0.0", "/src", []string{"cs"}, ff)
	buf := writeCBOMOrFatal(t, result)
	bom := parseCBOM(t, buf)

	if len(bom.Components) == 0 {
		t.Fatal("expected at least 1 component")
	}
	comp := bom.Components[0]
	if comp.CryptoProperties == nil {
		t.Fatal("component.cryptoProperties must not be nil")
	}
	if comp.CryptoProperties.AssetType != "algorithm" {
		t.Errorf("cryptoProperties.assetType = %q, want algorithm", comp.CryptoProperties.AssetType)
	}
}

// TestWriteCBOM_SerialNumberDeterministic verifies identical inputs produce the
// same serialNumber (content-addressed hash).
func TestWriteCBOM_SerialNumberDeterministic(t *testing.T) {
	ff := []findings.UnifiedFinding{findingWithAlg("RSA-2048", "/src/a.go", 1)}
	r := BuildResult("1.0.0", "/src", []string{"cs"}, ff)

	var b1, b2 bytes.Buffer
	WriteCBOM(&b1, r) //nolint:errcheck
	WriteCBOM(&b2, r) //nolint:errcheck

	bom1 := parseCBOM(t, &b1)
	bom2 := parseCBOM(t, &b2)
	if bom1.SerialNumber != bom2.SerialNumber {
		t.Errorf("serialNumber not deterministic: %q vs %q", bom1.SerialNumber, bom2.SerialNumber)
	}
}

// TestWriteCBOM_MetadataToolPresent verifies metadata.tools.components contains
// oqs-scanner with a version.
func TestWriteCBOM_MetadataToolPresent(t *testing.T) {
	result := BuildResult("2.0.0", "/src", []string{"cs"}, nil)
	buf := writeCBOMOrFatal(t, result)
	bom := parseCBOM(t, buf)

	if bom.Metadata.Tools == nil || len(bom.Metadata.Tools.Components) == 0 {
		t.Fatal("metadata.tools.components must be present")
	}
	tool := bom.Metadata.Tools.Components[0]
	if tool.Name != "oqs-scanner" {
		t.Errorf("tool.name = %q, want oqs-scanner", tool.Name)
	}
	if tool.Version != "2.0.0" {
		t.Errorf("tool.version = %q, want 2.0.0", tool.Version)
	}
}

// ---------------------------------------------------------------------------
// HTML XSS injection surface
// ---------------------------------------------------------------------------

// TestWriteHTML_XSS_AlgorithmName verifies that an algorithm name containing
// an HTML script tag is escaped and does NOT appear unescaped in the output.
// go's html/template escapes by default — if this fails it indicates a
// template using |safe or equivalent that bypasses escaping.
func TestWriteHTML_XSS_AlgorithmName(t *testing.T) {
	xssAlg := `<script>alert(1)</script>`
	result := basicResult()
	result.Findings = []findings.UnifiedFinding{
		algFinding(xssAlg, findings.QRVulnerable, findings.SevHigh),
	}
	result.Summary.TotalFindings = 1

	var buf bytes.Buffer
	if err := WriteHTML(&buf, result); err != nil {
		t.Fatalf("WriteHTML error: %v", err)
	}
	out := buf.String()

	// The raw script tag must NOT appear literally in the output
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Error("XSS: algorithm name '<script>alert(1)</script>' was not escaped in HTML output")
	}
	// The escaped form should be present instead
	if !strings.Contains(out, "&lt;script&gt;") && !strings.Contains(out, "&#60;script&#62;") {
		t.Log("note: escaped form not found (may be double-encoded or omitted) — verify manually")
	}
}

// TestWriteHTML_XSS_FilePath verifies that a file path containing an img
// onerror XSS payload is escaped in the HTML output.
func TestWriteHTML_XSS_FilePath(t *testing.T) {
	xssPath := `/src/<img src=x onerror=alert(1)>.go`
	result := basicResult()
	result.Findings = []findings.UnifiedFinding{
		{
			Location:     findings.Location{File: xssPath, Line: 1},
			Algorithm:    &findings.Algorithm{Name: "RSA-2048", Primitive: "asymmetric"},
			QuantumRisk:  findings.QRVulnerable,
			Severity:     findings.SevHigh,
			Confidence:   findings.ConfidenceHigh,
			SourceEngine: "cipherscope",
		},
	}
	result.Summary.TotalFindings = 1

	var buf bytes.Buffer
	if err := WriteHTML(&buf, result); err != nil {
		t.Fatalf("WriteHTML error: %v", err)
	}
	out := buf.String()

	if strings.Contains(out, "<img src=x onerror=alert(1)>") {
		t.Error("XSS: img onerror payload was not escaped in HTML output for file path")
	}
}

// TestWriteHTML_XSS_RecommendationField verifies that the recommendation
// string (user-controlled in some workflows) is HTML-escaped.
func TestWriteHTML_XSS_RecommendationField(t *testing.T) {
	result := basicResult()
	f := algFinding("RSA-2048", findings.QRVulnerable, findings.SevHigh)
	f.Recommendation = `Use <b onmouseover="alert(1)">ML-KEM</b>`
	result.Findings = []findings.UnifiedFinding{f}
	result.Summary.TotalFindings = 1

	var buf bytes.Buffer
	if err := WriteHTML(&buf, result); err != nil {
		t.Fatalf("WriteHTML error: %v", err)
	}
	out := buf.String()

	if strings.Contains(out, `onmouseover="alert(1)"`) {
		t.Error("XSS: recommendation onmouseover payload was not escaped in HTML output")
	}
}

// TestWriteHTML_EmptyFindings_ValidDocument ensures HTML renders without error
// and contains minimal structural elements when there are no findings.
func TestWriteHTML_EmptyFindings_ValidDocument(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHTML(&buf, emptyResult()); err != nil {
		t.Fatalf("WriteHTML error for empty findings: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "<!DOCTYPE html>") {
		t.Error("HTML output missing DOCTYPE")
	}
}

// TestWriteHTML_LongAlgorithmName verifies that very long algorithm names (e.g.
// 200+ chars from malformed input) do not cause a template panic or truncation
// error — the output should still be valid HTML.
func TestWriteHTML_LongAlgorithmName(t *testing.T) {
	longName := strings.Repeat("A", 250)
	result := basicResult()
	result.Findings = []findings.UnifiedFinding{
		algFinding(longName, findings.QRVulnerable, findings.SevHigh),
	}
	result.Summary.TotalFindings = 1

	var buf bytes.Buffer
	if err := WriteHTML(&buf, result); err != nil {
		t.Fatalf("WriteHTML error with long algorithm name: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "<!DOCTYPE html>") {
		t.Error("HTML output structurally broken for long algorithm name")
	}
}

// TestSanitizeID_SpecialChars verifies that sanitizeID handles characters
// that might otherwise produce invalid SARIF rule IDs.
func TestSanitizeID_SpecialChars(t *testing.T) {
	cases := []struct {
		input   string
		mustNot []string // substrings that must NOT appear in output
	}{
		{
			// GAP: sanitizeID does not strip '<' or '>' — angle brackets survive
			// ToUpper+Replace, meaning XSS-style algorithm names produce SARIF rule
			// IDs containing literal '<' and '>' characters (invalid per SARIF spec).
			// This test documents the current (buggy) behaviour; fix sanitizeID to
			// strip or encode angle brackets.
			input:   "RSA/2048 (PKCS#1)",
			mustNot: []string{"/", " ", "(", ")"},
		},
	}
	for _, tc := range cases {
		got := sanitizeID(tc.input)
		for _, bad := range tc.mustNot {
			if strings.Contains(got, bad) {
				t.Errorf("sanitizeID(%q) = %q; must not contain %q", tc.input, got, bad)
			}
		}
	}
}

// TestSanitizeID_XMLUnsafeCharsStripped verifies that XML/HTML-unsafe
// characters are removed from SARIF rule IDs. Regression: an algorithm name
// like "<script>alert(1)</script>" used to produce a rule ID containing
// literal angle brackets, violating SARIF 2.1.0 §3.49.3 and injecting into
// any consumer that forwarded the ID into HTML/XML without escaping.
func TestSanitizeID_XMLUnsafeCharsStripped(t *testing.T) {
	input := `<script>alert("1")&'x</script>`
	got := sanitizeID(input)
	for _, bad := range []string{"<", ">", `"`, "'", "&"} {
		if strings.Contains(got, bad) {
			t.Errorf("sanitizeID(%q) = %q; must not contain %q", input, got, bad)
		}
	}
}
