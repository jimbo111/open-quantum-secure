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

// sarifResultFor unmarshals a SARIF buffer and returns the first result.
func sarifResultFor(t *testing.T, buf *bytes.Buffer) map[string]interface{} {
	t.Helper()
	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	runs := parsed["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	results := run["results"].([]interface{})
	if len(results) == 0 {
		t.Fatal("no results in SARIF output")
	}
	return results[0].(map[string]interface{})
}

// sarifLogFrom unmarshals a SARIF buffer into the internal sarifLog struct.
func sarifLogFrom(t *testing.T, buf *bytes.Buffer) sarifLog {
	t.Helper()
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("failed to unmarshal SARIF: %v", err)
	}
	return log
}

// writeSARIFFor is a convenience wrapper.
func writeSARIFFor(t *testing.T, ff []findings.UnifiedFinding, target string) bytes.Buffer {
	t.Helper()
	result := BuildResult("0.1.0", target, []string{"test-engine"}, ff)
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, result); err != nil {
		t.Fatalf("WriteSARIF error: %v", err)
	}
	return buf
}

// ---------------------------------------------------------------------------
// 1. WriteSARIF with empty findings
// ---------------------------------------------------------------------------

func TestWriteSARIF_EmptyFindings(t *testing.T) {
	buf := writeSARIFFor(t, nil, "/project")
	log := sarifLogFrom(t, &buf)

	// Must be valid SARIF 2.1.0
	if log.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", log.Version)
	}
	if log.Schema == "" {
		t.Error("$schema must not be empty")
	}
	if !strings.Contains(log.Schema, "sarif") {
		t.Errorf("$schema %q does not look like a SARIF schema URL", log.Schema)
	}

	// Exactly one run
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(log.Runs))
	}

	// No findings → no results, no rules
	run := log.Runs[0]
	if len(run.Results) != 0 {
		t.Errorf("results = %d, want 0 for empty findings", len(run.Results))
	}
	if len(run.Tool.Driver.Rules) != 0 {
		t.Errorf("rules = %d, want 0 for empty findings", len(run.Tool.Driver.Rules))
	}

	// Driver name and version must be set
	if run.Tool.Driver.Name != "oqs-scanner" {
		t.Errorf("driver.name = %q, want oqs-scanner", run.Tool.Driver.Name)
	}
	if run.Tool.Driver.Version != "0.1.0" {
		t.Errorf("driver.version = %q, want 0.1.0", run.Tool.Driver.Version)
	}
}

func TestWriteSARIF_EmptyFindings_ValidJSON(t *testing.T) {
	buf := writeSARIFFor(t, nil, "/project")

	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("empty-findings output is not valid JSON: %v", err)
	}
	if raw["version"] != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0", raw["version"])
	}
	if _, ok := raw["$schema"]; !ok {
		t.Error("missing $schema field")
	}
}

func TestWriteSARIF_EmptyFindings_ResultsIsEmptyArray(t *testing.T) {
	buf := writeSARIFFor(t, nil, "/project")

	// Unmarshal as raw map to distinguish [] from null
	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	runs := raw["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	results := run["results"]

	// SARIF 2.1.0 spec section 3.27.5: results SHALL be an empty array, not null
	if results == nil {
		t.Fatal("results is null, SARIF 2.1.0 requires []")
	}
	arr, ok := results.([]interface{})
	if !ok {
		t.Fatalf("results is %T, want []interface{}", results)
	}
	if len(arr) != 0 {
		t.Errorf("results has %d elements, want 0", len(arr))
	}
}

func TestWriteSARIF_CodeFlows_FromDataFlowPath(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:     findings.Location{File: "/project/main.go", Line: 50},
			Algorithm:    &findings.Algorithm{Name: "AES-128", Primitive: "symmetric", KeySize: 128},
			Confidence:   findings.ConfidenceHigh,
			SourceEngine: "semgrep",
			QuantumRisk:  findings.QRWeakened,
			Severity:     findings.SevMedium,
			DataFlowPath: []findings.FlowStep{
				{File: "/project/config.go", Line: 10, Message: "Key defined here"},
				{File: "/project/crypto.go", Line: 25, Column: 8, Message: "Passed to cipher init"},
				{File: "/project/main.go", Line: 50, Message: "Used in encryption"},
			},
		},
	}
	buf := writeSARIFFor(t, ff, "/project")

	// Parse as raw map to inspect codeFlows structure
	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	runs := raw["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	results := run["results"].([]interface{})
	if len(results) != 1 {
		t.Fatalf("results = %d, want 1", len(results))
	}

	result := results[0].(map[string]interface{})
	codeFlows, ok := result["codeFlows"]
	if !ok || codeFlows == nil {
		t.Fatal("codeFlows missing from result with DataFlowPath")
	}

	flows := codeFlows.([]interface{})
	if len(flows) != 1 {
		t.Fatalf("codeFlows = %d, want 1", len(flows))
	}

	flow := flows[0].(map[string]interface{})
	threadFlows := flow["threadFlows"].([]interface{})
	if len(threadFlows) != 1 {
		t.Fatalf("threadFlows = %d, want 1", len(threadFlows))
	}

	tf := threadFlows[0].(map[string]interface{})
	locations := tf["locations"].([]interface{})
	if len(locations) != 3 {
		t.Fatalf("threadFlow locations = %d, want 3", len(locations))
	}

	// Verify first step
	step0 := locations[0].(map[string]interface{})
	loc0 := step0["location"].(map[string]interface{})
	phys0 := loc0["physicalLocation"].(map[string]interface{})
	artLoc0 := phys0["artifactLocation"].(map[string]interface{})
	if uri := artLoc0["uri"].(string); uri != "config.go" {
		t.Errorf("step 0 uri = %q, want config.go", uri)
	}
	msg0 := step0["message"].(map[string]interface{})
	if text := msg0["text"].(string); text != "Key defined here" {
		t.Errorf("step 0 message = %q, want 'Key defined here'", text)
	}

	// Verify second step has column in region
	step1 := locations[1].(map[string]interface{})
	loc1 := step1["location"].(map[string]interface{})
	phys1 := loc1["physicalLocation"].(map[string]interface{})
	region1 := phys1["region"].(map[string]interface{})
	if col, ok := region1["startColumn"]; !ok || col.(float64) != 8 {
		t.Errorf("step 1 startColumn = %v, want 8", region1["startColumn"])
	}
}

// ---------------------------------------------------------------------------
// 2. WriteSARIF with algorithm findings
// ---------------------------------------------------------------------------

func TestWriteSARIF_AlgorithmFindings(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:    findings.Location{File: "/project/main.go", Line: 10, Column: 5},
			Algorithm:   &findings.Algorithm{Name: "RSA-2048", Primitive: "signature", KeySize: 2048},
			Confidence:  findings.ConfidenceHigh,
			SourceEngine: "cipherscope",
			QuantumRisk: findings.QRVulnerable,
			Severity:    findings.SevCritical,
		},
	}
	buf := writeSARIFFor(t, ff, "/project")
	log := sarifLogFrom(t, &buf)

	run := log.Runs[0]

	// One rule must be created
	if len(run.Tool.Driver.Rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(run.Tool.Driver.Rules))
	}
	rule := run.Tool.Driver.Rules[0]
	if rule.ID != "OQS-ALG-RSA-2048" {
		t.Errorf("rule.ID = %q, want OQS-ALG-RSA-2048", rule.ID)
	}
	if rule.Name != "RSA-2048" {
		t.Errorf("rule.Name = %q, want RSA-2048", rule.Name)
	}
	if rule.ShortDescription == nil || rule.ShortDescription.Text == "" {
		t.Error("rule.ShortDescription must be set")
	}

	// One result
	if len(run.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(run.Results))
	}
	res := run.Results[0]
	if res.RuleID != "OQS-ALG-RSA-2048" {
		t.Errorf("result.RuleID = %q, want OQS-ALG-RSA-2048", res.RuleID)
	}
	if res.Level != "error" {
		t.Errorf("result.Level = %q, want error (critical severity)", res.Level)
	}
	if !strings.Contains(res.Message.Text, "RSA-2048") {
		t.Errorf("message %q should contain RSA-2048", res.Message.Text)
	}
}

func TestWriteSARIF_AlgorithmRule_PrimitiveProperty(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:  findings.Location{File: "/x.go", Line: 1},
			Algorithm: &findings.Algorithm{Name: "AES-256-GCM", Primitive: "ae"},
			Severity:  findings.SevInfo,
		},
	}
	buf := writeSARIFFor(t, ff, "/")
	log := sarifLogFrom(t, &buf)

	rule := log.Runs[0].Tool.Driver.Rules[0]
	if rule.Properties == nil {
		t.Fatal("rule.Properties should be set when primitive is present")
	}
	if prim, ok := rule.Properties["primitive"]; !ok || prim != "ae" {
		t.Errorf("rule.Properties[primitive] = %v, want ae", prim)
	}
}

// ---------------------------------------------------------------------------
// 3. WriteSARIF with dependency findings — OQS-DEP rules
// ---------------------------------------------------------------------------

func TestWriteSARIF_DependencyFindings(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:     findings.Location{File: "/project/go.mod", Line: 3},
			Dependency:   &findings.Dependency{Library: "openssl"},
			Confidence:   findings.ConfidenceMedium,
			SourceEngine: "depscan",
		},
	}
	buf := writeSARIFFor(t, ff, "/project")
	log := sarifLogFrom(t, &buf)

	run := log.Runs[0]

	// Rule must use OQS-DEP prefix
	if len(run.Tool.Driver.Rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(run.Tool.Driver.Rules))
	}
	rule := run.Tool.Driver.Rules[0]
	if rule.ID != "OQS-DEP-OPENSSL" {
		t.Errorf("rule.ID = %q, want OQS-DEP-OPENSSL", rule.ID)
	}
	if rule.Name != "openssl" {
		t.Errorf("rule.Name = %q, want openssl", rule.Name)
	}
	if rule.ShortDescription == nil || !strings.Contains(rule.ShortDescription.Text, "openssl") {
		t.Errorf("shortDescription should mention openssl, got %v", rule.ShortDescription)
	}

	// Result must reference the same rule ID
	if len(run.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(run.Results))
	}
	res := run.Results[0]
	if res.RuleID != "OQS-DEP-OPENSSL" {
		t.Errorf("result.RuleID = %q, want OQS-DEP-OPENSSL", res.RuleID)
	}
	if !strings.Contains(res.Message.Text, "openssl") {
		t.Errorf("message %q should contain library name openssl", res.Message.Text)
	}
}

func TestWriteSARIF_DependencyFindings_MultipleLibraries(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:   findings.Location{File: "/a.go", Line: 1},
			Dependency: &findings.Dependency{Library: "openssl"},
		},
		{
			Location:   findings.Location{File: "/b.go", Line: 2},
			Dependency: &findings.Dependency{Library: "libsodium"},
		},
	}
	buf := writeSARIFFor(t, ff, "/")
	log := sarifLogFrom(t, &buf)

	run := log.Runs[0]
	if len(run.Tool.Driver.Rules) != 2 {
		t.Errorf("rules = %d, want 2 (one per library)", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 2 {
		t.Errorf("results = %d, want 2", len(run.Results))
	}
}

// ---------------------------------------------------------------------------
// 4. levelForFinding — all severity → SARIF level mappings
// ---------------------------------------------------------------------------

func TestLevelForFinding_AllSeverities(t *testing.T) {
	tests := []struct {
		name     string
		severity findings.Severity
		want     string
	}{
		{"critical->error", findings.SevCritical, "error"},
		{"high->warning", findings.SevHigh, "warning"},
		{"medium->warning", findings.SevMedium, "warning"},
		{"low->note", findings.SevLow, "note"},
		{"info->none", findings.SevInfo, "none"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := findings.UnifiedFinding{Severity: tt.severity}
			got := levelForFinding(f)
			if got != tt.want {
				t.Errorf("levelForFinding(severity=%q) = %q, want %q", tt.severity, got, tt.want)
			}
		})
	}
}

func TestLevelForFinding_ConfidenceFallback(t *testing.T) {
	// When severity is unset, confidence should determine level.
	tests := []struct {
		name       string
		confidence findings.Confidence
		want       string
	}{
		{"high-confidence->warning", findings.ConfidenceHigh, "warning"},
		{"medium-confidence->warning", findings.ConfidenceMedium, "warning"},
		{"low-confidence->note", findings.ConfidenceLow, "note"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := findings.UnifiedFinding{
				Confidence: tt.confidence,
				// Severity intentionally left empty to exercise fallback
			}
			got := levelForFinding(f)
			if got != tt.want {
				t.Errorf("levelForFinding(confidence=%q) = %q, want %q", tt.confidence, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 5. buildMessage — algorithms, dependencies, corroborated findings
// ---------------------------------------------------------------------------

func TestBuildMessage_AlgorithmBasic(t *testing.T) {
	f := findings.UnifiedFinding{
		Algorithm: &findings.Algorithm{Name: "RSA-2048"},
	}
	msg := buildMessage(f)
	if !strings.Contains(msg, "RSA-2048") {
		t.Errorf("message %q should contain RSA-2048", msg)
	}
	if !strings.Contains(msg, "Cryptographic algorithm detected") {
		t.Errorf("message %q should contain 'Cryptographic algorithm detected'", msg)
	}
}

func TestBuildMessage_AlgorithmWithAllFields(t *testing.T) {
	f := findings.UnifiedFinding{
		Algorithm: &findings.Algorithm{
			Name:      "AES-256-GCM",
			Primitive: "ae",
			KeySize:   256,
			Mode:      "GCM",
		},
	}
	msg := buildMessage(f)

	if !strings.Contains(msg, "AES-256-GCM") {
		t.Errorf("message %q should contain algorithm name", msg)
	}
	if !strings.Contains(msg, "primitive=ae") {
		t.Errorf("message %q should contain primitive=ae", msg)
	}
	if !strings.Contains(msg, "keySize=256") {
		t.Errorf("message %q should contain keySize=256", msg)
	}
	if !strings.Contains(msg, "mode=GCM") {
		t.Errorf("message %q should contain mode=GCM", msg)
	}
}

func TestBuildMessage_AlgorithmNoOptionalFields(t *testing.T) {
	// When Primitive, KeySize, and Mode are all zero values, message
	// should still be well-formed (no trailing commas or garbage).
	f := findings.UnifiedFinding{
		Algorithm: &findings.Algorithm{Name: "MD5"},
	}
	msg := buildMessage(f)
	if !strings.Contains(msg, "MD5") {
		t.Errorf("message %q should contain MD5", msg)
	}
	if strings.Contains(msg, "primitive=") {
		t.Errorf("message %q should not mention primitive when empty", msg)
	}
	if strings.Contains(msg, "keySize=") {
		t.Errorf("message %q should not mention keySize when zero", msg)
	}
	if strings.Contains(msg, "mode=") {
		t.Errorf("message %q should not mention mode when empty", msg)
	}
}

func TestBuildMessage_Dependency(t *testing.T) {
	f := findings.UnifiedFinding{
		Dependency: &findings.Dependency{Library: "openssl"},
	}
	msg := buildMessage(f)
	if !strings.Contains(msg, "openssl") {
		t.Errorf("message %q should contain library name", msg)
	}
	if !strings.Contains(msg, "Cryptographic library detected") {
		t.Errorf("message %q should contain 'Cryptographic library detected'", msg)
	}
}

func TestBuildMessage_NeitherAlgorithmNorDependency(t *testing.T) {
	f := findings.UnifiedFinding{}
	msg := buildMessage(f)
	if msg == "" {
		t.Error("buildMessage should return a non-empty fallback message")
	}
	if !strings.Contains(msg, "Cryptographic usage detected") {
		t.Errorf("message %q should be the fallback text", msg)
	}
}

// ---------------------------------------------------------------------------
// 5a. buildMessage — corroborated findings
// ---------------------------------------------------------------------------

func TestBuildMessage_AlgorithmCorroborated(t *testing.T) {
	f := findings.UnifiedFinding{
		Algorithm:      &findings.Algorithm{Name: "RSA-2048"},
		SourceEngine:   "cipherscope",
		CorroboratedBy: []string{"cryptoscan"},
	}
	msg := buildMessage(f)
	if !strings.Contains(msg, "confirmed by") {
		t.Errorf("message %q should contain 'confirmed by' for corroborated finding", msg)
	}
	if !strings.Contains(msg, "cipherscope") {
		t.Errorf("message %q should mention source engine cipherscope", msg)
	}
	if !strings.Contains(msg, "cryptoscan") {
		t.Errorf("message %q should mention corroborating engine cryptoscan", msg)
	}
}

func TestBuildMessage_DependencyCorroborated(t *testing.T) {
	f := findings.UnifiedFinding{
		Dependency:     &findings.Dependency{Library: "libsodium"},
		SourceEngine:   "depscan",
		CorroboratedBy: []string{"syft", "trivy"},
	}
	msg := buildMessage(f)
	if !strings.Contains(msg, "confirmed by") {
		t.Errorf("message %q should contain 'confirmed by'", msg)
	}
	if !strings.Contains(msg, "depscan") {
		t.Errorf("message %q should mention source engine", msg)
	}
	if !strings.Contains(msg, "syft") {
		t.Errorf("message %q should mention syft", msg)
	}
	if !strings.Contains(msg, "trivy") {
		t.Errorf("message %q should mention trivy", msg)
	}
}

func TestBuildMessage_NotCorroborated_NoConfirmedByText(t *testing.T) {
	// When CorroboratedBy is empty, "confirmed by" must NOT appear.
	f := findings.UnifiedFinding{
		Algorithm:    &findings.Algorithm{Name: "RSA-2048"},
		SourceEngine: "cipherscope",
	}
	msg := buildMessage(f)
	if strings.Contains(msg, "confirmed by") {
		t.Errorf("message %q should NOT contain 'confirmed by' when not corroborated", msg)
	}
}

// ---------------------------------------------------------------------------
// 6. ruleKeyForFinding — prefix tests
// ---------------------------------------------------------------------------

func TestRuleKeyForFinding(t *testing.T) {
	tests := []struct {
		name    string
		finding findings.UnifiedFinding
		want    string
	}{
		{
			name: "algorithm prefix",
			finding: findings.UnifiedFinding{
				Algorithm: &findings.Algorithm{Name: "RSA-2048"},
			},
			want: "alg/RSA-2048",
		},
		{
			name: "dependency prefix",
			finding: findings.UnifiedFinding{
				Dependency: &findings.Dependency{Library: "openssl"},
			},
			want: "dep/openssl",
		},
		{
			name: "unknown when algorithm name empty",
			finding: findings.UnifiedFinding{
				Algorithm: &findings.Algorithm{Name: ""},
			},
			want: "unknown/",
		},
		{
			name:    "unknown when neither algorithm nor dependency",
			finding: findings.UnifiedFinding{},
			want:    "unknown/",
		},
		{
			name: "algorithm name preserved exactly",
			finding: findings.UnifiedFinding{
				Algorithm: &findings.Algorithm{Name: "AES-256-GCM"},
			},
			want: "alg/AES-256-GCM",
		},
		{
			name: "dependency library name preserved exactly",
			finding: findings.UnifiedFinding{
				Dependency: &findings.Dependency{Library: "libsodium"},
			},
			want: "dep/libsodium",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ruleKeyForFinding(tt.finding)
			if got != tt.want {
				t.Errorf("ruleKeyForFinding() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 7. sanitizeID — special character replacement
// ---------------------------------------------------------------------------

func TestSanitizeID(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		// Spaces become hyphens
		{"RSA 2048", "RSA-2048"},
		// Slashes become hyphens
		{"SHA-256/512", "SHA-256-512"},
		// Dots become hyphens
		{"libssl.so.3", "LIBSSL-SO-3"},
		// Parentheses are removed
		{"AES(256)", "AES256"},
		// Plus becomes PLUS
		{"ChaCha20+Poly1305", "CHACHA20PLUSPOLY1305"},
		// Names already clean: hyphens and digits pass through
		{"AES-256-GCM", "AES-256-GCM"},
		{"SHA-1", "SHA-1"},
		// Output is always uppercase
		{"openssl", "OPENSSL"},
		{"libsodium", "LIBSODIUM"},
		// Combined: space + slash + parens — space→hyphen, parens stripped, slash→hyphen
		{"EC (P-384)/SHA-256", "EC-P-384-SHA-256"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := sanitizeID(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeID(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 8. Region omission when Line == 0
// ---------------------------------------------------------------------------

func TestWriteSARIF_Region_OmittedWhenLineIsZero(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			// Line == 0 means location is unknown; region must be omitted
			Location:  findings.Location{File: "/project/go.mod", Line: 0},
			Dependency: &findings.Dependency{Library: "openssl"},
		},
	}
	buf := writeSARIFFor(t, ff, "/project")

	// Unmarshal as raw map to inspect JSON structure faithfully.
	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	run := raw["runs"].([]interface{})[0].(map[string]interface{})
	results := run["results"].([]interface{})
	result := results[0].(map[string]interface{})
	locations := result["locations"].([]interface{})
	physLoc := locations[0].(map[string]interface{})["physicalLocation"].(map[string]interface{})

	// "region" key must not be present when line == 0
	if _, hasRegion := physLoc["region"]; hasRegion {
		t.Errorf("physicalLocation must NOT have a 'region' key when Location.Line == 0 (SARIF spec requires startLine >= 1)")
	}
}

func TestWriteSARIF_Region_OmittedWhenLineIsZero_ViaStruct(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:  findings.Location{File: "/project/go.mod", Line: 0, Column: 0},
			Algorithm: &findings.Algorithm{Name: "RSA-2048"},
			Severity:  findings.SevHigh,
		},
	}
	buf := writeSARIFFor(t, ff, "/project")
	log := sarifLogFrom(t, &buf)

	physLoc := log.Runs[0].Results[0].Locations[0].PhysicalLocation
	if physLoc.Region != nil {
		t.Errorf("Region must be nil (omitted) when Location.Line == 0, got %+v", physLoc.Region)
	}
}

// ---------------------------------------------------------------------------
// 9. Region present when Line > 0
// ---------------------------------------------------------------------------

func TestWriteSARIF_Region_PresentWhenLineIsPositive(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:  findings.Location{File: "/project/main.go", Line: 42, Column: 7},
			Algorithm: &findings.Algorithm{Name: "AES-256-GCM"},
			Severity:  findings.SevLow,
		},
	}
	buf := writeSARIFFor(t, ff, "/project")
	log := sarifLogFrom(t, &buf)

	physLoc := log.Runs[0].Results[0].Locations[0].PhysicalLocation
	if physLoc.Region == nil {
		t.Fatal("Region must be set when Location.Line > 0")
	}
	if physLoc.Region.StartLine != 42 {
		t.Errorf("StartLine = %d, want 42", physLoc.Region.StartLine)
	}
	if physLoc.Region.StartColumn != 7 {
		t.Errorf("StartColumn = %d, want 7", physLoc.Region.StartColumn)
	}
}

func TestWriteSARIF_Region_LineOneIsValid(t *testing.T) {
	// Line = 1 is the minimum valid SARIF line; it must produce a region.
	ff := []findings.UnifiedFinding{
		{
			Location:  findings.Location{File: "/project/main.go", Line: 1, Column: 1},
			Algorithm: &findings.Algorithm{Name: "SHA-1"},
			Severity:  findings.SevMedium,
		},
	}
	buf := writeSARIFFor(t, ff, "/project")
	log := sarifLogFrom(t, &buf)

	physLoc := log.Runs[0].Results[0].Locations[0].PhysicalLocation
	if physLoc.Region == nil {
		t.Fatal("Region must be set for Line == 1")
	}
	if physLoc.Region.StartLine != 1 {
		t.Errorf("StartLine = %d, want 1", physLoc.Region.StartLine)
	}
}

// ---------------------------------------------------------------------------
// 10. Quantum risk properties in result.properties
// ---------------------------------------------------------------------------

func TestWriteSARIF_QuantumRiskProperties_Present(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:       findings.Location{File: "/project/main.go", Line: 5},
			Algorithm:      &findings.Algorithm{Name: "RSA-2048"},
			QuantumRisk:    findings.QRVulnerable,
			Severity:       findings.SevCritical,
			Recommendation: "Migrate to ML-KEM-768",
		},
	}
	buf := writeSARIFFor(t, ff, "/project")
	log := sarifLogFrom(t, &buf)

	res := log.Runs[0].Results[0]
	if res.Properties == nil {
		t.Fatal("result.Properties must be set when QuantumRisk is present")
	}

	qr, ok := res.Properties["quantumRisk"]
	if !ok {
		t.Fatal("Properties must contain 'quantumRisk' key")
	}
	if qr != string(findings.QRVulnerable) {
		t.Errorf("quantumRisk = %v, want %q", qr, findings.QRVulnerable)
	}

	sev, ok := res.Properties["severity"]
	if !ok {
		t.Fatal("Properties must contain 'severity' key")
	}
	if sev != string(findings.SevCritical) {
		t.Errorf("severity = %v, want %q", sev, findings.SevCritical)
	}

	rec, ok := res.Properties["recommendation"]
	if !ok {
		t.Fatal("Properties must contain 'recommendation' key when Recommendation is set")
	}
	if rec != "Migrate to ML-KEM-768" {
		t.Errorf("recommendation = %v, want Migrate to ML-KEM-768", rec)
	}
}

func TestWriteSARIF_QuantumRiskProperties_AllRiskLevels(t *testing.T) {
	risks := []findings.QuantumRisk{
		findings.QRVulnerable,
		findings.QRWeakened,
		findings.QRSafe,
		findings.QRResistant,
		findings.QRDeprecated,
		findings.QRUnknown,
	}

	for _, risk := range risks {
		t.Run(string(risk), func(t *testing.T) {
			ff := []findings.UnifiedFinding{
				{
					Location:    findings.Location{File: "/x.go", Line: 1},
					Algorithm:   &findings.Algorithm{Name: "AES-256"},
					QuantumRisk: risk,
					Severity:    findings.SevMedium,
				},
			}
			buf := writeSARIFFor(t, ff, "/")
			log := sarifLogFrom(t, &buf)

			res := log.Runs[0].Results[0]
			if res.Properties == nil {
				t.Fatalf("result.Properties must be set for QuantumRisk=%q", risk)
			}
			if got := res.Properties["quantumRisk"]; got != string(risk) {
				t.Errorf("quantumRisk = %v, want %q", got, risk)
			}
		})
	}
}

func TestWriteSARIF_QuantumRiskProperties_Absent_WhenNoQuantumRisk(t *testing.T) {
	// Properties are always present (sourceEngine/confidence/reachable always emit),
	// but quantumRisk key should be absent when QuantumRisk is empty.
	ff := []findings.UnifiedFinding{
		{
			Location:     findings.Location{File: "/x.go", Line: 1},
			Algorithm:    &findings.Algorithm{Name: "AES-256"},
			SourceEngine: "test-engine",
			Confidence:   findings.ConfidenceHigh,
			// QuantumRisk intentionally omitted
		},
	}
	buf := writeSARIFFor(t, ff, "/")
	log := sarifLogFrom(t, &buf)

	res := log.Runs[0].Results[0]
	if res.Properties == nil {
		t.Fatal("result.Properties should be non-nil (sourceEngine/confidence/reachable always present)")
	}
	if _, ok := res.Properties["quantumRisk"]; ok {
		t.Error("Properties must NOT have 'quantumRisk' key when QuantumRisk is empty")
	}
	if _, ok := res.Properties["sourceEngine"]; !ok {
		t.Error("Properties must have 'sourceEngine' key")
	}
	if _, ok := res.Properties["confidence"]; !ok {
		t.Error("Properties must have 'confidence' key")
	}
	if _, ok := res.Properties["reachable"]; !ok {
		t.Error("Properties must have 'reachable' key")
	}
}

func TestWriteSARIF_AlgorithmFinding_HasSourceEngineConfidenceReachable(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:     findings.Location{File: "/x.go", Line: 1},
			Algorithm:    &findings.Algorithm{Name: "RSA-2048"},
			SourceEngine: "cipherscope",
			Confidence:   findings.ConfidenceHigh,
			Reachable:    findings.ReachableYes,
			QuantumRisk:  findings.QRVulnerable,
			Severity:     findings.SevHigh,
		},
	}
	buf := writeSARIFFor(t, ff, "/")
	log := sarifLogFrom(t, &buf)

	res := log.Runs[0].Results[0]
	if res.Properties == nil {
		t.Fatal("result.Properties should be non-nil")
	}
	if got, _ := res.Properties["sourceEngine"].(string); got != "cipherscope" {
		t.Errorf("sourceEngine = %q, want %q", got, "cipherscope")
	}
	if got, _ := res.Properties["confidence"].(string); got != string(findings.ConfidenceHigh) {
		t.Errorf("confidence = %q, want %q", got, string(findings.ConfidenceHigh))
	}
	if got, _ := res.Properties["reachable"].(string); got != string(findings.ReachableYes) {
		t.Errorf("reachable = %q, want %q", got, string(findings.ReachableYes))
	}
}

func TestWriteSARIF_DependencyFinding_HasSourceEngineConfidenceReachable(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:     findings.Location{File: "/go.mod", Line: 5},
			Dependency:   &findings.Dependency{Library: "openssl"},
			SourceEngine: "cryptodeps",
			Confidence:   findings.ConfidenceMedium,
			Reachable:    findings.ReachableNo,
		},
	}
	buf := writeSARIFFor(t, ff, "/")
	log := sarifLogFrom(t, &buf)

	res := log.Runs[0].Results[0]
	if res.Properties == nil {
		t.Fatal("result.Properties should be non-nil for dependency finding")
	}
	if got, _ := res.Properties["sourceEngine"].(string); got != "cryptodeps" {
		t.Errorf("sourceEngine = %q, want %q", got, "cryptodeps")
	}
	if got, _ := res.Properties["confidence"].(string); got != string(findings.ConfidenceMedium) {
		t.Errorf("confidence = %q, want %q", got, string(findings.ConfidenceMedium))
	}
	if got, _ := res.Properties["reachable"].(string); got != string(findings.ReachableNo) {
		t.Errorf("reachable = %q, want %q", got, string(findings.ReachableNo))
	}
}

func TestWriteSARIF_QuantumRiskProperties_RecommendationOmitted_WhenEmpty(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:    findings.Location{File: "/x.go", Line: 1},
			Algorithm:   &findings.Algorithm{Name: "AES-256"},
			QuantumRisk: findings.QRSafe,
			Severity:    findings.SevLow,
			// Recommendation intentionally empty
		},
	}
	buf := writeSARIFFor(t, ff, "/")
	log := sarifLogFrom(t, &buf)

	res := log.Runs[0].Results[0]
	if _, ok := res.Properties["recommendation"]; ok {
		t.Error("Properties must NOT have 'recommendation' key when Recommendation is empty")
	}
}

// ---------------------------------------------------------------------------
// 11. Rule deduplication
// ---------------------------------------------------------------------------

func TestWriteSARIF_RuleDeduplication_SameAlgorithm(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:  findings.Location{File: "/a.go", Line: 10},
			Algorithm: &findings.Algorithm{Name: "RSA-2048"},
			Severity:  findings.SevHigh,
		},
		{
			Location:  findings.Location{File: "/b.go", Line: 20},
			Algorithm: &findings.Algorithm{Name: "RSA-2048"},
			Severity:  findings.SevHigh,
		},
		{
			Location:  findings.Location{File: "/c.go", Line: 30},
			Algorithm: &findings.Algorithm{Name: "RSA-2048"},
			Severity:  findings.SevHigh,
		},
	}
	buf := writeSARIFFor(t, ff, "/")
	log := sarifLogFrom(t, &buf)

	run := log.Runs[0]
	if len(run.Tool.Driver.Rules) != 1 {
		t.Errorf("rules = %d, want 1 (all three RSA-2048 occurrences share one rule)", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 3 {
		t.Errorf("results = %d, want 3 (one per finding)", len(run.Results))
	}
	// All results must reference the same rule ID
	for i, r := range run.Results {
		if r.RuleID != "OQS-ALG-RSA-2048" {
			t.Errorf("result[%d].RuleID = %q, want OQS-ALG-RSA-2048", i, r.RuleID)
		}
	}
}

func TestWriteSARIF_RuleDeduplication_SameDependency(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:   findings.Location{File: "/go.mod", Line: 5},
			Dependency: &findings.Dependency{Library: "openssl"},
		},
		{
			Location:   findings.Location{File: "/vendor/openssl/main.go", Line: 1},
			Dependency: &findings.Dependency{Library: "openssl"},
		},
	}
	buf := writeSARIFFor(t, ff, "/")
	log := sarifLogFrom(t, &buf)

	run := log.Runs[0]
	if len(run.Tool.Driver.Rules) != 1 {
		t.Errorf("rules = %d, want 1 (duplicate dep/openssl)", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 2 {
		t.Errorf("results = %d, want 2", len(run.Results))
	}
}

func TestWriteSARIF_RuleDeduplication_MixedTypes(t *testing.T) {
	// Algorithms and dependencies with different keys must each get their own rule.
	ff := []findings.UnifiedFinding{
		{
			Location:  findings.Location{File: "/a.go", Line: 1},
			Algorithm: &findings.Algorithm{Name: "RSA-2048"},
		},
		{
			Location:  findings.Location{File: "/b.go", Line: 2},
			Algorithm: &findings.Algorithm{Name: "AES-256-GCM"},
		},
		{
			Location:   findings.Location{File: "/go.mod", Line: 3},
			Dependency: &findings.Dependency{Library: "openssl"},
		},
		// Repeat of RSA-2048 — should NOT add a second rule
		{
			Location:  findings.Location{File: "/c.go", Line: 4},
			Algorithm: &findings.Algorithm{Name: "RSA-2048"},
		},
	}
	buf := writeSARIFFor(t, ff, "/")
	log := sarifLogFrom(t, &buf)

	run := log.Runs[0]
	if len(run.Tool.Driver.Rules) != 3 {
		t.Errorf("rules = %d, want 3 (RSA-2048, AES-256-GCM, openssl)", len(run.Tool.Driver.Rules))
	}
	if len(run.Results) != 4 {
		t.Errorf("results = %d, want 4", len(run.Results))
	}
}

// ---------------------------------------------------------------------------
// 12. Corroborated finding messages — "confirmed by" text
// ---------------------------------------------------------------------------

func TestWriteSARIF_CorroboratedFinding_InOutput(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:       findings.Location{File: "/project/crypto.go", Line: 15},
			Algorithm:      &findings.Algorithm{Name: "RSA-2048"},
			SourceEngine:   "cipherscope",
			CorroboratedBy: []string{"cryptoscan", "semgrep"},
			Severity:       findings.SevCritical,
		},
	}
	buf := writeSARIFFor(t, ff, "/project")
	log := sarifLogFrom(t, &buf)

	msg := log.Runs[0].Results[0].Message.Text
	if !strings.Contains(msg, "confirmed by") {
		t.Errorf("corroborated finding message %q should contain 'confirmed by'", msg)
	}
	if !strings.Contains(msg, "cipherscope") {
		t.Errorf("message %q should list source engine cipherscope", msg)
	}
	if !strings.Contains(msg, "cryptoscan") {
		t.Errorf("message %q should list corroborating engine cryptoscan", msg)
	}
	if !strings.Contains(msg, "semgrep") {
		t.Errorf("message %q should list corroborating engine semgrep", msg)
	}
}

func TestWriteSARIF_NonCorroboratedFinding_NoConfirmedByText(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:     findings.Location{File: "/project/main.go", Line: 10},
			Algorithm:    &findings.Algorithm{Name: "AES-256-GCM"},
			SourceEngine: "cipherscope",
			// CorroboratedBy intentionally empty
			Severity: findings.SevInfo,
		},
	}
	buf := writeSARIFFor(t, ff, "/project")
	log := sarifLogFrom(t, &buf)

	msg := log.Runs[0].Results[0].Message.Text
	if strings.Contains(msg, "confirmed by") {
		t.Errorf("non-corroborated message %q should NOT contain 'confirmed by'", msg)
	}
}

// ---------------------------------------------------------------------------
// Integration: full SARIF round-trip with schema/version/runs structure
// ---------------------------------------------------------------------------

func TestWriteSARIF_ValidJSON_WithFindings(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:    findings.Location{File: "/test/main.go", Line: 10},
			Algorithm:   &findings.Algorithm{Name: "RSA-2048", Primitive: "signature"},
			Confidence:  findings.ConfidenceHigh,
			QuantumRisk: findings.QRVulnerable,
			Severity:    findings.SevCritical,
		},
		{
			Location:    findings.Location{File: "/test/main.go", Line: 20},
			Algorithm:   &findings.Algorithm{Name: "AES-256-GCM", Primitive: "ae", KeySize: 256, Mode: "GCM"},
			Confidence:  findings.ConfidenceMedium,
			QuantumRisk: findings.QRResistant,
			Severity:    findings.SevInfo,
		},
	}
	result := BuildResult("0.1.0", "/test", []string{"cipherscope"}, ff)

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, result); err != nil {
		t.Fatalf("WriteSARIF error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if v := parsed["version"]; v != "2.1.0" {
		t.Errorf("version = %v, want 2.1.0", v)
	}
	if _, ok := parsed["$schema"]; !ok {
		t.Error("missing $schema field")
	}

	runs, ok := parsed["runs"].([]interface{})
	if !ok || len(runs) != 1 {
		t.Fatalf("expected 1 run, got %v", runs)
	}
}

// ---------------------------------------------------------------------------
// Additional sanitizeID edge cases
// ---------------------------------------------------------------------------

func TestSanitizeID_EmptyString(t *testing.T) {
	// sanitizeID("") must not panic and must return an empty string.
	got := sanitizeID("")
	if got != "" {
		t.Errorf("sanitizeID(%q) = %q, want %q", "", got, "")
	}
}

func TestSanitizeID_UnicodeCharacters(t *testing.T) {
	// sanitizeID with unicode characters must not panic.
	// The function uses strings.ToUpper which handles unicode safely.
	input := "AES-256-\u65e5\u672c\u8a9e" // "AES-256-日本語"
	got := sanitizeID(input)
	// We just need it not to panic and to contain the ASCII prefix uppercase.
	if len(got) == 0 {
		t.Errorf("sanitizeID(%q) returned empty string, want non-empty", input)
	}
	// The ASCII part should be uppercased and intact.
	expectedPrefix := "AES-256-"
	if len(got) < len(expectedPrefix) || got[:len(expectedPrefix)] != expectedPrefix {
		t.Errorf("sanitizeID(%q) = %q, want prefix %q", input, got, expectedPrefix)
	}
}

func TestWriteSARIF_RulesDedup(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:  findings.Location{File: "/a.go", Line: 10},
			Algorithm: &findings.Algorithm{Name: "RSA-2048"},
			Severity:  findings.SevHigh,
		},
		{
			Location:  findings.Location{File: "/b.go", Line: 20},
			Algorithm: &findings.Algorithm{Name: "RSA-2048"},
			Severity:  findings.SevHigh,
		},
	}
	result := BuildResult("0.1.0", "/test", []string{"cs"}, ff)

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, result); err != nil {
		t.Fatalf("WriteSARIF error: %v", err)
	}

	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("parse: %v", err)
	}

	if len(log.Runs[0].Tool.Driver.Rules) != 1 {
		t.Errorf("rules = %d, want 1 (deduped)", len(log.Runs[0].Tool.Driver.Rules))
	}
	if len(log.Runs[0].Results) != 2 {
		t.Errorf("results = %d, want 2", len(log.Runs[0].Results))
	}
}

// ---------------------------------------------------------------------------
// 8. PQC migration properties in SARIF result.properties
// ---------------------------------------------------------------------------

// TestSARIF_MigrationProperties verifies that TargetAlgorithm, TargetStandard,
// and MigrationSnippet on a finding are emitted as structured properties on the
// corresponding SARIF result.
func TestSARIF_MigrationProperties(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:        findings.Location{File: "/project/auth.go", Line: 12},
			Algorithm:       &findings.Algorithm{Name: "RSA-2048", Primitive: "asymmetric", KeySize: 2048},
			Confidence:      findings.ConfidenceHigh,
			SourceEngine:    "cipherscope",
			QuantumRisk:     findings.QRVulnerable,
			Severity:        findings.SevCritical,
			TargetAlgorithm: "ML-KEM-768",
			TargetStandard:  "NIST FIPS 203",
			MigrationSnippet: &findings.MigrationSnippet{
				Language:    "go",
				Before:      `rsa.GenerateKey(rand.Reader, 2048)`,
				After:       `kemkem.GenerateKey()`,
				Explanation: "Replace RSA key exchange with ML-KEM-768",
			},
		},
	}
	buf := writeSARIFFor(t, ff, "/project")

	// Parse via the raw map so we can inspect the dynamic properties sub-object
	// without needing a typed wrapper for map[string]any.
	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	runs := raw["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	results := run["results"].([]interface{})
	if len(results) != 1 {
		t.Fatalf("results count = %d, want 1", len(results))
	}
	result := results[0].(map[string]interface{})

	props, ok := result["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("result.properties is missing or not an object")
	}

	// targetAlgorithm
	if got, ok := props["targetAlgorithm"].(string); !ok || got != "ML-KEM-768" {
		t.Errorf("properties.targetAlgorithm = %v, want ML-KEM-768", props["targetAlgorithm"])
	}

	// targetStandard
	if got, ok := props["targetStandard"].(string); !ok || got != "NIST FIPS 203" {
		t.Errorf("properties.targetStandard = %v, want NIST FIPS 203", props["targetStandard"])
	}

	// migrationSnippet must be a nested object
	snippet, ok := props["migrationSnippet"].(map[string]interface{})
	if !ok {
		t.Fatal("properties.migrationSnippet is missing or not an object")
	}

	if got, ok := snippet["language"].(string); !ok || got != "go" {
		t.Errorf("migrationSnippet.language = %v, want go", snippet["language"])
	}
	if before, ok := snippet["before"].(string); !ok || before == "" {
		t.Errorf("migrationSnippet.before must be non-empty, got %v", snippet["before"])
	}
	if after, ok := snippet["after"].(string); !ok || after == "" {
		t.Errorf("migrationSnippet.after must be non-empty, got %v", snippet["after"])
	}
}

// TestSARIF_NegotiatedGroupFieldSeparation verifies that the SARIF property for
// the human-readable group name is keyed "negotiatedGroupName" (not "negotiatedGroup"),
// preventing a collision with the JSON field negotiatedGroup (uint16 codepoint).
// JSON: negotiatedGroup = uint16, negotiatedGroupName = string.
// SARIF result.properties: negotiatedGroupName = string (name only; codepoint not emitted).
func TestSARIF_NegotiatedGroupFieldSeparation(t *testing.T) {
	const codepoint = uint16(0x11EC) // X25519MLKEM768
	const name = "X25519MLKEM768"

	ff := []findings.UnifiedFinding{
		{
			Location:            findings.Location{File: "/project/server.go", Line: 1},
			Algorithm:           &findings.Algorithm{Name: name, Primitive: "key-exchange"},
			Confidence:          findings.ConfidenceHigh,
			SourceEngine:        "tls-probe",
			Reachable:           findings.ReachableYes,
			NegotiatedGroup:     codepoint,
			NegotiatedGroupName: name,
			PQCPresent:          true,
		},
	}

	// ── JSON marshaling: uint16 codepoint under "negotiatedGroup" ────────────
	jsonBytes, err := json.Marshal(ff[0])
	if err != nil {
		t.Fatalf("json.Marshal UnifiedFinding: %v", err)
	}
	var jsonMap map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &jsonMap); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if cpt, ok := jsonMap["negotiatedGroup"].(float64); !ok || uint16(cpt) != codepoint {
		t.Errorf("JSON negotiatedGroup = %v, want uint16 codepoint %d", jsonMap["negotiatedGroup"], codepoint)
	}
	if n, ok := jsonMap["negotiatedGroupName"].(string); !ok || n != name {
		t.Errorf("JSON negotiatedGroupName = %v, want %q", jsonMap["negotiatedGroupName"], name)
	}

	// ── SARIF result.properties: string name under "negotiatedGroupName" ─────
	buf := writeSARIFFor(t, ff, "/project")
	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	runs := raw["runs"].([]interface{})
	result := runs[0].(map[string]interface{})["results"].([]interface{})[0].(map[string]interface{})
	props, ok := result["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("result.properties missing")
	}

	gotName, ok := props["negotiatedGroupName"].(string)
	if !ok || gotName != name {
		t.Errorf("SARIF properties.negotiatedGroupName = %v, want %q", props["negotiatedGroupName"], name)
	}
	// The old collision key must not appear.
	if v, present := props["negotiatedGroup"]; present {
		t.Errorf("SARIF properties.negotiatedGroup must be absent (old collision key), got %v", v)
	}
}

// TestSARIF_NoMigrationWhenEmpty verifies that findings with no migration data
// do NOT produce targetAlgorithm or migrationSnippet keys in result.properties.
func TestSARIF_NoMigrationWhenEmpty(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:    findings.Location{File: "/project/crypto.go", Line: 5},
			Algorithm:   &findings.Algorithm{Name: "AES-256-GCM", Primitive: "ae"},
			Confidence:  findings.ConfidenceHigh,
			SourceEngine: "cipherscope",
			QuantumRisk: findings.QRResistant,
			Severity:    findings.SevInfo,
			// TargetAlgorithm: "" (zero value)
			// TargetStandard:  "" (zero value)
			// MigrationSnippet: nil
		},
	}
	buf := writeSARIFFor(t, ff, "/project")

	var raw map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	runs := raw["runs"].([]interface{})
	run := runs[0].(map[string]interface{})
	results := run["results"].([]interface{})
	if len(results) != 1 {
		t.Fatalf("results count = %d, want 1", len(results))
	}
	result := results[0].(map[string]interface{})

	props, ok := result["properties"].(map[string]interface{})
	if !ok {
		t.Fatal("result.properties is missing or not an object")
	}

	if _, present := props["targetAlgorithm"]; present {
		t.Error("properties.targetAlgorithm must be absent when TargetAlgorithm is empty")
	}
	if _, present := props["targetStandard"]; present {
		t.Error("properties.targetStandard must be absent when TargetStandard is empty")
	}
	if _, present := props["migrationSnippet"]; present {
		t.Error("properties.migrationSnippet must be absent when MigrationSnippet is nil")
	}
}

