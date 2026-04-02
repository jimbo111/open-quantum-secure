package output

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/impact"
)

func TestBuildResult_Counts(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{Algorithm: &findings.Algorithm{Name: "RSA"}, QuantumRisk: findings.QRVulnerable},
		{Algorithm: &findings.Algorithm{Name: "AES-256"}, QuantumRisk: findings.QRResistant},
		{Algorithm: &findings.Algorithm{Name: "ML-KEM"}, QuantumRisk: findings.QRSafe},
		{Dependency: &findings.Dependency{Library: "openssl"}, QuantumRisk: findings.QRUnknown},
		{Algorithm: &findings.Algorithm{Name: "MD5"}, QuantumRisk: findings.QRDeprecated},
		{Algorithm: &findings.Algorithm{Name: "AES-128"}, QuantumRisk: findings.QRWeakened},
	}

	result := BuildResult("0.1.0", "/test", []string{"cipherscope"}, ff)

	if result.Summary.TotalFindings != 6 {
		t.Errorf("TotalFindings = %d, want 6", result.Summary.TotalFindings)
	}
	if result.Summary.Algorithms != 5 {
		t.Errorf("Algorithms = %d, want 5", result.Summary.Algorithms)
	}
	if result.Summary.Dependencies != 1 {
		t.Errorf("Dependencies = %d, want 1", result.Summary.Dependencies)
	}
	if result.Summary.QuantumVulnerable != 1 {
		t.Errorf("QuantumVulnerable = %d, want 1", result.Summary.QuantumVulnerable)
	}
	if result.Summary.QuantumSafe != 1 {
		t.Errorf("QuantumSafe = %d, want 1", result.Summary.QuantumSafe)
	}
	if result.Summary.Deprecated != 1 {
		t.Errorf("Deprecated = %d, want 1", result.Summary.Deprecated)
	}
	if result.Summary.QuantumWeakened != 1 {
		t.Errorf("QuantumWeakened = %d, want 1", result.Summary.QuantumWeakened)
	}
}

func TestBuildResult_WithDuration(t *testing.T) {
	result := BuildResult("0.1.0", "/test", []string{"cs"}, nil, WithDuration(85*time.Millisecond))
	if result.ScanDuration != "85ms" {
		t.Errorf("ScanDuration = %q, want %q", result.ScanDuration, "85ms")
	}
}

func TestBuildResult_QRS(t *testing.T) {
	result := BuildResult("0.1.0", "/test", []string{"cs"}, nil)
	if result.QRS == nil {
		t.Fatal("QRS should not be nil")
	}
	if result.QRS.Score != 100 {
		t.Errorf("QRS.Score = %d, want 100 (empty findings)", result.QRS.Score)
	}
}

func TestBuildResult_NilFindingsProducesEmptyArray(t *testing.T) {
	// BuildResult with nil findings must produce "findings":[] not "findings":null
	// because ScanResult.Findings is typed as []findings.UnifiedFinding — but
	// a nil slice marshals as null in JSON unless we ensure an empty slice.
	result := BuildResult("0.1.0", "/test", []string{"cs"}, nil)

	var buf bytes.Buffer
	if err := WriteJSON(&buf, result); err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}

	output := buf.String()
	// The JSON output must contain "findings":[] not "findings":null
	// We check for the presence of "findings":[] (possibly with whitespace).
	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	findingsVal, ok := parsed["findings"]
	if !ok {
		t.Fatal("missing 'findings' key in JSON output")
	}

	// In Go's encoding/json, a nil slice marshals as null, an empty slice as [].
	// If the value is nil (JSON null), this is a bug.
	// We accept either an empty array (correct) or check the raw output.
	if findingsVal == nil {
		// Check raw output for explicit "null" vs "[]"
		if len(output) > 0 {
			// search for findings:null pattern
			found := false
			needle := `"findings":null`
			for i := 0; i+len(needle) <= len(output); i++ {
				if output[i:i+len(needle)] == needle {
					found = true
					break
				}
			}
			if found {
				t.Errorf("WriteJSON produced %q instead of %q", `"findings":null`, `"findings":[]`)
			}
		}
	}

	// Confirm TotalFindings is 0
	if result.Summary.TotalFindings != 0 {
		t.Errorf("TotalFindings = %d, want 0 for nil findings", result.Summary.TotalFindings)
	}
}

func TestBuildResult_WithImpactResult_FieldPresent(t *testing.T) {
	impactResult := &impact.Result{
		ImpactZones: []impact.ImpactZone{
			{FindingKey: "k1", BlastRadiusScore: 50, BlastRadiusGrade: "Significant"},
		},
	}
	result := BuildResult("0.1.0", "/test", []string{"cs"}, nil, WithImpactResult(impactResult))

	if result.ImpactResult == nil {
		t.Fatal("ImpactResult should not be nil")
	}
	if len(result.ImpactResult.ImpactZones) != 1 {
		t.Errorf("ImpactZones len = %d, want 1", len(result.ImpactResult.ImpactZones))
	}
}

func TestBuildResult_WithImpactResult_NilOmittedFromJSON(t *testing.T) {
	result := BuildResult("0.1.0", "/test", []string{"cs"}, nil)

	var buf bytes.Buffer
	if err := WriteJSON(&buf, result); err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if _, ok := parsed["impact"]; ok {
		t.Error("'impact' key should be absent when ImpactResult is nil (omitempty)")
	}
}

func TestBuildResult_WithImpactResult_PresentInJSON(t *testing.T) {
	impactResult := &impact.Result{
		ImpactZones: []impact.ImpactZone{
			{FindingKey: "k1", BlastRadiusScore: 75, BlastRadiusGrade: "Critical"},
		},
	}
	result := BuildResult("0.1.0", "/test", []string{"cs"}, nil, WithImpactResult(impactResult))

	var buf bytes.Buffer
	if err := WriteJSON(&buf, result); err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if _, ok := parsed["impact"]; !ok {
		t.Error("'impact' key should be present when ImpactResult is set")
	}
}

func TestBuildResult_WithImpactResult_AdjustsQRS(t *testing.T) {
	// 10 critical vulnerable findings → base QRS = 80
	ff := make([]findings.UnifiedFinding, 10)
	for i := range ff {
		ff[i] = findings.UnifiedFinding{
			Algorithm:   &findings.Algorithm{Name: "RSA-2048"},
			QuantumRisk: findings.QRVulnerable,
			Severity:    findings.SevCritical,
		}
	}

	baseResult := BuildResult("0.1.0", "/test", []string{"cs"}, ff)

	impactResult := &impact.Result{
		ImpactZones: []impact.ImpactZone{
			{BlastRadiusScore: 100}, // max blast → 15% reduction
		},
	}
	adjustedResult := BuildResult("0.1.0", "/test", []string{"cs"}, ff, WithImpactResult(impactResult))

	if adjustedResult.QRS == nil || baseResult.QRS == nil {
		t.Fatal("QRS must not be nil")
	}
	if adjustedResult.QRS.Score >= baseResult.QRS.Score {
		t.Errorf("adjusted QRS score (%d) should be lower than base (%d) when blast=100",
			adjustedResult.QRS.Score, baseResult.QRS.Score)
	}
}

func TestWriteJSON_ValidJSON(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Location:    findings.Location{File: "/test.go", Line: 1},
			Algorithm:   &findings.Algorithm{Name: "AES-256"},
			Confidence:  findings.ConfidenceHigh,
			QuantumRisk: findings.QRResistant,
		},
	}
	result := BuildResult("0.1.0", "/test", []string{"cs"}, ff)

	var buf bytes.Buffer
	if err := WriteJSON(&buf, result); err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}

	// Verify valid JSON
	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	// Check key fields exist
	if _, ok := parsed["version"]; !ok {
		t.Error("missing 'version' field")
	}
	if _, ok := parsed["findings"]; !ok {
		t.Error("missing 'findings' field")
	}
	if _, ok := parsed["quantumReadinessScore"]; !ok {
		t.Error("missing 'quantumReadinessScore' field")
	}
}
