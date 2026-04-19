package compliance

import (
	"strings"
	"testing"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

var fixedDate = time.Date(2026, 4, 2, 12, 0, 0, 0, time.UTC)

// testFW is the CNSA 2.0 framework used in report tests.
var testFW Framework = cnsa20Framework{}

// algFindingWithEffort creates a finding with MigrationEffort set.
func algFindingWithEffort(name, primitive string, keySize int, qr findings.QuantumRisk, effort string) findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Algorithm:       &findings.Algorithm{Name: name, Primitive: primitive, KeySize: keySize},
		QuantumRisk:     qr,
		MigrationEffort: effort,
	}
}

func TestBuildReportData_Compliant(t *testing.T) {
	ff := []findings.UnifiedFinding{
		algFinding("AES-256-GCM", "symmetric", 256, findings.QRResistant, ""),
		algFinding("ML-KEM-1024", "kem", 1024, findings.QRSafe, "immediate"),
		algFinding("SHA-512", "hash", 512, findings.QRResistant, ""),
	}
	violations := Evaluate(ff)
	data := BuildReportData(testFW, ff, violations,"TestProject", "1.2.3", fixedDate)

	if !data.Compliant {
		t.Errorf("expected Compliant=true, got false; violations: %v", violations)
	}
	if len(data.Violations) != 0 {
		t.Errorf("expected 0 violations, got %d", len(data.Violations))
	}
	if data.TotalFindings != 3 {
		t.Errorf("expected TotalFindings=3, got %d", data.TotalFindings)
	}
	if len(data.Algorithms) != 3 {
		t.Errorf("expected 3 unique algorithms, got %d", len(data.Algorithms))
	}
	if data.Project != "TestProject" {
		t.Errorf("expected Project=TestProject, got %q", data.Project)
	}
	if data.ScannerVer != "1.2.3" {
		t.Errorf("expected ScannerVer=1.2.3, got %q", data.ScannerVer)
	}
	if data.Standard != "CNSA 2.0" {
		t.Errorf("expected Standard=CNSA 2.0, got %q", data.Standard)
	}
}

func TestBuildReportData_NonCompliant(t *testing.T) {
	ff := []findings.UnifiedFinding{
		algFinding("RSA-2048", "asymmetric", 2048, findings.QRVulnerable, "immediate"),
		algFinding("SHA-256", "hash", 256, findings.QRResistant, ""),
	}
	violations := Evaluate(ff)
	data := BuildReportData(testFW, ff, violations,"MyApp", "0.9.0", fixedDate)

	if data.Compliant {
		t.Error("expected Compliant=false for non-compliant findings")
	}
	if len(data.Violations) == 0 {
		t.Error("expected at least one violation")
	}

	// RSA-2048 should appear as violated in algorithm summaries.
	var rsaSummary *AlgorithmSummary
	for i := range data.Algorithms {
		if data.Algorithms[i].Name == "RSA-2048" {
			rsaSummary = &data.Algorithms[i]
			break
		}
	}
	if rsaSummary == nil {
		t.Fatal("RSA-2048 not found in algorithm summaries")
	}
	if rsaSummary.Compliant {
		t.Error("RSA-2048 should be marked non-compliant")
	}
	if rsaSummary.Risk != "Vulnerable" {
		t.Errorf("expected Risk=Vulnerable for RSA-2048, got %q", rsaSummary.Risk)
	}
}

func TestBuildReportData_Empty(t *testing.T) {
	data := BuildReportData(testFW, nil, nil,"", "1.0.0", fixedDate)

	if !data.Compliant {
		t.Error("empty findings should be compliant (no violations possible)")
	}
	if data.TotalFindings != 0 {
		t.Errorf("expected TotalFindings=0, got %d", data.TotalFindings)
	}
	if len(data.Algorithms) != 0 {
		t.Errorf("expected 0 unique algorithms, got %d", len(data.Algorithms))
	}
	if data.ScanDate != fixedDate {
		t.Errorf("expected ScanDate to be fixedDate, got %v", data.ScanDate)
	}
}

func TestBuildReportData_ScanDateDefault(t *testing.T) {
	before := time.Now()
	data := BuildReportData(testFW, nil, nil,"", "1.0.0", time.Time{})
	after := time.Now()

	if data.ScanDate.Before(before) || data.ScanDate.After(after) {
		t.Errorf("expected ScanDate to default to ~now, got %v", data.ScanDate)
	}
}

func TestBuildReportData_AlgorithmDedup(t *testing.T) {
	// Same algorithm name appears multiple times across findings.
	ff := []findings.UnifiedFinding{
		algFinding("AES-128", "symmetric", 128, findings.QRResistant, ""),
		algFinding("AES-128", "symmetric", 128, findings.QRResistant, ""),
		algFinding("AES-128", "symmetric", 128, findings.QRResistant, ""),
		algFinding("RSA-2048", "asymmetric", 2048, findings.QRVulnerable, ""),
	}
	violations := Evaluate(ff)
	data := BuildReportData(testFW, ff, violations,"", "1.0.0", fixedDate)

	// Must have exactly 2 unique algorithms: AES-128 and RSA-2048.
	if len(data.Algorithms) != 2 {
		t.Errorf("expected 2 unique algorithms after dedup, got %d: %v", len(data.Algorithms), data.Algorithms)
	}
	// AES-128 must have occurrences=3.
	var aesSummary *AlgorithmSummary
	for i := range data.Algorithms {
		if data.Algorithms[i].Name == "AES-128" {
			aesSummary = &data.Algorithms[i]
			break
		}
	}
	if aesSummary == nil {
		t.Fatal("AES-128 not found in algorithm summaries")
	}
	if aesSummary.Occurrences != 3 {
		t.Errorf("expected AES-128 Occurrences=3, got %d", aesSummary.Occurrences)
	}
	if data.TotalFindings != 4 {
		t.Errorf("expected TotalFindings=4, got %d", data.TotalFindings)
	}
}

func TestBuildReportData_MultipleViolations(t *testing.T) {
	ff := []findings.UnifiedFinding{
		algFinding("RSA-2048", "asymmetric", 2048, findings.QRVulnerable, "immediate"),
		algFinding("ECDSA", "signature", 0, findings.QRVulnerable, "deferred"),
		algFinding("SHA-256", "hash", 256, findings.QRResistant, ""),
		algFinding("AES-128", "symmetric", 128, findings.QRResistant, ""),
	}
	violations := Evaluate(ff)
	data := BuildReportData(testFW, ff, violations,"BigProject", "2.0.0", fixedDate)

	if len(data.Violations) < 3 {
		t.Errorf("expected at least 3 violations (RSA, ECDSA, SHA-256), got %d", len(data.Violations))
	}
}

func TestBuildReportData_DependencyFinding(t *testing.T) {
	ff := []findings.UnifiedFinding{
		{
			Dependency:    &findings.Dependency{Library: "openssl-1.0.2"},
			RawIdentifier: "openssl-1.0.2",
			QuantumRisk:   findings.QRVulnerable,
			HNDLRisk:      "deferred",
		},
	}
	violations := Evaluate(ff)
	data := BuildReportData(testFW, ff, violations,"", "1.0.0", fixedDate)

	if data.Compliant {
		t.Error("expected non-compliant for quantum-vulnerable dependency")
	}
	if len(data.Algorithms) != 1 {
		t.Errorf("expected 1 algorithm summary for dependency, got %d", len(data.Algorithms))
	}
	if data.Algorithms[0].Name != "openssl-1.0.2" {
		t.Errorf("expected algorithm name=openssl-1.0.2, got %q", data.Algorithms[0].Name)
	}
}

// --- GenerateMarkdown tests ---

func TestGenerateMarkdown_PassStatus(t *testing.T) {
	ff := []findings.UnifiedFinding{
		algFinding("AES-256-GCM", "symmetric", 256, findings.QRResistant, ""),
		algFinding("SHA-512", "hash", 512, findings.QRResistant, ""),
	}
	violations := Evaluate(ff)
	data := BuildReportData(testFW, ff, violations,"GoodProject", "1.0.0", fixedDate)

	var sb strings.Builder
	if err := GenerateMarkdown(&sb, data); err != nil {
		t.Fatalf("GenerateMarkdown returned error: %v", err)
	}
	out := sb.String()

	assertContains(t, out, "**Status:** PASS")
	assertContains(t, out, "no violations")
	assertContains(t, out, "GoodProject")
	assertContains(t, out, "All algorithms meet CNSA 2.0 requirements.")
	assertContains(t, out, "## CNSA 2.0 Approved Algorithms Reference")
	assertContains(t, out, "## Key Deadlines")
	assertContains(t, out, "2030-01-01")
	assertContains(t, out, "2035-12-31")
	// Footer
	assertContains(t, out, "Generated by OQS Scanner")
}

func TestGenerateMarkdown_FailStatus(t *testing.T) {
	ff := []findings.UnifiedFinding{
		algFinding("RSA-2048", "asymmetric", 2048, findings.QRVulnerable, "immediate"),
	}
	violations := Evaluate(ff)
	data := BuildReportData(testFW, ff, violations,"LegacyApp", "1.5.0", fixedDate)

	var sb strings.Builder
	if err := GenerateMarkdown(&sb, data); err != nil {
		t.Fatalf("GenerateMarkdown returned error: %v", err)
	}
	out := sb.String()

	assertContains(t, out, "**Status:** FAIL")
	assertContains(t, out, "1 violation")
	assertContains(t, out, "## Violations")
	assertContains(t, out, "cnsa2-quantum-vulnerable")
	assertContains(t, out, "RSA-2048")
	// Remediation must be present for quantum-vulnerable rule
	assertContains(t, out, "ML-KEM-1024")
	// NOT APPROVED status in compliance table
	assertContains(t, out, "NOT APPROVED")
}

func TestGenerateMarkdown_EmptyFindings(t *testing.T) {
	data := BuildReportData(testFW, nil, nil,"EmptyProject", "1.0.0", fixedDate)

	var sb strings.Builder
	if err := GenerateMarkdown(&sb, data); err != nil {
		t.Fatalf("GenerateMarkdown returned error: %v", err)
	}
	out := sb.String()

	assertContains(t, out, "**Status:** PASS")
	assertContains(t, out, "No cryptographic algorithms were found")
	assertContains(t, out, "No violations found.")
}

func TestGenerateMarkdown_MultipleViolations(t *testing.T) {
	ff := []findings.UnifiedFinding{
		algFinding("RSA-2048", "asymmetric", 2048, findings.QRVulnerable, "immediate"),
		algFinding("ECDH", "key-exchange", 0, findings.QRVulnerable, "deferred"),
		algFinding("SHA-256", "hash", 256, findings.QRResistant, ""),
	}
	violations := Evaluate(ff)
	data := BuildReportData(testFW, ff, violations,"MultiViolProject", "2.0.0", fixedDate)

	var sb strings.Builder
	if err := GenerateMarkdown(&sb, data); err != nil {
		t.Fatalf("GenerateMarkdown returned error: %v", err)
	}
	out := sb.String()

	assertContains(t, out, "FAIL")
	// All violation rules must appear
	assertContains(t, out, "cnsa2-quantum-vulnerable")
	assertContains(t, out, "cnsa2-hash-output-size")
	// Numbered list: at least [1] and [2]
	assertContains(t, out, "### [1]")
	assertContains(t, out, "### [2]")
}

func TestGenerateMarkdown_AlgorithmTable_Approved(t *testing.T) {
	ff := []findings.UnifiedFinding{
		algFinding("ML-KEM-1024", "kem", 1024, findings.QRSafe, ""),
		algFinding("ML-DSA-87", "signature", 0, findings.QRSafe, ""),
	}
	violations := Evaluate(ff)
	data := BuildReportData(testFW, ff, violations,"", "1.0.0", fixedDate)

	var sb strings.Builder
	if err := GenerateMarkdown(&sb, data); err != nil {
		t.Fatalf("GenerateMarkdown returned error: %v", err)
	}
	out := sb.String()

	assertContains(t, out, "| ML-KEM-1024 |")
	assertContains(t, out, "| ML-DSA-87 |")
	// Both should say Approved, not NOT APPROVED
	if strings.Count(out, "NOT APPROVED") > 0 {
		t.Error("expected no NOT APPROVED rows for fully-compliant algorithms")
	}
}

func TestGenerateMarkdown_DeduplicatedAlgorithms(t *testing.T) {
	// Three occurrences of the same algorithm; report should list it once with count=3.
	ff := []findings.UnifiedFinding{
		algFinding("AES-128", "symmetric", 128, findings.QRResistant, ""),
		algFinding("AES-128", "symmetric", 128, findings.QRResistant, ""),
		algFinding("AES-128", "symmetric", 128, findings.QRResistant, ""),
	}
	violations := Evaluate(ff)
	data := BuildReportData(testFW, ff, violations,"", "1.0.0", fixedDate)

	var sb strings.Builder
	if err := GenerateMarkdown(&sb, data); err != nil {
		t.Fatalf("GenerateMarkdown returned error: %v", err)
	}
	out := sb.String()

	// AES-128 should appear in the table exactly once (as a row).
	rowCount := strings.Count(out, "| AES-128 |")
	if rowCount != 1 {
		t.Errorf("expected AES-128 row to appear exactly once, got %d", rowCount)
	}
	// Occurrence count of 3 must appear.
	assertContains(t, out, "| 3 |")
}

func TestGenerateMarkdown_ProjectDefault(t *testing.T) {
	data := BuildReportData(testFW, nil, nil,"", "1.0.0", fixedDate)

	var sb strings.Builder
	if err := GenerateMarkdown(&sb, data); err != nil {
		t.Fatalf("GenerateMarkdown returned error: %v", err)
	}
	out := sb.String()

	assertContains(t, out, "(unspecified)")
}

func TestGenerateMarkdown_VersionPrefix(t *testing.T) {
	// Version without "v" prefix should get one added.
	data := BuildReportData(testFW, nil, nil,"P", "2.1.0", fixedDate)
	var sb strings.Builder
	if err := GenerateMarkdown(&sb, data); err != nil {
		t.Fatalf("GenerateMarkdown returned error: %v", err)
	}
	assertContains(t, sb.String(), "v2.1.0")

	// Version that already starts with "v" should not get a duplicate prefix.
	data2 := BuildReportData(testFW, nil, nil, "P", "v3.0.0", fixedDate)
	var sb2 strings.Builder
	if err := GenerateMarkdown(&sb2, data2); err != nil {
		t.Fatalf("GenerateMarkdown returned error: %v", err)
	}
	out2 := sb2.String()
	assertContains(t, out2, "v3.0.0")
	if strings.Contains(out2, "vv3.0.0") {
		t.Error("version was double-prefixed with 'v'")
	}
}

func assertContains(t *testing.T, body, needle string) {
	t.Helper()
	if !strings.Contains(body, needle) {
		t.Errorf("expected output to contain %q", needle)
	}
}
