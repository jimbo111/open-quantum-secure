package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/quantum"
)

// helpers

func basicResult() ScanResult {
	return ScanResult{
		Version: "1.0.0",
		Target:  "/src/myproject",
		Engines: []string{"cipherscope", "cryptoscan"},
		Summary: Summary{},
	}
}

func algFinding(name string, risk findings.QuantumRisk, sev findings.Severity) findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Location:     findings.Location{File: "main.go", Line: 42},
		Algorithm:    &findings.Algorithm{Name: name, Primitive: "asymmetric"},
		QuantumRisk:  risk,
		Severity:     sev,
		Confidence:   findings.ConfidenceHigh,
		SourceEngine: "cipherscope",
	}
}

func render(t *testing.T, result ScanResult) string {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteHTML(&buf, result); err != nil {
		t.Fatalf("WriteHTML error: %v", err)
	}
	return buf.String()
}

// TestWriteHTML_BasicOutput verifies the template renders without error and
// contains key structural HTML elements.
func TestWriteHTML_BasicOutput(t *testing.T) {
	result := basicResult()
	result.Findings = []findings.UnifiedFinding{
		algFinding("RSA-2048", findings.QRVulnerable, findings.SevHigh),
	}
	result.Summary.TotalFindings = 1
	out := render(t, result)

	must := []string{
		"<!DOCTYPE html>",
		"OQS Scanner Report",
		"<table",
		"Quantum Readiness Score",
		"CNSA 2.0 Migration Timeline",
	}
	for _, want := range must {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

// TestWriteHTML_NoFindings verifies the empty-state message is shown.
func TestWriteHTML_NoFindings(t *testing.T) {
	result := basicResult()
	out := render(t, result)

	if !strings.Contains(out, "No findings detected") {
		t.Error("expected empty-state message when no findings")
	}
}

// TestWriteHTML_WithFindings verifies finding data appears in the output.
func TestWriteHTML_WithFindings(t *testing.T) {
	result := basicResult()
	result.Findings = []findings.UnifiedFinding{
		algFinding("RSA-2048", findings.QRVulnerable, findings.SevHigh),
	}
	result.Summary.TotalFindings = 1
	result.Summary.QuantumVulnerable = 1

	out := render(t, result)

	checks := []string{
		"RSA-2048",
		"main.go",
		"cipherscope",
	}
	for _, want := range checks {
		if !strings.Contains(out, want) {
			t.Errorf("output missing finding data %q", want)
		}
	}
}

// TestWriteHTML_QRSDisplay verifies score and grade appear in the output.
func TestWriteHTML_QRSDisplay(t *testing.T) {
	result := basicResult()
	qrs := quantum.QRS{Score: 85, Grade: "A"}
	result.QRS = &qrs

	out := render(t, result)

	if !strings.Contains(out, "85") {
		t.Error("expected score 85 in output")
	}
	if !strings.Contains(out, ">A<") {
		t.Error("expected grade A in output")
	}
}

// TestWriteHTML_NilQRS verifies nil QRS is handled gracefully (no panic, shows N/A).
func TestWriteHTML_NilQRS(t *testing.T) {
	result := basicResult()
	result.QRS = nil

	out := render(t, result) // must not panic

	if !strings.Contains(out, "N/A") {
		t.Error("expected N/A when QRS is nil")
	}
}

// TestWriteHTML_DataFlowPath verifies collapsible details element for data flow.
func TestWriteHTML_DataFlowPath(t *testing.T) {
	f := algFinding("AES-128", findings.QRWeakened, findings.SevMedium)
	f.DataFlowPath = []findings.FlowStep{
		{File: "crypto.go", Line: 10, Message: "key generated"},
		{File: "server.go", Line: 55, Message: "key used for TLS"},
	}

	result := basicResult()
	result.Findings = []findings.UnifiedFinding{f}
	result.Summary.TotalFindings = 1

	out := render(t, result)

	checks := []string{
		"<details>",
		"data flow",
		"crypto.go:10",
		"server.go:55",
		"key generated",
		"key used for TLS",
	}
	for _, want := range checks {
		if !strings.Contains(out, want) {
			t.Errorf("data flow output missing %q", want)
		}
	}
}

// TestWriteHTML_EmptyDataFlowPath verifies no details element when path is empty.
func TestWriteHTML_EmptyDataFlowPath(t *testing.T) {
	f := algFinding("AES-128", findings.QRWeakened, findings.SevMedium)
	// DataFlowPath is nil / zero value

	result := basicResult()
	result.Findings = []findings.UnifiedFinding{f}
	result.Summary.TotalFindings = 1

	out := render(t, result)

	if strings.Contains(out, "<details>") {
		t.Error("expected no <details> element when DataFlowPath is empty")
	}
}

// TestWriteHTML_XSSEscape verifies HTML special chars in algorithm name are escaped.
func TestWriteHTML_XSSEscape(t *testing.T) {
	f := algFinding("<script>alert(1)</script>", findings.QRVulnerable, findings.SevCritical)
	result := basicResult()
	result.Findings = []findings.UnifiedFinding{f}
	result.Summary.TotalFindings = 1

	out := render(t, result)

	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Error("raw <script> tag must be escaped in HTML output")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Error("expected HTML-escaped script tag in output")
	}
}

// TestWriteHTML_AllQuantumRisks verifies all risk types render proper badge classes.
func TestWriteHTML_AllQuantumRisks(t *testing.T) {
	cases := []struct {
		risk findings.QuantumRisk
		cls  string
	}{
		{findings.QRVulnerable, "badge-vulnerable"},
		{findings.QRWeakened, "badge-weakened"},
		{findings.QRSafe, "badge-safe"},
		{findings.QRResistant, "badge-resistant"},
		{findings.QRDeprecated, "badge-deprecated"},
	}

	for _, tc := range cases {
		f := algFinding("RSA", tc.risk, findings.SevMedium)
		result := basicResult()
		result.Findings = []findings.UnifiedFinding{f}
		result.Summary.TotalFindings = 1

		out := render(t, result)
		if !strings.Contains(out, tc.cls) {
			t.Errorf("risk %s: expected badge class %q in output", tc.risk, tc.cls)
		}
	}
}

// TestWriteHTML_ScanDuration verifies scan duration appears when set.
func TestWriteHTML_ScanDuration(t *testing.T) {
	result := basicResult()
	result.ScanDuration = "1.234s"

	out := render(t, result)

	if !strings.Contains(out, "1.234s") {
		t.Error("expected scan duration in output")
	}
}

// TestWriteHTML_NoDuration verifies no duration shown when field is empty.
func TestWriteHTML_NoDuration(t *testing.T) {
	result := basicResult()
	result.ScanDuration = ""

	out := render(t, result)

	if strings.Contains(out, "Duration:") {
		t.Error("expected no duration field when ScanDuration is empty")
	}
}

// TestWriteHTML_EnginesList verifies engines join properly.
func TestWriteHTML_EnginesList(t *testing.T) {
	result := basicResult()
	result.Engines = []string{"cipherscope", "cryptoscan", "ast-grep"}

	out := render(t, result)

	if !strings.Contains(out, "cipherscope, cryptoscan, ast-grep") {
		t.Error("expected comma-joined engine list in output")
	}
}

// TestGradeColor verifies gradeColorFunc returns the correct CSS colors.
func TestGradeColor(t *testing.T) {
	cases := []struct {
		grade string
		want  string
	}{
		{"A+", "#22c55e"},
		{"A", "#22c55e"},
		{"A-", "#22c55e"},
		{"B+", "#3b82f6"},
		{"B", "#3b82f6"},
		{"B-", "#3b82f6"},
		{"C+", "#eab308"},
		{"C", "#eab308"},
		{"C-", "#eab308"},
		{"D+", "#f97316"},
		{"D", "#f97316"},
		{"F", "#ef4444"},
	}

	for _, tc := range cases {
		got := gradeColorFunc(tc.grade)
		if got != tc.want {
			t.Errorf("gradeColorFunc(%q) = %q, want %q", tc.grade, got, tc.want)
		}
	}
}

// TestRiskColor verifies riskColorFunc returns the correct class suffixes.
func TestRiskColor(t *testing.T) {
	cases := []struct {
		risk findings.QuantumRisk
		want string
	}{
		{findings.QRVulnerable, "vulnerable"},
		{findings.QRWeakened, "weakened"},
		{findings.QRSafe, "safe"},
		{findings.QRResistant, "resistant"},
		{findings.QRDeprecated, "deprecated"},
		{findings.QRUnknown, "unknown"},
	}

	for _, tc := range cases {
		got := riskColorFunc(tc.risk)
		if got != tc.want {
			t.Errorf("riskColorFunc(%q) = %q, want %q", tc.risk, got, tc.want)
		}
	}
}

// TestRiskLabel verifies riskLabelFunc returns human-readable labels.
func TestRiskLabel(t *testing.T) {
	cases := []struct {
		risk findings.QuantumRisk
		want string
	}{
		{findings.QRVulnerable, "Vulnerable"},
		{findings.QRWeakened, "Weakened"},
		{findings.QRSafe, "Safe"},
		{findings.QRResistant, "Resistant"},
		{findings.QRDeprecated, "Deprecated"},
		{findings.QRUnknown, "Unknown"},
	}

	for _, tc := range cases {
		got := riskLabelFunc(tc.risk)
		if got != tc.want {
			t.Errorf("riskLabelFunc(%q) = %q, want %q", tc.risk, got, tc.want)
		}
	}
}

// TestSevColor verifies sevColorFunc returns the correct class suffixes.
func TestSevColor(t *testing.T) {
	cases := []struct {
		sev  findings.Severity
		want string
	}{
		{findings.SevCritical, "critical"},
		{findings.SevHigh, "high"},
		{findings.SevMedium, "medium"},
		{findings.SevLow, "low"},
		{findings.SevInfo, "info"},
	}

	for _, tc := range cases {
		got := sevColorFunc(tc.sev)
		if got != tc.want {
			t.Errorf("sevColorFunc(%q) = %q, want %q", tc.sev, got, tc.want)
		}
	}
}

// TestWriteHTML_DependencyFinding verifies dependency findings show library name.
func TestWriteHTML_DependencyFinding(t *testing.T) {
	f := findings.UnifiedFinding{
		Location:     findings.Location{File: "go.sum", Line: 1},
		Dependency:   &findings.Dependency{Library: "crypto/openssl"},
		QuantumRisk:  findings.QRVulnerable,
		Severity:     findings.SevHigh,
		Confidence:   findings.ConfidenceMedium,
		SourceEngine: "cryptodeps",
	}
	result := basicResult()
	result.Findings = []findings.UnifiedFinding{f}
	result.Summary.TotalFindings = 1

	out := render(t, result)

	if !strings.Contains(out, "crypto/openssl") {
		t.Error("expected library name in output")
	}
}

// TestWriteHTML_CNSATimeline verifies CNSA 2.0 section is present.
func TestWriteHTML_CNSATimeline(t *testing.T) {
	out := render(t, basicResult())

	checks := []string{
		"2030",
		"2035",
		"CNSA 2.0",
	}
	for _, want := range checks {
		if !strings.Contains(out, want) {
			t.Errorf("CNSA timeline section missing %q", want)
		}
	}
}

// TestWriteHTML_CorroboratedBy verifies corroboration data renders correctly.
func TestWriteHTML_CorroboratedBy(t *testing.T) {
	t.Run("corroborated finding shows engine names", func(t *testing.T) {
		f := algFinding("RSA-2048", findings.QRVulnerable, findings.SevHigh)
		f.CorroboratedBy = []string{"cipherscope", "cryptoscan"}

		result := basicResult()
		result.Findings = []findings.UnifiedFinding{f}
		result.Summary.TotalFindings = 1

		out := render(t, result)

		if !strings.Contains(out, "cipherscope") {
			t.Error("expected corroborating engine 'cipherscope' in output")
		}
		if !strings.Contains(out, "cryptoscan") {
			t.Error("expected corroborating engine 'cryptoscan' in output")
		}
	})

	t.Run("non-corroborated finding shows em-dash", func(t *testing.T) {
		f := algFinding("RSA-2048", findings.QRVulnerable, findings.SevHigh)
		// CorroboratedBy is nil

		result := basicResult()
		result.Findings = []findings.UnifiedFinding{f}
		result.Summary.TotalFindings = 1

		out := render(t, result)

		if !strings.Contains(out, "&mdash;") {
			t.Error("expected em-dash for nil CorroboratedBy")
		}
	})

	t.Run("XSS in engine name is escaped", func(t *testing.T) {
		f := algFinding("RSA-2048", findings.QRVulnerable, findings.SevHigh)
		f.CorroboratedBy = []string{"<script>alert(1)</script>"}

		result := basicResult()
		result.Findings = []findings.UnifiedFinding{f}
		result.Summary.TotalFindings = 1

		out := render(t, result)

		if strings.Contains(out, "<script>alert(1)</script>") {
			t.Error("raw <script> in CorroboratedBy must be escaped")
		}
		if !strings.Contains(out, "&lt;script&gt;") {
			t.Error("expected HTML-escaped script tag from CorroboratedBy")
		}
	})
}

// TestWriteHTML_ReachableBadges verifies reachability badges render with correct classes and labels.
func TestWriteHTML_ReachableBadges(t *testing.T) {
	cases := []struct {
		reach    findings.Reachability
		wantClass string
		wantLabel string
		sortKey   string
	}{
		{findings.ReachableYes, "badge-reachable", "Yes", "0"},
		{findings.ReachableNo, "badge-unreachable", "No", "2"},
		{findings.ReachableUnknown, "badge-unknown", "Unknown", "1"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(string(tc.reach), func(t *testing.T) {
			f := algFinding("AES-128", findings.QRWeakened, findings.SevMedium)
			f.Reachable = tc.reach

			result := basicResult()
			result.Findings = []findings.UnifiedFinding{f}
			result.Summary.TotalFindings = 1

			out := render(t, result)

			if !strings.Contains(out, tc.wantClass) {
				t.Errorf("reachable=%s: expected badge class %q in output", tc.reach, tc.wantClass)
			}
			if !strings.Contains(out, tc.wantLabel) {
				t.Errorf("reachable=%s: expected label %q in output", tc.reach, tc.wantLabel)
			}
			if !strings.Contains(out, `data-sort="`+tc.sortKey+`"`) {
				t.Errorf("reachable=%s: expected data-sort=%q in output", tc.reach, tc.sortKey)
			}
		})
	}
}

// TestReachBadge verifies reachBadgeFunc returns correct CSS class suffixes.
func TestReachBadge(t *testing.T) {
	cases := []struct {
		reach findings.Reachability
		want  string
	}{
		{findings.ReachableYes, "reachable"},
		{findings.ReachableNo, "unreachable"},
		{findings.ReachableUnknown, "unknown"},
		{"", "unknown"},
	}

	for _, tc := range cases {
		got := reachBadgeFunc(tc.reach)
		if got != tc.want {
			t.Errorf("reachBadgeFunc(%q) = %q, want %q", tc.reach, got, tc.want)
		}
	}
}

// TestReachLabel verifies reachLabelFunc returns correct human-readable labels.
func TestReachLabel(t *testing.T) {
	cases := []struct {
		reach findings.Reachability
		want  string
	}{
		{findings.ReachableYes, "Yes"},
		{findings.ReachableNo, "No"},
		{findings.ReachableUnknown, "Unknown"},
		{"", "Unknown"},
	}

	for _, tc := range cases {
		got := reachLabelFunc(tc.reach)
		if got != tc.want {
			t.Errorf("reachLabelFunc(%q) = %q, want %q", tc.reach, got, tc.want)
		}
	}
}

// TestReachSort verifies reachSortFunc returns correct numeric sort keys.
func TestReachSort(t *testing.T) {
	cases := []struct {
		reach findings.Reachability
		want  int
	}{
		{findings.ReachableYes, 0},
		{findings.ReachableNo, 2},
		{findings.ReachableUnknown, 1},
		{"", 1},
	}

	for _, tc := range cases {
		got := reachSortFunc(tc.reach)
		if got != tc.want {
			t.Errorf("reachSortFunc(%q) = %d, want %d", tc.reach, got, tc.want)
		}
	}
}
