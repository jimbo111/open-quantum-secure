// customer_fixes_format_test.go covers the customer-facing output fixes:
//   - table: RawIdentifier fallback for blank IDENTIFIER cells, EFFORT legend,
//     migration-target hint in DETAILS
//   - SARIF: remediation appended to result.message.text, rule
//     fullDescription/help, partialFingerprints from DedupeKey()

package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// --- Table -------------------------------------------------------------------

func TestWriteTable_RawIdentifierFallback(t *testing.T) {
	f := findings.UnifiedFinding{
		Location:      findings.Location{File: "/repo/crypto.py", Line: 12},
		RawIdentifier: "Crypto.PublicKey.RSA.generate",
		SourceEngine:  "cryptoscan",
	}
	result := BuildResult("0.1.0", "/repo", []string{"cryptoscan"}, []findings.UnifiedFinding{f})

	var buf bytes.Buffer
	if err := WriteTable(&buf, result); err != nil {
		t.Fatalf("WriteTable: %v", err)
	}
	out := buf.String()
	// nameW column is 28 runes, so the identifier is truncated with an
	// ellipsis — assert on the surviving prefix, not the full string.
	if !strings.Contains(out, "Crypto.PublicKey.RSA") {
		t.Errorf("expected RawIdentifier fallback in IDENTIFIER column, got:\n%s", out)
	}
}

func TestWriteTable_RawIdentifierFallback_TruncatedAt40(t *testing.T) {
	long := strings.Repeat("a", 60)
	f := findings.UnifiedFinding{
		Location:      findings.Location{File: "/repo/x.go", Line: 1},
		RawIdentifier: long,
	}
	var buf bytes.Buffer
	if err := WriteTable(&buf, BuildResult("0.1.0", "/repo", nil, []findings.UnifiedFinding{f})); err != nil {
		t.Fatalf("WriteTable: %v", err)
	}
	if strings.Contains(buf.String(), long) {
		t.Error("60-char RawIdentifier must be truncated, not rendered whole")
	}
}

func TestWriteTable_AlgorithmNameWins_OverRawIdentifier(t *testing.T) {
	f := findings.UnifiedFinding{
		Location:      findings.Location{File: "/repo/x.go", Line: 1},
		Algorithm:     &findings.Algorithm{Name: "RSA-2048"},
		RawIdentifier: "should-not-appear-in-identifier",
	}
	var buf bytes.Buffer
	if err := WriteTable(&buf, BuildResult("0.1.0", "/repo", nil, []findings.UnifiedFinding{f})); err != nil {
		t.Fatalf("WriteTable: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "RSA-2048") {
		t.Errorf("algorithm name must render, got:\n%s", out)
	}
	if strings.Contains(out, "should-not-appear") {
		t.Errorf("RawIdentifier must not override a populated Algorithm.Name:\n%s", out)
	}
}

func TestWriteTable_Legend_ExplainsEffortBadge(t *testing.T) {
	f := findings.UnifiedFinding{
		Location:  findings.Location{File: "/repo/x.go", Line: 1},
		Algorithm: &findings.Algorithm{Name: "RSA"},
	}
	var buf bytes.Buffer
	if err := WriteTable(&buf, BuildResult("0.1.0", "/repo", nil, []findings.UnifiedFinding{f})); err != nil {
		t.Fatalf("WriteTable: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "[EFFORT:S/M/C]") {
		t.Errorf("legend must explain the EFFORT badge, got:\n%s", out)
	}
	if !strings.Contains(out, "Simple/Moderate/Complex") {
		t.Errorf("legend must expand S/M/C, got:\n%s", out)
	}
}

func TestWriteTable_MigrationTargetHint(t *testing.T) {
	f := findings.UnifiedFinding{
		Location:        findings.Location{File: "/repo/x.go", Line: 3},
		Algorithm:       &findings.Algorithm{Name: "ECDH", Primitive: "kex"},
		TargetAlgorithm: "ML-KEM-768",
	}
	var buf bytes.Buffer
	if err := WriteTable(&buf, BuildResult("0.1.0", "/repo", nil, []findings.UnifiedFinding{f})); err != nil {
		t.Fatalf("WriteTable: %v", err)
	}
	if !strings.Contains(buf.String(), "→ ML-KEM-768") {
		t.Errorf("expected migration-target hint in DETAILS, got:\n%s", buf.String())
	}
}

func TestWriteTable_NoMigrationHint_WhenTargetEmpty(t *testing.T) {
	f := findings.UnifiedFinding{
		Location:  findings.Location{File: "/repo/x.go", Line: 3},
		Algorithm: &findings.Algorithm{Name: "AES-256"},
	}
	var buf bytes.Buffer
	if err := WriteTable(&buf, BuildResult("0.1.0", "/repo", nil, []findings.UnifiedFinding{f})); err != nil {
		t.Fatalf("WriteTable: %v", err)
	}
	if strings.Contains(buf.String(), "→") {
		t.Errorf("no arrow expected without TargetAlgorithm, got:\n%s", buf.String())
	}
}

// --- SARIF -------------------------------------------------------------------

func sarifFor(t *testing.T, ff []findings.UnifiedFinding) sarifLog {
	t.Helper()
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, BuildResult("0.1.0", "/repo", nil, ff)); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("unmarshal SARIF: %v", err)
	}
	return log
}

func remediatedFinding() findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Location:        findings.Location{File: "/repo/main.go", Line: 7},
		Algorithm:       &findings.Algorithm{Name: "RSA-2048", Primitive: "signature"},
		SourceEngine:    "cipherscope",
		QuantumRisk:     findings.QRVulnerable,
		Severity:        findings.SevCritical,
		Recommendation:  "Replace RSA key exchange with a hybrid ML-KEM scheme",
		TargetAlgorithm: "ML-DSA-87",
		TargetStandard:  "FIPS 204",
	}
}

func TestSARIF_Message_CarriesRemediation(t *testing.T) {
	log := sarifFor(t, []findings.UnifiedFinding{remediatedFinding()})
	msg := log.Runs[0].Results[0].Message.Text

	lines := strings.Split(msg, "\n")
	if !strings.HasPrefix(lines[0], "Cryptographic algorithm detected: RSA-2048") {
		t.Errorf("first line must stay the detection summary, got %q", lines[0])
	}
	if !strings.Contains(msg, "Recommendation: Replace RSA key exchange with a hybrid ML-KEM scheme") {
		t.Errorf("message must carry the recommendation, got %q", msg)
	}
	if !strings.Contains(msg, "Migrate to: ML-DSA-87 (FIPS 204)") {
		t.Errorf("message must carry the migration target, got %q", msg)
	}
}

func TestSARIF_Message_NoRemediation_Unchanged(t *testing.T) {
	f := findings.UnifiedFinding{
		Location:  findings.Location{File: "/repo/x.go", Line: 1},
		Algorithm: &findings.Algorithm{Name: "AES-256"},
	}
	log := sarifFor(t, []findings.UnifiedFinding{f})
	msg := log.Runs[0].Results[0].Message.Text
	if strings.Contains(msg, "\n") || strings.Contains(msg, "Recommendation") {
		t.Errorf("message without remediation content must stay single-line, got %q", msg)
	}
}

func TestSARIF_Rule_FullDescriptionAndHelp(t *testing.T) {
	log := sarifFor(t, []findings.UnifiedFinding{remediatedFinding()})
	rule := log.Runs[0].Tool.Driver.Rules[0]

	if rule.FullDescription == nil || rule.FullDescription.Text == "" {
		t.Fatal("rule.fullDescription must be populated")
	}
	if !strings.Contains(rule.FullDescription.Text, "quantum-vulnerable") {
		t.Errorf("fullDescription should carry the quantum risk, got %q", rule.FullDescription.Text)
	}
	if rule.Help == nil {
		t.Fatal("rule.help must be populated when remediation content exists")
	}
	if !strings.Contains(rule.Help.Text, "Replace RSA key exchange") {
		t.Errorf("help.text must carry the recommendation, got %q", rule.Help.Text)
	}
	if !strings.Contains(rule.Help.Markdown, "**Recommendation:**") {
		t.Errorf("help.markdown must be markdown-formatted, got %q", rule.Help.Markdown)
	}
	if !strings.Contains(rule.Help.Markdown, "`ML-DSA-87`") {
		t.Errorf("help.markdown must carry the migration target, got %q", rule.Help.Markdown)
	}
}

func TestSARIF_Rule_NoHelp_WithoutRemediation(t *testing.T) {
	f := findings.UnifiedFinding{
		Location:  findings.Location{File: "/repo/x.go", Line: 1},
		Algorithm: &findings.Algorithm{Name: "AES-256"},
	}
	log := sarifFor(t, []findings.UnifiedFinding{f})
	rule := log.Runs[0].Tool.Driver.Rules[0]
	if rule.Help != nil {
		t.Errorf("rule.help must be omitted without remediation content, got %+v", rule.Help)
	}
	if rule.FullDescription == nil {
		t.Error("rule.fullDescription should still be present (from shortDescription)")
	}
}

func TestSARIF_PartialFingerprints_FromDedupeKey(t *testing.T) {
	f := remediatedFinding()
	log := sarifFor(t, []findings.UnifiedFinding{f})
	res := log.Runs[0].Results[0]

	fp, ok := res.PartialFingerprints["oqsDedupeKey/v1"]
	if !ok {
		t.Fatalf("partialFingerprints must carry oqsDedupeKey/v1, got %v", res.PartialFingerprints)
	}
	if want := f.DedupeKey(); fp != want {
		t.Errorf("fingerprint = %q, want DedupeKey %q", fp, want)
	}
}

func TestSARIF_PartialFingerprints_StableAcrossRuns(t *testing.T) {
	ff := []findings.UnifiedFinding{remediatedFinding()}
	fp1 := sarifFor(t, ff).Runs[0].Results[0].PartialFingerprints["oqsDedupeKey/v1"]
	fp2 := sarifFor(t, ff).Runs[0].Results[0].PartialFingerprints["oqsDedupeKey/v1"]
	if fp1 == "" || fp1 != fp2 {
		t.Errorf("fingerprint must be stable, got %q vs %q", fp1, fp2)
	}
}
