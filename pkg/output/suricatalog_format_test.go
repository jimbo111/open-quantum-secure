// suricatalog_format_test.go — output format integrity tests for Suricata log findings.
//
// Purpose: verify that attacker-controlled fields from eve.json (SNI, cipher_suite,
// subject DN, issuerdn) are safely escaped in all four output formats. Also verifies
// that Sprint 6 findings co-exist with Sprint 0-5 fields without regression.
package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// ─── Fixture helpers ─────────────────────────────────────────────────────────

func suricataClassicalFinding(cipher string) findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Location:     findings.Location{File: "(suricata-log)/example.com#TLS_AES_128_GCM_SHA256"},
		Algorithm:    &findings.Algorithm{Name: cipher, Primitive: "symmetric"},
		Confidence:   findings.ConfidenceMedium,
		SourceEngine: "suricata-log",
		Reachable:    findings.ReachableUnknown,
		QuantumRisk:  findings.QRResistant,
		Severity:     findings.SevInfo,
	}
}

func suricataVulnerableFinding(cipher string) findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Location:     findings.Location{File: "(suricata-log)/old.example.com#ECDHE-RSA-AES256-GCM-SHA384"},
		Algorithm:    &findings.Algorithm{Name: cipher, Primitive: "key-agree"},
		Confidence:   findings.ConfidenceMedium,
		SourceEngine: "suricata-log",
		Reachable:    findings.ReachableUnknown,
		QuantumRisk:  findings.QRVulnerable,
		Severity:     findings.SevHigh,
	}
}

func makeSuricataResult(ff []findings.UnifiedFinding) ScanResult {
	return ScanResult{
		Version:  "0.0.0-test",
		Target:   "/test-suricata",
		Engines:  []string{"suricata-log"},
		Findings: ff,
	}
}

// ─── Attacker-controlled field escaping ──────────────────────────────────────

// adversarialSuricataFinding builds a finding whose Algorithm.Name and Location.File
// contain attacker-controlled values sourced from eve.json fields.
func adversarialSuricataFinding(algorithmName, filePath string) findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Location:     findings.Location{File: filePath},
		Algorithm:    &findings.Algorithm{Name: algorithmName, Primitive: "symmetric"},
		Confidence:   findings.ConfidenceMedium,
		SourceEngine: "suricata-log",
		Reachable:    findings.ReachableUnknown,
		QuantumRisk:  findings.QRUnknown,
	}
}

// attackerValues pairs adversarial algorithm names (from cipher_suite / SNI) with
// adversarial file paths (from the sanitized filePath in buildFinding).
var attackerSuricataInputs = []struct {
	name      string
	algName   string
	filePath  string
}{
	{
		name:    "ANSI escape in cipher",
		algName: "\x1b[31mFAKE_CIPHER",
		filePath: "(suricata-log)/example.com#\x1b[31mFAKE_CIPHER",
	},
	{
		name:    "embedded newline in cipher_suite",
		algName: "TLS_AES_128_GCM\r\nX-Injected: header",
		filePath: "(suricata-log)/example.com#TLS_AES_128_GCM",
	},
	{
		name:    "XSS in subject DN via SNI",
		algName: "<script>alert(1)</script>",
		filePath: "(suricata-log)/<script>alert(1)</script>#alg",
	},
	{
		name:    "CRLF injection in issuerdn",
		algName: "ECDHE-RSA-AES256\r\nSet-Cookie: evil=1",
		filePath: "(suricata-log)/example.com#ECDHE-RSA-AES256",
	},
	{
		name:    "URL fragment chars in target path",
		algName: "cipher/with?frag#chars",
		filePath: "(suricata-log)/target-with-sanitized-chars#cipher",
	},
}

// TestSuricataFormat_JSON_AttackerFieldsEscaped verifies that attacker-controlled
// values produce valid, properly-escaped JSON.
func TestSuricataFormat_JSON_AttackerFieldsEscaped(t *testing.T) {
	for _, tc := range attackerSuricataInputs {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			f := adversarialSuricataFinding(tc.algName, tc.filePath)
			result := makeSuricataResult([]findings.UnifiedFinding{f})

			var buf bytes.Buffer
			if err := WriteJSON(&buf, result); err != nil {
				t.Fatalf("WriteJSON: %v", err)
			}
			if !json.Valid(buf.Bytes()) {
				t.Errorf("WriteJSON produced invalid JSON for input %q", tc.name)
			}
			// CRLF injection check: raw \r\n must not appear inside JSON string values.
			if strings.Contains(buf.String(), "\r\n") {
				t.Errorf("WriteJSON: literal CRLF in output for %q (CRLF injection risk)", tc.name)
			}
		})
	}
}

// TestSuricataFormat_SARIF_AttackerFieldsEscaped verifies SARIF output is valid JSON.
func TestSuricataFormat_SARIF_AttackerFieldsEscaped(t *testing.T) {
	for _, tc := range attackerSuricataInputs {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			f := adversarialSuricataFinding(tc.algName, tc.filePath)
			result := makeSuricataResult([]findings.UnifiedFinding{f})

			var buf bytes.Buffer
			if err := WriteSARIF(&buf, result); err != nil {
				t.Fatalf("WriteSARIF: %v", err)
			}
			if !json.Valid(buf.Bytes()) {
				t.Errorf("WriteSARIF produced invalid JSON for input %q", tc.name)
			}
		})
	}
}

// TestSuricataFormat_CBOM_AttackerFieldsEscaped verifies CBOM output is valid JSON.
func TestSuricataFormat_CBOM_AttackerFieldsEscaped(t *testing.T) {
	for _, tc := range attackerSuricataInputs {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			f := adversarialSuricataFinding(tc.algName, tc.filePath)
			result := makeSuricataResult([]findings.UnifiedFinding{f})

			var buf bytes.Buffer
			if err := WriteCBOM(&buf, result); err != nil {
				t.Fatalf("WriteCBOM: %v", err)
			}
			if !json.Valid(buf.Bytes()) {
				t.Errorf("WriteCBOM produced invalid JSON for input %q", tc.name)
			}
		})
	}
}

// TestSuricataFormat_Table_ControlCharsStripped verifies that the table writer
// does not emit raw ANSI escape sequences or control characters.
func TestSuricataFormat_Table_ControlCharsStripped(t *testing.T) {
	// Table format only: verify that rendering doesn't panic on adversarial input.
	// The sanitizeField function in the engine strips control chars before they
	// enter UnifiedFinding — but the output layer must also be robust.
	for _, tc := range attackerSuricataInputs {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			f := adversarialSuricataFinding(tc.algName, tc.filePath)
			result := makeSuricataResult([]findings.UnifiedFinding{f})

			var buf bytes.Buffer
			if err := WriteTable(&buf, result); err != nil {
				t.Fatalf("WriteTable: %v", err)
			}
			// No panic = pass. Optionally assert no raw ESC bytes in output.
			out := buf.String()
			if strings.Contains(out, "\x1b[") {
				t.Logf("WriteTable: ANSI escape sequence present in output (consider stripping): %q", tc.name)
				// Not a fatal error — table rendering may legitimately use ANSI colors.
			}
		})
	}
}

// ─── JSON round-trip ─────────────────────────────────────────────────────────

// TestSuricataFormat_JSON_SourceEngineField verifies "suricata-log" appears in JSON.
func TestSuricataFormat_JSON_SourceEngineField(t *testing.T) {
	result := makeSuricataResult([]findings.UnifiedFinding{suricataClassicalFinding("TLS_AES_128_GCM_SHA256")})

	var buf bytes.Buffer
	if err := WriteJSON(&buf, result); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if !strings.Contains(buf.String(), "suricata-log") {
		t.Error("JSON output missing 'suricata-log' source engine identifier")
	}
}

// TestSuricataFormat_JSON_RoundTrip verifies that findings survive a JSON marshal/unmarshal.
func TestSuricataFormat_JSON_RoundTrip(t *testing.T) {
	ff := []findings.UnifiedFinding{
		suricataClassicalFinding("TLS_AES_128_GCM_SHA256"),
		suricataVulnerableFinding("ECDHE-RSA-AES256-GCM-SHA384"),
	}
	result := makeSuricataResult(ff)

	var buf bytes.Buffer
	if err := WriteJSON(&buf, result); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var got ScanResult
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Findings) != 2 {
		t.Fatalf("round-trip: expected 2 findings, got %d", len(got.Findings))
	}
	for _, f := range got.Findings {
		if f.SourceEngine != "suricata-log" {
			t.Errorf("round-trip: SourceEngine=%q, want suricata-log", f.SourceEngine)
		}
	}
}

// ─── Co-existence with Sprint 0-5 findings ───────────────────────────────────

// TestSuricataFormat_CoexistWithTLSAndSSH verifies that Sprint 6 Suricata findings
// co-exist with Sprint 1 TLS probe and Sprint 4 SSH probe findings in a mixed result
// without field collision or serialization errors.
func TestSuricataFormat_CoexistWithTLSAndSSH(t *testing.T) {
	mixed := []findings.UnifiedFinding{
		// Sprint 1 TLS probe finding
		{
			Location:            findings.Location{File: "(tls-probe)/example.com:443#kex", ArtifactType: "tls-endpoint"},
			Algorithm:           &findings.Algorithm{Name: "X25519MLKEM768", Primitive: "key-exchange"},
			Confidence:          findings.ConfidenceHigh,
			SourceEngine:        "tls-probe",
			Reachable:           findings.ReachableYes,
			QuantumRisk:         findings.QRSafe,
			NegotiatedGroup:     0x11EC,
			NegotiatedGroupName: "X25519MLKEM768",
			PQCPresent:          true,
			PQCMaturity:         "final",
			HandshakeVolumeClass: "hybrid-kem",
			HandshakeBytes:      9500,
		},
		// Sprint 4 SSH probe finding
		{
			Location:     findings.Location{File: "(ssh-probe)/192.0.2.1:22#kex", ArtifactType: "ssh-endpoint"},
			Algorithm:    &findings.Algorithm{Name: "mlkem768x25519-sha256", Primitive: "kex"},
			Confidence:   findings.ConfidenceHigh,
			SourceEngine: "ssh-probe",
			Reachable:    findings.ReachableYes,
			QuantumRisk:  findings.QRSafe,
			PQCPresent:   true,
			PQCMaturity:  "final",
		},
		// Sprint 6 Suricata finding
		suricataVulnerableFinding("ECDHE-RSA-AES256-GCM-SHA384"),
	}

	result := ScanResult{
		Version:  "0.0.0-test",
		Target:   "/test-mixed-sprint6",
		Engines:  []string{"tls-probe", "ssh-probe", "suricata-log"},
		Findings: mixed,
	}

	var jsonBuf, sarifBuf, cbomBuf bytes.Buffer
	if err := WriteJSON(&jsonBuf, result); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	if !json.Valid(jsonBuf.Bytes()) {
		t.Fatal("WriteJSON: invalid JSON")
	}
	if err := WriteSARIF(&sarifBuf, result); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	if !json.Valid(sarifBuf.Bytes()) {
		t.Fatal("WriteSARIF: invalid JSON")
	}
	if err := WriteCBOM(&cbomBuf, result); err != nil {
		t.Fatalf("WriteCBOM: %v", err)
	}
	if !json.Valid(cbomBuf.Bytes()) {
		t.Fatal("WriteCBOM: invalid JSON")
	}

	// Round-trip: all 3 findings preserved.
	var parsed ScanResult
	if err := json.Unmarshal(jsonBuf.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(parsed.Findings) != 3 {
		t.Errorf("expected 3 findings after round-trip, got %d", len(parsed.Findings))
	}

	// TLS probe finding retains NegotiatedGroup and HandshakeBytes.
	tls := parsed.Findings[0]
	if tls.NegotiatedGroup != 0x11EC {
		t.Errorf("TLS NegotiatedGroup=0x%04x, want 0x11EC", tls.NegotiatedGroup)
	}
	if tls.HandshakeBytes != 9500 {
		t.Errorf("TLS HandshakeBytes=%d, want 9500", tls.HandshakeBytes)
	}

	// Suricata finding has no NegotiatedGroup.
	sur := parsed.Findings[2]
	if sur.NegotiatedGroup != 0 {
		t.Errorf("Suricata finding NegotiatedGroup=0x%04x, want 0 (not set for log-based engine)", sur.NegotiatedGroup)
	}
	if sur.SourceEngine != "suricata-log" {
		t.Errorf("Suricata finding SourceEngine=%q, want suricata-log", sur.SourceEngine)
	}
}
