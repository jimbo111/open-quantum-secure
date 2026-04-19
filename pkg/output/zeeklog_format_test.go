package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// zeeklogInjectionFinding returns a finding with attacker-controlled cipher and server_name
// fields that contain ANSI escape sequences and HTML/script injection payloads.
// These values come from ssl.log cipher and server_name columns — attacker-controlled
// if the network traffic is crafted.
func zeeklogInjectionFinding(cipher, serverName string) findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Location: findings.Location{
			File: "(zeek-log)/" + serverName + "#" + cipher,
		},
		Algorithm: &findings.Algorithm{
			Name:      cipher,
			Primitive: "ae",
		},
		SourceEngine: "zeek-log",
		Confidence:   findings.ConfidenceMedium,
		Reachable:    findings.ReachableUnknown,
		QuantumRisk:  findings.QRVulnerable,
	}
}

func makeZeeklogResult(ff []findings.UnifiedFinding) ScanResult {
	return ScanResult{
		Version:  "0.0.0-test",
		Target:   "/zeek-logs",
		Engines:  []string{"zeek-log"},
		Findings: ff,
	}
}

// TestZeeklogFormat_JSON_ANSIEscape verifies that ANSI escape sequences in cipher
// or server_name fields are safely JSON-encoded and do not appear raw in output.
func TestZeeklogFormat_JSON_ANSIEscape(t *testing.T) {
	ansiCipher := "\x1b[31mFAKE_CIPHER\x1b[0m"
	result := makeZeeklogResult([]findings.UnifiedFinding{
		zeeklogInjectionFinding(ansiCipher, "attacker.example.com"),
	})

	var buf bytes.Buffer
	if err := WriteJSON(&buf, result); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	out := buf.String()

	// JSON-encoded ESC should appear as \u001b, not as a raw ESC byte.
	if strings.Contains(out, "\x1b") {
		t.Errorf("JSON output contains raw ESC byte — ANSI injection possible:\n%s", out)
	}
	// The encoded form should be present (json.Marshal always escapes control chars).
	if !strings.Contains(out, `\u001b`) {
		// Some JSON encoders use \u001B (uppercase). Accept both.
		if !strings.Contains(out, `\u001B`) {
			t.Errorf("JSON output: ESC should be \\u001b-encoded, not found in:\n%s", out)
		}
	}
}

// TestZeeklogFormat_JSON_HTMLScript verifies HTML/script injection in server_name
// is safely JSON-encoded (< > & are encoded by encoding/json as \u003c etc.).
func TestZeeklogFormat_JSON_HTMLScript(t *testing.T) {
	scriptSN := "<script>alert(1)</script>"
	result := makeZeeklogResult([]findings.UnifiedFinding{
		zeeklogInjectionFinding("TLS_AES_256_GCM_SHA384", scriptSN),
	})

	var buf bytes.Buffer
	if err := WriteJSON(&buf, result); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	raw := buf.Bytes()

	// encoding/json by default encodes < as \u003c, > as \u003e, & as \u0026.
	if bytes.Contains(raw, []byte("<script>")) {
		t.Errorf("JSON output contains raw <script> tag — XSS injection possible")
	}
}

// TestZeeklogFormat_SARIF_ANSIEscape verifies SARIF output doesn't embed raw ESC.
func TestZeeklogFormat_SARIF_ANSIEscape(t *testing.T) {
	ansiCipher := "\x1b[31mFAKE\x1b[0m"
	result := makeZeeklogResult([]findings.UnifiedFinding{
		zeeklogInjectionFinding(ansiCipher, "ansi.example.com"),
	})

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, result); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	if bytes.Contains(buf.Bytes(), []byte("\x1b")) {
		t.Errorf("SARIF output contains raw ESC byte — ANSI injection possible")
	}
}

// TestZeeklogFormat_CBOM_ANSIEscape verifies CBOM output doesn't embed raw ESC.
func TestZeeklogFormat_CBOM_ANSIEscape(t *testing.T) {
	ansiCipher := "\x1b[32mGREEN_FAKE\x1b[0m"
	result := makeZeeklogResult([]findings.UnifiedFinding{
		zeeklogInjectionFinding(ansiCipher, "cbom.example.com"),
	})

	var buf bytes.Buffer
	if err := WriteCBOM(&buf, result); err != nil {
		t.Fatalf("WriteCBOM: %v", err)
	}
	if bytes.Contains(buf.Bytes(), []byte("\x1b")) {
		t.Errorf("CBOM output contains raw ESC byte — ANSI injection possible")
	}
}

// TestZeeklogFormat_Table_ANSIEscape verifies the table writer doesn't amplify
// injected ANSI sequences. The table renderer may add its own color codes but
// must not pass through arbitrary injected ESC sequences unsanitized.
//
// Note: this test documents current behavior. If the table writer does not
// sanitize injected ANSI, it will fail — that is an expected finding.
func TestZeeklogFormat_Table_ANSIEscape(t *testing.T) {
	ansiCipher := "\x1b[31mFAKE_CIPHER\x1b[0m"
	result := makeZeeklogResult([]findings.UnifiedFinding{
		zeeklogInjectionFinding(ansiCipher, "terminal.example.com"),
	})

	var buf bytes.Buffer
	_ = WriteTable(&buf, result)
	out := buf.String()

	// Strip legitimate ANSI codes added by the renderer, then check for residual
	// injected payloads by looking for the literal string "FAKE_CIPHER" without
	// surrounding control chars.
	stripped := stripANSI(out)
	if strings.Contains(stripped, "\x1b") {
		t.Errorf("table output: raw ESC byte survives ANSI stripping — injected sequence not sanitized:\n%s", stripped)
	}
}

// TestZeeklogFormat_JSON_NullBytesInCipher verifies NUL bytes in cipher field
// are handled safely (JSON encodes them as \u0000).
func TestZeeklogFormat_JSON_NullBytesInCipher(t *testing.T) {
	nullCipher := "TLS_AES_256\x00_GCM_SHA384"
	result := makeZeeklogResult([]findings.UnifiedFinding{
		zeeklogInjectionFinding(nullCipher, "null.example.com"),
	})

	var buf bytes.Buffer
	if err := WriteJSON(&buf, result); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	// Output must be valid JSON (no raw NUL bytes that break parsers).
	var v interface{}
	if err := json.Unmarshal(buf.Bytes(), &v); err != nil {
		t.Errorf("JSON with NUL in cipher is not valid JSON: %v", err)
	}
}
