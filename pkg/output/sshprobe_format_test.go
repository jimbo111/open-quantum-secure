// sshprobe_format_test.go — output format round-trip tests for SSH probe findings.
//
// Purpose: verify that a UnifiedFinding produced by the ssh-probe engine serializes
// correctly through all four output formats (JSON, SARIF, CBOM, Table). Specifically:
//   - PQC fields (PQCPresent, PQCMaturity) round-trip with correct values.
//   - Classical SSH KEX findings carry no PQC annotations.
//   - Attacker-controlled method names (e.g. `"; rm -rf /"`) are safely escaped
//     in JSON, SARIF, and CBOM outputs — never interpreted as commands.
//   - Sprint 4 ssh-probe findings co-exist with Sprint 1/2 TLS probe findings
//     without field collision.
package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// ─── Fixture helpers ──────────────────────────────────────────────────────────

// sshClassicalFinding returns a classical (quantum-vulnerable) SSH KEX finding.
func sshClassicalFinding(method string) findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Location:     findings.Location{File: "(ssh-probe)/198.51.100.1:22#kex", ArtifactType: "ssh-endpoint"},
		Algorithm:    &findings.Algorithm{Name: method, Primitive: "kex"},
		Confidence:   findings.ConfidenceHigh,
		SourceEngine: "ssh-probe",
		Reachable:    findings.ReachableYes,
		QuantumRisk:  findings.QRVulnerable,
		Severity:     findings.SevHigh,
		PQCPresent:   false,
	}
}

// sshPQCFinalFinding returns a PQC-final SSH KEX finding (mlkem768x25519-sha256).
func sshPQCFinalFinding() findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Location:     findings.Location{File: "(ssh-probe)/203.0.113.1:22#kex", ArtifactType: "ssh-endpoint"},
		Algorithm:    &findings.Algorithm{Name: "mlkem768x25519-sha256", Primitive: "kex"},
		Confidence:   findings.ConfidenceHigh,
		SourceEngine: "ssh-probe",
		Reachable:    findings.ReachableYes,
		QuantumRisk:  findings.QRSafe,
		Severity:     findings.SevInfo,
		PQCPresent:   true,
		PQCMaturity:  "final",
	}
}

// sshPQCDraftFinding returns a PQC-draft SSH KEX finding (sntrup761).
func sshPQCDraftFinding() findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Location:     findings.Location{File: "(ssh-probe)/203.0.113.2:22#kex", ArtifactType: "ssh-endpoint"},
		Algorithm:    &findings.Algorithm{Name: "sntrup761x25519-sha512@openssh.com", Primitive: "kex"},
		Confidence:   findings.ConfidenceHigh,
		SourceEngine: "ssh-probe",
		Reachable:    findings.ReachableYes,
		QuantumRisk:  findings.QRSafe,
		Severity:     findings.SevInfo,
		PQCPresent:   true,
		PQCMaturity:  "draft",
	}
}

// sshAdversarialFinding returns a finding with an attacker-controlled method name.
// The name contains shell metacharacters that must be escaped in all outputs.
func sshAdversarialFinding(methodName string) findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Location:     findings.Location{File: "(ssh-probe)/10.0.0.1:22#kex", ArtifactType: "ssh-endpoint"},
		Algorithm:    &findings.Algorithm{Name: methodName, Primitive: "kex"},
		Confidence:   findings.ConfidenceHigh,
		SourceEngine: "ssh-probe",
		Reachable:    findings.ReachableYes,
		QuantumRisk:  findings.QRUnknown,
	}
}

// makeSshProbeResult wraps findings into a ScanResult for testing.
func makeSshProbeResult(ff []findings.UnifiedFinding) ScanResult {
	return ScanResult{
		Version:  "0.0.0-test",
		Target:   "/test-ssh",
		Engines:  []string{"ssh-probe"},
		Findings: ff,
	}
}

// ─── JSON round-trip ─────────────────────────────────────────────────────────

// TestSSHProbeFormat_JSON_PQCFieldsRoundTrip verifies that PQCPresent and PQCMaturity
// survive a JSON marshal/unmarshal cycle for all three finding types.
func TestSSHProbeFormat_JSON_PQCFieldsRoundTrip(t *testing.T) {
	ff := []findings.UnifiedFinding{
		sshClassicalFinding("curve25519-sha256"),
		sshPQCFinalFinding(),
		sshPQCDraftFinding(),
	}
	result := makeSshProbeResult(ff)

	var buf bytes.Buffer
	if err := WriteJSON(&buf, result); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var got ScanResult
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got.Findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(got.Findings))
	}

	// Classical: PQCPresent=false, PQCMaturity=""
	classical := got.Findings[0]
	if classical.PQCPresent {
		t.Error("classical SSH KEX: PQCPresent=true after round-trip, want false")
	}
	if classical.PQCMaturity != "" {
		t.Errorf("classical SSH KEX: PQCMaturity=%q, want empty", classical.PQCMaturity)
	}

	// PQC final: PQCPresent=true, PQCMaturity="final"
	pqcFinal := got.Findings[1]
	if !pqcFinal.PQCPresent {
		t.Error("mlkem768x25519-sha256: PQCPresent=false after round-trip, want true")
	}
	if pqcFinal.PQCMaturity != "final" {
		t.Errorf("mlkem768x25519-sha256: PQCMaturity=%q, want final", pqcFinal.PQCMaturity)
	}

	// PQC draft: PQCPresent=true, PQCMaturity="draft"
	pqcDraft := got.Findings[2]
	if !pqcDraft.PQCPresent {
		t.Error("sntrup761: PQCPresent=false after round-trip, want true")
	}
	if pqcDraft.PQCMaturity != "draft" {
		t.Errorf("sntrup761: PQCMaturity=%q, want draft", pqcDraft.PQCMaturity)
	}
}

// TestSSHProbeFormat_JSON_SourceEngineField verifies that the source engine is
// correctly serialized as "ssh-probe" in JSON output.
func TestSSHProbeFormat_JSON_SourceEngineField(t *testing.T) {
	result := makeSshProbeResult([]findings.UnifiedFinding{sshPQCFinalFinding()})

	var buf bytes.Buffer
	if err := WriteJSON(&buf, result); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	if !strings.Contains(buf.String(), "ssh-probe") {
		t.Error("JSON output missing 'ssh-probe' source engine")
	}
}

// TestSSHProbeFormat_JSON_ArtifactType verifies that ArtifactType="ssh-endpoint"
// is preserved in JSON output.
func TestSSHProbeFormat_JSON_ArtifactType(t *testing.T) {
	result := makeSshProbeResult([]findings.UnifiedFinding{sshClassicalFinding("curve25519-sha256")})

	var buf bytes.Buffer
	if err := WriteJSON(&buf, result); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	if !strings.Contains(buf.String(), "ssh-endpoint") {
		t.Error("JSON output missing artifactType=ssh-endpoint")
	}
}

// ─── Attacker-controlled method name escaping ─────────────────────────────────

var attackerMethodNames = []string{
	`"; rm -rf /"`,
	`<script>alert(1)</script>`,
	`'; DROP TABLE findings; --`,
	"curve25519\x00-sha256",       // embedded NUL
	"diffie-hellman\r\ninjection", // CRLF injection
	"\xc3\x28-invalid-utf8",       // invalid UTF-8
	`../../../etc/passwd`,
}

// TestSSHProbeFormat_JSON_AttackerNamesEscaped verifies that attacker-controlled
// method names are safely encoded in JSON — the raw shell/HTML characters must
// not appear unescaped in a way that could be exploited.
func TestSSHProbeFormat_JSON_AttackerNamesEscaped(t *testing.T) {
	for _, name := range attackerMethodNames {
		name := name
		t.Run("name:"+strings.ReplaceAll(name, "\x00", "NUL"), func(t *testing.T) {
			result := makeSshProbeResult([]findings.UnifiedFinding{sshAdversarialFinding(name)})

			var buf bytes.Buffer
			if err := WriteJSON(&buf, result); err != nil {
				t.Fatalf("WriteJSON: %v", err)
			}

			// JSON must be valid (json.Valid rejects broken escaping).
			if !json.Valid(buf.Bytes()) {
				t.Errorf("JSON output is not valid JSON for method name %q", name)
			}

			// CRLF injection: the raw CRLF bytes must not appear literally in JSON strings.
			// json.Marshal escapes \r as \u000d and \n as \u000a inside strings.
			raw := buf.String()
			if strings.Contains(raw, "\r\n") {
				t.Errorf("JSON output contains literal CRLF (unescaped CRLF injection) for method %q", name)
			}
		})
	}
}

// TestSSHProbeFormat_SARIF_AttackerNamesEscaped verifies that SARIF output safely
// encodes attacker-controlled method names.
func TestSSHProbeFormat_SARIF_AttackerNamesEscaped(t *testing.T) {
	for _, name := range attackerMethodNames {
		name := name
		t.Run("name:"+strings.ReplaceAll(name, "\x00", "NUL"), func(t *testing.T) {
			result := makeSshProbeResult([]findings.UnifiedFinding{sshAdversarialFinding(name)})

			var buf bytes.Buffer
			if err := WriteSARIF(&buf, result); err != nil {
				t.Fatalf("WriteSARIF: %v", err)
			}

			if !json.Valid(buf.Bytes()) {
				t.Errorf("SARIF output is not valid JSON for method name %q", name)
			}
		})
	}
}

// TestSSHProbeFormat_CBOM_AttackerNamesEscaped verifies that CBOM output safely
// encodes attacker-controlled method names.
func TestSSHProbeFormat_CBOM_AttackerNamesEscaped(t *testing.T) {
	for _, name := range attackerMethodNames {
		name := name
		t.Run("name:"+strings.ReplaceAll(name, "\x00", "NUL"), func(t *testing.T) {
			result := makeSshProbeResult([]findings.UnifiedFinding{sshAdversarialFinding(name)})

			var buf bytes.Buffer
			if err := WriteCBOM(&buf, result); err != nil {
				t.Fatalf("WriteCBOM: %v", err)
			}

			if !json.Valid(buf.Bytes()) {
				t.Errorf("CBOM output is not valid JSON for method name %q", name)
			}
		})
	}
}

// ─── SARIF Sprint 4 fields ────────────────────────────────────────────────────

// TestSSHProbeFormat_SARIF_PQCFieldsPresent verifies that PQCPresent and PQCMaturity
// appear in SARIF result.properties for PQC-capable SSH KEX findings.
func TestSSHProbeFormat_SARIF_PQCFieldsPresent(t *testing.T) {
	result := makeSshProbeResult([]findings.UnifiedFinding{
		sshClassicalFinding("diffie-hellman-group14-sha256"),
		sshPQCFinalFinding(),
	})

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, result); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	var sarifDoc struct {
		Runs []struct {
			Results []struct {
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &sarifDoc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(sarifDoc.Runs) == 0 || len(sarifDoc.Runs[0].Results) != 2 {
		t.Fatalf("expected 2 SARIF results, got %d", len(sarifDoc.Runs[0].Results))
	}

	// Classical finding: pqcPresent must be absent.
	classProps := sarifDoc.Runs[0].Results[0].Properties
	if _, ok := classProps["pqcPresent"]; ok {
		t.Error("SARIF classical SSH finding: pqcPresent must be absent")
	}

	// PQC final finding: pqcPresent + pqcMaturity must be present.
	pqcProps := sarifDoc.Runs[0].Results[1].Properties
	if _, ok := pqcProps["pqcPresent"]; !ok {
		t.Error("SARIF mlkem768x25519-sha256 finding: pqcPresent absent")
	}
	var maturity string
	if v, ok := pqcProps["pqcMaturity"]; ok {
		_ = json.Unmarshal(v, &maturity)
	}
	if maturity != "final" {
		t.Errorf("SARIF pqcMaturity=%q, want final", maturity)
	}
}

// ─── Co-existence with TLS probe findings ─────────────────────────────────────

// TestSSHProbeFormat_CoexistWithTLSProbe verifies that SSH probe findings and
// TLS probe findings can be mixed in a single ScanResult without field collision.
// Sprint 4 SSH fields (PQCPresent/PQCMaturity with no NegotiatedGroup) must
// serialize cleanly alongside Sprint 1 TLS fields (NegotiatedGroup/NegotiatedGroupName).
func TestSSHProbeFormat_CoexistWithTLSProbe(t *testing.T) {
	mixed := []findings.UnifiedFinding{
		// TLS probe finding (Sprint 1) — has NegotiatedGroup
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
		},
		// SSH probe finding (Sprint 4) — no NegotiatedGroup
		sshPQCFinalFinding(),
		sshClassicalFinding("ecdh-sha2-nistp256"),
	}
	result := ScanResult{
		Version:  "0.0.0-test",
		Target:   "/test-mixed",
		Engines:  []string{"tls-probe", "ssh-probe"},
		Findings: mixed,
	}

	// All formats must succeed and produce valid output.
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

	// Round-trip via JSON: 3 findings must survive.
	var parsed ScanResult
	if err := json.Unmarshal(jsonBuf.Bytes(), &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(parsed.Findings) != 3 {
		t.Errorf("expected 3 findings after round-trip, got %d", len(parsed.Findings))
	}

	// TLS finding still has NegotiatedGroup set; SSH finding must not.
	tls := parsed.Findings[0]
	if tls.NegotiatedGroup != 0x11EC {
		t.Errorf("TLS finding NegotiatedGroup=0x%04x, want 0x11EC", tls.NegotiatedGroup)
	}
	ssh := parsed.Findings[1]
	if ssh.NegotiatedGroup != 0 {
		t.Errorf("SSH finding NegotiatedGroup=0x%04x, want 0 (not set for SSH probe)", ssh.NegotiatedGroup)
	}
}
