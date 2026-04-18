package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// pqc_fields_format_test.go — round-trip serialization tests for the Sprint 1 PQC
// fields (NegotiatedGroup, NegotiatedGroupName, PQCPresent, PQCMaturity) across
// all four output formats: JSON, SARIF, CBOM, and table.
//
// Three fixtures:
//   1. RSA classical   — no PQC fields set
//   2. X25519MLKEM768  — final hybrid PQC
//   3. X25519Kyber768Draft00 — deprecated draft PQC

func makePQCTestResult(ff []findings.UnifiedFinding) ScanResult {
	return ScanResult{
		Version:  "0.0.0-test",
		Target:   "/test",
		Engines:  []string{"tls-probe"},
		Findings: ff,
	}
}

// rsaFinding is a classical RSA key-exchange finding with no PQC fields.
func rsaFinding() findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Location:     findings.Location{File: "(tls-probe)/rsa.example.com:443#kex"},
		Algorithm:    &findings.Algorithm{Name: "RSA", Primitive: "key-exchange"},
		SourceEngine: "tls-probe",
		Confidence:   findings.ConfidenceHigh,
		Reachable:    findings.ReachableYes,
		QuantumRisk:  findings.QRVulnerable,
		// PQC fields deliberately left zero
	}
}

// pqcFinalFinding is a final hybrid PQC finding (X25519MLKEM768).
func pqcFinalFinding() findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Location:            findings.Location{File: "(tls-probe)/hybrid.example.com:443#kex"},
		Algorithm:           &findings.Algorithm{Name: "X25519MLKEM768", Primitive: "key-exchange"},
		SourceEngine:        "tls-probe",
		Confidence:          findings.ConfidenceHigh,
		Reachable:           findings.ReachableYes,
		QuantumRisk:         findings.QRSafe,
		NegotiatedGroup:     0x11EC,
		NegotiatedGroupName: "X25519MLKEM768",
		PQCPresent:          true,
		PQCMaturity:         "final",
	}
}

// pqcDraftFinding is a deprecated-draft Kyber finding (X25519Kyber768Draft00).
func pqcDraftFinding() findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Location:            findings.Location{File: "(tls-probe)/draft.example.com:443#kex"},
		Algorithm:           &findings.Algorithm{Name: "X25519Kyber768Draft00", Primitive: "key-exchange"},
		SourceEngine:        "tls-probe",
		Confidence:          findings.ConfidenceHigh,
		Reachable:           findings.ReachableYes,
		QuantumRisk:         findings.QRDeprecated,
		NegotiatedGroup:     0x6399,
		NegotiatedGroupName: "X25519Kyber768Draft00",
		PQCPresent:          true,
		PQCMaturity:         "draft",
	}
}

// ── JSON round-trip ──────────────────────────────────────────────────────────

func TestPQCFormat_JSON_RoundTrip(t *testing.T) {
	result := makePQCTestResult([]findings.UnifiedFinding{
		rsaFinding(),
		pqcFinalFinding(),
		pqcDraftFinding(),
	})

	var buf bytes.Buffer
	if err := WriteJSON(&buf, result); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	// Unmarshal back via ScanResult structure.
	var got ScanResult
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("json.Unmarshal ScanResult: %v", err)
	}
	if len(got.Findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(got.Findings))
	}

	// [0] RSA classical — PQC fields must round-trip as zero.
	rsa := got.Findings[0]
	if rsa.PQCPresent {
		t.Error("RSA finding: PQCPresent=true after JSON round-trip, want false")
	}
	if rsa.NegotiatedGroupName != "" {
		t.Errorf("RSA finding: NegotiatedGroupName=%q after round-trip, want empty", rsa.NegotiatedGroupName)
	}
	if rsa.PQCMaturity != "" {
		t.Errorf("RSA finding: PQCMaturity=%q after round-trip, want empty", rsa.PQCMaturity)
	}

	// [1] X25519MLKEM768 final — all PQC fields must survive.
	hybrid := got.Findings[1]
	if hybrid.NegotiatedGroup != 0x11EC {
		t.Errorf("hybrid: NegotiatedGroup=0x%04x, want 0x11EC", hybrid.NegotiatedGroup)
	}
	if hybrid.NegotiatedGroupName != "X25519MLKEM768" {
		t.Errorf("hybrid: NegotiatedGroupName=%q, want X25519MLKEM768", hybrid.NegotiatedGroupName)
	}
	if !hybrid.PQCPresent {
		t.Error("hybrid: PQCPresent=false after round-trip, want true")
	}
	if hybrid.PQCMaturity != "final" {
		t.Errorf("hybrid: PQCMaturity=%q, want final", hybrid.PQCMaturity)
	}

	// [2] X25519Kyber768Draft00 deprecated — draft maturity must survive.
	draft := got.Findings[2]
	if !draft.PQCPresent {
		t.Error("draft: PQCPresent=false after round-trip, want true")
	}
	if draft.PQCMaturity != "draft" {
		t.Errorf("draft: PQCMaturity=%q, want draft", draft.PQCMaturity)
	}
	if draft.NegotiatedGroup != 0x6399 {
		t.Errorf("draft: NegotiatedGroup=0x%04x, want 0x6399", draft.NegotiatedGroup)
	}
}

// TestPQCFormat_JSON_OmitEmpty verifies that zero-value PQC fields are absent
// from the JSON output for the RSA classical finding. The omitempty tags on
// UnifiedFinding must suppress these keys so non-TLS findings stay compact.
func TestPQCFormat_JSON_OmitEmpty(t *testing.T) {
	result := makePQCTestResult([]findings.UnifiedFinding{rsaFinding()})

	var buf bytes.Buffer
	if err := WriteJSON(&buf, result); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	// Extract the first finding as a raw JSON map to inspect key presence.
	var raw struct {
		Findings []map[string]json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal raw: %v", err)
	}
	if len(raw.Findings) == 0 {
		t.Fatal("no findings in JSON output")
	}

	f := raw.Findings[0]
	for _, key := range []string{"negotiatedGroup", "negotiatedGroupName", "pqcPresent", "pqcMaturity"} {
		if _, present := f[key]; present {
			t.Errorf("field %q must be omitted for classical (zero-value) finding, but it was present", key)
		}
	}
}

// ── SARIF round-trip ─────────────────────────────────────────────────────────

func TestPQCFormat_SARIF_PQCFieldsInProperties(t *testing.T) {
	result := makePQCTestResult([]findings.UnifiedFinding{
		rsaFinding(),
		pqcFinalFinding(),
		pqcDraftFinding(),
	})

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, result); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}

	// Parse into a generic map to inspect the properties sub-object.
	var sarifDoc struct {
		Runs []struct {
			Results []struct {
				Properties map[string]json.RawMessage `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(buf.Bytes(), &sarifDoc); err != nil {
		t.Fatalf("unmarshal SARIF: %v", err)
	}
	if len(sarifDoc.Runs) == 0 || len(sarifDoc.Runs[0].Results) != 3 {
		t.Fatalf("expected 3 SARIF results, got %d", len(sarifDoc.Runs[0].Results))
	}

	// RSA finding: pqcPresent, pqcMaturity, negotiatedGroupName must be absent.
	rsaProps := sarifDoc.Runs[0].Results[0].Properties
	for _, key := range []string{"pqcPresent", "pqcMaturity", "negotiatedGroupName"} {
		if _, ok := rsaProps[key]; ok {
			t.Errorf("SARIF RSA finding: properties[%q] present, want absent", key)
		}
	}

	// Hybrid final finding: all three PQC keys must be present.
	hybridProps := sarifDoc.Runs[0].Results[1].Properties
	if _, ok := hybridProps["pqcPresent"]; !ok {
		t.Error("SARIF hybrid finding: properties[\"pqcPresent\"] absent")
	}
	if _, ok := hybridProps["negotiatedGroupName"]; !ok {
		t.Error("SARIF hybrid finding: properties[\"negotiatedGroupName\"] absent")
	}
	var maturity string
	if v, ok := hybridProps["pqcMaturity"]; ok {
		_ = json.Unmarshal(v, &maturity)
	} else {
		t.Error("SARIF hybrid finding: properties[\"pqcMaturity\"] absent")
	}
	if maturity != "final" {
		t.Errorf("SARIF hybrid finding: pqcMaturity=%q, want final", maturity)
	}

	// Draft finding: pqcMaturity must be "draft".
	draftProps := sarifDoc.Runs[0].Results[2].Properties
	var draftMaturity string
	if v, ok := draftProps["pqcMaturity"]; ok {
		_ = json.Unmarshal(v, &draftMaturity)
	} else {
		t.Error("SARIF draft finding: properties[\"pqcMaturity\"] absent")
	}
	if draftMaturity != "draft" {
		t.Errorf("SARIF draft finding: pqcMaturity=%q, want draft", draftMaturity)
	}
}

// ── CBOM round-trip ──────────────────────────────────────────────────────────

func TestPQCFormat_CBOM_OQSPropertyConventions(t *testing.T) {
	result := makePQCTestResult([]findings.UnifiedFinding{
		rsaFinding(),
		pqcFinalFinding(),
		pqcDraftFinding(),
	})

	var buf bytes.Buffer
	if err := WriteCBOM(&buf, result); err != nil {
		t.Fatalf("WriteCBOM: %v", err)
	}

	// Parse CBOM to examine component properties.
	var bom struct {
		Components []struct {
			Name       string `json:"name"`
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"components"`
	}
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatalf("unmarshal CBOM: %v", err)
	}
	if len(bom.Components) < 3 {
		t.Fatalf("expected at least 3 CBOM components, got %d", len(bom.Components))
	}

	// Build a helper: find property value by name for a component.
	findProp := func(props []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	}, name string) (string, bool) {
		for _, p := range props {
			if p.Name == name {
				return p.Value, true
			}
		}
		return "", false
	}

	// RSA component: oqs:pqcPresent and oqs:pqcMaturity must be absent.
	rsaProps := bom.Components[0].Properties
	for _, prop := range []string{"oqs:pqcPresent", "oqs:pqcMaturity", "oqs:negotiatedGroupName"} {
		if v, ok := findProp(rsaProps, prop); ok {
			t.Errorf("CBOM RSA component: property %q present (value=%q), want absent", prop, v)
		}
	}

	// Hybrid component: oqs:pqcPresent="true", oqs:pqcMaturity="final",
	// oqs:negotiatedGroupName="X25519MLKEM768" must all be present.
	// Note: renamed from oqs:negotiatedGroup → oqs:negotiatedGroupName (S2.5 carryover fix).
	hybridProps := bom.Components[1].Properties
	if v, ok := findProp(hybridProps, "oqs:pqcPresent"); !ok || v != "true" {
		t.Errorf("CBOM hybrid component: oqs:pqcPresent=%q ok=%v, want \"true\" present", v, ok)
	}
	if v, ok := findProp(hybridProps, "oqs:pqcMaturity"); !ok || v != "final" {
		t.Errorf("CBOM hybrid component: oqs:pqcMaturity=%q ok=%v, want \"final\" present", v, ok)
	}
	if v, ok := findProp(hybridProps, "oqs:negotiatedGroupName"); !ok || v != "X25519MLKEM768" {
		t.Errorf("CBOM hybrid component: oqs:negotiatedGroupName=%q ok=%v, want \"X25519MLKEM768\"", v, ok)
	}

	// Draft component: oqs:pqcMaturity must be "draft".
	draftProps := bom.Components[2].Properties
	if v, ok := findProp(draftProps, "oqs:pqcMaturity"); !ok || v != "draft" {
		t.Errorf("CBOM draft component: oqs:pqcMaturity=%q ok=%v, want \"draft\" present", v, ok)
	}
	// oqs:pqcPresent must also be set for draft (PQCPresent=true).
	if v, ok := findProp(draftProps, "oqs:pqcPresent"); !ok || v != "true" {
		t.Errorf("CBOM draft component: oqs:pqcPresent=%q ok=%v, want \"true\" present", v, ok)
	}

	// CycloneDX 1.7 property name convention: all oqs:pqc* names must use
	// the "oqs:" namespace prefix — no bare "pqcPresent" keys.
	for i, comp := range bom.Components {
		for _, p := range comp.Properties {
			if strings.HasPrefix(p.Name, "pqc") && !strings.HasPrefix(p.Name, "oqs:") {
				t.Errorf("component[%d] %q: property %q lacks oqs: namespace prefix (CycloneDX 1.7 convention)",
					i, comp.Name, p.Name)
			}
		}
	}
}

// ── Table format ─────────────────────────────────────────────────────────────

// TestPQCFormat_Table_PQCBadges verifies that the table renderer emits [PQC]
// for final hybrid findings and [PQC:DRAFT] for deprecated draft findings,
// and that the RSA classical finding carries neither badge.
func TestPQCFormat_Table_PQCBadges(t *testing.T) {
	result := makePQCTestResult([]findings.UnifiedFinding{
		rsaFinding(),
		pqcFinalFinding(),
		pqcDraftFinding(),
	})

	var buf bytes.Buffer
	if err := WriteTable(&buf, result); err != nil {
		t.Fatalf("WriteTable: %v", err)
	}
	out := buf.String()

	// Strip ANSI colour codes for reliable string matching.
	out = stripANSI(out)

	// Final hybrid must emit [PQC] badge.
	if !strings.Contains(out, "[PQC]") {
		t.Errorf("table output: expected [PQC] badge for X25519MLKEM768 (final hybrid), not found:\n%s", out)
	}

	// Deprecated draft must emit [PQC:DRAFT] badge.
	if !strings.Contains(out, "[PQC:DRAFT]") {
		t.Errorf("table output: expected [PQC:DRAFT] badge for X25519Kyber768Draft00, not found:\n%s", out)
	}

	// Identify the lines containing each algorithm name and check badge placement.
	lines := strings.Split(out, "\n")
	for _, line := range lines {
		if strings.Contains(line, "X25519MLKEM768") && !strings.Contains(line, "Draft") {
			if !strings.Contains(line, "[PQC]") {
				t.Errorf("X25519MLKEM768 line missing [PQC] badge: %q", line)
			}
		}
		if strings.Contains(line, "X25519Kyber768Draft00") {
			if !strings.Contains(line, "[PQC:DRAFT]") {
				t.Errorf("X25519Kyber768Draft00 line missing [PQC:DRAFT] badge: %q", line)
			}
		}
		if strings.Contains(line, "RSA") && strings.Contains(line, "algorithm") {
			// RSA line must not carry a PQC badge.
			if strings.Contains(line, "[PQC]") {
				t.Errorf("RSA line incorrectly carries [PQC] badge: %q", line)
			}
		}
	}
}

// stripANSI removes ANSI escape sequences from s so badge checks work
// regardless of whether colour output is enabled.
func stripANSI(s string) string {
	var out strings.Builder
	i := 0
	for i < len(s) {
		if s[i] == '\033' && i+1 < len(s) && s[i+1] == '[' {
			// Consume until 'm'.
			j := i + 2
			for j < len(s) && s[j] != 'm' {
				j++
			}
			i = j + 1
			continue
		}
		out.WriteByte(s[i])
		i++
	}
	return out.String()
}
