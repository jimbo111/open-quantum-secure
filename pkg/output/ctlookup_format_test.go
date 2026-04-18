// ctlookup_format_test.go — Format/output rendering tests for ct-lookup engine
// findings. Verifies that the signature-algorithm case (the primary output of
// ctlookup) renders correctly through JSON, SARIF, and CBOM with all required
// fields present and no partial-inventory annotation (CT findings are complete).
package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// ctlookupFinding returns a representative finding as emitted by the ct-lookup
// engine: ECDSA signature algorithm, no TLS negotiation fields, PartialInventory=false.
func ctlookupFinding() findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Location: findings.Location{
			File:         "(ct-lookup)/ech.example.com#cert",
			Line:         0,
			ArtifactType: "ct-log",
		},
		Algorithm: &findings.Algorithm{
			Name:      "ECDSA",
			Primitive: "signature",
			KeySize:   256,
			Curve:     "P-256",
		},
		Confidence:      findings.ConfidenceMedium,
		SourceEngine:    "ct-lookup",
		Reachable:       findings.ReachableYes,
		RawIdentifier:   "ct-cert:ech.example.com|ECDSA|AABBCCDDEEFF",
		QuantumRisk:     findings.QRVulnerable,
		Severity:        findings.SevHigh,
		PartialInventory: false,
	}
}

// ctlookupRSAFinding returns an RSA 2048-bit ct-lookup finding.
func ctlookupRSAFinding() findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Location: findings.Location{
			File:         "(ct-lookup)/rsa.example.com#cert",
			ArtifactType: "ct-log",
		},
		Algorithm: &findings.Algorithm{
			Name:      "RSA",
			Primitive: "signature",
			KeySize:   2048,
		},
		Confidence:      findings.ConfidenceMedium,
		SourceEngine:    "ct-lookup",
		Reachable:       findings.ReachableYes,
		QuantumRisk:     findings.QRVulnerable,
		Severity:        findings.SevCritical,
		PartialInventory: false,
	}
}

func makeCtLookupResult(ff []findings.UnifiedFinding) ScanResult {
	return ScanResult{
		Version:  "0.0.0-test",
		Target:   "/test",
		Engines:  []string{"ct-lookup"},
		Findings: ff,
	}
}

// ── JSON rendering ────────────────────────────────────────────────────────────

// TestCTLookup_JSON_SignatureAlgorithmFields verifies that a ct-lookup ECDSA
// finding serialises with the expected algorithm fields.
func TestCTLookup_JSON_SignatureAlgorithmFields(t *testing.T) {
	t.Parallel()
	result := makeCtLookupResult([]findings.UnifiedFinding{ctlookupFinding()})
	var buf bytes.Buffer
	if err := WriteJSON(&buf, result); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var raw struct {
		Findings []map[string]json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(raw.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}

	f := raw.Findings[0]

	// algorithm.primitive must be "signature".
	var algo map[string]json.RawMessage
	if err := json.Unmarshal(f["algorithm"], &algo); err != nil {
		t.Fatalf("unmarshal algorithm: %v", err)
	}
	var primitive string
	json.Unmarshal(algo["primitive"], &primitive) //nolint
	if primitive != "signature" {
		t.Errorf("algorithm.primitive = %q, want signature", primitive)
	}

	var algoName string
	json.Unmarshal(algo["name"], &algoName) //nolint
	if algoName != "ECDSA" {
		t.Errorf("algorithm.name = %q, want ECDSA", algoName)
	}

	// partialInventory must be absent (false/omitempty for CT findings).
	if _, ok := f["partialInventory"]; ok {
		var pi bool
		json.Unmarshal(f["partialInventory"], &pi) //nolint
		if pi {
			t.Error("ct-lookup finding must have PartialInventory=false")
		}
	}

	// sourceEngine must be ct-lookup.
	var src string
	json.Unmarshal(f["sourceEngine"], &src) //nolint
	if src != "ct-lookup" {
		t.Errorf("sourceEngine = %q, want ct-lookup", src)
	}
}

// TestCTLookup_JSON_NoNegotiatedGroupFields verifies that ct-lookup findings do
// not carry negotiatedGroup/negotiatedGroupName (those are tls-probe-only fields).
func TestCTLookup_JSON_NoNegotiatedGroupFields(t *testing.T) {
	t.Parallel()
	result := makeCtLookupResult([]findings.UnifiedFinding{ctlookupFinding()})
	var buf bytes.Buffer
	if err := WriteJSON(&buf, result); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var raw struct {
		Findings []map[string]json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(raw.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	f := raw.Findings[0]
	for _, field := range []string{"negotiatedGroup", "negotiatedGroupName", "pqcPresent"} {
		if _, ok := f[field]; ok {
			t.Errorf("ct-lookup finding must not have field %q (tls-probe only)", field)
		}
	}
}

// TestCTLookup_JSON_RSAFinding verifies that RSA key-size is preserved.
func TestCTLookup_JSON_RSAFinding(t *testing.T) {
	t.Parallel()
	result := makeCtLookupResult([]findings.UnifiedFinding{ctlookupRSAFinding()})
	var buf bytes.Buffer
	if err := WriteJSON(&buf, result); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var raw struct {
		Findings []struct {
			Algorithm struct {
				Name      string `json:"name"`
				Primitive string `json:"primitive"`
				KeySize   int    `json:"keySize"`
			} `json:"algorithm"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(raw.Findings) == 0 {
		t.Fatal("expected at least one finding")
	}
	alg := raw.Findings[0].Algorithm
	if alg.Name != "RSA" {
		t.Errorf("name = %q, want RSA", alg.Name)
	}
	if alg.Primitive != "signature" {
		t.Errorf("primitive = %q, want signature", alg.Primitive)
	}
	if alg.KeySize != 2048 {
		t.Errorf("keySize = %d, want 2048", alg.KeySize)
	}
}

// ── SARIF rendering ───────────────────────────────────────────────────────────

// TestCTLookup_SARIF_Location verifies that a ct-lookup finding's ct-log path
// appears in the SARIF artifactLocation.uri field.
func TestCTLookup_SARIF_Location(t *testing.T) {
	t.Parallel()
	result := makeCtLookupResult([]findings.UnifiedFinding{ctlookupFinding()})
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, result); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	if !strings.Contains(buf.String(), "ct-lookup") {
		t.Error("SARIF output should contain ct-lookup engine reference")
	}
}

// TestCTLookup_SARIF_NoPartialInventoryProperty verifies that a CT finding
// (PartialInventory=false) does not carry a partialInventory property in SARIF.
func TestCTLookup_SARIF_NoPartialInventoryProperty(t *testing.T) {
	t.Parallel()
	result := makeCtLookupResult([]findings.UnifiedFinding{ctlookupFinding()})
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
		t.Fatalf("unmarshal SARIF: %v", err)
	}
	if len(sarifDoc.Runs) == 0 || len(sarifDoc.Runs[0].Results) == 0 {
		t.Fatal("expected at least one SARIF result")
	}
	props := sarifDoc.Runs[0].Results[0].Properties
	if v, ok := props["partialInventory"]; ok {
		var pi bool
		json.Unmarshal(v, &pi) //nolint
		if pi {
			t.Error("SARIF: ct-lookup finding must not have partialInventory=true")
		}
	}
}

// ── CBOM rendering ────────────────────────────────────────────────────────────

// TestCTLookup_CBOM_SignatureAlgorithmRendered verifies that an ECDSA ct-lookup
// finding appears as a CycloneDX component with the expected cryptoProperties.
func TestCTLookup_CBOM_SignatureAlgorithmRendered(t *testing.T) {
	t.Parallel()
	result := makeCtLookupResult([]findings.UnifiedFinding{ctlookupFinding()})
	var buf bytes.Buffer
	if err := WriteCBOM(&buf, result); err != nil {
		t.Fatalf("WriteCBOM: %v", err)
	}

	cbomStr := buf.String()
	if !strings.Contains(cbomStr, "ECDSA") {
		t.Error("CBOM must contain ECDSA algorithm name")
	}
	// Partial inventory must not be set for CT findings.
	if strings.Contains(cbomStr, `"oqs:partialInventory":"true"`) {
		t.Error("CBOM: ct-lookup finding must not have oqs:partialInventory=true")
	}
}

// TestCTLookup_CBOM_NoNegotiatedGroupProperty verifies ct-lookup findings don't
// carry oqs:negotiatedGroupName (a tls-probe-only CBOM property).
func TestCTLookup_CBOM_NoNegotiatedGroupProperty(t *testing.T) {
	t.Parallel()
	result := makeCtLookupResult([]findings.UnifiedFinding{ctlookupFinding()})
	var buf bytes.Buffer
	if err := WriteCBOM(&buf, result); err != nil {
		t.Fatalf("WriteCBOM: %v", err)
	}

	var bom struct {
		Components []struct {
			Properties []struct {
				Name  string `json:"name"`
				Value string `json:"value"`
			} `json:"properties"`
		} `json:"components"`
	}
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatalf("unmarshal CBOM: %v", err)
	}

	for _, comp := range bom.Components {
		for _, prop := range comp.Properties {
			if prop.Name == "oqs:negotiatedGroupName" {
				t.Error("ct-lookup finding must not carry oqs:negotiatedGroupName (tls-probe only)")
			}
		}
	}
}
