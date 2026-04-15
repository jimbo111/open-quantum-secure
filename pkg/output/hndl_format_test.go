package output

// hndl_format_test.go — validates that all output formats (JSON, SARIF, CycloneDX CBOM)
// correctly surface the HNDL risk and quantum risk fields for each finding type.
//
// Three findings are used throughout:
//  1. RSA-2048 (kem)        — HNDLRisk = "immediate", QuantumRisk = quantum-vulnerable
//  2. ECDHE-X25519 (kex)    — HNDLRisk = "immediate", QuantumRisk = quantum-vulnerable
//  3. X25519MLKEM768 (kem)  — HNDLRisk = ""           QuantumRisk = quantum-safe
//
// Cross-check invariant: a finding with HNDLRisk != "" must have QuantumRisk
// "quantum-vulnerable" (or similar non-safe); a finding with QuantumRisk
// "quantum-safe" must have HNDLRisk == "".

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// testFindings returns the 3 canonical findings used in format tests.
func testFindings() []findings.UnifiedFinding {
	return []findings.UnifiedFinding{
		{
			Location:    findings.Location{File: "/src/rsa.go", Line: 10},
			Algorithm:   &findings.Algorithm{Name: "RSA-2048", Primitive: "kem"},
			SourceEngine: "cipherscope",
			QuantumRisk:  findings.QRVulnerable,
			Severity:     findings.SevCritical,
			HNDLRisk:     "immediate",
			Confidence:   findings.ConfidenceHigh,
			Reachable:    findings.ReachableYes,
		},
		{
			Location:    findings.Location{File: "/src/tls.go", Line: 42},
			Algorithm:   &findings.Algorithm{Name: "ECDHE-X25519", Primitive: "key-exchange"},
			SourceEngine: "cipherscope",
			QuantumRisk:  findings.QRVulnerable,
			Severity:     findings.SevCritical,
			HNDLRisk:     "immediate",
			Confidence:   findings.ConfidenceHigh,
			Reachable:    findings.ReachableYes,
		},
		{
			Location:    findings.Location{File: "/src/hybrid.go", Line: 7},
			Algorithm:   &findings.Algorithm{Name: "X25519MLKEM768", Primitive: "kem"},
			SourceEngine: "cipherscope",
			QuantumRisk:  findings.QRSafe,
			Severity:     findings.SevInfo,
			HNDLRisk:     "", // PQ-safe — no harvest risk
			Confidence:   findings.ConfidenceHigh,
			Reachable:    findings.ReachableYes,
		},
	}
}

// TestHNDLFormat_JSONSurfacesHNDLRisk verifies that the JSON output for each
// finding includes the correct hndlRisk field (or omits it for PQ-safe findings).
func TestHNDLFormat_JSONSurfacesHNDLRisk(t *testing.T) {
	result := BuildResult("0.1.0", "/src", []string{"cipherscope"}, testFindings())
	var buf bytes.Buffer
	if err := WriteJSON(&buf, result); err != nil {
		t.Fatalf("WriteJSON error: %v", err)
	}

	// Parse back to validate individual findings.
	var parsed struct {
		Findings []map[string]interface{} `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("JSON unmarshal error: %v", err)
	}
	if len(parsed.Findings) != 3 {
		t.Fatalf("expected 3 findings, got %d", len(parsed.Findings))
	}

	cases := []struct {
		algName      string
		wantHNDLRisk string // "" means omitempty — key should be absent
		wantQRisk    string
	}{
		{"RSA-2048", "immediate", "quantum-vulnerable"},
		{"ECDHE-X25519", "immediate", "quantum-vulnerable"},
		{"X25519MLKEM768", "", "quantum-safe"},
	}

	for _, tc := range cases {
		// Find the parsed finding for this algorithm.
		var finding map[string]interface{}
		for _, f := range parsed.Findings {
			alg, _ := f["algorithm"].(map[string]interface{})
			if alg != nil && alg["name"] == tc.algName {
				finding = f
				break
			}
		}
		if finding == nil {
			t.Errorf("JSON: finding for %q not found", tc.algName)
			continue
		}

		// Check hndlRisk field.
		gotHNDL, hasHNDL := finding["hndlRisk"].(string)
		if tc.wantHNDLRisk == "" {
			if hasHNDL && gotHNDL != "" {
				t.Errorf("JSON %q: hndlRisk = %q, want absent/empty (PQ-safe)", tc.algName, gotHNDL)
			}
		} else {
			if gotHNDL != tc.wantHNDLRisk {
				t.Errorf("JSON %q: hndlRisk = %q, want %q", tc.algName, gotHNDL, tc.wantHNDLRisk)
			}
		}

		// Check quantumRisk field (consistency cross-check).
		gotQRisk, _ := finding["quantumRisk"].(string)
		if gotQRisk != tc.wantQRisk {
			t.Errorf("JSON %q: quantumRisk = %q, want %q", tc.algName, gotQRisk, tc.wantQRisk)
		}

		// Cross-check invariant: immediate HNDL ↔ quantum-vulnerable.
		if gotHNDL == "immediate" && gotQRisk != "quantum-vulnerable" {
			t.Errorf("JSON %q: HNDLRisk=immediate but quantumRisk=%q (inconsistent)", tc.algName, gotQRisk)
		}
		if gotQRisk == "quantum-safe" && gotHNDL != "" {
			t.Errorf("JSON %q: quantumRisk=quantum-safe but hndlRisk=%q (inconsistent)", tc.algName, gotHNDL)
		}
	}
}

// TestHNDLFormat_SARIFSurfacesHNDLRisk verifies that the SARIF output includes
// hndlRisk in the result properties for vulnerable findings and omits it for safe ones.
func TestHNDLFormat_SARIFSurfacesHNDLRisk(t *testing.T) {
	result := BuildResult("0.1.0", "/src", []string{"cipherscope"}, testFindings())
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, result); err != nil {
		t.Fatalf("WriteSARIF error: %v", err)
	}

	// Parse SARIF as generic JSON.
	var sarif map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &sarif); err != nil {
		t.Fatalf("SARIF unmarshal error: %v", err)
	}

	runs, _ := sarif["runs"].([]interface{})
	if len(runs) == 0 {
		t.Fatal("SARIF: no runs")
	}
	sarifResults, _ := runs[0].(map[string]interface{})["results"].([]interface{})
	if len(sarifResults) != 3 {
		t.Fatalf("SARIF: expected 3 results, got %d", len(sarifResults))
	}

	// Build a map: algorithm name → SARIF result.
	algToSarif := make(map[string]map[string]interface{})
	for _, raw := range sarifResults {
		res, _ := raw.(map[string]interface{})
		msg, _ := res["message"].(map[string]interface{})
		text, _ := msg["text"].(string)
		// Message starts with "Cryptographic algorithm detected: <name>"
		for _, alg := range []string{"RSA-2048", "ECDHE-X25519", "X25519MLKEM768"} {
			if strings.Contains(text, alg) {
				algToSarif[alg] = res
			}
		}
	}

	cases := []struct {
		alg          string
		wantHNDLRisk string
		wantLevel    string
	}{
		{"RSA-2048", "immediate", "error"},      // SevCritical → SARIF error
		{"ECDHE-X25519", "immediate", "error"},
		{"X25519MLKEM768", "", "none"},           // SevInfo → SARIF none
	}

	for _, tc := range cases {
		res := algToSarif[tc.alg]
		if res == nil {
			t.Errorf("SARIF: result for %q not found", tc.alg)
			continue
		}

		// Check SARIF level.
		level, _ := res["level"].(string)
		if level != tc.wantLevel {
			t.Errorf("SARIF %q: level = %q, want %q", tc.alg, level, tc.wantLevel)
		}

		// Check hndlRisk in properties.
		props, _ := res["properties"].(map[string]interface{})
		gotHNDL, _ := props["hndlRisk"].(string)
		if tc.wantHNDLRisk == "" {
			if gotHNDL != "" {
				t.Errorf("SARIF %q: properties.hndlRisk = %q, want absent/empty", tc.alg, gotHNDL)
			}
		} else {
			if gotHNDL != tc.wantHNDLRisk {
				t.Errorf("SARIF %q: properties.hndlRisk = %q, want %q", tc.alg, gotHNDL, tc.wantHNDLRisk)
			}
		}

		// Cross-check: immediate HNDL → quantumRisk must be quantum-vulnerable.
		qr, _ := props["quantumRisk"].(string)
		if gotHNDL == "immediate" && qr != "quantum-vulnerable" {
			t.Errorf("SARIF %q: hndlRisk=immediate but quantumRisk=%q (inconsistent)", tc.alg, qr)
		}
	}
}

// TestHNDLFormat_CBOMSurfacesHNDLRisk verifies that the CycloneDX CBOM output
// includes oqs:hndlRisk in the component properties for vulnerable algorithms
// and omits it for PQ-safe ones.
func TestHNDLFormat_CBOMSurfacesHNDLRisk(t *testing.T) {
	result := BuildResult("0.1.0", "/src", []string{"cipherscope"}, testFindings())
	var buf bytes.Buffer
	if err := WriteCBOM(&buf, result); err != nil {
		t.Fatalf("WriteCBOM error: %v", err)
	}

	// Parse CBOM as generic JSON.
	var cbom map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &cbom); err != nil {
		t.Fatalf("CBOM unmarshal error: %v", err)
	}

	components, _ := cbom["components"].([]interface{})
	if len(components) == 0 {
		t.Fatal("CBOM: no components")
	}

	// Index components by name.
	compByName := make(map[string]map[string]interface{})
	for _, raw := range components {
		comp, _ := raw.(map[string]interface{})
		name, _ := comp["name"].(string)
		compByName[name] = comp
	}

	cases := []struct {
		alg          string
		wantHNDLRisk string // "" means property should be absent
		wantPQVerdict string // oqs:policyVerdict
	}{
		{"RSA-2048", "immediate", "quantum-vulnerable"},
		{"ECDHE-X25519", "immediate", "quantum-vulnerable"},
		{"X25519MLKEM768", "", "quantum-safe"},
	}

	for _, tc := range cases {
		comp := compByName[tc.alg]
		if comp == nil {
			names := make([]string, 0, len(compByName))
			for k := range compByName {
				names = append(names, k)
			}
			t.Errorf("CBOM: component %q not found (components: %v)", tc.alg, names)
			continue
		}

		props, _ := comp["properties"].([]interface{})

		// Find oqs:hndlRisk and oqs:policyVerdict in properties.
		var hndlRisk, policyVerdict string
		for _, p := range props {
			prop, _ := p.(map[string]interface{})
			name, _ := prop["name"].(string)
			value, _ := prop["value"].(string)
			switch name {
			case "oqs:hndlRisk":
				hndlRisk = value
			case "oqs:policyVerdict":
				policyVerdict = value
			}
		}

		if tc.wantHNDLRisk == "" {
			if hndlRisk != "" {
				t.Errorf("CBOM %q: oqs:hndlRisk = %q, want absent (PQ-safe)", tc.alg, hndlRisk)
			}
		} else {
			if hndlRisk != tc.wantHNDLRisk {
				t.Errorf("CBOM %q: oqs:hndlRisk = %q, want %q", tc.alg, hndlRisk, tc.wantHNDLRisk)
			}
		}

		if policyVerdict != tc.wantPQVerdict {
			t.Errorf("CBOM %q: oqs:policyVerdict = %q, want %q", tc.alg, policyVerdict, tc.wantPQVerdict)
		}

		// Cross-check invariant.
		if hndlRisk == "immediate" && policyVerdict != "quantum-vulnerable" {
			t.Errorf("CBOM %q: hndlRisk=immediate but policyVerdict=%q (inconsistent)", tc.alg, policyVerdict)
		}
		if policyVerdict == "quantum-safe" && hndlRisk != "" {
			t.Errorf("CBOM %q: policyVerdict=quantum-safe but hndlRisk=%q (inconsistent)", tc.alg, hndlRisk)
		}
	}
}

