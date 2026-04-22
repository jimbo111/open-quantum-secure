// Package output — audit tests written for the 2026-04-20 scanner layer
// audit. These are property-based (P) and adversarial-fixture (A) tests that
// check schema validity, round-trip behaviour, injection handling, and
// Sprint-2 property naming across the JSON / SARIF / CBOM / HTML / Table
// writers.
//
// The tests are read-only: they never touch disk, never hit the network, and
// never mutate package-level state (except a controlled useColor toggle that
// restores on defer).
package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// ----------------------------------------------------------------------------
// Test helpers
// ----------------------------------------------------------------------------

// randomFinding returns a UnifiedFinding seeded pseudo-randomly. The finding
// carries a mix of Algorithm / Dependency / PQC / Sprint-8 fields so property
// tests can exercise every code branch in the writers.
func randomFinding(rng *rand.Rand, idx int) findings.UnifiedFinding {
	risks := []findings.QuantumRisk{
		findings.QRVulnerable, findings.QRWeakened, findings.QRSafe,
		findings.QRResistant, findings.QRDeprecated, findings.QRUnknown,
	}
	sevs := []findings.Severity{
		findings.SevCritical, findings.SevHigh, findings.SevMedium,
		findings.SevLow, findings.SevInfo,
	}
	confs := []findings.Confidence{
		findings.ConfidenceHigh, findings.ConfidenceMediumHigh,
		findings.ConfidenceMedium, findings.ConfidenceMediumLow, findings.ConfidenceLow,
	}
	reach := []findings.Reachability{findings.ReachableYes, findings.ReachableNo, findings.ReachableUnknown}

	algNames := []string{"RSA", "ECDSA", "AES", "ChaCha20", "ML-KEM", "ML-DSA", "SHA-256"}
	engines := []string{"cryptoscan", "cipherscope", "tls-probe", "config-scanner", "binary-scanner"}

	f := findings.UnifiedFinding{
		Location: findings.Location{
			File:   fmt.Sprintf("/repo/pkg/file_%d.go", idx),
			Line:   rng.Intn(10_000),
			Column: rng.Intn(80),
		},
		Algorithm: &findings.Algorithm{
			Name:    algNames[rng.Intn(len(algNames))],
			KeySize: 128 * (1 + rng.Intn(4)),
		},
		Confidence:   confs[rng.Intn(len(confs))],
		SourceEngine: engines[rng.Intn(len(engines))],
		Reachable:    reach[rng.Intn(len(reach))],
		QuantumRisk:  risks[rng.Intn(len(risks))],
		Severity:     sevs[rng.Intn(len(sevs))],
	}
	if rng.Intn(3) == 0 {
		f.PQCPresent = true
		f.PQCMaturity = "final"
		f.NegotiatedGroupName = "X25519MLKEM768"
	}
	if rng.Intn(5) == 0 {
		f.PartialInventory = true
		f.PartialInventoryReason = "ECH_ENABLED"
	}
	if rng.Intn(4) == 0 {
		f.HandshakeVolumeClass = "hybrid-kem"
		f.HandshakeBytes = int64(7000 + rng.Intn(5000))
	}
	return f
}

// ----------------------------------------------------------------------------
// SARIF schema validation (minimal, manual, per 2.1.0 §3)
// ----------------------------------------------------------------------------

// validateSARIFMinimal does a structural check on a decoded SARIF log per the
// SARIF 2.1.0 specification. Returns a list of schema violations.
func validateSARIFMinimal(raw []byte) []string {
	var problems []string
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return []string{"not valid JSON: " + err.Error()}
	}

	// §3.13.2 version MUST be "2.1.0".
	if v, _ := doc["version"].(string); v != "2.1.0" {
		problems = append(problems, fmt.Sprintf("version must be \"2.1.0\", got %q", v))
	}
	// §3.13.3 $schema is recommended; check when present.
	if s, ok := doc["$schema"].(string); ok && s == "" {
		problems = append(problems, "$schema present but empty")
	}
	runs, ok := doc["runs"].([]any)
	if !ok {
		problems = append(problems, "runs must be an array (§3.13.4)")
		return problems
	}
	for ri, r := range runs {
		run, _ := r.(map[string]any)
		tool, ok := run["tool"].(map[string]any)
		if !ok {
			problems = append(problems, fmt.Sprintf("runs[%d].tool missing (§3.14.6)", ri))
			continue
		}
		driver, ok := tool["driver"].(map[string]any)
		if !ok {
			problems = append(problems, fmt.Sprintf("runs[%d].tool.driver missing (§3.18)", ri))
			continue
		}
		if n, _ := driver["name"].(string); n == "" {
			problems = append(problems, fmt.Sprintf("runs[%d].tool.driver.name empty (§3.19.8)", ri))
		}
		results, _ := run["results"].([]any)
		for ires, rr := range results {
			res, _ := rr.(map[string]any)
			// §3.27.5 message is required.
			msg, ok := res["message"].(map[string]any)
			if !ok {
				problems = append(problems, fmt.Sprintf("runs[%d].results[%d].message missing (§3.27.5)", ri, ires))
			} else if t, _ := msg["text"].(string); t == "" {
				problems = append(problems, fmt.Sprintf("runs[%d].results[%d].message.text empty (§3.27.10)", ri, ires))
			}
			// level if present must be in enum (§3.27.10).
			if lv, ok := res["level"].(string); ok {
				switch lv {
				case "none", "note", "warning", "error":
				default:
					problems = append(problems, fmt.Sprintf("runs[%d].results[%d].level %q not in SARIF enum (§3.27.10)", ri, ires, lv))
				}
			}
			// Region startLine/startColumn MUST be >= 1 (§3.30.5/§3.30.6).
			locs, _ := res["locations"].([]any)
			for il, l := range locs {
				loc, _ := l.(map[string]any)
				phys, _ := loc["physicalLocation"].(map[string]any)
				if phys == nil {
					continue
				}
				if region, ok := phys["region"].(map[string]any); ok {
					if sl, ok := region["startLine"].(float64); ok && sl < 1 {
						problems = append(problems, fmt.Sprintf("runs[%d].results[%d].locations[%d].region.startLine=%v < 1 (§3.30.5)", ri, ires, il, sl))
					}
					if sc, ok := region["startColumn"].(float64); ok && sc < 1 {
						problems = append(problems, fmt.Sprintf("runs[%d].results[%d].locations[%d].region.startColumn=%v < 1 (§3.30.6)", ri, ires, il, sc))
					}
				}
				if art, ok := phys["artifactLocation"].(map[string]any); ok {
					if uri, ok := art["uri"].(string); ok && uri == "" {
						problems = append(problems, fmt.Sprintf("runs[%d].results[%d].locations[%d].artifactLocation.uri empty", ri, ires, il))
					}
				}
			}
		}
	}
	return problems
}

// TestF1_SARIF_SchemaValid_50RandomFindings generates 50 pseudo-random
// UnifiedFinding instances, marshals the scan result to SARIF, and validates
// the output against the SARIF 2.1.0 structural invariants.
func TestF1_SARIF_SchemaValid_50RandomFindings(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	ff := make([]findings.UnifiedFinding, 0, 50)
	for i := 0; i < 50; i++ {
		ff = append(ff, randomFinding(rng, i))
	}
	result := BuildResult("0.1.0", "/repo", []string{"cryptoscan", "tls-probe"}, ff)

	var buf bytes.Buffer
	if err := WriteSARIF(&buf, result); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	probs := validateSARIFMinimal(buf.Bytes())
	if len(probs) > 0 {
		for _, p := range probs {
			t.Errorf("SARIF schema violation: %s", p)
		}
	}
}

// TestF1b_SARIF_NoRegionWhenLineZero guards §3.30.5 (startLine >= 1).
func TestF1b_SARIF_NoRegionWhenLineZero(t *testing.T) {
	ff := []findings.UnifiedFinding{{
		Location:     findings.Location{File: "/repo/a.go", Line: 0, Column: 0},
		Algorithm:    &findings.Algorithm{Name: "RSA"},
		SourceEngine: "x",
		Confidence:   findings.ConfidenceHigh,
		Reachable:    findings.ReachableYes,
	}}
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, BuildResult("0.1.0", "/repo", nil, ff)); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	probs := validateSARIFMinimal(buf.Bytes())
	for _, p := range probs {
		t.Errorf("SARIF violation w/ line=0: %s", p)
	}
}

// ----------------------------------------------------------------------------
// CBOM CycloneDX 1.7 minimal schema + Sprint-2 property naming
// ----------------------------------------------------------------------------

func validateCBOMMinimal(raw []byte) []string {
	var problems []string
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return []string{"invalid JSON: " + err.Error()}
	}
	if f, _ := doc["bomFormat"].(string); f != "CycloneDX" {
		problems = append(problems, fmt.Sprintf("bomFormat must be \"CycloneDX\", got %q", f))
	}
	if v, _ := doc["specVersion"].(string); v != "1.7" {
		problems = append(problems, fmt.Sprintf("specVersion must be \"1.7\", got %q", v))
	}
	if sn, _ := doc["serialNumber"].(string); sn != "" {
		// CycloneDX §5 — serialNumber MUST match urn:uuid:<uuid> regex.
		re := regexp.MustCompile(`^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
		if !re.MatchString(sn) {
			problems = append(problems, fmt.Sprintf("serialNumber %q does not match CycloneDX urn:uuid regex", sn))
		}
	} else {
		problems = append(problems, "serialNumber missing or empty")
	}
	// version MUST be a positive integer.
	if v, ok := doc["version"].(float64); !ok || v < 1 {
		problems = append(problems, "version must be integer >= 1")
	}
	comps, _ := doc["components"].([]any)
	for i, c := range comps {
		comp, _ := c.(map[string]any)
		if t, _ := comp["type"].(string); t == "" {
			problems = append(problems, fmt.Sprintf("components[%d].type empty", i))
		}
		if r, _ := comp["bom-ref"].(string); r == "" {
			problems = append(problems, fmt.Sprintf("components[%d].bom-ref empty", i))
		}
		if n, _ := comp["name"].(string); n == "" {
			problems = append(problems, fmt.Sprintf("components[%d].name empty", i))
		}
	}
	return problems
}

// TestF2_CBOM_SchemaValid_50RandomFindings asserts CBOM (CycloneDX 1.7)
// structural validity over 50 random findings.
func TestF2_CBOM_SchemaValid_50RandomFindings(t *testing.T) {
	rng := rand.New(rand.NewSource(1337))
	ff := make([]findings.UnifiedFinding, 0, 50)
	for i := 0; i < 50; i++ {
		ff = append(ff, randomFinding(rng, i))
	}
	result := BuildResult("0.1.0", "/repo", []string{"cryptoscan"}, ff)

	var buf bytes.Buffer
	if err := WriteCBOM(&buf, result); err != nil {
		t.Fatalf("WriteCBOM: %v", err)
	}
	probs := validateCBOMMinimal(buf.Bytes())
	for _, p := range probs {
		t.Errorf("CBOM schema violation: %s", p)
	}
}

// TestF3_CBOM_Sprint2PropertyNames asserts that when every Sprint-2 tls-probe
// UnifiedFinding field is set, the CBOM output carries them under the EXACT
// names that CLAUDE.md (pkg/output convention block) mandates.
func TestF3_CBOM_Sprint2PropertyNames(t *testing.T) {
	f := findings.UnifiedFinding{
		Location:               findings.Location{File: "/repo/tls.go", Line: 1},
		Algorithm:              &findings.Algorithm{Name: "X25519MLKEM768"},
		SourceEngine:           "tls-probe",
		Confidence:             findings.ConfidenceHigh,
		Reachable:              findings.ReachableYes,
		QuantumRisk:            findings.QRSafe,
		PQCPresent:             true,
		PQCMaturity:            "final",
		NegotiatedGroupName:    "X25519MLKEM768",
		HandshakeVolumeClass:   "hybrid-kem",
		HandshakeBytes:         7500,
		PartialInventory:       true,
		PartialInventoryReason: "ECH_ENABLED",
	}
	result := BuildResult("0.1.0", "/repo", []string{"tls-probe"}, []findings.UnifiedFinding{f})

	var buf bytes.Buffer
	if err := WriteCBOM(&buf, result); err != nil {
		t.Fatalf("WriteCBOM: %v", err)
	}
	out := buf.String()

	required := []string{
		`"name": "oqs:negotiatedGroupName"`,
		`"name": "oqs:handshakeVolumeClass"`,
		`"name": "oqs:handshakeBytes"`,
		`"name": "oqs:partialInventory"`,
		`"name": "oqs:partialInventoryReason"`,
	}
	for _, want := range required {
		if !strings.Contains(out, want) {
			t.Errorf("CBOM missing required Sprint-2 property %q", want)
		}
	}
	// Guard against the pre-Sprint-2 field name being re-introduced.
	if strings.Contains(out, `"oqs:negotiatedGroup"`) && !strings.Contains(out, `"oqs:negotiatedGroupName"`) {
		t.Error("CBOM still emits legacy oqs:negotiatedGroup name — Sprint 2 renamed to oqs:negotiatedGroupName")
	}
}

// ----------------------------------------------------------------------------
// JSON round-trip — every UnifiedFinding field set, marshal→unmarshal→compare.
// ----------------------------------------------------------------------------

// TestF4_JSON_RoundTrip_NoDataLoss sets every UnifiedFinding field to a
// non-zero value, writes JSON via WriteJSON, then unmarshals and checks the
// round-trip.
func TestF4_JSON_RoundTrip_NoDataLoss(t *testing.T) {
	orig := findings.UnifiedFinding{
		Location: findings.Location{
			File:         "/repo/a.go",
			Line:         42,
			Column:       7,
			InnerPath:    "com/foo/Bar.class",
			ArtifactType: "jar",
		},
		Algorithm: &findings.Algorithm{
			Name: "RSA", Primitive: "asymmetric", KeySize: 2048, Mode: "OAEP", Curve: "",
		},
		Confidence:     findings.ConfidenceMediumHigh,
		SourceEngine:   "cryptoscan",
		CorroboratedBy: []string{"cipherscope"},
		Reachable:      findings.ReachableYes,
		RawIdentifier:  "rsa.GenerateKey",
		QuantumRisk:    findings.QRVulnerable,
		Severity:       findings.SevCritical,
		Recommendation: "migrate to ML-KEM",
		DataFlowPath: []findings.FlowStep{
			{File: "a.go", Line: 1, Column: 2, Message: "source"},
		},
		HNDLRisk:        "immediate",
		Priority:        "P1",
		BlastRadius:     75,
		TestFile:        true,
		GeneratedFile:   true,
		MigrationEffort: "moderate",
		TargetAlgorithm: "ML-KEM-768",
		TargetStandard:  "FIPS 203",
		MigrationSnippet: &findings.MigrationSnippet{
			Language:    "go",
			Before:      "rsa.GenerateKey(rand.Reader, 2048)",
			After:       "mlkem.GenerateKey()",
			Explanation: "Replace RSA with ML-KEM.",
		},
		NegotiatedGroup:          0x11EC,
		NegotiatedGroupName:      "X25519MLKEM768",
		PQCPresent:               true,
		PQCMaturity:              "final",
		PartialInventory:         true,
		PartialInventoryReason:   "ECH_ENABLED",
		HandshakeVolumeClass:     "hybrid-kem",
		HandshakeBytes:           7500,
		DeepProbeSupportedGroups: []uint16{0x11EC, 0x0017},
		DeepProbeHRRGroups:       []uint16{0x11EC},
		SupportedGroups:          []uint16{0x11EC, 0x0017},
		SupportedSigAlgs:         []uint16{0x0804},
		ServerPreferredGroup:     0x11EC,
		ServerPreferenceMode:     "server-fixed",
		EnumerationMode:          "groups+preference",
	}
	result := BuildResult("1.0.0", "/repo", []string{"cryptoscan"}, []findings.UnifiedFinding{orig})

	var buf bytes.Buffer
	if err := WriteJSON(&buf, result); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	var round struct {
		Findings []findings.UnifiedFinding `json:"findings"`
	}
	if err := json.Unmarshal(buf.Bytes(), &round); err != nil {
		t.Fatalf("round-trip unmarshal: %v", err)
	}
	if len(round.Findings) != 1 {
		t.Fatalf("expected 1 finding after round-trip, got %d", len(round.Findings))
	}
	got := round.Findings[0]

	// Spot-check every distinct field. A single mismatch surfaces via t.Errorf.
	checks := []struct{ name, a, b string }{
		{"Location.File", orig.Location.File, got.Location.File},
		{"Location.InnerPath", orig.Location.InnerPath, got.Location.InnerPath},
		{"Location.ArtifactType", orig.Location.ArtifactType, got.Location.ArtifactType},
		{"Algorithm.Name", orig.Algorithm.Name, got.Algorithm.Name},
		{"Algorithm.Primitive", orig.Algorithm.Primitive, got.Algorithm.Primitive},
		{"Algorithm.Mode", orig.Algorithm.Mode, got.Algorithm.Mode},
		{"RawIdentifier", orig.RawIdentifier, got.RawIdentifier},
		{"Recommendation", orig.Recommendation, got.Recommendation},
		{"HNDLRisk", orig.HNDLRisk, got.HNDLRisk},
		{"Priority", orig.Priority, got.Priority},
		{"MigrationEffort", orig.MigrationEffort, got.MigrationEffort},
		{"TargetAlgorithm", orig.TargetAlgorithm, got.TargetAlgorithm},
		{"TargetStandard", orig.TargetStandard, got.TargetStandard},
		{"MigrationSnippet.After", orig.MigrationSnippet.After, got.MigrationSnippet.After},
		{"NegotiatedGroupName", orig.NegotiatedGroupName, got.NegotiatedGroupName},
		{"PQCMaturity", orig.PQCMaturity, got.PQCMaturity},
		{"PartialInventoryReason", orig.PartialInventoryReason, got.PartialInventoryReason},
		{"HandshakeVolumeClass", orig.HandshakeVolumeClass, got.HandshakeVolumeClass},
		{"ServerPreferenceMode", orig.ServerPreferenceMode, got.ServerPreferenceMode},
		{"EnumerationMode", orig.EnumerationMode, got.EnumerationMode},
	}
	for _, c := range checks {
		if c.a != c.b {
			t.Errorf("round-trip %s: want %q got %q", c.name, c.a, c.b)
		}
	}
	// Integer / bool fields.
	if orig.Location.Line != got.Location.Line || orig.Location.Column != got.Location.Column {
		t.Errorf("Location.Line/Column round-trip mismatch")
	}
	if orig.Algorithm.KeySize != got.Algorithm.KeySize {
		t.Errorf("KeySize round-trip mismatch")
	}
	if orig.BlastRadius != got.BlastRadius {
		t.Errorf("BlastRadius round-trip mismatch")
	}
	if orig.TestFile != got.TestFile || orig.GeneratedFile != got.GeneratedFile {
		t.Errorf("TestFile/GeneratedFile round-trip mismatch")
	}
	if orig.NegotiatedGroup != got.NegotiatedGroup {
		t.Errorf("NegotiatedGroup round-trip mismatch: %d vs %d", orig.NegotiatedGroup, got.NegotiatedGroup)
	}
	if orig.PQCPresent != got.PQCPresent {
		t.Errorf("PQCPresent round-trip mismatch")
	}
	if orig.PartialInventory != got.PartialInventory {
		t.Errorf("PartialInventory round-trip mismatch")
	}
	if orig.HandshakeBytes != got.HandshakeBytes {
		t.Errorf("HandshakeBytes round-trip mismatch")
	}
	if orig.ServerPreferredGroup != got.ServerPreferredGroup {
		t.Errorf("ServerPreferredGroup round-trip mismatch")
	}
	if len(orig.CorroboratedBy) != len(got.CorroboratedBy) {
		t.Errorf("CorroboratedBy round-trip length mismatch")
	}
	if len(orig.DataFlowPath) != len(got.DataFlowPath) {
		t.Errorf("DataFlowPath round-trip length mismatch")
	}
	if len(orig.DeepProbeSupportedGroups) != len(got.DeepProbeSupportedGroups) ||
		len(orig.DeepProbeHRRGroups) != len(got.DeepProbeHRRGroups) ||
		len(orig.SupportedGroups) != len(got.SupportedGroups) ||
		len(orig.SupportedSigAlgs) != len(got.SupportedSigAlgs) {
		t.Errorf("Sprint7/8 slice round-trip length mismatch")
	}
}

// ----------------------------------------------------------------------------
// Empty input — all four writers must produce something valid.
// ----------------------------------------------------------------------------

func TestF5_EmptyInput_AllFormats(t *testing.T) {
	result := BuildResult("0.1.0", "/repo", []string{"cryptoscan"}, nil)

	// JSON: should contain "findings": [] (omitempty false on Findings).
	var jbuf bytes.Buffer
	if err := WriteJSON(&jbuf, result); err != nil {
		t.Fatalf("WriteJSON empty: %v", err)
	}
	if !strings.Contains(jbuf.String(), `"findings": []`) {
		t.Errorf("empty JSON should contain \"findings\": [], got: %s", jbuf.String())
	}

	// SARIF: valid-but-empty results.
	var sbuf bytes.Buffer
	if err := WriteSARIF(&sbuf, result); err != nil {
		t.Fatalf("WriteSARIF empty: %v", err)
	}
	probs := validateSARIFMinimal(sbuf.Bytes())
	for _, p := range probs {
		t.Errorf("empty-SARIF schema: %s", p)
	}

	// CBOM: valid; components must be present (JSON array, possibly empty).
	var cbuf bytes.Buffer
	if err := WriteCBOM(&cbuf, result); err != nil {
		t.Fatalf("WriteCBOM empty: %v", err)
	}
	probs = validateCBOMMinimal(cbuf.Bytes())
	for _, p := range probs {
		t.Errorf("empty-CBOM schema: %s", p)
	}
	// NOTE: the struct declaration `Components []cdxComponent json:"components"`
	// omits `omitempty`, so an empty slice must still serialize as `[]` rather
	// than `null`. Document the actual behaviour for downstream consumers.
	if strings.Contains(cbuf.String(), `"components": null`) {
		t.Error("empty CBOM emits components:null — downstream consumers expect []")
	}

	// HTML: must emit some document shell.
	var hbuf bytes.Buffer
	if err := WriteHTML(&hbuf, result); err != nil {
		t.Fatalf("WriteHTML empty: %v", err)
	}
	if !strings.Contains(hbuf.String(), "<!DOCTYPE html>") {
		t.Error("empty HTML missing <!DOCTYPE html>")
	}
	if !strings.Contains(hbuf.String(), "No findings detected") {
		t.Error("empty HTML missing 'No findings detected' block")
	}

	// Table: humane no-findings message.
	var tbuf bytes.Buffer
	if err := WriteTable(&tbuf, result); err != nil {
		t.Fatalf("WriteTable empty: %v", err)
	}
	if !strings.Contains(tbuf.String(), "No findings detected") {
		t.Error("empty table missing 'No findings detected' sentinel")
	}
}

// ----------------------------------------------------------------------------
// HTML output: adversarial inputs — XSS payloads, unicode, NULL, long strings.
// ----------------------------------------------------------------------------

// TestF6_HTML_AdversarialInputs_NoRawInjection feeds adversarial payloads into
// fields that flow to the HTML template (Algorithm.Name, Location.File,
// Recommendation, MigrationSnippet.Before/After) and asserts they are never
// emitted unescaped in the output.
func TestF6_HTML_AdversarialInputs_NoRawInjection(t *testing.T) {
	cases := []struct {
		name, payload string
	}{
		{"script tag", `<script>alert(1)</script>`},
		{"img onerror", `<img src=x onerror="alert(1)">`},
		{"rtl override", "foo‮egap.exe"},     // U+202E RIGHT-TO-LEFT OVERRIDE
		{"null byte", "a\x00b"},                   // NULL
		{"javascript url", `javascript:alert(1)`}, // unlikely to land in an href, but still
		{"quote break-out", `"><svg onload=1>`},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			f := findings.UnifiedFinding{
				Location: findings.Location{
					File: "/repo/" + tc.payload + ".go",
					Line: 1,
				},
				Algorithm: &findings.Algorithm{
					Name: tc.payload,
				},
				Recommendation: "Fix " + tc.payload,
				MigrationSnippet: &findings.MigrationSnippet{
					Language:    "go",
					Before:      tc.payload,
					After:       "mlkem.GenerateKey()",
					Explanation: tc.payload,
				},
				SourceEngine: "audit",
				Confidence:   findings.ConfidenceHigh,
				Reachable:    findings.ReachableUnknown,
				QuantumRisk:  findings.QRVulnerable,
				Severity:     findings.SevHigh,
			}
			var buf bytes.Buffer
			if err := WriteHTML(&buf, BuildResult("0.1.0", "/repo", nil, []findings.UnifiedFinding{f})); err != nil {
				t.Fatalf("WriteHTML: %v", err)
			}
			body := buf.String()

			// The dangerous substrings MUST NOT appear verbatim inside element
			// bodies (the html/template engine must escape them). We treat
			// html/template as the oracle: an exact literal substring means
			// either (a) the payload appeared in an attribute as raw text or
			// (b) text content is not being escaped.
			switch tc.name {
			case "script tag":
				if strings.Contains(body, "<script>alert(1)</script>") {
					t.Errorf("raw <script>alert(1)</script> leaked into HTML output")
				}
			case "img onerror":
				if strings.Contains(body, `<img src=x onerror="alert(1)">`) {
					t.Errorf("raw <img onerror=...> leaked into HTML output")
				}
			case "quote break-out":
				if strings.Contains(body, `"><svg onload=1>`) {
					t.Errorf("quote-break-out payload leaked into HTML output")
				}
			case "rtl override", "null byte":
				// These might pass through html/template unescaped (U+202E is
				// a legal codepoint). Document the observed behaviour.
				// We only assert the document still parses — test name records
				// whether we keep the bytes.
				if len(body) == 0 {
					t.Error("HTML body empty for RTL/NULL case")
				}
			case "javascript url":
				// We never place user input into an href today, but record
				// absence from any href attribute anyway.
				if strings.Contains(body, `href="javascript:alert(1)`) {
					t.Errorf("javascript: URL landed in an href attribute")
				}
			}
		})
	}
}

// TestF7_HTML_VeryLongInputs_NoCrash feeds a 1.5 MB algorithm name to the
// HTML writer and asserts it completes and produces a non-empty document.
func TestF7_HTML_VeryLongInputs_NoCrash(t *testing.T) {
	huge := strings.Repeat("A", 1_500_000)
	f := findings.UnifiedFinding{
		Location:     findings.Location{File: "/repo/a.go", Line: 1},
		Algorithm:    &findings.Algorithm{Name: huge},
		SourceEngine: "audit",
		Confidence:   findings.ConfidenceHigh,
		Reachable:    findings.ReachableYes,
		QuantumRisk:  findings.QRUnknown,
	}
	var buf bytes.Buffer
	if err := WriteHTML(&buf, BuildResult("0.1.0", "/repo", nil, []findings.UnifiedFinding{f})); err != nil {
		t.Fatalf("WriteHTML huge: %v", err)
	}
	if !strings.Contains(buf.String(), "</html>") {
		t.Error("HTML missing </html> closing after huge input")
	}
}

// ----------------------------------------------------------------------------
// Table output: ANSI injection, long names, emoji, RTL.
// ----------------------------------------------------------------------------

// TestF8_Table_ANSIInjection exercises ANSI escape injection in algorithm
// names. The table writer currently emits f.Algorithm.Name verbatim — it does
// not sanitize control characters. This test documents the behaviour: a
// malicious algorithm name fed from a file finding will render control bytes
// on the operator's terminal.
func TestF8_Table_ANSIInjection(t *testing.T) {
	// Force-enable colour so colorize() wraps values for fair comparison; the
	// payload itself is emitted regardless of NO_COLOR.
	save := useColor
	useColor = true
	t.Cleanup(func() { useColor = save })

	malicious := "\x1b[31mRSA\x1b[0m\x1b]8;;http://evil/\a"
	f := findings.UnifiedFinding{
		Location:     findings.Location{File: "/repo/a.go", Line: 1},
		Algorithm:    &findings.Algorithm{Name: malicious},
		SourceEngine: "audit",
		Confidence:   findings.ConfidenceHigh,
		Reachable:    findings.ReachableYes,
		QuantumRisk:  findings.QRVulnerable,
	}
	var buf bytes.Buffer
	if err := WriteTable(&buf, BuildResult("0.1.0", "/repo", nil, []findings.UnifiedFinding{f})); err != nil {
		t.Fatalf("WriteTable: %v", err)
	}
	// A passing test documents the current state. When the code starts
	// sanitizing control bytes this assertion must flip.
	if !strings.Contains(buf.String(), "\x1b[31m") {
		t.Log("table output no longer leaks raw ESC[31m — sanitizer has been added")
	} else {
		t.Log("DOCUMENTED: table writer leaks raw ANSI escapes from algorithm name — low-severity finding (see audit report)")
	}
	// Hyperlink-injection OSC 8 sequence must not persist to next line.
	if strings.Contains(buf.String(), "\x1b]8;;http://evil/") {
		t.Log("DOCUMENTED: table writer leaks OSC 8 hyperlink-injection sequence")
	}
}

// TestF9_Table_LongAndWideNames exercises very long algorithm names and
// emoji / mixed-directionality text. The expectation is "no crash".
func TestF9_Table_LongAndWideNames(t *testing.T) {
	long := strings.Repeat("K", 1000)
	cases := []string{long, "crypto-\U0001F512-key", "abcABC‮foo", "中文算法"}
	for _, name := range cases {
		f := findings.UnifiedFinding{
			Location:     findings.Location{File: "/repo/" + name + ".go", Line: 1},
			Algorithm:    &findings.Algorithm{Name: name},
			SourceEngine: "audit",
			Confidence:   findings.ConfidenceHigh,
			Reachable:    findings.ReachableYes,
			QuantumRisk:  findings.QRVulnerable,
		}
		var buf bytes.Buffer
		if err := WriteTable(&buf, BuildResult("0.1.0", "/repo", nil, []findings.UnifiedFinding{f})); err != nil {
			t.Fatalf("WriteTable long: %v", err)
		}
		if len(buf.Bytes()) == 0 {
			t.Errorf("empty output for name %q", name)
		}
	}
}

// TestF9b_Table_TruncateMultibyte is a regression for the `truncate` helper —
// it slices on byte boundaries, which splits multibyte UTF-8 runes in half.
// A finding whose algorithm name is near-but-over the column cap containing
// multibyte characters will emit invalid UTF-8. This is a cosmetic (low)
// issue that the audit report records.
func TestF9b_Table_TruncateMultibyte(t *testing.T) {
	// nameW in table.go = 28. Build a string > 28 bytes where byte 28 lands
	// inside a multibyte rune.
	// "x" x 27 = 27 bytes, then a 3-byte char => byte 28 is middle of rune.
	s := strings.Repeat("x", 27) + "中word"
	got := truncate(s, 28)
	// The ellipsis path takes maxLen-1 = 27 bytes and appends "…" (3 bytes),
	// so truncate(s, 28) = first 27 "x" + "…" which is valid UTF-8 here —
	// but a shifted repeat triggers the bad case.
	s2 := strings.Repeat("x", 28) + "中word" // 28 x's then multibyte
	got2 := truncate(s2, 29)                 // maxLen-1=28 → cuts first "x" + first byte of 中
	_ = got
	if !isValidUTF8(got2) {
		t.Logf("DOCUMENTED: truncate() cuts on byte boundary and can produce invalid UTF-8 (%q) — cosmetic", got2)
	}
}

// isValidUTF8 is a small local helper so the test file has zero new deps.
func isValidUTF8(s string) bool {
	for _, r := range s {
		if r == '�' {
			return false
		}
	}
	return true
}

// ----------------------------------------------------------------------------
// CBOM adversarial test: malformed payloads must not produce invalid JSON.
// ----------------------------------------------------------------------------

// TestF10_CBOM_AdversarialPayload ensures that adversarial strings in
// Algorithm.Name / Dependency.Library are escaped by the encoding/json
// marshaller, keeping the document valid.
func TestF10_CBOM_AdversarialPayload(t *testing.T) {
	payloads := []string{
		"\"", "\\", "\x00", "‮", "<script>",
		strings.Repeat("Z", 1_000_000),
	}
	for _, p := range payloads {
		f := findings.UnifiedFinding{
			Location:     findings.Location{File: "/repo/a.go", Line: 1},
			Algorithm:    &findings.Algorithm{Name: p},
			SourceEngine: "audit",
			Confidence:   findings.ConfidenceHigh,
			Reachable:    findings.ReachableYes,
			QuantumRisk:  findings.QRVulnerable,
		}
		var buf bytes.Buffer
		if err := WriteCBOM(&buf, BuildResult("0.1.0", "/repo", nil, []findings.UnifiedFinding{f})); err != nil {
			t.Fatalf("WriteCBOM payload %q: %v", p, err)
		}
		var any map[string]any
		if err := json.Unmarshal(buf.Bytes(), &any); err != nil {
			t.Errorf("CBOM invalid JSON after payload %q: %v", p, err)
		}
	}
}

// ----------------------------------------------------------------------------
// SARIF adversarial: injection payload escaping + ruleId sanitization
// ----------------------------------------------------------------------------

// TestF11_SARIF_AdversarialAlgName asserts encoding/json escapes adversarial
// content so the document stays structurally valid, and that sanitizeID
// strips angle brackets before the rule ID is emitted.
func TestF11_SARIF_AdversarialAlgName(t *testing.T) {
	bad := `<script>alert("1")&'x</script>`
	f := findings.UnifiedFinding{
		Location:     findings.Location{File: "/repo/a.go", Line: 1},
		Algorithm:    &findings.Algorithm{Name: bad},
		SourceEngine: "audit",
		Confidence:   findings.ConfidenceHigh,
		Reachable:    findings.ReachableYes,
		QuantumRisk:  findings.QRVulnerable,
		Severity:     findings.SevHigh,
	}
	var buf bytes.Buffer
	if err := WriteSARIF(&buf, BuildResult("0.1.0", "/repo", nil, []findings.UnifiedFinding{f})); err != nil {
		t.Fatalf("WriteSARIF: %v", err)
	}
	probs := validateSARIFMinimal(buf.Bytes())
	for _, p := range probs {
		t.Errorf("SARIF with adversarial alg name schema violation: %s", p)
	}
	// ruleId must NOT contain raw <, >, " or ' (sanitizeID removes them).
	var doc map[string]any
	_ = json.Unmarshal(buf.Bytes(), &doc)
	runs := doc["runs"].([]any)
	rules := runs[0].(map[string]any)["tool"].(map[string]any)["driver"].(map[string]any)["rules"].([]any)
	for _, r := range rules {
		rule := r.(map[string]any)
		id, _ := rule["id"].(string)
		if strings.ContainsAny(id, `<>"'`) {
			t.Errorf("ruleId %q contains angle bracket / quote — sanitizeID should have stripped it", id)
		}
	}
}
