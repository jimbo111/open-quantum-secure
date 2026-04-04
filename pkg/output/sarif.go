package output

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// SARIF 2.1.0 structures
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules,omitempty"`
}

type sarifRule struct {
	ID               string             `json:"id"`
	Name             string             `json:"name,omitempty"`
	ShortDescription *sarifMessage      `json:"shortDescription,omitempty"`
	HelpURI          string             `json:"helpUri,omitempty"`
	Properties       map[string]any     `json:"properties,omitempty"`
}

type sarifResult struct {
	RuleID     string            `json:"ruleId"`
	Level      string            `json:"level"` // "error", "warning", "note", "none"
	Message    sarifMessage      `json:"message"`
	Locations  []sarifLocation   `json:"locations,omitempty"`
	CodeFlows  []sarifCodeFlow   `json:"codeFlows,omitempty"`
	Properties map[string]any    `json:"properties,omitempty"`
}

type sarifCodeFlow struct {
	ThreadFlows []sarifThreadFlow `json:"threadFlows"`
}

type sarifThreadFlow struct {
	Locations []sarifThreadFlowLocation `json:"locations"`
}

type sarifThreadFlowLocation struct {
	Location sarifLocation `json:"location"`
	Message  *sarifMessage `json:"message,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
}

// WriteSARIF writes findings in SARIF 2.1.0 format.
func WriteSARIF(w io.Writer, result ScanResult) error {
	rules, ruleIndex := buildRules(result.Findings)

	results := make([]sarifResult, 0, len(result.Findings))
	for _, f := range result.Findings {
		results = append(results, findingToSARIF(f, result.Target, ruleIndex))
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "oqs-scanner",
						Version:        result.Version,
						InformationURI: "https://github.com/jimbo111/open-quantum-secure",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// findingToSARIF converts a UnifiedFinding to a SARIF result.
func findingToSARIF(f findings.UnifiedFinding, scanTarget string, ruleIndex map[string]string) sarifResult {
	ruleID := ruleIndex[ruleKeyForFinding(f)]
	msg := buildMessage(f)
	level := levelForFinding(f)

	// Make path relative to scan target for SARIF (forward slashes per RFC 3986)
	uri := f.Location.File
	if rel, err := filepath.Rel(scanTarget, uri); err == nil {
		uri = filepath.ToSlash(rel)
	}
	// Append InnerPath for binary findings (e.g. "app.jar!com/foo/Bar.class")
	if f.Location.InnerPath != "" {
		uri += "!" + f.Location.InnerPath
	}

	physLoc := sarifPhysicalLocation{
		ArtifactLocation: sarifArtifactLocation{
			URI: uri,
		},
	}
	// SARIF 2.1.0 spec: startLine must be >= 1; omit region when line is unknown.
	// startColumn must also be >= 1 when present; omit when column is unknown (0).
	if f.Location.Line > 0 {
		region := &sarifRegion{StartLine: f.Location.Line}
		if f.Location.Column > 0 {
			region.StartColumn = f.Location.Column
		}
		physLoc.Region = region
	}

	result := sarifResult{
		RuleID:  ruleID,
		Level:   level,
		Message: sarifMessage{Text: msg},
		Locations: []sarifLocation{
			{PhysicalLocation: physLoc},
		},
	}

	// Add codeFlows from DataFlowPath (Tier 2 taint analysis)
	if len(f.DataFlowPath) > 0 {
		var tflocs []sarifThreadFlowLocation
		for _, step := range f.DataFlowPath {
			stepURI := step.File
			if rel, err := filepath.Rel(scanTarget, stepURI); err == nil {
				stepURI = filepath.ToSlash(rel)
			}
			stepPhys := sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: stepURI},
			}
			if step.Line > 0 {
				region := &sarifRegion{StartLine: step.Line}
				if step.Column > 0 {
					region.StartColumn = step.Column
				}
				stepPhys.Region = region
			}
			tfl := sarifThreadFlowLocation{
				Location: sarifLocation{PhysicalLocation: stepPhys},
			}
			if step.Message != "" {
				tfl.Message = &sarifMessage{Text: step.Message}
			}
			tflocs = append(tflocs, tfl)
		}
		result.CodeFlows = []sarifCodeFlow{
			{ThreadFlows: []sarifThreadFlow{{Locations: tflocs}}},
		}
	}

	// Add properties — sourceEngine/confidence/reachable always emitted;
	// quantumRisk/severity/recommendation only when non-empty.
	props := map[string]any{
		"sourceEngine": f.SourceEngine,
		"confidence":   string(f.Confidence),
		"reachable":    string(f.Reachable),
	}
	if f.QuantumRisk != "" {
		props["quantumRisk"] = string(f.QuantumRisk)
	}
	if f.Severity != "" {
		props["severity"] = string(f.Severity)
	}
	if f.Recommendation != "" {
		props["recommendation"] = f.Recommendation
	}
	if f.HNDLRisk != "" {
		props["hndlRisk"] = f.HNDLRisk
	}
	if f.Location.ArtifactType != "" {
		props["artifactType"] = f.Location.ArtifactType
	}
	if f.SourceEngine == "config-scanner" {
		props["sourceType"] = "config"
	}
	if f.MigrationEffort != "" {
		props["migrationEffort"] = f.MigrationEffort
	}
	if f.TargetAlgorithm != "" {
		props["targetAlgorithm"] = f.TargetAlgorithm
	}
	if f.TargetStandard != "" {
		props["targetStandard"] = f.TargetStandard
	}
	if f.MigrationSnippet != nil {
		props["migrationSnippet"] = map[string]string{
			"language":    f.MigrationSnippet.Language,
			"before":      f.MigrationSnippet.Before,
			"after":       f.MigrationSnippet.After,
			"explanation": f.MigrationSnippet.Explanation,
		}
	}
	result.Properties = props

	return result
}

// buildMessage creates a human-readable description for a finding.
func buildMessage(f findings.UnifiedFinding) string {
	if f.Dependency != nil {
		msg := fmt.Sprintf("Cryptographic library detected: %s", f.Dependency.Library)
		if len(f.CorroboratedBy) > 0 {
			msg += fmt.Sprintf(" (confirmed by %s)", joinEngines(f.SourceEngine, f.CorroboratedBy))
		}
		return msg
	}

	if f.Algorithm != nil {
		var parts []string
		parts = append(parts, fmt.Sprintf("Cryptographic algorithm detected: %s", f.Algorithm.Name))
		if f.Algorithm.Primitive != "" {
			parts = append(parts, fmt.Sprintf("primitive=%s", f.Algorithm.Primitive))
		}
		if f.Algorithm.KeySize > 0 {
			parts = append(parts, fmt.Sprintf("keySize=%d", f.Algorithm.KeySize))
		}
		if f.Algorithm.Mode != "" {
			parts = append(parts, fmt.Sprintf("mode=%s", f.Algorithm.Mode))
		}
		if f.Algorithm.Curve != "" {
			parts = append(parts, fmt.Sprintf("curve=%s", f.Algorithm.Curve))
		}
		msg := strings.Join(parts, ", ")
		if len(f.CorroboratedBy) > 0 {
			msg += fmt.Sprintf(" (confirmed by %s)", joinEngines(f.SourceEngine, f.CorroboratedBy))
		}
		return msg
	}

	return "Cryptographic usage detected"
}

// levelForFinding maps severity and quantum risk to SARIF level.
func levelForFinding(f findings.UnifiedFinding) string {
	// Use severity if available (from quantum classification)
	switch f.Severity {
	case findings.SevCritical:
		return "error"
	case findings.SevHigh:
		return "warning"
	case findings.SevMedium:
		return "warning"
	case findings.SevLow:
		return "note"
	case findings.SevInfo:
		return "none"
	}
	// Fallback to confidence
	switch f.Confidence {
	case findings.ConfidenceHigh, findings.ConfidenceMediumHigh:
		return "warning"
	case findings.ConfidenceMedium:
		return "warning"
	case findings.ConfidenceMediumLow:
		return "note"
	default:
		return "note"
	}
}

// ruleKeyForFinding generates a key for deduplicating rules.
func ruleKeyForFinding(f findings.UnifiedFinding) string {
	if f.Dependency != nil && f.Dependency.Library != "" {
		return "dep/" + f.Dependency.Library
	}
	if f.Algorithm != nil && f.Algorithm.Name != "" {
		return "alg/" + f.Algorithm.Name
	}
	// Include RawIdentifier to avoid collisions among untyped findings
	if f.RawIdentifier != "" {
		return "raw/" + f.RawIdentifier
	}
	return "unknown/" + f.SourceEngine
}

// buildRules extracts unique rules from findings for the SARIF rules array.
// Returns the rules slice and a map from ruleKey → ruleID.
func buildRules(ff []findings.UnifiedFinding) ([]sarifRule, map[string]string) {
	ruleIndex := make(map[string]string)
	var rules []sarifRule
	seen := make(map[string]bool)

	for _, f := range ff {
		key := ruleKeyForFinding(f)
		if seen[key] {
			continue
		}
		seen[key] = true

		var rule sarifRule
		if f.Dependency != nil {
			rule = sarifRule{
				ID:               "OQS-DEP-" + sanitizeID(f.Dependency.Library),
				Name:             f.Dependency.Library,
				ShortDescription: &sarifMessage{Text: fmt.Sprintf("Cryptographic library: %s", f.Dependency.Library)},
			}
		} else if f.Algorithm != nil && f.Algorithm.Name != "" {
			props := map[string]any{}
			if f.Algorithm.Primitive != "" {
				props["primitive"] = f.Algorithm.Primitive
			}
			rule = sarifRule{
				ID:               "OQS-ALG-" + sanitizeID(f.Algorithm.Name),
				Name:             f.Algorithm.Name,
				ShortDescription: &sarifMessage{Text: fmt.Sprintf("Cryptographic algorithm: %s", f.Algorithm.Name)},
				Properties:       props,
			}
		} else {
			ruleID := "OQS-UNKNOWN"
			desc := "Unknown cryptographic usage"
			if f.RawIdentifier != "" {
				ruleID = "OQS-RAW-" + sanitizeID(f.RawIdentifier)
				desc = fmt.Sprintf("Cryptographic usage: %s", f.RawIdentifier)
			}
			rule = sarifRule{
				ID:               ruleID,
				ShortDescription: &sarifMessage{Text: desc},
			}
		}

		ruleIndex[key] = rule.ID
		rules = append(rules, rule)
	}

	return rules, ruleIndex
}

// joinEngines builds a comma-separated list starting with the source engine
// followed by corroborating engines, without mutating the corroboratedBy slice.
func joinEngines(source string, corroboratedBy []string) string {
	all := make([]string, 0, 1+len(corroboratedBy))
	all = append(all, source)
	all = append(all, corroboratedBy...)
	return strings.Join(all, ", ")
}

// sanitizeID converts an algorithm/library name into a valid SARIF rule ID.
func sanitizeID(name string) string {
	r := strings.NewReplacer(
		" ", "-",
		"/", "-",
		".", "-",
		"(", "",
		")", "",
		"+", "PLUS",
	)
	return strings.ToUpper(r.Replace(name))
}
