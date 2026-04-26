package semgrep

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

//go:embed rules/crypto-taint/*.yaml
var embeddedRules embed.FS

// Engine is the Semgrep engine wrapper for taint/flow analysis.
type Engine struct {
	binaryPath string
	rulesDir   string // external rules dir override, empty = use embedded
}

// New creates a Semgrep engine, searching for the binary and rules in the given dirs.
func New(engineDirs ...string) *Engine {
	e := &Engine{}
	e.binaryPath = findBinary(engineDirs)
	e.rulesDir = findRulesDir(engineDirs)
	return e
}

func (e *Engine) Name() string       { return "semgrep" }
func (e *Engine) Tier() engines.Tier { return engines.Tier2Flow }
func (e *Engine) Available() bool    { return e.binaryPath != "" }
func (e *Engine) Version() string    { return engines.ProbeVersion(e.binaryPath) }

func (e *Engine) SupportedLanguages() []string {
	return []string{
		"java", "python", "go", "javascript", "typescript",
		"c", "cpp", "ruby", "rust", "php",
	}
}

// Scan runs semgrep and normalizes SARIF output into UnifiedFindings.
func (e *Engine) Scan(ctx context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error) {
	if !e.Available() {
		return nil, fmt.Errorf("semgrep binary not found")
	}

	rulesDir, tmpCleanup, err := e.resolveRulesDir()
	if err != nil {
		return nil, fmt.Errorf("semgrep rules: %w", err)
	}
	if tmpCleanup != nil {
		defer tmpCleanup()
	}

	// Create temp file for SARIF output.
	tmpFile, err := os.CreateTemp("", "oqs-semgrep-sarif-*.json")
	if err != nil {
		return nil, fmt.Errorf("semgrep: create temp sarif file: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	args := []string{
		"scan",
		"--config", rulesDir,
		"--sarif",
		"--output", tmpPath,
		opts.TargetPath,
	}

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, e.binaryPath, args...)
	cmd.Stderr = &stderr
	// Bound ctx-cancel cleanup; see audit F1.
	cmd.WaitDelay = 2 * time.Second

	// Semgrep exits 1 when findings are present — tolerate non-zero exit.
	// But propagate context cancellation and detect real failures.
	runErr := cmd.Run()
	if runErr != nil && ctx.Err() != nil {
		return nil, fmt.Errorf("semgrep: %w", ctx.Err())
	}

	data, err := os.ReadFile(tmpPath)
	if err != nil {
		if runErr != nil {
			return nil, fmt.Errorf("semgrep failed (stderr: %s): %w", engines.RedactStderr(stderr.String()), runErr)
		}
		return nil, fmt.Errorf("semgrep: read sarif output: %w", err)
	}

	if len(data) == 0 {
		if msg := engines.RedactStderr(stderr.String()); msg != "" {
			return nil, fmt.Errorf("semgrep: no output produced, stderr: %s", msg)
		}
		return nil, nil
	}

	return parseSARIF(data)
}

// resolveRulesDir returns the directory of YAML rules to pass to semgrep.
func (e *Engine) resolveRulesDir() (string, func(), error) {
	if e.rulesDir != "" {
		return e.rulesDir, nil, nil
	}
	return extractEmbeddedRules()
}

// extractEmbeddedRules writes the embedded YAML files to a temp directory.
func extractEmbeddedRules() (string, func(), error) {
	tmp, err := os.MkdirTemp("", "oqs-semgrep-rules-*")
	if err != nil {
		return "", nil, fmt.Errorf("create temp rules dir: %w", err)
	}

	cleanup := func() { os.RemoveAll(tmp) }

	err = fs.WalkDir(embeddedRules, "rules/crypto-taint", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".yaml") {
			return nil
		}
		data, err := embeddedRules.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read embedded rule %s: %w", path, err)
		}
		dst := filepath.Join(tmp, d.Name())
		return os.WriteFile(dst, data, 0644)
	})
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("extract embedded rules: %w", err)
	}

	return tmp, cleanup, nil
}

// parseSARIF decodes SARIF bytes and normalizes them into UnifiedFindings.
func parseSARIF(data []byte) ([]findings.UnifiedFinding, error) {
	var sarif sarifInput
	if err := json.Unmarshal(data, &sarif); err != nil {
		return nil, fmt.Errorf("semgrep: parse sarif: %w", err)
	}

	var result []findings.UnifiedFinding
	for _, run := range sarif.Runs {
		// Build a lookup for rule metadata (algorithm, primitive).
		ruleMeta := buildRuleMetaLookup(run.Tool.Driver.Rules)
		result = append(result, normalize(run.Results, ruleMeta)...)
	}
	return result, nil
}

// normalize converts SARIF results into UnifiedFindings.
func normalize(results []sarifInputResult, ruleMeta map[string]ruleMetadata) []findings.UnifiedFinding {
	out := make([]findings.UnifiedFinding, 0, len(results))

	for _, r := range results {
		uf := findings.UnifiedFinding{
			SourceEngine:  "semgrep",
			Reachable:     findings.ReachableUnknown,
			RawIdentifier: r.RuleID,
		}

		// Location from first entry.
		if len(r.Locations) > 0 {
			loc := r.Locations[0].PhysicalLocation
			line := 0
			col := 0
			if loc.Region != nil {
				line = loc.Region.StartLine
				col = loc.Region.StartColumn
			}
			uf.Location = findings.Location{
				File:   cleanURI(loc.ArtifactLocation.URI),
				Line:   line,
				Column: col,
			}
		}

		// Algorithm and primitive from rule metadata, with fallback to ruleID inference.
		meta := ruleMeta[r.RuleID]
		algName := meta.Algorithm
		if algName == "" {
			algName = inferAlgorithmFromRuleID(r.RuleID)
		}
		primitive := meta.Primitive
		if primitive == "" {
			primitive = primitiveFromRuleID(r.RuleID)
		}

		if algName != "" {
			uf.Algorithm = &findings.Algorithm{
				Name:      algName,
				Primitive: primitive,
			}
		}

		// Confidence, DataFlowPath, and Reachability from codeFlows.
		flowPath := extractDataFlowPath(r.CodeFlows)
		if len(flowPath) > 0 {
			uf.Confidence = findings.ConfidenceHigh
			uf.DataFlowPath = flowPath
			uf.Reachable = findings.ReachableYes
		} else {
			uf.Confidence = findings.ConfidenceMedium
		}

		out = append(out, uf)
	}

	return out
}

// extractDataFlowPath converts SARIF codeFlows into FlowStep slice.
func extractDataFlowPath(codeFlows []sarifInputCodeFlow) []findings.FlowStep {
	if len(codeFlows) == 0 {
		return nil
	}
	// Use the first codeFlow and first threadFlow.
	cf := codeFlows[0]
	if len(cf.ThreadFlows) == 0 {
		return nil
	}
	tf := cf.ThreadFlows[0]
	steps := make([]findings.FlowStep, 0, len(tf.Locations))
	for _, tfl := range tf.Locations {
		phys := tfl.Location.PhysicalLocation
		step := findings.FlowStep{
			File: cleanURI(phys.ArtifactLocation.URI),
		}
		if phys.Region != nil {
			step.Line = phys.Region.StartLine
			step.Column = phys.Region.StartColumn
		}
		if tfl.Message != nil {
			step.Message = tfl.Message.Text
		}
		steps = append(steps, step)
	}
	return steps
}

// ruleMetadata holds extracted metadata fields from a SARIF rule descriptor.
type ruleMetadata struct {
	Algorithm string
	Primitive string
}

// buildRuleMetaLookup builds a map of ruleID -> ruleMetadata.
func buildRuleMetaLookup(rules []sarifInputRule) map[string]ruleMetadata {
	m := make(map[string]ruleMetadata, len(rules))
	for _, r := range rules {
		meta := ruleMetadata{}
		if r.Properties != nil {
			if v, ok := r.Properties["algorithm"]; ok {
				if s, ok := v.(string); ok {
					meta.Algorithm = s
				}
			}
			if v, ok := r.Properties["primitive"]; ok {
				if s, ok := v.(string); ok {
					meta.Primitive = s
				}
			}
		}
		m[r.ID] = meta
	}
	return m
}

// ruleIDTokenSep is the set of characters that separate tokens in a rule ID.
// Rule IDs are conventionally kebab-case but may also use underscores, dots,
// or slashes. Splitting on any of these gives the per-token view used by
// inferAlgorithmFromRuleID to avoid substring false positives.
const ruleIDTokenSep = "-_./"

// tokenizeRuleID splits ruleID into lowercase tokens. Empty tokens (from
// consecutive separators) are dropped.
func tokenizeRuleID(ruleID string) []string {
	lower := strings.ToLower(ruleID)
	parts := strings.FieldsFunc(lower, func(r rune) bool {
		return strings.ContainsRune(ruleIDTokenSep, r)
	})
	return parts
}

// ruleIDHasToken reports whether any of the supplied tokens appears in the
// rule ID's token list. Used to avoid substring matches like "rsa" inside
// "persaepe" (false positive) or "parser" (not containing "rsa" anyway).
func ruleIDHasToken(tokens []string, candidates ...string) bool {
	for _, t := range tokens {
		for _, c := range candidates {
			if t == c {
				return true
			}
		}
	}
	return false
}

// inferAlgorithmFromRuleID extracts a canonical algorithm name from the rule
// ID. Uses token-boundary matching (not substring) so e.g. "persaepe-latin"
// does NOT resolve to "RSA". Priority ordering is preserved from the prior
// implementation: more specific algorithms win.
func inferAlgorithmFromRuleID(ruleID string) string {
	tokens := tokenizeRuleID(ruleID)
	lower := strings.ToLower(ruleID)
	switch {
	case ruleIDHasToken(tokens, "rsa"):
		return "RSA"
	case ruleIDHasToken(tokens, "ecdsa"):
		return "ECDSA"
	case ruleIDHasToken(tokens, "ecdh"):
		return "ECDH"
	case ruleIDHasToken(tokens, "aes"):
		return "AES"
	case ruleIDHasToken(tokens, "hmac"):
		return "HMAC"
	case ruleIDHasToken(tokens, "sha256", "sha-256"):
		return "SHA-256"
	case ruleIDHasToken(tokens, "sha512", "sha-512"):
		return "SHA-512"
	case ruleIDHasToken(tokens, "sha1", "sha-1"):
		return "SHA-1"
	case ruleIDHasToken(tokens, "sha"):
		return "SHA"
	case ruleIDHasToken(tokens, "md5"):
		return "MD5"
	case ruleIDHasToken(tokens, "tls"):
		return "TLS"
	case ruleIDHasToken(tokens, "des", "3des") || strings.Contains(lower, "triple-des"):
		return "DES"
	}
	return ""
}

// primitiveFromRuleID makes a best-effort primitive classification from the rule ID.
func primitiveFromRuleID(ruleID string) string {
	id := strings.ToLower(ruleID)
	switch {
	case strings.Contains(id, "rsa") || strings.Contains(id, "ecdsa") || strings.Contains(id, "ecdh") || strings.Contains(id, "-ec-") || strings.HasSuffix(id, "-ec"):
		return "asymmetric"
	case strings.Contains(id, "aes") || strings.Contains(id, "cipher") || strings.Contains(id, "encrypt") || strings.Contains(id, "decrypt") || strings.Contains(id, "secret-key"):
		return "symmetric"
	case strings.Contains(id, "hmac") || strings.Contains(id, "mac"):
		return "mac"
	case strings.Contains(id, "sha") || strings.Contains(id, "md5") || strings.Contains(id, "digest") || strings.Contains(id, "hash"):
		return "hash"
	case strings.Contains(id, "tls") || strings.Contains(id, "-ssl-") || strings.HasSuffix(id, "-ssl"):
		return "protocol"
	case strings.Contains(id, "kdf"):
		return "kdf"
	}
	return ""
}

// findBinary locates semgrep, checking engineDirs then PATH.
func findBinary(extraDirs []string) string {
	return engines.FindBinary(extraDirs, "semgrep")
}

// cleanURI strips file:// scheme prefixes from SARIF artifact URIs.
// file:///home/user/path → /home/user/path (preserves leading /)
func cleanURI(uri string) string {
	return strings.TrimPrefix(uri, "file://")
}

// findRulesDir returns the path to an external semgrep-rules directory if present.
func findRulesDir(extraDirs []string) string {
	for _, dir := range extraDirs {
		p := filepath.Join(dir, "semgrep-rules")
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			return p
		}
	}
	return ""
}

func isExecutable(path string) bool {
	return engines.IsExecutable(path)
}

// --- Private SARIF input types (do NOT reuse output/sarif.go types) ---

type sarifInput struct {
	Runs []sarifInputRun `json:"runs"`
}

type sarifInputRun struct {
	Results []sarifInputResult `json:"results"`
	Tool    sarifInputTool     `json:"tool"`
}

type sarifInputTool struct {
	Driver sarifInputDriver `json:"driver"`
}

type sarifInputDriver struct {
	Rules []sarifInputRule `json:"rules"`
}

type sarifInputRule struct {
	ID                   string                 `json:"id"`
	Properties           map[string]interface{} `json:"properties,omitempty"`
	DefaultConfiguration *sarifInputConfig      `json:"defaultConfiguration,omitempty"`
}

type sarifInputConfig struct {
	Level string `json:"level"`
}

type sarifInputResult struct {
	RuleID    string               `json:"ruleId"`
	Message   sarifInputMessage    `json:"message"`
	Locations []sarifInputLocation `json:"locations"`
	CodeFlows []sarifInputCodeFlow `json:"codeFlows,omitempty"`
	Level     string               `json:"level"`
}

type sarifInputMessage struct {
	Text string `json:"text"`
}

type sarifInputLocation struct {
	PhysicalLocation sarifInputPhysical `json:"physicalLocation"`
}

type sarifInputPhysical struct {
	ArtifactLocation sarifInputArtifact `json:"artifactLocation"`
	Region           *sarifInputRegion  `json:"region,omitempty"`
}

type sarifInputArtifact struct {
	URI string `json:"uri"`
}

type sarifInputRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
}

type sarifInputCodeFlow struct {
	ThreadFlows []sarifInputThreadFlow `json:"threadFlows"`
}

type sarifInputThreadFlow struct {
	Locations []sarifInputThreadFlowLocation `json:"locations"`
}

type sarifInputThreadFlowLocation struct {
	Location sarifInputLocation `json:"location"`
	Message  *sarifInputMessage `json:"message,omitempty"`
}
