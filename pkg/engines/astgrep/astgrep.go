package astgrep

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

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

//go:embed rules/*.yml
var embeddedRules embed.FS

// rawMatch mirrors a single entry in ast-grep's JSON array output.
type rawMatch struct {
	Text     string         `json:"text"`
	Range    rawRange       `json:"range"`
	File     string         `json:"file"`
	Language string         `json:"language"`
	RuleID   string         `json:"ruleId"`
	Message  string         `json:"message"`
	Severity string         `json:"severity"`
	MetaVars rawMetaVars    `json:"metaVariables"`
}

type rawRange struct {
	Start rawPosition `json:"start"`
	End   rawPosition `json:"end"`
}

type rawPosition struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

// rawMetaVars holds captured metavariable bindings from ast-grep rules.
type rawMetaVars map[string]rawMetaVar

type rawMetaVar struct {
	Text string `json:"text"`
}

// Engine is the ast-grep engine wrapper.
type Engine struct {
	binaryPath string
	rulesDir   string // external rules dir, empty = use embedded
}

// New creates an ast-grep engine, searching for the binary and rules in known locations.
func New(engineDirs ...string) *Engine {
	e := &Engine{}
	e.binaryPath = e.findBinary(engineDirs)
	e.rulesDir = findRulesDir(engineDirs)
	return e
}

func (e *Engine) Name() string       { return "astgrep" }
func (e *Engine) Tier() engines.Tier { return engines.Tier1Pattern }
func (e *Engine) Available() bool    { return e.binaryPath != "" }
func (e *Engine) Version() string    { return engines.ProbeVersion(e.binaryPath) }
func (e *Engine) SupportedLanguages() []string {
	return []string{
		"c", "cpp", "java", "python", "go",
		"javascript", "typescript", "rust", "ruby", "csharp", "kotlin", "php",
	}
}

// Scan runs ast-grep and normalizes its JSON output into UnifiedFindings.
func (e *Engine) Scan(ctx context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error) {
	if !e.Available() {
		return nil, fmt.Errorf("ast-grep binary not found")
	}

	rulesDir, tmpCleanup, err := e.resolveRulesDir()
	if err != nil {
		return nil, fmt.Errorf("astgrep rules: %w", err)
	}
	if tmpCleanup != nil {
		defer tmpCleanup()
	}

	args := []string{"scan", opts.TargetPath, "--json"}
	if rulesDir != "" {
		args = append(args, "--rule", rulesDir)
	}

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, e.binaryPath, args...)
	cmd.Stderr = &stderr

	out, err := cmd.Output()
	if err != nil {
		// Propagate context cancellation before attempting to parse partial output.
		if ctx.Err() != nil {
			return nil, fmt.Errorf("ast-grep: %w", ctx.Err())
		}
		// ast-grep exits non-zero when findings are present (similar to grep).
		// Only fail if output is empty.
		if len(out) == 0 {
			msg := strings.TrimSpace(stderr.String())
			if msg != "" {
				return nil, fmt.Errorf("astgrep failed: %w: %s", err, msg)
			}
			return nil, fmt.Errorf("astgrep failed: %w", err)
		}
	}

	if len(out) == 0 {
		return nil, nil
	}

	var matches []rawMatch
	if err := json.Unmarshal(out, &matches); err != nil {
		return nil, fmt.Errorf("astgrep JSON parse: %w", err)
	}

	result := make([]findings.UnifiedFinding, 0, len(matches))
	for _, m := range matches {
		result = append(result, normalize(m))
	}

	return result, nil
}

// resolveRulesDir returns the directory of YAML rules to pass to ast-grep.
// If an external rules dir was found at construction time, it is used directly.
// Otherwise the embedded rules are extracted to a temp directory.
// The second return value is a cleanup function (may be nil).
func (e *Engine) resolveRulesDir() (string, func(), error) {
	if e.rulesDir != "" {
		return e.rulesDir, nil, nil
	}
	return extractEmbeddedRules()
}

// extractEmbeddedRules writes the embedded YAML files to a temp directory
// and returns its path along with a cleanup function.
func extractEmbeddedRules() (string, func(), error) {
	tmp, err := os.MkdirTemp("", "oqs-astgrep-rules-*")
	if err != nil {
		return "", nil, fmt.Errorf("create temp rules dir: %w", err)
	}

	cleanup := func() { os.RemoveAll(tmp) }

	entries, err := fs.ReadDir(embeddedRules, "rules")
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("read embedded rules: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".yml") {
			continue
		}
		data, err := embeddedRules.ReadFile("rules/" + entry.Name())
		if err != nil {
			cleanup()
			return "", nil, fmt.Errorf("read embedded rule %s: %w", entry.Name(), err)
		}
		dst := filepath.Join(tmp, entry.Name())
		if err := os.WriteFile(dst, data, 0644); err != nil {
			cleanup()
			return "", nil, fmt.Errorf("write rule %s: %w", entry.Name(), err)
		}
	}

	return tmp, cleanup, nil
}

// normalize converts an ast-grep match into a UnifiedFinding.
func normalize(m rawMatch) findings.UnifiedFinding {
	algName := extractAlgorithm(m)

	uf := findings.UnifiedFinding{
		Location: findings.Location{
			File:   m.File,
			Line:   m.Range.Start.Line + 1, // ast-grep is 0-indexed
			Column: m.Range.Start.Column + 1,
		},
		Confidence:    confidenceFromSeverity(m.Severity),
		SourceEngine:  "astgrep",
		Reachable:     findings.ReachableUnknown,
		RawIdentifier: m.RuleID,
	}

	if algName != "" {
		uf.Algorithm = &findings.Algorithm{
			Name:      algName,
			Primitive: primitiveFromRuleID(m.RuleID),
		}
	}

	return uf
}

// extractAlgorithm derives a canonical algorithm name from the match.
// Priority: ALGO metavariable > message substring > ruleId suffix.
func extractAlgorithm(m rawMatch) string {
	// 1. Prefer the ALGO metavariable captured by the rule.
	if mv, ok := m.MetaVars["ALGO"]; ok && mv.Text != "" {
		return strings.Trim(mv.Text, `"'`)
	}

	// 2. Try to pull a quoted string literal from the message.
	if name := extractQuoted(m.Message); name != "" {
		return name
	}

	// 3. Fall back to last segment of the ruleId (e.g. "crypto-java-cipher" -> "cipher").
	parts := strings.Split(m.RuleID, "-")
	if len(parts) > 0 {
		return strings.ToUpper(parts[len(parts)-1])
	}

	return m.RuleID
}

// extractQuoted returns the first colon-separated suffix after a colon in msg,
// used to pull "AES-256" from messages like "Java Cipher.getInstance: AES-256".
func extractQuoted(msg string) string {
	idx := strings.LastIndex(msg, ": ")
	if idx < 0 {
		return ""
	}
	candidate := strings.TrimSpace(msg[idx+2:])
	// Strip surrounding quotes from literal captures like `"AES/CBC/PKCS5Padding"`.
	candidate = strings.Trim(candidate, `"'`)
	if candidate == "" || strings.ContainsAny(candidate, " \t\n") {
		return ""
	}
	return candidate
}

// confidenceFromSeverity maps ast-grep severity to our Confidence enum.
func confidenceFromSeverity(sev string) findings.Confidence {
	switch strings.ToLower(sev) {
	case "error":
		return findings.ConfidenceHigh
	case "warning":
		return findings.ConfidenceMedium
	default:
		return findings.ConfidenceLow
	}
}

// primitiveFromRuleID makes a best-effort primitive classification from the rule ID.
func primitiveFromRuleID(ruleID string) string {
	id := strings.ToLower(ruleID)
	switch {
	case strings.Contains(id, "rsa") || strings.Contains(id, "ecdsa") || strings.Contains(id, "ecdh") || strings.Contains(id, "-ec-") || strings.HasSuffix(id, "-ec"):
		return "asymmetric"
	case strings.Contains(id, "aes") || strings.Contains(id, "cipher") || strings.Contains(id, "encrypt") || strings.Contains(id, "decrypt") || strings.Contains(id, "secret-key"):
		return "symmetric"
	case strings.Contains(id, "sha") || strings.Contains(id, "md5") || strings.Contains(id, "digest") || strings.Contains(id, "hash"):
		return "hash"
	case strings.Contains(id, "hmac") || strings.Contains(id, "mac"):
		return "mac"
	case strings.Contains(id, "tls") || strings.Contains(id, "-ssl-") || strings.HasSuffix(id, "-ssl"):
		return "protocol"
	case strings.Contains(id, "kdf"):
		return "kdf"
	}
	return ""
}

// findBinary locates ast-grep, checking engineDirs then PATH.
// ast-grep ships as both "ast-grep" and the shorter "sg".
func (e *Engine) findBinary(extraDirs []string) string {
	candidates := []string{"ast-grep", "sg"}

	for _, dir := range extraDirs {
		for _, name := range candidates {
			p := filepath.Join(dir, name)
			if isExecutable(p) {
				return p
			}
		}
	}

	for _, name := range candidates {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}

	return ""
}

// findRulesDir returns the path to an external astgrep-rules directory if present.
func findRulesDir(extraDirs []string) string {
	for _, dir := range extraDirs {
		p := filepath.Join(dir, "astgrep-rules")
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			return p
		}
	}
	return ""
}

func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir() && info.Mode()&0111 != 0
}
