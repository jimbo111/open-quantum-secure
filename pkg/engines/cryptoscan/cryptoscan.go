package cryptoscan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// rawResults is the top-level JSON envelope from cryptoscan.
type rawResults struct {
	Findings []rawFinding `json:"findings"`
}

// rawFinding mirrors a single finding from cryptoscan's JSON output.
type rawFinding struct {
	ID          string `json:"id"`
	FindingType string `json:"findingType"` // "algorithm", "config", "protocol"
	Category    string `json:"category"`
	Algorithm   string `json:"algorithm"`
	Primitive   string `json:"primitive"` // "hash", "pke", "signature", "aead", "kem", "kdf", "mac"
	KeySize     int    `json:"keySize"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Column      int    `json:"column"`
	Severity    int    `json:"severity"`    // 0=INFO, 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL
	QuantumRisk string `json:"quantumRisk"` // VULNERABLE, PARTIAL, SAFE, UNKNOWN
	Confidence  string `json:"confidence"`  // HIGH, MEDIUM, LOW
}

// Engine is the cryptoscan engine wrapper.
type Engine struct {
	binaryPath string
}

// New creates a cryptoscan engine, searching for the binary in known locations.
func New(engineDirs ...string) *Engine {
	e := &Engine{}
	e.binaryPath = e.findBinary(engineDirs)
	return e
}

func (e *Engine) Name() string       { return "cryptoscan" }
func (e *Engine) Tier() engines.Tier { return engines.Tier1Pattern }
func (e *Engine) Available() bool    { return e.binaryPath != "" }
func (e *Engine) Version() string    { return engines.ProbeVersion(e.binaryPath) }
func (e *Engine) SupportedLanguages() []string {
	return []string{"c", "cpp", "java", "python", "go", "swift", "php", "rust",
		"javascript", "typescript", "ruby", "csharp", "kotlin", "scala"}
}

// Scan runs the cryptoscan binary and normalizes its JSON output.
func (e *Engine) Scan(ctx context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error) {
	if !e.Available() {
		return nil, fmt.Errorf("cryptoscan binary not found")
	}

	args := []string{"scan", opts.TargetPath, "--format", "json"}

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, e.binaryPath, args...)
	cmd.Stderr = &stderr
	// Bound ctx-cancel cleanup; see audit F1.
	cmd.WaitDelay = 2 * time.Second

	out, err := cmd.Output()
	if err != nil {
		// cryptoscan may exit non-zero with --fail-on; still try to parse output
		if len(out) == 0 {
			if msg := engines.RedactStderr(stderr.String()); msg != "" {
				return nil, fmt.Errorf("cryptoscan failed: %w: %s", err, msg)
			}
			return nil, fmt.Errorf("cryptoscan failed: %w", err)
		}
	}

	var raw rawResults
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, fmt.Errorf("cryptoscan JSON parse: %w", err)
	}

	result := make([]findings.UnifiedFinding, 0, len(raw.Findings))
	for _, f := range raw.Findings {
		// Skip findings with no algorithm name (generic/unparsed detections)
		if f.Algorithm == "" && f.FindingType != "config" && f.FindingType != "protocol" {
			continue
		}
		uf := normalize(f)
		result = append(result, uf)
	}

	return result, nil
}

// normalize converts a cryptoscan finding into a UnifiedFinding.
func normalize(raw rawFinding) findings.UnifiedFinding {
	uf := findings.UnifiedFinding{
		Location: findings.Location{
			File:   raw.File,
			Line:   raw.Line,
			Column: raw.Column,
		},
		Confidence:    mapConfidence(raw.Confidence),
		SourceEngine:  "cryptoscan",
		Reachable:     findings.ReachableUnknown,
		RawIdentifier: raw.Algorithm,
	}

	switch raw.FindingType {
	case "algorithm":
		uf.Algorithm = &findings.Algorithm{
			Name:      raw.Algorithm,
			Primitive: mapPrimitive(raw.Primitive),
			KeySize:   raw.KeySize,
		}
	case "config", "protocol":
		// Treat configs/protocols as algorithm-level findings
		if raw.Algorithm != "" {
			uf.Algorithm = &findings.Algorithm{
				Name:      raw.Algorithm,
				Primitive: mapPrimitive(raw.Primitive),
				KeySize:   raw.KeySize,
			}
		}
	}

	return uf
}

// mapConfidence normalizes cryptoscan confidence to our enum.
func mapConfidence(cs string) findings.Confidence {
	switch strings.ToUpper(cs) {
	case "HIGH":
		return findings.ConfidenceHigh
	case "LOW":
		return findings.ConfidenceLow
	default:
		return findings.ConfidenceMedium
	}
}

// mapPrimitive normalizes cryptoscan primitive names to our convention.
// The comparison is case-insensitive so upstream engines emitting "PKE" or
// "AEAD" still get mapped correctly.
func mapPrimitive(p string) string {
	switch strings.ToLower(p) {
	case "pke":
		return "asymmetric"
	case "kem":
		return "kem"
	case "aead":
		return "symmetric"
	case "block-cipher":
		return "symmetric"
	case "stream-cipher":
		return "symmetric"
	case "key-exchange":
		return "key-exchange"
	default:
		// hash, signature, kdf, mac — normalise casing so downstream
		// consumers (policy, compliance) don't see a mix of "HASH" / "hash".
		return strings.ToLower(p)
	}
}

func (e *Engine) findBinary(extraDirs []string) string {
	return engines.FindBinary(extraDirs, "cryptoscan")
}

func isExecutable(path string) bool {
	return engines.IsExecutable(path)
}
