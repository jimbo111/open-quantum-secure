package cbomkit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// rawOutput is the top-level JSON envelope from cbomkit-theia.
type rawOutput struct {
	Assets []rawAsset `json:"assets"`
}

// rawAsset mirrors a single asset from cbomkit-theia's JSON output.
type rawAsset struct {
	Type      string          `json:"type"`      // "certificate", "private-key", "keystore", "config", "ssh-key", etc.
	Algorithm string          `json:"algorithm"` // e.g. "RSA", "EC", "TLS 1.2"
	KeySize   int             `json:"keySize"`
	Curve     string          `json:"curve,omitempty"`
	File      string          `json:"file"`
	Line      int             `json:"line"`
	Details   json.RawMessage `json:"details,omitempty"`
}

// Engine is the cbomkit-theia engine wrapper.
type Engine struct {
	binaryPath string
}

// New creates a cbomkit-theia engine, searching for the binary in known locations.
func New(engineDirs ...string) *Engine {
	e := &Engine{}
	e.binaryPath = e.findBinary(engineDirs)
	return e
}

func (e *Engine) Name() string       { return "cbomkit-theia" }
func (e *Engine) Tier() engines.Tier { return engines.Tier3SCA }
func (e *Engine) Available() bool    { return e.binaryPath != "" }
func (e *Engine) Version() string    { return engines.ProbeVersion(e.binaryPath) }

// SupportedLanguages returns the artifact marker used in the engine registry.
// cbomkit-theia operates on deployed filesystem artifacts (certificates, keystores,
// config files), not source-code languages. The "(artifacts)" token matches the
// registry entry in pkg/enginemgr/enginemgr.go.
func (e *Engine) SupportedLanguages() []string { return []string{"(artifacts)"} }

// Scan runs the cbomkit-theia binary and normalizes its JSON output.
func (e *Engine) Scan(ctx context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error) {
	if !e.Available() {
		return nil, fmt.Errorf("cbomkit-theia binary not found")
	}

	// Write output to a temp file — cbomkit-theia uses --output flag.
	tmpFile, err := os.CreateTemp("", "cbomkit-output-*.json")
	if err != nil {
		return nil, fmt.Errorf("cbomkit-theia temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	args := []string{"scan", "--dir", opts.TargetPath, "--format", "json", "--output", tmpPath}

	var stderrBuf bytes.Buffer
	cmd := exec.CommandContext(ctx, e.binaryPath, args...)
	cmd.Stderr = &stderrBuf

	if err := cmd.Run(); err != nil {
		// Propagate context cancellation instead of raw exec error.
		if ctx.Err() != nil {
			return nil, fmt.Errorf("cbomkit-theia: %w", ctx.Err())
		}
		msg := strings.TrimSpace(stderrBuf.String())
		if msg != "" {
			return nil, fmt.Errorf("cbomkit-theia exited: %w: %s", err, msg)
		}
		return nil, fmt.Errorf("cbomkit-theia exited: %w", err)
	}

	data, err := os.ReadFile(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("cbomkit-theia read output: %w", err)
	}

	if len(data) == 0 {
		return nil, nil
	}

	var raw rawOutput
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("cbomkit-theia JSON parse: %w", err)
	}

	result := make([]findings.UnifiedFinding, 0, len(raw.Assets))
	for _, asset := range raw.Assets {
		result = append(result, normalize(asset))
	}

	return result, nil
}

// normalize converts a cbomkit-theia raw asset into a UnifiedFinding.
func normalize(asset rawAsset) findings.UnifiedFinding {
	var alg *findings.Algorithm
	if asset.Algorithm != "" {
		alg = &findings.Algorithm{
			Name:      asset.Algorithm,
			Primitive: primitiveFromAssetType(asset.Type),
			KeySize:   asset.KeySize,
			Curve:     asset.Curve,
		}
	}

	return findings.UnifiedFinding{
		Location: findings.Location{
			File: asset.File,
			Line: asset.Line,
		},
		Algorithm:     alg,
		Confidence:    findings.ConfidenceMedium,
		SourceEngine:  "cbomkit-theia",
		Reachable:     findings.ReachableUnknown,
		RawIdentifier: asset.Type + ":" + asset.Algorithm,
	}
}

// primitiveFromAssetType maps a cbomkit-theia asset type to a cryptographic primitive.
func primitiveFromAssetType(assetType string) string {
	switch assetType {
	case "certificate", "private-key", "keystore", "ssh-key", "pgp-key":
		return "asymmetric"
	case "config":
		return "protocol"
	default:
		return ""
	}
}

// findBinary locates the cbomkit-theia binary.
func (e *Engine) findBinary(extraDirs []string) string {
	// 1. Check extra dirs (e.g. ./engines/cbomkit-theia)
	for _, dir := range extraDirs {
		p := filepath.Join(dir, "cbomkit-theia")
		if isExecutable(p) {
			return p
		}
	}

	// 2. Check PATH
	if p, err := exec.LookPath("cbomkit-theia"); err == nil {
		return p
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
