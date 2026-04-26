package cbomkit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"

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
	// Bound ctx-cancel cleanup: grand-children that inherit the stderr pipe
	// (e.g. double-forked helpers) can keep the pipe open past Kill, causing
	// Run() to block on the reader goroutine for the full subprocess lifetime.
	// WaitDelay force-closes the pipe 2s after kill. See audit F1.
	cmd.WaitDelay = 2 * time.Second

	// cbomkit-theia exits non-zero in practice when some internal scanners
	// partially fail while others produce valid output. Read the output file
	// regardless of exit code and let presence-of-data drive the decision —
	// mirrors cdxgen's pattern.
	runErr := cmd.Run()

	// Propagate context cancellation before reading stale/empty output.
	if ctx.Err() != nil {
		return nil, fmt.Errorf("cbomkit-theia: %w", ctx.Err())
	}

	data, err := os.ReadFile(tmpPath)
	if err != nil || len(data) == 0 {
		if runErr != nil {
			msg := engines.RedactStderr(stderrBuf.String())
			if msg != "" {
				return nil, fmt.Errorf("cbomkit-theia exited with no output: %w: %s", runErr, msg)
			}
			return nil, fmt.Errorf("cbomkit-theia exited with no output: %w", runErr)
		}
		if err != nil {
			return nil, fmt.Errorf("cbomkit-theia read output: %w", err)
		}
		return nil, fmt.Errorf("cbomkit-theia produced no output (check installation)")
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
//
// When the raw asset has no File (certificate detected in-memory, keystore
// entry with no file association) we synthesise a pseudo-path of the form
// "cbom://<asset-type>" so that different asset types don't all collapse to
// the same DedupeKey ("|0|alg|RSA" for every empty-File RSA asset).
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

	file := asset.File
	if file == "" && asset.Type != "" {
		file = "cbom://" + asset.Type
	}

	return findings.UnifiedFinding{
		Location: findings.Location{
			File: file,
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
	return engines.FindBinary(extraDirs, "cbomkit-theia")
}

func isExecutable(path string) bool {
	return engines.IsExecutable(path)
}
