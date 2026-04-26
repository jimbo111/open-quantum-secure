package cryptodeps

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"time"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// rawOutput mirrors the top-level JSON object that cryptodeps emits.
type rawOutput struct {
	Dependencies []rawDependency `json:"dependencies"`
}

// rawDependency describes a single dependency with its crypto usages.
type rawDependency struct {
	Name         string           `json:"name"`
	Version      string           `json:"version"`
	Ecosystem    string           `json:"ecosystem"`
	CryptoUsages []rawCryptoUsage `json:"cryptoUsages"`
}

// rawCryptoUsage describes a single cryptographic usage within a dependency.
type rawCryptoUsage struct {
	Algorithm   string   `json:"algorithm"`
	QuantumRisk string   `json:"quantumRisk"`
	Reachable   *bool    `json:"reachable"` // pointer so we can distinguish false from missing
	CallPath    []string `json:"callPath"`
	File        string   `json:"file"`
	Line        int      `json:"line"`
}

// Engine is the cryptodeps engine wrapper.
type Engine struct {
	binaryPath string
}

// New creates a cryptodeps engine, searching for the binary in known locations.
func New(engineDirs ...string) *Engine {
	e := &Engine{}
	e.binaryPath = e.findBinary(engineDirs)
	return e
}

func (e *Engine) Name() string       { return "cryptodeps" }
func (e *Engine) Tier() engines.Tier { return engines.Tier3SCA }
func (e *Engine) Available() bool    { return e.binaryPath != "" }
func (e *Engine) Version() string    { return engines.ProbeVersion(e.binaryPath) }
func (e *Engine) SupportedLanguages() []string {
	return []string{"go", "java", "python", "javascript", "rust", "ruby", "dotnet", "php"}
}

// Scan runs the cryptodeps binary and normalizes its JSON output into UnifiedFindings.
func (e *Engine) Scan(ctx context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error) {
	if !e.Available() {
		return nil, fmt.Errorf("cryptodeps binary not found")
	}

	args := []string{"analyze", "--path", opts.TargetPath, "--format", "json", "--output", "-"}

	var stderrBuf bytes.Buffer
	cmd := exec.CommandContext(ctx, e.binaryPath, args...)
	cmd.Stderr = &stderrBuf
	// Bound ctx-cancel cleanup. Critical here because io.ReadAll(stdout)
	// below only returns when the stdout pipe reaches EOF — a grand-child
	// holding stdout open would hang ReadAll past ctx cancellation.
	// See audit F1.
	cmd.WaitDelay = 2 * time.Second

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("cryptodeps stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("cryptodeps start: %w", err)
	}

	// ReadAll MUST complete before Wait — see cmd.StdoutPipe docs.
	data, readErr := io.ReadAll(stdout)
	waitErr := cmd.Wait()

	// Propagate context cancellation before attempting to parse partial output.
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	if readErr != nil {
		return nil, fmt.Errorf("cryptodeps stdout read: %w", readErr)
	}

	if len(data) == 0 {
		if waitErr != nil {
			msg := engines.RedactStderr(stderrBuf.String())
			if msg != "" {
				return nil, fmt.Errorf("cryptodeps exited: %w: %s", waitErr, msg)
			}
			return nil, fmt.Errorf("cryptodeps exited: %w", waitErr)
		}
		return nil, nil
	}

	var raw rawOutput
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("cryptodeps JSON parse: %w", err)
	}

	result := normalize(raw, opts.TargetPath)

	if waitErr != nil {
		msg := engines.RedactStderr(stderrBuf.String())
		if msg != "" {
			return result, fmt.Errorf("cryptodeps exited: %w: %s", waitErr, msg)
		}
		return result, fmt.Errorf("cryptodeps exited: %w", waitErr)
	}

	return result, nil
}

// normalize converts a cryptodeps raw output into a slice of UnifiedFindings.
// Each cryptoUsage becomes an algorithm finding; each unique dependency also
// produces a dependency finding.
func normalize(raw rawOutput, targetPath string) []findings.UnifiedFinding {
	var result []findings.UnifiedFinding

	for _, dep := range raw.Dependencies {
		rawID := dep.Name
		if dep.Version != "" {
			rawID = dep.Name + "@" + dep.Version
		}

		// Emit one dependency finding per dependency.
		depFinding := findings.UnifiedFinding{
			Location: findings.Location{
				File: targetPath,
			},
			Confidence:    findings.ConfidenceMedium,
			SourceEngine:  "cryptodeps",
			Reachable:     findings.ReachableUnknown,
			RawIdentifier: rawID,
			Dependency: &findings.Dependency{
				Library: dep.Name,
				Version: dep.Version,
			},
		}
		result = append(result, depFinding)

		// Emit one algorithm finding per crypto usage.
		for _, usage := range dep.CryptoUsages {
			if usage.Algorithm == "" {
				continue // skip malformed entries
			}

			file := usage.File
			if file == "" {
				file = targetPath
			}

			uf := findings.UnifiedFinding{
				Location: findings.Location{
					File: file,
					Line: usage.Line,
				},
				Confidence:    findings.ConfidenceMedium,
				SourceEngine:  "cryptodeps",
				Reachable:     reachabilityFrom(usage.Reachable),
				RawIdentifier: usage.Algorithm,
				Algorithm: &findings.Algorithm{
					Name: usage.Algorithm,
				},
			}

			result = append(result, uf)
		}
	}

	return result
}

// reachabilityFrom maps a *bool from the JSON output to a Reachability constant.
func reachabilityFrom(r *bool) findings.Reachability {
	if r == nil {
		return findings.ReachableUnknown
	}
	if *r {
		return findings.ReachableYes
	}
	return findings.ReachableNo
}

// findBinary locates the cryptodeps binary.
func (e *Engine) findBinary(extraDirs []string) string {
	return engines.FindBinary(extraDirs, "cryptodeps")
}

func isExecutable(path string) bool {
	return engines.IsExecutable(path)
}
