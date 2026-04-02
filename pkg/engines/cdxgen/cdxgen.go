package cdxgen

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

// rawBOM mirrors the CycloneDX JSON schema fields we need.
type rawBOM struct {
	Components []rawComponent `json:"components"`
}

type rawComponent struct {
	Type        string        `json:"type"`
	Name        string        `json:"name"`
	Version     string        `json:"version"`
	PURL        string        `json:"purl"`
	Group       string        `json:"group"`
	Description string        `json:"description"`
	Properties  []rawProperty `json:"properties"`
}

type rawProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Engine is the cdxgen engine wrapper.
type Engine struct {
	binaryPath string
}

// New creates a cdxgen engine, searching for the binary in known locations.
func New(engineDirs ...string) *Engine {
	e := &Engine{}
	e.binaryPath = e.findBinary(engineDirs)
	return e
}

func (e *Engine) Name() string       { return "cdxgen" }
func (e *Engine) Tier() engines.Tier { return engines.Tier3SCA }
func (e *Engine) Available() bool    { return e.binaryPath != "" }
func (e *Engine) Version() string    { return engines.ProbeVersion(e.binaryPath) }
func (e *Engine) SupportedLanguages() []string {
	return []string{
		"javascript", "typescript", "java", "python", "go",
		"ruby", "rust", "dotnet", "php", "swift", "kotlin",
		"scala", "cpp", "c",
	}
}

// Scan runs cdxgen and normalizes the CycloneDX JSON output.
func (e *Engine) Scan(ctx context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error) {
	if !e.Available() {
		return nil, fmt.Errorf("cdxgen binary not found")
	}

	// cdxgen writes to a file; use a temp file to capture output.
	tmp, err := os.CreateTemp("", "cdxgen-output-*.json")
	if err != nil {
		return nil, fmt.Errorf("cdxgen create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	tmp.Close()
	defer os.Remove(tmpPath)

	args := []string{"-o", tmpPath, "--spec-version", "1.5", opts.TargetPath}

	var stderrBuf bytes.Buffer
	cmd := exec.CommandContext(ctx, e.binaryPath, args...)
	cmd.Stderr = &stderrBuf

	// cdxgen frequently exits non-zero even when it produces valid output
	// (e.g., mixed-language projects, partial ecosystem support). Check the
	// output file regardless of exit code.
	runErr := cmd.Run()

	// Propagate context cancellation before reading stale/empty output.
	if ctx.Err() != nil {
		return nil, fmt.Errorf("cdxgen: %w", ctx.Err())
	}

	data, err := os.ReadFile(tmpPath)
	if err != nil || len(data) == 0 {
		if runErr != nil {
			msg := strings.TrimSpace(stderrBuf.String())
			if msg != "" {
				return nil, fmt.Errorf("cdxgen exited with no output: %w: %s", runErr, msg)
			}
			return nil, fmt.Errorf("cdxgen exited with no output: %w", runErr)
		}
		if err != nil {
			return nil, fmt.Errorf("cdxgen read output: %w", err)
		}
		return nil, nil // empty output, no error = no findings
	}

	// cdxgen frequently exits non-zero even with valid output; ignore exit code if we have data.

	var bom rawBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		return nil, fmt.Errorf("cdxgen parse output: %w", err)
	}

	return normalizeAll(bom.Components, opts.TargetPath), nil
}

// normalizeAll converts CycloneDX components to UnifiedFindings, skipping non-library types.
func normalizeAll(components []rawComponent, targetPath string) []findings.UnifiedFinding {
	result := make([]findings.UnifiedFinding, 0, len(components))
	for _, c := range components {
		if c.Type != "library" {
			continue
		}
		result = append(result, normalize(c, targetPath))
	}
	return result
}

// normalize converts a single CycloneDX component into a UnifiedFinding.
func normalize(c rawComponent, targetPath string) findings.UnifiedFinding {
	library := c.Name
	if c.Group != "" {
		library = c.Group + ":" + c.Name
	}

	rawID := c.PURL
	if rawID == "" {
		rawID = c.Name
		if c.Version != "" {
			rawID = c.Name + "@" + c.Version
		}
	}

	uf := findings.UnifiedFinding{
		Location: findings.Location{
			File: manifestFile(targetPath, c.PURL),
			Line: 0,
		},
		Confidence:    findings.ConfidenceLow,
		SourceEngine:  "cdxgen",
		Reachable:     findings.ReachableUnknown,
		RawIdentifier: rawID,
		Dependency: &findings.Dependency{
			Library: library,
		},
	}

	// Extract crypto algorithm from cdx:crypto properties.
	for _, prop := range c.Properties {
		if strings.HasPrefix(prop.Name, "cdx:crypto:") && prop.Value != "" {
			uf.Algorithm = &findings.Algorithm{
				Name: prop.Value,
			}
			break
		}
	}

	return uf
}

// manifestFile infers a manifest filename from the purl ecosystem or falls back to target path.
func manifestFile(targetPath, purl string) string {
	switch {
	case strings.HasPrefix(purl, "pkg:npm/"):
		return filepath.Join(targetPath, "package.json")
	case strings.HasPrefix(purl, "pkg:maven/"):
		return filepath.Join(targetPath, "pom.xml")
	case strings.HasPrefix(purl, "pkg:golang/"):
		return filepath.Join(targetPath, "go.mod")
	case strings.HasPrefix(purl, "pkg:pypi/"):
		return filepath.Join(targetPath, "requirements.txt")
	case strings.HasPrefix(purl, "pkg:gem/"):
		return filepath.Join(targetPath, "Gemfile")
	case strings.HasPrefix(purl, "pkg:cargo/"):
		return filepath.Join(targetPath, "Cargo.toml")
	case strings.HasPrefix(purl, "pkg:nuget/"):
		return targetPath // .csproj filename varies; use target dir
	case strings.HasPrefix(purl, "pkg:composer/"):
		return filepath.Join(targetPath, "composer.json")
	case strings.HasPrefix(purl, "pkg:swift/"):
		return filepath.Join(targetPath, "Package.swift")
	default:
		return targetPath
	}
}

// findBinary locates the cdxgen binary.
func (e *Engine) findBinary(extraDirs []string) string {
	for _, dir := range extraDirs {
		p := filepath.Join(dir, "cdxgen")
		if isExecutable(p) {
			return p
		}
	}

	if p, err := exec.LookPath("cdxgen"); err == nil {
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
