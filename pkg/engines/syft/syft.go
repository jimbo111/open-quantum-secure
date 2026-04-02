package syft

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

// rawBOM mirrors the top-level CycloneDX JSON structure that syft emits.
type rawBOM struct {
	BOMFormat  string         `json:"bomFormat"`
	Components []rawComponent `json:"components"`
}

// rawComponent mirrors a single component entry in the CycloneDX components array.
type rawComponent struct {
	Type       string        `json:"type"`
	Name       string        `json:"name"`
	Version    string        `json:"version"`
	PURL       string        `json:"purl"`
	Properties []rawProperty `json:"properties"`
}

// rawProperty mirrors a CycloneDX property key-value pair.
type rawProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Engine is the syft engine wrapper.
type Engine struct {
	binaryPath string
}

// New creates a syft engine, searching for the binary in known locations.
func New(engineDirs ...string) *Engine {
	e := &Engine{}
	e.binaryPath = e.findBinary(engineDirs)
	return e
}

func (e *Engine) Name() string       { return "syft" }
func (e *Engine) Tier() engines.Tier { return engines.Tier3SCA }
func (e *Engine) Available() bool    { return e.binaryPath != "" }
func (e *Engine) Version() string    { return engines.ProbeVersion(e.binaryPath) }
func (e *Engine) SupportedLanguages() []string {
	return []string{"go", "java", "python", "javascript", "ruby", "rust", "dotnet", "php", "cpp", "c"}
}

// Scan runs the syft binary and normalizes its CycloneDX JSON output into UnifiedFindings.
// syft writes output to a file rather than stdout, so a temp file is used.
func (e *Engine) Scan(ctx context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error) {
	if !e.Available() {
		return nil, fmt.Errorf("syft binary not found")
	}

	// syft writes to a file; create a temp file to receive the output.
	tmpFile, err := os.CreateTemp("", "syft-output-*.json")
	if err != nil {
		return nil, fmt.Errorf("syft create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	// syft dir:<targetPath> -o cyclonedx-json=<tmpPath> -q
	outputArg := "cyclonedx-json=" + tmpPath
	args := []string{
		"dir:" + opts.TargetPath,
		"-o", outputArg,
		"-q",
	}

	var stderrBuf bytes.Buffer
	cmd := exec.CommandContext(ctx, e.binaryPath, args...)
	cmd.Stderr = &stderrBuf

	if err := cmd.Run(); err != nil {
		// Propagate context cancellation instead of raw exec error.
		if ctx.Err() != nil {
			return nil, fmt.Errorf("syft: %w", ctx.Err())
		}
		msg := strings.TrimSpace(stderrBuf.String())
		if msg != "" {
			return nil, fmt.Errorf("syft run: %w: %s", err, msg)
		}
		return nil, fmt.Errorf("syft run: %w", err)
	}

	data, err := os.ReadFile(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("syft read output: %w", err)
	}

	if len(data) == 0 {
		return nil, nil
	}

	var raw rawBOM
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("syft JSON parse: %w", err)
	}

	return normalize(raw, opts.TargetPath), nil
}

// normalize converts a syft CycloneDX BOM into a slice of UnifiedFindings.
// Only components with type "library" are included.
func normalize(raw rawBOM, targetPath string) []findings.UnifiedFinding {
	result := make([]findings.UnifiedFinding, 0, len(raw.Components))

	for _, comp := range raw.Components {
		if comp.Type != "library" {
			continue
		}

		rawID := comp.PURL
		if rawID == "" {
			rawID = comp.Name
			if comp.Version != "" {
				rawID = comp.Name + "@" + comp.Version
			}
		}

		// Extract namespace from PURL for consistent cross-engine dedup.
		// e.g. "pkg:maven/org.springframework/spring-core@5.3.0" → "org.springframework:spring-core"
		library := comp.Name
		if ns := purlNamespace(comp.PURL); ns != "" {
			library = ns + ":" + comp.Name
		}

		uf := findings.UnifiedFinding{
			Location: findings.Location{
				File: targetPath,
				Line: 0,
			},
			Confidence:    findings.ConfidenceLow,
			SourceEngine:  "syft",
			Reachable:     findings.ReachableUnknown,
			RawIdentifier: rawID,
			Dependency: &findings.Dependency{
				Library: library,
			},
		}

		result = append(result, uf)
	}

	return result
}

// purlNamespace extracts the namespace from a PURL (e.g. "org.springframework"
// from "pkg:maven/org.springframework/spring-core@5.3.0"). Returns "" if no
// namespace is present.
func purlNamespace(purl string) string {
	if purl == "" {
		return ""
	}
	// Strip "pkg:<type>/"
	idx := strings.Index(purl, "/")
	if idx < 0 {
		return ""
	}
	rest := purl[idx+1:]
	// Remove version suffix
	if at := strings.Index(rest, "@"); at >= 0 {
		rest = rest[:at]
	}
	// If there's a second "/" it separates namespace from name
	if slash := strings.Index(rest, "/"); slash >= 0 {
		return rest[:slash]
	}
	return ""
}

// findBinary locates the syft binary.
func (e *Engine) findBinary(extraDirs []string) string {
	for _, dir := range extraDirs {
		p := filepath.Join(dir, "syft")
		if isExecutable(p) {
			return p
		}
	}

	if p, err := exec.LookPath("syft"); err == nil {
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
