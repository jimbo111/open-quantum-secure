// Package configscanner implements a Tier 1 config-file scanner that detects
// cryptographic parameters in YAML, JSON, .properties, .env, TOML, XML, INI, and HCL files.
// It is pure Go, always available, and requires no external binaries.
package configscanner

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

const maxConfigFileSize = 10 * 1024 * 1024 // 10 MB

// Engine is the config-scanner engine. Pure Go, always available.
type Engine struct{}

// New returns a new Engine.
func New() *Engine { return &Engine{} }

// Name returns the engine identifier.
func (e *Engine) Name() string { return "config-scanner" }

// Tier returns Tier1Pattern.
func (e *Engine) Tier() engines.Tier { return engines.Tier1Pattern }

// Available always returns true because this engine is pure Go.
func (e *Engine) Available() bool { return true }

// Version returns "embedded" because this engine is pure Go and has no external binary.
func (e *Engine) Version() string { return "embedded" }

// SupportedLanguages returns the config file types this engine handles.
func (e *Engine) SupportedLanguages() []string {
	return []string{"yaml", "json", "properties", "env", "toml", "xml", "ini", "hcl"}
}

// Scan walks opts.TargetPath and scans every config file found.
func (e *Engine) Scan(ctx context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error) {
	var result []findings.UnifiedFinding

	err := filepath.WalkDir(opts.TargetPath, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			// Permission errors, stale symlinks, etc. — skip gracefully.
			return nil
		}

		// Propagate cancellation / deadline early.
		if err := ctx.Err(); err != nil {
			return err
		}

		if d.IsDir() {
			base := filepath.Base(path)
			if base == "vendor" || base == "node_modules" || base == ".git" {
				return filepath.SkipDir
			}
			return nil
		}

		// Size guard — skip oversized files and non-regular files (FIFOs, devices).
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > maxConfigFileSize {
			return nil
		}

		if !isConfigFile(path) {
			return nil
		}

		fds, parseErr := e.scanConfigFile(path)
		if parseErr != nil {
			return nil
		}
		result = append(result, fds...)
		return nil
	})

	if err != nil && err != context.Canceled && err != context.DeadlineExceeded {
		return result, fmt.Errorf("walk %q: %w", opts.TargetPath, err)
	}
	if err != nil {
		return result, err
	}
	return result, nil
}

// scanConfigFile reads a single config file, parses it into key-value pairs,
// and matches those pairs against the crypto vocabulary.
func (e *Engine) scanConfigFile(path string) ([]findings.UnifiedFinding, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	lower := strings.ToLower(path)
	ext := filepath.Ext(lower)
	base := strings.ToLower(filepath.Base(path))

	var kvPairs []KeyValue

	switch {
	case ext == ".yaml" || ext == ".yml":
		kvPairs, err = parseYAML(data)
	case ext == ".json":
		kvPairs, err = parseJSON(data)
	case ext == ".properties":
		kvPairs, err = parseProperties(data)
	case ext == ".toml":
		kvPairs, err = parseTOML(data)
	case ext == ".xml" || ext == ".config":
		kvPairs, err = parseXML(data)
	case ext == ".ini" || ext == ".cfg" || ext == ".cnf":
		kvPairs, err = parseINI(data)
	case ext == ".tf" || ext == ".hcl" || ext == ".tfvars":
		kvPairs, err = parseHCL(data)
	case base == ".env" || strings.HasPrefix(base, ".env."):
		kvPairs, err = parseEnv(data)
	default:
		return nil, nil
	}

	if err != nil && len(kvPairs) == 0 {
		return nil, err
	}
	// On partial parse errors (e.g., multi-doc YAML with one bad doc),
	// continue with whatever key-value pairs were successfully extracted.

	return matchCryptoParams(path, kvPairs), nil
}
