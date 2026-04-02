package cipherscope

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// rawFinding mirrors the JSONL schema that cipherscope emits.
type rawFinding struct {
	AssetType  string          `json:"assetType"`  // "library" or "algorithm"
	Identifier string          `json:"identifier"` // e.g. "AES-256-GCM", "OpenSSL"
	Path       string          `json:"path"`
	Evidence   rawEvidence     `json:"evidence"`
	Metadata   json.RawMessage `json:"metadata,omitempty"`
}

type rawEvidence struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

type rawMetadata struct {
	KeySize   interface{} `json:"keysize,omitempty"`   // can be int or string
	Primitive string      `json:"primitive,omitempty"`
	Mode      string      `json:"mode,omitempty"`
	Curve     string      `json:"curve,omitempty"`
}

// Engine is the cipherscope engine wrapper.
type Engine struct {
	binaryPath string
}

// New creates a cipherscope engine, searching for the binary in known locations.
func New(engineDirs ...string) *Engine {
	e := &Engine{}
	e.binaryPath = e.findBinary(engineDirs)
	return e
}

func (e *Engine) Name() string                  { return "cipherscope" }
func (e *Engine) Tier() engines.Tier            { return engines.Tier1Pattern }
func (e *Engine) Available() bool               { return e.binaryPath != "" }
func (e *Engine) Version() string               { return engines.ProbeVersion(e.binaryPath) }
func (e *Engine) SupportedLanguages() []string {
	return []string{"c", "cpp", "java", "python", "go", "swift", "php", "objc", "rust", "javascript", "typescript"}
}

// Scan runs the cipherscope binary and normalizes its JSONL output.
func (e *Engine) Scan(ctx context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error) {
	if !e.Available() {
		return nil, fmt.Errorf("cipherscope binary not found")
	}

	args := []string{"--roots", opts.TargetPath, "--output", "-"}
	if opts.MaxFileMB > 0 {
		args = append(args, "--max-file-mb", strconv.Itoa(opts.MaxFileMB))
	}

	var stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, e.binaryPath, args...)
	cmd.Stderr = &stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("cipherscope stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("cipherscope start: %w", err)
	}

	var result []findings.UnifiedFinding
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024) // 10MB max line

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var raw rawFinding
		if err := json.Unmarshal(line, &raw); err != nil {
			continue // skip malformed lines
		}

		uf := normalize(raw)
		result = append(result, uf)
	}

	scanErr := scanner.Err()

	// Drain remaining stdout and reap subprocess.
	// ReadAll/drain MUST complete before Wait — see cmd.StdoutPipe docs.
	io.Copy(io.Discard, stdout)
	waitErr := cmd.Wait()

	if scanErr != nil {
		return result, fmt.Errorf("cipherscope stdout read: %w", scanErr)
	}
	if waitErr != nil {
		// cipherscope exits 0 on success; non-zero is unexpected but we still return partial results
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return result, fmt.Errorf("cipherscope exited: %w: %s", waitErr, msg)
		}
		return result, fmt.Errorf("cipherscope exited: %w", waitErr)
	}

	return result, nil
}

// normalize converts a cipherscope raw finding into a UnifiedFinding.
func normalize(raw rawFinding) findings.UnifiedFinding {
	uf := findings.UnifiedFinding{
		Location: findings.Location{
			File:   raw.Path,
			Line:   raw.Evidence.Line,
			Column: raw.Evidence.Column,
		},
		Confidence:    findings.ConfidenceMedium, // AST-only, no taint
		SourceEngine:  "cipherscope",
		Reachable:     findings.ReachableUnknown,
		RawIdentifier: raw.Identifier,
	}

	switch raw.AssetType {
	case "library":
		uf.Dependency = &findings.Dependency{
			Library: raw.Identifier,
		}
	case "algorithm":
		alg := parseAlgorithm(raw.Identifier)

		// Overlay metadata from cipherscope if available
		if len(raw.Metadata) > 0 {
			var meta rawMetadata
			if json.Unmarshal(raw.Metadata, &meta) == nil {
				if meta.Primitive != "" {
					alg.Primitive = meta.Primitive
				}
				if meta.Mode != "" {
					alg.Mode = meta.Mode
				}
				if meta.Curve != "" {
					alg.Curve = meta.Curve
				}
				if ks := parseKeySize(meta.KeySize); ks > 0 {
					alg.KeySize = ks
				}
			}
		}

		uf.Algorithm = &alg
	}

	return uf
}

// parseAlgorithm parses an identifier like "AES-256-GCM" into structured fields.
func parseAlgorithm(identifier string) findings.Algorithm {
	alg := findings.Algorithm{Name: identifier}

	parts := strings.Split(identifier, "-")
	if len(parts) == 1 {
		return alg
	}

	// Try to extract key size and mode from the parts
	for _, part := range parts[1:] {
		if n, err := strconv.Atoi(part); err == nil && n >= 64 {
			// Only treat as key size if >= 64 bits (avoids SHA-1, SHA-3, etc.)
			alg.KeySize = n
		} else {
			// Likely a mode like GCM, CBC, CTR, etc.
			upper := strings.ToUpper(part)
			switch upper {
			case "GCM", "CBC", "CTR", "ECB", "CFB", "OFB", "CCM", "XTS", "WRAP":
				alg.Mode = upper
			case "P256", "P384", "P521", "CURVE25519", "ED25519", "ED448", "X25519", "X448":
				alg.Curve = upper
			}
		}
	}

	return alg
}

// parseKeySize attempts to extract a numeric key size from cipherscope metadata.
// Returns 0 for out-of-range or non-integer values.
func parseKeySize(v interface{}) int {
	switch ks := v.(type) {
	case float64:
		// Reject NaN, Inf, negative, non-integer, and values that don't fit in int
		if ks != ks || ks < 0 || ks > 1<<31-1 || ks != float64(int(ks)) {
			return 0
		}
		return int(ks)
	case int:
		if ks < 0 {
			return 0
		}
		return ks
	case string:
		n, _ := strconv.Atoi(ks)
		if n < 0 {
			return 0
		}
		return n
	}
	return 0
}

// findBinary locates the cipherscope binary.
func (e *Engine) findBinary(extraDirs []string) string {
	// 1. Check extra dirs (e.g. ./engines/cipherscope)
	for _, dir := range extraDirs {
		p := filepath.Join(dir, "cipherscope")
		if isExecutable(p) {
			return p
		}
	}

	// 2. Check PATH
	if p, err := exec.LookPath("cipherscope"); err == nil {
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
