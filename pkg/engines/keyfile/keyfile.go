// Package keyfile implements a Tier 1 engine that statically inventories
// cryptographic key and certificate material checked into repositories:
// PEM certificates, private/public keys, DER certificates, and OpenSSH
// key files (authorized_keys, known_hosts, id_* and *.pub).
//
// It is pure Go, always available, and requires no external binaries.
// go.mod does not include golang.org/x/crypto, so SSH material is parsed
// with a minimal built-in SSH wire-format reader (see ssh.go) instead of
// golang.org/x/crypto/ssh.
package keyfile

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// maxKeyFileSize bounds per-file reads. Key/cert material is tiny; anything
// larger than a few MB is not a key file worth parsing.
const maxKeyFileSize = 4 * 1024 * 1024 // 4 MB

// keyExtensions lists file extensions that may contain key/cert material.
var keyExtensions = map[string]bool{
	".pem": true,
	".crt": true,
	".cer": true,
	".der": true,
	".pub": true,
	".key": true,
	".p8":  true,
}

// wellKnownKeyBasenames lists extension-less filenames that hold SSH key
// material. The .pub variants (id_rsa.pub, ...) are caught by keyExtensions.
var wellKnownKeyBasenames = map[string]bool{
	"authorized_keys":  true,
	"authorized_keys2": true,
	"known_hosts":      true,
	"known_hosts2":     true,
	"id_rsa":           true,
	"id_ecdsa":         true,
	"id_ed25519":       true,
	"id_dsa":           true,
}

// Engine is the key-file inventory engine. Pure Go, always available.
type Engine struct{}

// New returns a new Engine.
func New() *Engine { return &Engine{} }

// Name returns the engine identifier.
func (e *Engine) Name() string { return "keyfile" }

// Tier returns Tier1Pattern.
func (e *Engine) Tier() engines.Tier { return engines.Tier1Pattern }

// Available always returns true because this engine is pure Go.
func (e *Engine) Available() bool { return true }

// Version returns "embedded" because this engine has no external binary.
func (e *Engine) Version() string { return "embedded" }

// SupportedLanguages returns "(artifacts)" — key files are matched by
// basename/extension inside the engine's own walker, not by source language.
func (e *Engine) SupportedLanguages() []string { return []string{"(artifacts)"} }

// Scan walks opts.TargetPath and inventories every key/cert file found.
// Malformed files never fail the scan — they are skipped silently.
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
			// Skip dot-directories (except the scan root itself) and
			// dependency trees.
			if path != opts.TargetPath && strings.HasPrefix(base, ".") {
				return filepath.SkipDir
			}
			if base == "vendor" || base == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}

		// Size guard — skip oversized files and non-regular files (FIFOs, devices).
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() || info.Size() > maxKeyFileSize {
			return nil
		}

		if !isKeyFile(path) {
			return nil
		}

		result = append(result, scanKeyFile(path)...)
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

// isKeyFile returns true if path should be inspected for key material.
func isKeyFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if wellKnownKeyBasenames[base] {
		return true
	}
	return keyExtensions[strings.ToLower(filepath.Ext(path))]
}

// scanKeyFile reads one file and dispatches by content shape. Any parse
// failure yields zero findings, never an error.
func scanKeyFile(path string) []findings.UnifiedFinding {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	if bytes.Contains(data, []byte("-----BEGIN ")) {
		return scanPEM(path, data)
	}

	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".der" || ext == ".cer" || ext == ".crt" {
		return scanDERCertificate(path, data)
	}

	// SSH single-line public key formats: authorized_keys, known_hosts, *.pub.
	return scanSSHKeyLines(path, data)
}

// newFinding builds a UnifiedFinding with the engine's fixed metadata.
func newFinding(path string, line int, alg *findings.Algorithm, rawID string, conf findings.Confidence) findings.UnifiedFinding {
	return findings.UnifiedFinding{
		Location:      findings.Location{File: path, Line: line},
		Algorithm:     alg,
		Confidence:    conf,
		SourceEngine:  "keyfile",
		Reachable:     findings.ReachableUnknown,
		RawIdentifier: rawID,
	}
}
