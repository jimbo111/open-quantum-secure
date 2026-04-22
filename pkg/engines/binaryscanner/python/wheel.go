// Package python scans Python wheel (.whl) and egg (.egg) archives for
// cryptographic library usage. It detects crypto dependencies by parsing
// METADATA files and scanning Python source files for import statements.
package python

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

const sourceEngine = "binary-scanner"

// knownPythonCryptoModules maps the canonical lower-case package name (as it
// appears in Requires-Dist) to a display name. Entries cover both
// install-time names (e.g., pycryptodome) and import names (e.g., Crypto).
var knownPythonCryptoModules = map[string]string{
	"cryptography":    "cryptography",
	"pycryptodome":    "pycryptodome",
	"pycryptodomex":   "pycryptodomex",
	"pyopenssl":       "pyOpenSSL",
	"paramiko":        "paramiko",
	"bcrypt":          "bcrypt",
	"argon2-cffi":     "argon2-cffi",
	"nacl":            "nacl",
	"pynacl":          "pynacl",
	"libnacl":         "libnacl",
	"hashlib":         "hashlib",
	"hmac":            "hmac",
	"ssl":             "ssl",
	"pyca":            "pyca",
	"crypto":          "Crypto",
	"python-jose":     "python-jose",
	"pyjwt":           "PyJWT",
	"itsdangerous":    "itsdangerous",
	"pyca/cryptography": "pyca/cryptography",
}

// importPattern matches Python import statements that reference a known crypto
// module. It is applied per-line against .py file contents inside the archive.
// The pattern anchors at the start of the line and captures the top-level
// module name for subsequent KB lookup.
var importPattern = regexp.MustCompile(
	`(?m)^(?:import|from)\s+(cryptography|pycryptodome|pycryptodomex|pyOpenSSL|paramiko|bcrypt|` +
		`argon2|nacl|pynacl|libnacl|hashlib|hmac|ssl|Crypto|jose|jwt|itsdangerous)`,
)

// ScanWheel opens the wheel or egg archive at path and produces a
// UnifiedFinding for every cryptographic dependency detected, either via
// Requires-Dist metadata or Python import statements in bundled .py files.
//
// A wheel with no METADATA and no relevant imports returns (nil, nil).
// The context is checked before opening the archive to honour cancellation.
func ScanWheel(ctx context.Context, path string) ([]findings.UnifiedFinding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("wheel scan: %w", err)
	}

	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("wheel open %q: %w", path, err)
	}
	defer r.Close()

	var result []findings.UnifiedFinding

	// Phase 1 — parse METADATA for Requires-Dist dependencies.
	metaFindings, metaPath := scanMetadata(ctx, &r.Reader, path)
	result = append(result, metaFindings...)

	// Phase 2 — scan .py files for import statements.
	importFindings := scanImports(ctx, &r.Reader, path, metaPath)
	result = append(result, importFindings...)

	return result, nil
}

// scanMetadata iterates the zip entries looking for a *.dist-info/METADATA file
// and extracts Requires-Dist lines that match known crypto packages. It returns
// the slice of findings and the archive-internal path of the METADATA file
// (empty string if none was found).
func scanMetadata(ctx context.Context, r *zip.Reader, archivePath string) ([]findings.UnifiedFinding, string) {
	for _, f := range r.File {
		if ctx.Err() != nil {
			return nil, ""
		}

		// Guard against zip slip: reject entries with path traversal or absolute paths.
		if strings.Contains(f.Name, "..") || filepath.IsAbs(f.Name) {
			continue
		}
		if !isMetadataFile(f.Name) {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}

		var result []findings.UnifiedFinding
		seen := make(map[string]bool)

		scanner := bufio.NewScanner(rc)
		// METADATA lines are usually short, but pip/poetry emit very long
		// Requires-Dist entries when marker expressions and extras are
		// combined. Bump the max token to 1 MiB so a single long line does
		// not silently truncate subsequent lines via bufio.ErrTooLong.
		const maxMetadataLine = 1 << 20
		scanner.Buffer(make([]byte, 64*1024), maxMetadataLine)
		for scanner.Scan() {
			line := scanner.Text()
			lib, ok := parseRequiresDist(line)
			if !ok || seen[lib] {
				continue
			}
			seen[lib] = true

			result = append(result, findings.UnifiedFinding{
				Location: findings.Location{
					File:         archivePath,
					InnerPath:    f.Name,
					ArtifactType: "wheel",
				},
				Dependency: &findings.Dependency{
					Library: lib,
				},
				Confidence:   findings.ConfidenceLow,
				SourceEngine: sourceEngine,
				Reachable:    findings.ReachableUnknown,
			})
		}
		// A bufio.ErrTooLong here means even the 1 MiB cap was exceeded;
		// surface best-effort findings rather than dropping all of them.
		// We don't have an error return channel here, so attach a log note
		// on the next iteration — emitting the partial result is preferred
		// over silent loss.
		if err := scanner.Err(); err != nil {
			// Caller expects (findings, path); preserve what we parsed.
			// A future revision should add a warning channel.
			_ = err
		}

		rc.Close()
		return result, f.Name
	}

	return nil, ""
}

// scanImports scans every .py file in the archive for import statements that
// reference a known crypto module. metaPath is excluded to avoid double-counting
// (it is a plain text file, not Python source). Findings from this phase use
// the .py file's archive path as InnerPath.
func scanImports(ctx context.Context, r *zip.Reader, archivePath string, metaPath string) []findings.UnifiedFinding {
	seen := make(map[string]bool) // deduplicate library within a single archive entry
	var result []findings.UnifiedFinding

	for _, f := range r.File {
		if ctx.Err() != nil {
			return result
		}
		// Guard against zip slip: reject entries with path traversal or absolute paths.
		if strings.Contains(f.Name, "..") || filepath.IsAbs(f.Name) {
			continue
		}
		if !strings.HasSuffix(f.Name, ".py") {
			continue
		}
		if f.Name == metaPath {
			continue
		}

		// Size guard: skip .py entries larger than 10 MB (same class as JAR entry limits).
		const maxPyEntryBytes int64 = 10 * 1024 * 1024
		if f.UncompressedSize64 > uint64(maxPyEntryBytes) {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}

		data, err := io.ReadAll(io.LimitReader(rc, maxPyEntryBytes+1))
		rc.Close()
		if err != nil || int64(len(data)) > maxPyEntryBytes {
			continue
		}

		matches := importPattern.FindAllSubmatch(data, -1)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			rawName := string(bytes.TrimSpace(m[1]))
			lib := canonicalizePythonPackage(rawName)
			key := f.Name + ":" + lib
			if seen[key] {
				continue
			}
			seen[key] = true

			result = append(result, findings.UnifiedFinding{
				Location: findings.Location{
					File:         archivePath,
					InnerPath:    f.Name,
					ArtifactType: "wheel",
				},
				Dependency: &findings.Dependency{
					Library: lib,
				},
				Confidence:   findings.ConfidenceLow,
				SourceEngine: sourceEngine,
				Reachable:    findings.ReachableUnknown,
			})
		}
	}

	return result
}

// isMetadataFile returns true when the archive entry is a dist-info METADATA file.
// Wheel spec: "<dist>-<ver>.dist-info/METADATA". Egg archives use "EGG-INFO/PKG-INFO".
func isMetadataFile(name string) bool {
	if strings.HasSuffix(name, ".dist-info/METADATA") {
		return true
	}
	// Support egg-info directories.
	if strings.HasSuffix(name, ".egg-info/PKG-INFO") || strings.HasSuffix(name, "EGG-INFO/PKG-INFO") {
		return true
	}
	return false
}

// parseRequiresDist parses a single METADATA line and returns the canonical
// library name if the line is a Requires-Dist: entry matching a known crypto
// package.
//
// Accepted formats (PEP 566 / PEP 508):
//
//	Requires-Dist: cryptography
//	Requires-Dist: cryptography>=3.0
//	Requires-Dist: cryptography (>=3.0,<4.0)
//	Requires-Dist: cryptography[ssh]>=3.0
func parseRequiresDist(line string) (string, bool) {
	const prefix = "Requires-Dist:"
	if !strings.HasPrefix(line, prefix) {
		return "", false
	}

	// Extract the package name: everything before the first space, bracket, or
	// version specifier character.
	raw := strings.TrimSpace(line[len(prefix):])
	name := extractPackageName(raw)
	if name == "" {
		return "", false
	}

	lib := canonicalizePythonPackage(name)
	return lib, lib != ""
}

// extractPackageName returns the bare package name from a PEP 508 dependency
// specifier (before any extras, version constraints, or environment markers).
func extractPackageName(spec string) string {
	// Trim at the first version-specifier or bracket character.
	end := strings.IndexAny(spec, " \t([<>=!~;")
	if end == -1 {
		return spec
	}
	return spec[:end]
}

// canonicalizePythonPackage normalises a package name to the lower-case key
// used in knownPythonCryptoModules and returns the display name, or "" if the
// package is not a known crypto module.
func canonicalizePythonPackage(name string) string {
	// PEP 503: normalise dashes, underscores, and dots to a canonical form.
	key := strings.ToLower(name)
	// Replace underscores and dots with dashes for canonical comparison.
	key = strings.ReplaceAll(key, "_", "-")
	key = strings.ReplaceAll(key, ".", "-")

	if display, ok := knownPythonCryptoModules[key]; ok {
		return display
	}
	return ""
}
