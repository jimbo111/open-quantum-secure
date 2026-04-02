package java

import (
	"archive/zip"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

const (
	// maxEntryBytes is the maximum bytes read from a single archive entry (100 MB).
	maxEntryBytes = 100 * 1024 * 1024
	// maxTotalEntries is the maximum number of entries processed per archive.
	maxTotalEntries = 10_000
	// ctxCheckInterval is the entry count interval between context cancellation checks.
	ctxCheckInterval = 100
	// defaultMaxDepth is the default maximum nesting depth for recursive archives.
	defaultMaxDepth = 3
)

// ScanArchive opens a JAR/WAR/EAR at path, walks its entries, and returns
// UnifiedFinding results. Nested JAR/WAR/EAR archives are recursively scanned
// up to maxDepth levels.
func ScanArchive(ctx context.Context, path string, maxDepth int) ([]findings.UnifiedFinding, error) {
	return scanArchiveAtDepth(ctx, path, path, maxDepth, 0)
}

// scanArchiveAtDepth is the internal recursive implementation. archivePath is
// the on-disk path of the ZIP/JAR to open; rootPath is the outermost archive
// path (used in Location.File for all findings).
func scanArchiveAtDepth(ctx context.Context, archivePath, rootPath string, maxDepth, depth int) ([]findings.UnifiedFinding, error) {
	zr, err := zip.OpenReader(archivePath)
	if err != nil {
		return nil, fmt.Errorf("open archive %q: %w", archivePath, err)
	}
	defer zr.Close()

	return walkZipEntries(ctx, &zr.Reader, archivePath, rootPath, maxDepth, depth)
}

// scanArchiveFromBytes reads a ZIP archive from buf, scanning it in-memory.
// Used for nested archives extracted to temp files.
func scanArchiveFromBytes(ctx context.Context, buf []byte, outerPath, innerPath, rootPath string, maxDepth, depth int) ([]findings.UnifiedFinding, error) {
	zr, err := zip.NewReader(bytes.NewReader(buf), int64(len(buf)))
	if err != nil {
		return nil, fmt.Errorf("open nested archive %q!%q: %w", outerPath, innerPath, err)
	}
	return walkZipEntries(ctx, zr, outerPath+"!"+innerPath, rootPath, maxDepth, depth)
}

// walkZipEntries iterates over entries in a zip.Reader, handling class files
// and nested archives.
//
// archivePath is the virtual path of the current archive being walked. For the
// top-level archive it equals the on-disk path. For nested archives it is the
// chain built by scanArchiveFromBytes, e.g. "/app.ear!lib/service.war".
// rootPath is always the on-disk path of the outermost archive (Location.File).
func walkZipEntries(ctx context.Context, zr *zip.Reader, archivePath, rootPath string, maxDepth, depth int) ([]findings.UnifiedFinding, error) {
	var result []findings.UnifiedFinding
	entryCount := 0

	// innerPrefix is the portion of archivePath that comes after the root
	// archive path. For a top-level walk it is empty. For nested walks it is
	// something like "lib/service.war" or "lib/service.war!WEB-INF/lib/x.jar".
	// We use it to construct the fully-chained InnerPath for class findings.
	innerPrefix := ""
	if len(archivePath) > len(rootPath) {
		// archivePath = rootPath + "!" + nestedChain
		innerPrefix = archivePath[len(rootPath)+1:]
	}

	for i, f := range zr.File {
		// Periodic context check.
		if i%ctxCheckInterval == 0 {
			if err := ctx.Err(); err != nil {
				return result, err
			}
		}
		// Total entry guard.
		if entryCount >= maxTotalEntries {
			break
		}
		entryCount++

		name := f.Name
		if name == "" || strings.HasSuffix(name, "/") {
			continue // skip directories
		}
		// Guard against zip slip: reject entries with path traversal.
		if strings.Contains(name, "..") || filepath.IsAbs(name) {
			continue
		}

		// Size guard (uncompressed).
		if f.UncompressedSize64 > maxEntryBytes {
			continue
		}

		isClass := strings.HasSuffix(name, ".class")
		isArchive := isArchiveEntry(name)

		if !isClass && !isArchive {
			continue
		}

		// Read entry content.
		data, err := readZipEntry(f)
		if err != nil {
			// Non-fatal: skip corrupted entries.
			continue
		}

		if isClass {
			ev, err := ParseClassFile(bytes.NewReader(data))
			if err != nil {
				// Non-fatal: malformed class file — skip.
				continue
			}
			// Build the full chained inner path:
			//   top-level:  "com/App.class"
			//   one level:  "WEB-INF/lib/crypto.jar!com/App.class"
			//   two levels: "lib/svc.war!WEB-INF/lib/crypto.jar!com/App.class"
			classInnerPath := name
			if innerPrefix != "" {
				classInnerPath = innerPrefix + "!" + name
			}
			fds := evidenceToFindings(ev, rootPath, classInnerPath, archiveType(rootPath))
			result = append(result, fds...)
		}

		if isArchive && depth < maxDepth {
			// Recurse into nested archive using in-memory scan.
			nested, err := scanArchiveFromBytes(ctx, data, archivePath, name, rootPath, maxDepth, depth+1)
			if err != nil {
				// Non-fatal: skip nested archives we cannot parse.
				continue
			}
			result = append(result, nested...)
		}
	}

	return result, nil
}

// readZipEntry reads the full uncompressed content of a zip entry, enforcing
// the per-entry size limit.
func readZipEntry(f *zip.File) ([]byte, error) {
	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("open zip entry %q: %w", f.Name, err)
	}
	defer rc.Close()

	lr := io.LimitReader(rc, maxEntryBytes+1)
	data, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("read zip entry %q: %w", f.Name, err)
	}
	if int64(len(data)) > maxEntryBytes {
		return nil, fmt.Errorf("zip entry %q exceeds size limit", f.Name)
	}
	return data, nil
}

// isArchiveEntry reports whether name is a nested archive file.
func isArchiveEntry(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".jar") ||
		strings.HasSuffix(lower, ".war") ||
		strings.HasSuffix(lower, ".ear") ||
		strings.HasSuffix(lower, ".aar")
}

// archiveType returns the ArtifactType string based on the archive file extension.
func archiveType(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".war"):
		return "war"
	case strings.HasSuffix(lower, ".ear"):
		return "ear"
	case strings.HasSuffix(lower, ".aar"):
		return "aar"
	default:
		return "jar"
	}
}

// evidenceToFindings converts CryptoEvidence from a single class file into
// UnifiedFinding records.
func evidenceToFindings(ev *CryptoEvidence, archivePath, innerPath, artifactType string) []findings.UnifiedFinding {
	if ev == nil {
		return nil
	}

	var result []findings.UnifiedFinding

	// One finding per classified algorithm string.
	for _, ref := range ev.AlgorithmStrings {
		ca := classifyAlgorithmString(ref.Value)
		if ca == nil {
			continue
		}
		uf := findings.UnifiedFinding{
			Location: findings.Location{
				File:         archivePath,
				InnerPath:    innerPath,
				ArtifactType: artifactType,
			},
			Algorithm: &findings.Algorithm{
				Name:      ca.Name,
				Primitive: ca.Primitive,
				Mode:      ca.Mode,
				KeySize:   ca.KeySize,
			},
			Confidence:   findings.ConfidenceMedium,
			SourceEngine: "binary-scanner",
			Reachable:    findings.ReachableUnknown,
			RawIdentifier: ref.Value,
		}
		result = append(result, uf)
	}

	// One finding per detected crypto API (as a dependency-style finding).
	for _, api := range ev.APIsDetected {
		uf := findings.UnifiedFinding{
			Location: findings.Location{
				File:         archivePath,
				InnerPath:    innerPath,
				ArtifactType: artifactType,
			},
			Dependency: &findings.Dependency{
				Library: api,
			},
			Confidence:   findings.ConfidenceMedium,
			SourceEngine: "binary-scanner",
			Reachable:    findings.ReachableUnknown,
			RawIdentifier: api,
		}
		result = append(result, uf)
	}

	return result
}

// writeToTempFile writes data to a temporary file and returns the path.
// Callers are responsible for removing the file when done.
func writeToTempFile(data []byte, pattern string) (string, error) {
	f, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	defer f.Close()

	if _, err := f.Write(data); err != nil {
		os.Remove(f.Name())
		return "", fmt.Errorf("write temp file: %w", err)
	}
	return f.Name(), nil
}

