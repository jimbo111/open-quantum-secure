// Package binaryscanner implements a Tier 4 binary artifact scanner for the
// OQS PQC scanner. It inspects compiled artifacts — JARs, WAR/EAR archives,
// and native binaries — for cryptographic API usage without requiring source
// code access.
package binaryscanner

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/binaryscanner/dotnet"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/binaryscanner/gobinary"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/binaryscanner/java"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/binaryscanner/native"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/binaryscanner/python"
	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

const (
	defaultMaxArchiveDepth = 3
	defaultMaxBinarySize   = 500 * 1024 * 1024 // 500 MB
)

// Engine is the binary-scanner engine. It is pure Go and always Available.
type Engine struct {
	maxArchiveDepth int
	maxBinarySize   int64
}

// New returns an Engine with production defaults.
func New() *Engine {
	return &Engine{
		maxArchiveDepth: defaultMaxArchiveDepth,
		maxBinarySize:   defaultMaxBinarySize,
	}
}

// Name returns the engine identifier.
func (e *Engine) Name() string { return "binary-scanner" }

// Tier returns Tier4Binary.
func (e *Engine) Tier() engines.Tier { return engines.Tier4Binary }

// Available always returns true because the binary scanner is pure Go.
func (e *Engine) Available() bool { return true }

// Version returns "embedded" because this engine is pure Go and has no external binary.
func (e *Engine) Version() string { return "embedded" }

// SupportedLanguages returns the compiled artifact types this engine handles.
func (e *Engine) SupportedLanguages() []string {
	return []string{"java", "go", "c", "cpp", "python", "csharp"}
}

// Scan runs the binary scanner. When opts.BinaryPaths is non-empty those paths
// are scanned directly; otherwise the engine walks opts.TargetPath to discover
// binary artifacts automatically.
func (e *Engine) Scan(ctx context.Context, opts engines.ScanOptions) ([]findings.UnifiedFinding, error) {
	if len(opts.BinaryPaths) > 0 {
		return e.scanExplicitPaths(ctx, opts.BinaryPaths)
	}
	return e.walkAndScan(ctx, opts.TargetPath)
}

// scanExplicitPaths scans each path provided by the caller.
func (e *Engine) scanExplicitPaths(ctx context.Context, paths []string) ([]findings.UnifiedFinding, error) {
	var result []findings.UnifiedFinding
	for _, p := range paths {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		fds, err := e.scanArtifact(ctx, p)
		if err != nil {
			// Non-fatal: log and continue.
			continue
		}
		result = append(result, fds...)
	}
	return result, nil
}

// walkAndScan walks root recursively and scans any binary artifacts found.
func (e *Engine) walkAndScan(ctx context.Context, root string) ([]findings.UnifiedFinding, error) {
	var result []findings.UnifiedFinding

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil // skip unreadable entries
		}
		if d.IsDir() {
			return nil
		}

		// Check context between files.
		if err := ctx.Err(); err != nil {
			return err
		}

		// Size guard — skip non-regular files (symlinks, devices, FIFOs).
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() {
			return nil
		}
		if info.Size() > e.maxBinarySize {
			return nil
		}

		if !e.isBinaryArtifact(path) {
			return nil
		}

		fds, err := e.scanArtifact(ctx, path)
		if err != nil {
			return nil // non-fatal
		}
		result = append(result, fds...)
		return nil
	})
	if err != nil && err != context.Canceled && err != context.DeadlineExceeded {
		return result, fmt.Errorf("walk %q: %w", root, err)
	}
	if err != nil {
		return result, err
	}
	return result, nil
}

// scanArtifact detects the type of a single binary artifact and dispatches to
// the appropriate sub-scanner. Returns nil, nil for unrecognised types.
func (e *Engine) scanArtifact(ctx context.Context, path string) ([]findings.UnifiedFinding, error) {
	// Size guard.
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %q: %w", path, err)
	}
	if info.Size() > e.maxBinarySize {
		return nil, nil
	}

	lower := strings.ToLower(path)

	// Extension-based routing.
	switch {
	case isJavaArchive(lower):
		return java.ScanArchive(ctx, path, e.maxArchiveDepth)
	case isPythonPackage(lower):
		return python.ScanWheel(ctx, path)
	case strings.HasSuffix(lower, ".dll"):
		// .dll may be a .NET assembly or a native Windows DLL.
		// Try .NET scanner first; fall back to native if not a .NET assembly.
		if dotnet.IsDotNetAssembly(path) {
			return dotnet.Scan(ctx, path)
		}
		return native.Scan(ctx, path)
	case strings.HasSuffix(lower, ".exe"):
		// .exe may be a .NET assembly or a native Windows binary.
		if dotnet.IsDotNetAssembly(path) {
			return dotnet.Scan(ctx, path)
		}
		return native.Scan(ctx, path)
	case strings.HasSuffix(lower, ".so") || strings.HasSuffix(lower, ".dylib"):
		return native.Scan(ctx, path)
	}

	// Magic-byte routing for extensionless files.
	// Read 8 bytes so fat Mach-O (CAFEBABE + arch count) can be distinguished
	// from Java class files (CAFEBABE + version number).
	magic, err := readMagicBytes(path, 8)
	if err != nil {
		return nil, nil // can't read magic — skip silently
	}

	switch {
	case isELFMagic(magic):
		// Try Go binary first; fall back to native scanner.
		if goFindings, goErr := gobinary.Scan(ctx, path); goErr == nil && len(goFindings) > 0 {
			return goFindings, nil
		}
		return native.Scan(ctx, path)
	case isPEMagic(magic):
		// Check for .NET CLI header before falling back to native PE scanner.
		if dotnet.IsDotNetAssembly(path) {
			return dotnet.Scan(ctx, path)
		}
		return native.Scan(ctx, path)
	case native.IsMachOMagic(magic):
		return native.Scan(ctx, path)
	case native.IsFatMachOMagic(magic):
		return native.ScanFatMachO(ctx, path)
	}

	return nil, nil
}

// isBinaryArtifact returns true if path looks like a binary artifact worth scanning.
func (e *Engine) isBinaryArtifact(path string) bool {
	lower := strings.ToLower(path)
	if isJavaArchive(lower) || isPythonPackage(lower) {
		return true
	}
	// Native shared libraries, .NET assemblies, and Windows executables.
	if strings.HasSuffix(lower, ".so") || strings.HasSuffix(lower, ".dylib") ||
		strings.HasSuffix(lower, ".dll") || strings.HasSuffix(lower, ".exe") {
		return true
	}
	// Check magic bytes for extensionless binaries.
	// Read 8 bytes so fat Mach-O can be distinguished from Java class files.
	magic, err := readMagicBytes(path, 8)
	if err != nil {
		return false
	}
	return isELFMagic(magic) || isPEMagic(magic) || native.IsMachOMagic(magic) || native.IsFatMachOMagic(magic)
}

// --- helper predicates ---

func isJavaArchive(lower string) bool {
	return strings.HasSuffix(lower, ".jar") ||
		strings.HasSuffix(lower, ".war") ||
		strings.HasSuffix(lower, ".ear") ||
		strings.HasSuffix(lower, ".aar")
}

func isPythonPackage(lower string) bool {
	return strings.HasSuffix(lower, ".whl") ||
		strings.HasSuffix(lower, ".egg")
}

func isELFMagic(magic []byte) bool {
	return len(magic) >= 4 &&
		magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F'
}

func isPEMagic(magic []byte) bool {
	return len(magic) >= 2 && magic[0] == 'M' && magic[1] == 'Z'
}


// readMagicBytes reads up to n bytes from the start of the file.
func readMagicBytes(path string, n int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf := make([]byte, n)
	read, err := io.ReadFull(f, buf)
	if err != nil && read == 0 {
		return nil, err
	}
	return buf[:read], nil
}
