package gobinary

import (
	"context"
	"debug/buildinfo"
	"fmt"
	"os"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

const sourceEngine = "binary-scanner"

// IsGoBinary reports whether the file at path is a compiled Go binary that
// contains embedded build information. A non-Go file, a stripped binary, or
// any file that cannot be read returns false without an error.
func IsGoBinary(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	_, err = buildinfo.Read(f)
	return err == nil
}

// Scan reads the Go build information embedded in the binary at path and
// produces a UnifiedFinding for every module dependency that appears in the
// crypto knowledge base.
//
// A stripped binary (no build info) is treated as a non-fatal condition:
// (nil, nil) is returned so callers can continue scanning other artifacts.
//
// The context is respected for cancellation; the underlying buildinfo.Read is
// synchronous, so cancellation is checked before and after the read.
func Scan(ctx context.Context, path string) ([]findings.UnifiedFinding, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("gobinary scan: %w", err)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("gobinary open %q: %w", path, err)
	}
	defer f.Close()

	info, err := buildinfo.Read(f)
	if err != nil {
		// No build info — stripped binary or non-Go ELF. Non-fatal.
		return nil, nil //nolint:nilerr
	}

	// Check for cancellation after the (potentially slow) read.
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("gobinary scan: %w", err)
	}

	var result []findings.UnifiedFinding

	for _, dep := range info.Deps {
		if dep == nil {
			continue
		}

		// Honour replace directives: use the replacement module path for KB lookup
		// so that replaced stdlib forks and vendored copies are correctly identified.
		lookupPath := dep.Path
		version := dep.Version
		if dep.Replace != nil {
			lookupPath = dep.Replace.Path
			version = dep.Replace.Version
		}

		entry := LookupModule(lookupPath)
		if entry == nil {
			continue
		}

		algName := ""
		if len(entry.Algorithms) > 0 {
			algName = entry.Algorithms[0]
		}

		library := dep.Path
		if version != "" {
			library = dep.Path + "@" + version
		}

		uf := findings.UnifiedFinding{
			Location: findings.Location{
				File:         path,
				ArtifactType: "go-binary",
			},
			Algorithm: &findings.Algorithm{
				Name:      algName,
				Primitive: entry.Primitive,
			},
			Dependency: &findings.Dependency{
				Library: library,
			},
			Confidence:    findings.ConfidenceMedium,
			SourceEngine:  sourceEngine,
			Reachable:     findings.ReachableUnknown,
			RawIdentifier: dep.Path,
		}

		result = append(result, uf)
	}

	return result, nil
}
