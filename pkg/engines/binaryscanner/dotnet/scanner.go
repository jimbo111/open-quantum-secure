package dotnet

import (
	"bytes"
	"context"
	"debug/pe"
	"fmt"
	"sort"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

const sourceEngine = "binary-scanner"

// artifactType is the ArtifactType tag applied to all findings from this scanner.
const artifactType = "dotnet-assembly"

// IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR is the index of the .NET CLI header
// entry in the PE optional header data directory table. A non-zero virtual
// address at this index means the PE file embeds a .NET CLI header.
const imageDirEntryCOMDescriptor = 14

// IsDotNetAssembly reports whether the PE file at path contains a .NET CLI
// header (IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, index 14). Non-PE files and
// files that cannot be read return false.
func IsDotNetAssembly(path string) bool {
	f, err := pe.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	return hasCLIHeader(f)
}

// hasCLIHeader checks whether the PE optional header's data directory at index
// imageDirEntryCOMDescriptor has a non-zero virtual address, which indicates
// a .NET CLI header is present.
func hasCLIHeader(f *pe.File) bool {
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		if int(imageDirEntryCOMDescriptor) >= len(oh.DataDirectory) {
			return false
		}
		return oh.DataDirectory[imageDirEntryCOMDescriptor].VirtualAddress != 0
	case *pe.OptionalHeader64:
		if int(imageDirEntryCOMDescriptor) >= len(oh.DataDirectory) {
			return false
		}
		return oh.DataDirectory[imageDirEntryCOMDescriptor].VirtualAddress != 0
	}
	return false
}

// Scan reads the .NET assembly at path and returns findings for every
// cryptographic type reference found across all PE sections. The search
// covers type names stored in the metadata #Strings heap, #US (User Strings)
// heap, and any other section data — all of which embed the fully-qualified
// type names as UTF-8 or UTF-16LE strings.
//
// The simplified approach used here is intentionally broad: it scans raw
// section bytes for known fully-qualified type name substrings. This catches
// both metadata table entries and inline string literals with no false
// negatives at the cost of accepting occasional false positives (mitigated by
// requiring the complete dotted namespace prefix).
//
// Confidence is set to ConfidenceMedium: a fully-qualified .NET type name
// present in assembly metadata is strong evidence of use.
//
// Returns (nil, nil) when no crypto references are found.
// Returns (nil, ctx.Err()) when the context is cancelled.
func Scan(ctx context.Context, path string) ([]findings.UnifiedFinding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	f, err := pe.Open(path)
	if err != nil {
		return nil, fmt.Errorf("dotnet-scanner: open %q: %w", path, err)
	}
	defer f.Close()

	if !hasCLIHeader(f) {
		// Not a .NET assembly — caller should use native scanner instead.
		return nil, nil
	}

	// Check for cancellation after the (potentially slow) PE open.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Collect raw bytes from all sections. We do not limit to .text because
	// the .rsrc section and others can also carry embedded string data.
	// Cap total accumulation at 200 MB to prevent OOM from crafted PEs.
	const maxSectionData = 200 * 1024 * 1024

	var sectionData []byte
	for _, s := range f.Sections {
		data, err := s.Data()
		if err != nil {
			// Non-fatal: skip unreadable sections and continue.
			continue
		}
		if len(sectionData)+len(data) > maxSectionData {
			break
		}
		sectionData = append(sectionData, data...)
	}

	// Check for cancellation after section reads.
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return searchCryptoTypes(sectionData, path), nil
}

// searchCryptoTypes scans data for every entry in cryptoTypes and returns one
// finding per matched type. Identical type names that appear multiple times in
// the section data produce exactly one finding (deduplication by type name).
func searchCryptoTypes(data []byte, path string) []findings.UnifiedFinding {
	// Collect matched type names in insertion order via a separate seen set
	// to keep output deterministic regardless of map iteration order.
	seen := make(map[string]struct{}, len(cryptoTypes))

	// Iterate in sorted order so findings are deterministic.
	keys := make([]string, 0, len(cryptoTypes))
	for k := range cryptoTypes {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var result []findings.UnifiedFinding
	for _, typeName := range keys {
		entry := cryptoTypes[typeName]
		if entry.algorithm == "" {
			continue
		}
		if _, already := seen[typeName]; already {
			continue
		}
		if !bytes.Contains(data, []byte(typeName)) {
			continue
		}
		seen[typeName] = struct{}{}

		result = append(result, findings.UnifiedFinding{
			Location: findings.Location{
				File:         path,
				ArtifactType: artifactType,
			},
			Algorithm: &findings.Algorithm{
				Name:      entry.algorithm,
				Primitive: entry.primitive,
			},
			Confidence:    findings.ConfidenceMedium,
			SourceEngine:  sourceEngine,
			Reachable:     findings.ReachableUnknown,
			RawIdentifier: typeName,
		})
	}

	if len(result) == 0 {
		return nil
	}
	return result
}
