package native

import (
	"context"
	"debug/macho"
	"fmt"
	"os"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

const sourceEngine = "binary-scanner"

// maxNativeBinarySize is the per-file read limit for the native scanner.
// The engine-level walk enforces the same limit, but Scan and ScanFatMachO
// are exported and may be called directly, so each enforces its own guard.
const maxNativeBinarySize = 500 * 1024 * 1024 // 500 MB

// formatELF etc. are the canonical format names returned by DetectFormat.
const (
	formatELF      = "elf"
	formatPE       = "pe"
	formatMachO    = "macho"
	formatMachOFat = "macho-fat"
)

// DetectFormat reads the magic bytes at path and returns the binary format
// ("elf", "pe", "macho", "macho-fat") or an empty string for unrecognised
// formats.
func DetectFormat(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	// Read 8 bytes so we can distinguish fat Mach-O from Java class files
	// (both share the 0xCAFEBABE magic at bytes 0-3).
	magic := make([]byte, 8)
	n, err := f.Read(magic)
	if err != nil || n < 2 {
		return ""
	}
	magic = magic[:n]

	switch {
	case n >= 4 && magic[0] == 0x7F && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F':
		return formatELF
	case magic[0] == 'M' && magic[1] == 'Z':
		return formatPE
	case n >= 4 && IsMachOMagic(magic):
		return formatMachO
	case n >= 8 && IsFatMachOMagic(magic):
		return formatMachOFat
	}
	return ""
}

// isFatMachOMagic returns true when b begins with the Mach-O fat binary magic
// 0xCAFEBABE (big-endian) or 0xBEBAFECA (little-endian) AND the following
// four bytes, read as a big-endian uint32, represent an architecture count
// that is plausible for a fat binary (≤ 30).
//
// The 0xCAFEBABE value is shared with Java class files. The disambiguation
// heuristic is reliable because:
//   - Java class files store the major version number (45–65 for Java 1–21) in
//     bytes 6–7 of the file header.  The combined 4-byte field at bytes 4–7
//     always produces values ≥ 40 when interpreted as a big-endian uint32.
//   - Fat binaries store the architecture count at bytes 4–7, which is always
//     small (typically 2–4, maximum ~10 for universal builds).
//
// A threshold of 30 safely separates the two: any value > 30 is treated as a
// Java class file (or other non-fat-binary format).
func IsFatMachOMagic(b []byte) bool {
	if len(b) < 8 {
		return false
	}
	// Big-endian fat binary: 0xCA 0xFE 0xBA 0xBE
	if b[0] == 0xCA && b[1] == 0xFE && b[2] == 0xBA && b[3] == 0xBE {
		archCount := uint32(b[4])<<24 | uint32(b[5])<<16 | uint32(b[6])<<8 | uint32(b[7])
		return archCount > 0 && archCount <= 30
	}
	// Little-endian fat binary: 0xBE 0xBA 0xFE 0xCA
	// The arch count is also little-endian in this variant.
	if b[0] == 0xBE && b[1] == 0xBA && b[2] == 0xFE && b[3] == 0xCA {
		archCount := uint32(b[4]) | uint32(b[5])<<8 | uint32(b[6])<<16 | uint32(b[7])<<24
		return archCount > 0 && archCount <= 30
	}
	return false
}

// isMachOMagic returns true for any of the four Mach-O magic values:
//
//	0xFEEDFACF (64-bit LE), 0xFEEDFACE (32-bit LE)
//	0xCFFAEDFE (64-bit BE), 0xCEFAEDFE (32-bit BE)
func IsMachOMagic(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	// Little-endian Mach-O: first byte 0xCE or 0xCF, second 0xFA, third 0xED, fourth 0xFE
	if b[0] == 0xCF && b[1] == 0xFA && b[2] == 0xED && b[3] == 0xFE {
		return true
	}
	if b[0] == 0xCE && b[1] == 0xFA && b[2] == 0xED && b[3] == 0xFE {
		return true
	}
	// Big-endian Mach-O: 0xFE 0xED 0xFA 0xCF or 0xFE 0xED 0xFA 0xCE
	if b[0] == 0xFE && b[1] == 0xED && b[2] == 0xFA && b[3] == 0xCF {
		return true
	}
	if b[0] == 0xFE && b[1] == 0xED && b[2] == 0xFA && b[3] == 0xCE {
		return true
	}
	return false
}

// signalSummary aggregates distinct signal types collected across all scanners.
type signalSummary struct {
	hasConstant  bool
	hasStaticSym bool
	hasDynSym    bool
	hasDynLib    bool
}

// signalCount returns how many independent signal categories are active.
func (s signalSummary) signalCount() int {
	n := 0
	if s.hasConstant {
		n++
	}
	if s.hasStaticSym {
		n++
	}
	if s.hasDynSym {
		n++
	}
	if s.hasDynLib {
		n++
	}
	return n
}

// promoteConfidence determines the confidence level for a finding based on
// the number and type of independent signals that support it.
//
//   - Any dynamic symbol (.dynsym / PE import) → ConfidenceMedium (runtime linkage proven)
//   - 3+ independent signal categories → ConfidenceMedium
//   - Otherwise → ConfidenceLow
func promoteConfidence(sig signalSummary) findings.Confidence {
	if sig.hasDynSym {
		return findings.ConfidenceMedium
	}
	if sig.signalCount() >= 3 {
		return findings.ConfidenceMedium
	}
	return findings.ConfidenceLow
}

// Scan analyses the binary at path and returns all cryptographic findings.
// It detects the binary format, then runs:
//  1. Byte constant scanning (entire file data)
//  2. Symbol table scanning (format-specific)
//  3. Dynamic library dependency scanning
//
// Confidence is promoted per promoteConfidence rules.
func Scan(ctx context.Context, path string) ([]findings.UnifiedFinding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	format := DetectFormat(path)

	// Fat binary scanning is handled by ScanFatMachO which manages its
	// own file I/O and deduplication across arches; delegate entirely.
	// This early return avoids a wasted os.ReadFile + ScanConstants cycle
	// whose results would be discarded anyway.
	if format == formatMachOFat {
		return ScanFatMachO(ctx, path)
	}

	// Enforce size limit before reading. Scan and ScanFatMachO are exported
	// and may be called directly, so each must guard independently.
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("binary-scanner: stat %q: %w", path, err)
	}
	if fi.Size() > maxNativeBinarySize {
		return nil, fmt.Errorf("binary-scanner: %q exceeds %d byte limit", path, maxNativeBinarySize)
	}

	// Read the entire file once for constant scanning.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("binary-scanner: read %q: %w", path, err)
	}

	// --- Stage 1: crypto constant byte patterns ---
	constMatches := ScanConstants(data)

	// --- Stage 2: symbol table ---
	var symMatches []SymbolMatch
	switch format {
	case formatELF:
		syms, symErr := ScanELFSymbols(path)
		if symErr == nil {
			symMatches = syms
		}
	case formatPE:
		syms, symErr := ScanPESymbols(path)
		if symErr == nil {
			symMatches = syms
		}
	case formatMachO:
		syms, symErr := ScanMachOSymbols(path)
		if symErr == nil {
			symMatches = syms
		}
	}

	// --- Stage 3: dynamic library dependencies ---
	var libMatches []DynLibMatch
	libMatches, _ = ScanDynamicLibraries(path)

	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Build signal summary across all sources.
	sig := buildSignalSummary(constMatches, symMatches, libMatches)

	// Convert each signal set into UnifiedFindings.
	var result []findings.UnifiedFinding
	result = append(result, constantsToFindings(constMatches, path, format, sig)...)
	result = append(result, symbolsToFindings(symMatches, path, format, sig)...)
	result = append(result, libsToFindings(libMatches, path, format, sig)...)

	return result, nil
}

// ScanFatMachO analyses a Mach-O fat (universal) binary at path and returns
// all cryptographic findings. It iterates each architecture slice and:
//  1. Scans symbols from each arch's Symtab.
//  2. Scans byte-constant patterns against the file data (once for all arches).
//  3. Scans dynamic library dependencies from each arch.
//
// Findings from multiple architecture slices are deduplicated: the same
// (algorithm, primitive, rawIdentifier) tuple produces a single finding.
// ArtifactType is set to "macho-fat" to distinguish from regular "macho".
func ScanFatMachO(ctx context.Context, path string) ([]findings.UnifiedFinding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Enforce size limit before opening or reading the file.
	fi, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("binary-scanner: stat %q: %w", path, err)
	}
	if fi.Size() > maxNativeBinarySize {
		return nil, fmt.Errorf("binary-scanner: %q exceeds %d byte limit", path, maxNativeBinarySize)
	}

	ff, err := macho.OpenFat(path)
	if err != nil {
		return nil, fmt.Errorf("binary-scanner: open fat Mach-O %q: %w", path, err)
	}
	defer ff.Close()

	// Read file data once for constant scanning (shared across all arches).
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("binary-scanner: read %q: %w", path, err)
	}

	// --- Stage 1: crypto constant byte patterns (format-wide, not per-arch) ---
	constMatches := ScanConstants(data)

	// --- Stage 2 & 3: per-arch symbol and dynlib scanning ---
	// Collect all raw matches; dedup happens when building UnifiedFindings.
	var allSymMatches []SymbolMatch
	var allLibMatches []DynLibMatch

	for _, arch := range ff.Arches {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		syms := scanMachOFile(arch.File)
		allSymMatches = append(allSymMatches, syms...)

		libs := scanMachOFileDynLibs(arch.File)
		allLibMatches = append(allLibMatches, libs...)
	}

	// Build signal summary across all sources.
	sig := buildSignalSummary(constMatches, allSymMatches, allLibMatches)

	// Convert matches to UnifiedFindings using macho-fat as the artifact type.
	var raw []findings.UnifiedFinding
	raw = append(raw, constantsToFindings(constMatches, path, formatMachOFat, sig)...)
	raw = append(raw, symbolsToFindings(allSymMatches, path, formatMachOFat, sig)...)
	raw = append(raw, libsToFindings(allLibMatches, path, formatMachOFat, sig)...)

	// Deduplicate findings that were duplicated across architecture slices.
	// Two findings are identical when their (algorithm name, primitive,
	// rawIdentifier) tuple matches.
	return deduplicateFindings(raw), nil
}

// deduplicateFindings removes duplicate UnifiedFinding entries that arise when
// the same symbol or library appears in multiple architecture slices of a fat
// binary. Two findings are considered duplicates when they share the same
// algorithm name, primitive, and raw identifier.
func deduplicateFindings(in []findings.UnifiedFinding) []findings.UnifiedFinding {
	if len(in) == 0 {
		return nil
	}

	type dedupKey struct {
		algorithm     string
		primitive     string
		rawIdentifier string
	}

	seen := make(map[dedupKey]struct{}, len(in))
	out := make([]findings.UnifiedFinding, 0, len(in))

	for _, f := range in {
		algName := ""
		primitive := ""
		if f.Algorithm != nil {
			algName = f.Algorithm.Name
			primitive = f.Algorithm.Primitive
		}
		k := dedupKey{
			algorithm:     algName,
			primitive:     primitive,
			rawIdentifier: f.RawIdentifier,
		}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, f)
	}

	return out
}

// buildSignalSummary inspects the collected matches and marks which signal
// categories are active.
func buildSignalSummary(consts []ConstantMatch, syms []SymbolMatch, libs []DynLibMatch) signalSummary {
	var sig signalSummary
	if len(consts) > 0 {
		sig.hasConstant = true
	}
	for _, s := range syms {
		if s.IsDynamic {
			sig.hasDynSym = true
		} else {
			sig.hasStaticSym = true
		}
	}
	if len(libs) > 0 {
		sig.hasDynLib = true
	}
	return sig
}

// constantsToFindings converts ConstantMatch entries to UnifiedFinding.
func constantsToFindings(matches []ConstantMatch, path, format string, sig signalSummary) []findings.UnifiedFinding {
	out := make([]findings.UnifiedFinding, 0, len(matches))
	for _, m := range matches {
		conf := promoteConfidence(sig)
		out = append(out, findings.UnifiedFinding{
			Location: findings.Location{
				File:         path,
				ArtifactType: format,
			},
			Algorithm: &findings.Algorithm{
				Name:      m.Algorithm,
				Primitive: m.Primitive,
			},
			Confidence:   conf,
			SourceEngine: sourceEngine,
			Reachable:    findings.ReachableUnknown,
			RawIdentifier: m.PatternName,
		})
	}
	return out
}

// symbolsToFindings converts SymbolMatch entries to UnifiedFinding.
func symbolsToFindings(matches []SymbolMatch, path, format string, sig signalSummary) []findings.UnifiedFinding {
	out := make([]findings.UnifiedFinding, 0, len(matches))
	for _, m := range matches {
		// Per-symbol confidence: dynamic import always proves runtime linkage.
		symSig := sig
		symSig.hasDynSym = m.IsDynamic
		conf := promoteConfidence(symSig)

		out = append(out, findings.UnifiedFinding{
			Location: findings.Location{
				File:         path,
				ArtifactType: format,
			},
			Algorithm: &findings.Algorithm{
				Name:      m.Algorithm,
				Primitive: m.Primitive,
			},
			Confidence:   conf,
			SourceEngine: sourceEngine,
			Reachable:    findings.ReachableUnknown,
			RawIdentifier: m.Name,
		})
	}
	return out
}

// libsToFindings converts DynLibMatch entries to UnifiedFinding.
func libsToFindings(matches []DynLibMatch, path, format string, sig signalSummary) []findings.UnifiedFinding {
	out := make([]findings.UnifiedFinding, 0, len(matches))
	for _, m := range matches {
		conf := promoteConfidence(sig)
		out = append(out, findings.UnifiedFinding{
			Location: findings.Location{
				File:         path,
				ArtifactType: format,
			},
			Algorithm: &findings.Algorithm{
				Name:      m.Algorithm,
				Primitive: m.Primitive,
			},
			Confidence:   conf,
			SourceEngine: sourceEngine,
			Reachable:    findings.ReachableUnknown,
			RawIdentifier: m.Library,
		})
	}
	return out
}
