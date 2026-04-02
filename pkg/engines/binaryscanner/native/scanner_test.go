package native

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// ---------------------------------------------------------------------------
// DetectFormat
// ---------------------------------------------------------------------------

func TestDetectFormat_ELF(t *testing.T) {
	path := writeTempFile(t, []byte{0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00})
	got := DetectFormat(path)
	if got != "elf" {
		t.Errorf("DetectFormat ELF magic = %q, want %q", got, "elf")
	}
}

func TestDetectFormat_PE(t *testing.T) {
	path := writeTempFile(t, []byte{'M', 'Z', 0x00, 0x00})
	got := DetectFormat(path)
	if got != "pe" {
		t.Errorf("DetectFormat PE magic = %q, want %q", got, "pe")
	}
}

func TestDetectFormat_MachO_64LE(t *testing.T) {
	// 0xCFFAEDFE — 64-bit little-endian Mach-O
	path := writeTempFile(t, []byte{0xCF, 0xFA, 0xED, 0xFE})
	got := DetectFormat(path)
	if got != "macho" {
		t.Errorf("DetectFormat Mach-O 64LE = %q, want %q", got, "macho")
	}
}

func TestDetectFormat_MachO_32LE(t *testing.T) {
	// 0xCEFAEDFE — 32-bit little-endian Mach-O
	path := writeTempFile(t, []byte{0xCE, 0xFA, 0xED, 0xFE})
	got := DetectFormat(path)
	if got != "macho" {
		t.Errorf("DetectFormat Mach-O 32LE = %q, want %q", got, "macho")
	}
}

func TestDetectFormat_MachO_64BE(t *testing.T) {
	// 0xFEEDFACF — 64-bit big-endian Mach-O
	path := writeTempFile(t, []byte{0xFE, 0xED, 0xFA, 0xCF})
	got := DetectFormat(path)
	if got != "macho" {
		t.Errorf("DetectFormat Mach-O 64BE = %q, want %q", got, "macho")
	}
}

func TestDetectFormat_MachO_32BE(t *testing.T) {
	// 0xFEEDFACE — 32-bit big-endian Mach-O
	path := writeTempFile(t, []byte{0xFE, 0xED, 0xFA, 0xCE})
	got := DetectFormat(path)
	if got != "macho" {
		t.Errorf("DetectFormat Mach-O 32BE = %q, want %q", got, "macho")
	}
}

func TestDetectFormat_Unrecognised(t *testing.T) {
	tests := []struct {
		name  string
		magic []byte
	}{
		{"zip header", []byte{0x50, 0x4B, 0x03, 0x04}},
		{"pdf header", []byte{0x25, 0x50, 0x44, 0x46}},
		{"random bytes", []byte{0xDE, 0xAD, 0xBE, 0xEF}},
		{"too short", []byte{0x7F}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := writeTempFile(t, tc.magic)
			got := DetectFormat(path)
			if got != "" {
				t.Errorf("DetectFormat(%q) = %q, want empty string", tc.name, got)
			}
		})
	}
}

func TestDetectFormat_NonExistentFile(t *testing.T) {
	got := DetectFormat("/no/such/file/exists.bin")
	if got != "" {
		t.Errorf("expected empty string for missing file, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// IsMachOMagic unit test
// ---------------------------------------------------------------------------

func TestIsMachOMagic(t *testing.T) {
	tests := []struct {
		name  string
		b     []byte
		want  bool
	}{
		{"64LE", []byte{0xCF, 0xFA, 0xED, 0xFE}, true},
		{"32LE", []byte{0xCE, 0xFA, 0xED, 0xFE}, true},
		{"64BE", []byte{0xFE, 0xED, 0xFA, 0xCF}, true},
		{"32BE", []byte{0xFE, 0xED, 0xFA, 0xCE}, true},
		{"ELF", []byte{0x7F, 'E', 'L', 'F'}, false},
		{"PE", []byte{'M', 'Z', 0x00, 0x00}, false},
		{"short", []byte{0xFE, 0xED}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsMachOMagic(tc.b)
			if got != tc.want {
				t.Errorf("IsMachOMagic(%x) = %v, want %v", tc.b, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// promoteConfidence
// ---------------------------------------------------------------------------

func TestPromoteConfidence_DynSymAlwaysMedium(t *testing.T) {
	sig := signalSummary{hasDynSym: true}
	got := promoteConfidence(sig)
	if got != findings.ConfidenceMedium {
		t.Errorf("expected ConfidenceMedium for hasDynSym, got %q", got)
	}
}

func TestPromoteConfidence_ThreePlusSignalsMedium(t *testing.T) {
	tests := []struct {
		name string
		sig  signalSummary
		want findings.Confidence
	}{
		{
			name: "constant+staticSym+dynLib = 3 signals",
			sig:  signalSummary{hasConstant: true, hasStaticSym: true, hasDynLib: true},
			want: findings.ConfidenceMedium,
		},
		{
			name: "all four signals",
			sig:  signalSummary{hasConstant: true, hasStaticSym: true, hasDynSym: true, hasDynLib: true},
			want: findings.ConfidenceMedium,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := promoteConfidence(tc.sig)
			if got != tc.want {
				t.Errorf("promoteConfidence(%+v) = %q, want %q", tc.sig, got, tc.want)
			}
		})
	}
}

func TestPromoteConfidence_LessThanThreeSignalsLow(t *testing.T) {
	tests := []struct {
		name string
		sig  signalSummary
	}{
		{"no signals", signalSummary{}},
		{"only constant", signalSummary{hasConstant: true}},
		{"only staticSym", signalSummary{hasStaticSym: true}},
		{"only dynLib", signalSummary{hasDynLib: true}},
		{"constant+dynLib = 2 signals", signalSummary{hasConstant: true, hasDynLib: true}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := promoteConfidence(tc.sig)
			if got != findings.ConfidenceLow {
				t.Errorf("promoteConfidence(%+v) = %q, want ConfidenceLow", tc.sig, got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Scan — integration-style test using synthetic file data
// ---------------------------------------------------------------------------

func TestScan_ConstantFindingsFromSyntheticFile(t *testing.T) {
	// Embed the ChaCha20 constant into a synthetic "binary" prefixed with ELF
	// magic. DetectFormat will see ELF; symbol/dynlib scanners will fail gracefully
	// on the malformed ELF, and constant scanner will find ChaCha20.
	elfMagic := []byte{0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00}
	chacha := cryptoConstants[8].pattern // "expand 32-byte k"

	buf := make([]byte, len(elfMagic)+256+len(chacha)+64)
	copy(buf, elfMagic)
	for i := len(elfMagic); i < len(elfMagic)+256; i++ {
		buf[i] = 0xAA
	}
	copy(buf[len(elfMagic)+256:], chacha)
	for i := len(elfMagic) + 256 + len(chacha); i < len(buf); i++ {
		buf[i] = 0xAA
	}

	path := writeTempFile(t, buf)

	ctx := context.Background()
	res, err := Scan(ctx, path)
	if err != nil {
		t.Fatalf("Scan returned error: %v", err)
	}

	found := false
	for _, f := range res {
		if f.Algorithm != nil && f.Algorithm.Name == "ChaCha20" {
			found = true
			if f.SourceEngine != sourceEngine {
				t.Errorf("SourceEngine = %q, want %q", f.SourceEngine, sourceEngine)
			}
			if f.Location.File != path {
				t.Errorf("Location.File = %q, want %q", f.Location.File, path)
			}
			if f.Location.ArtifactType != "elf" {
				t.Errorf("ArtifactType = %q, want %q", f.Location.ArtifactType, "elf")
			}
		}
	}
	if !found {
		t.Errorf("ChaCha20 not found in scan results (got %d results)", len(res))
	}
}

func TestScan_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	path := writeTempFile(t, []byte{0x7F, 'E', 'L', 'F', 0x00, 0x00, 0x00, 0x00})
	_, err := Scan(ctx, path)
	if err == nil {
		t.Error("expected error for cancelled context, got nil")
	}
}

func TestScan_CorrectFieldsSet(t *testing.T) {
	// Build a buffer with ELF magic + AES S-box constant.
	elfMagic := []byte{0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00}
	aesSbox := cryptoConstants[0].pattern

	buf := make([]byte, len(elfMagic)+len(aesSbox)+16)
	copy(buf, elfMagic)
	copy(buf[len(elfMagic):], aesSbox)

	path := writeTempFile(t, buf)
	res, err := Scan(context.Background(), path)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	for _, f := range res {
		if f.SourceEngine != sourceEngine {
			t.Errorf("SourceEngine = %q, want %q", f.SourceEngine, sourceEngine)
		}
		if f.Location.File == "" {
			t.Error("Location.File must not be empty")
		}
		if f.Algorithm == nil {
			t.Error("Algorithm must not be nil")
			continue
		}
		if f.Algorithm.Name == "" {
			t.Error("Algorithm.Name must not be empty")
		}
		if f.Reachable == "" {
			t.Error("Reachable must not be empty")
		}
	}
}

func TestScan_NonExistentFile(t *testing.T) {
	_, err := Scan(context.Background(), "/no/such/binary.elf")
	if err == nil {
		t.Error("expected error for non-existent file, got nil")
	}
}

// ---------------------------------------------------------------------------
// buildSignalSummary
// ---------------------------------------------------------------------------

func TestBuildSignalSummary(t *testing.T) {
	consts := []ConstantMatch{{Algorithm: "AES"}}
	symsStatic := []SymbolMatch{{IsDynamic: false}}
	symsDynamic := []SymbolMatch{{IsDynamic: true}}
	libs := []DynLibMatch{{Library: "libssl.so.3"}}

	tests := []struct {
		name   string
		consts []ConstantMatch
		syms   []SymbolMatch
		libs   []DynLibMatch
		want   signalSummary
	}{
		{
			name:   "only constant",
			consts: consts,
			want:   signalSummary{hasConstant: true},
		},
		{
			name: "static symbol only",
			syms: symsStatic,
			want: signalSummary{hasStaticSym: true},
		},
		{
			name: "dynamic symbol only",
			syms: symsDynamic,
			want: signalSummary{hasDynSym: true},
		},
		{
			name: "dynlib only",
			libs: libs,
			want: signalSummary{hasDynLib: true},
		},
		{
			name:   "all signals",
			consts: consts,
			syms:   append(symsStatic, symsDynamic...),
			libs:   libs,
			want:   signalSummary{hasConstant: true, hasStaticSym: true, hasDynSym: true, hasDynLib: true},
		},
		{
			name: "empty everything",
			want: signalSummary{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildSignalSummary(tc.consts, tc.syms, tc.libs)
			if got != tc.want {
				t.Errorf("buildSignalSummary = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// IsFatMachOMagic unit test
// ---------------------------------------------------------------------------

func TestIsFatMachOMagic(t *testing.T) {
	tests := []struct {
		name string
		b    []byte
		want bool
	}{
		// Big-endian fat binary with 2 arches (arm64 + x86_64).
		{
			name: "CAFEBABE archCount=2",
			b:    []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x02},
			want: true,
		},
		// Edge of the threshold: exactly 30 arches is still accepted.
		{
			name: "CAFEBABE archCount=30",
			b:    []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x1E},
			want: true,
		},
		// Java class file: CAFEBABE followed by minor=0, major=61 (Java 17).
		// The 4-byte field at bytes 4-7 is 0x0000003D = 61, which is > 30.
		{
			name: "CAFEBABE Java minor=0 major=61",
			b:    []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x3D},
			want: false,
		},
		// Java class file: minor=0, major=52 (Java 8). 0x00000034 = 52 > 30.
		{
			name: "CAFEBABE Java minor=0 major=52",
			b:    []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34},
			want: false,
		},
		// Arch count = 31 — exceeds threshold, treated as non-fat.
		{
			name: "CAFEBABE archCount=31",
			b:    []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x1F},
			want: false,
		},
		// Little-endian fat binary magic — arch count is LE too.
		{
			name: "BEBAFECA archCount=2 (LE byte order)",
			b:    []byte{0xBE, 0xBA, 0xFE, 0xCA, 0x02, 0x00, 0x00, 0x00},
			want: true,
		},
		// LE fat binary with archCount=0 — rejected (must be > 0).
		{
			name: "BEBAFECA archCount=0",
			b:    []byte{0xBE, 0xBA, 0xFE, 0xCA, 0x00, 0x00, 0x00, 0x00},
			want: false,
		},
		// Regular Mach-O (64-bit LE) — not a fat binary.
		{
			name: "single-arch MachO 64LE",
			b:    []byte{0xCF, 0xFA, 0xED, 0xFE, 0x0C, 0x00, 0x00, 0x01},
			want: false,
		},
		// ELF magic — not a fat binary.
		{
			name: "ELF magic",
			b:    []byte{0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00},
			want: false,
		},
		// Too short — must have at least 8 bytes.
		{
			name: "too short (4 bytes)",
			b:    []byte{0xCA, 0xFE, 0xBA, 0xBE},
			want: false,
		},
		// Too short — only 7 bytes.
		{
			name: "too short (7 bytes)",
			b:    []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00},
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := IsFatMachOMagic(tc.b)
			if got != tc.want {
				t.Errorf("IsFatMachOMagic(%x) = %v, want %v", tc.b, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// DetectFormat — fat Mach-O
// ---------------------------------------------------------------------------

func TestDetectFormat_FatMachO(t *testing.T) {
	// CAFEBABE followed by arch count 2 (big-endian).
	data := []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00}
	path := writeTempFile(t, data)
	got := DetectFormat(path)
	if got != formatMachOFat {
		t.Errorf("DetectFormat fat Mach-O = %q, want %q", got, formatMachOFat)
	}
}

func TestDetectFormat_JavaClassNotFatMachO(t *testing.T) {
	// CAFEBABE followed by minor=0, major=61 (Java 17) — should NOT be
	// detected as fat Mach-O.
	data := []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x3D, 0x00, 0x02}
	path := writeTempFile(t, data)
	got := DetectFormat(path)
	if got == formatMachOFat {
		t.Errorf("DetectFormat Java class file = %q, must NOT be %q", got, formatMachOFat)
	}
}

// ---------------------------------------------------------------------------
// ScanFatMachO
// ---------------------------------------------------------------------------

func TestScanFatMachO_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled

	// The file path does not need to exist — context check fires first.
	_, err := ScanFatMachO(ctx, "/no/such/fat/binary")
	if err == nil {
		t.Error("expected error for cancelled context, got nil")
	}
}

func TestScanFatMachO_NilArches(t *testing.T) {
	// Build a minimal fat Mach-O header with zero architecture entries.
	// Fat header: magic (4) + nfat_arch (4) = 8 bytes.
	// magic = 0xCAFEBABE, nfat_arch = 0
	data := []byte{
		0xCA, 0xFE, 0xBA, 0xBE, // magic
		0x00, 0x00, 0x00, 0x00, // nfat_arch = 0
	}
	path := writeTempFile(t, data)

	// macho.OpenFat will succeed (valid header) but return zero arches.
	// The scan should return nil findings without error.
	res, err := ScanFatMachO(context.Background(), path)
	// Either succeeds with zero findings or returns a parse error — both are
	// acceptable; we must not panic.
	if err != nil {
		// Acceptable: macho.OpenFat may reject a header with no arches.
		t.Logf("ScanFatMachO with zero arches returned error (acceptable): %v", err)
		return
	}
	if len(res) != 0 {
		t.Errorf("expected no findings from empty fat binary, got %d", len(res))
	}
}

func TestScanFatMachO_DeduplicationAcrossArches(t *testing.T) {
	// We cannot build a valid fat Mach-O in-memory without an external linker,
	// so we test deduplicateFindings directly — it is the deduplication
	// mechanism used by ScanFatMachO.
	const path = "/fake/universal"

	mkFinding := func(alg, prim, raw string) findings.UnifiedFinding {
		return findings.UnifiedFinding{
			Location: findings.Location{
				File:         path,
				ArtifactType: formatMachOFat,
			},
			Algorithm:     &findings.Algorithm{Name: alg, Primitive: prim},
			RawIdentifier: raw,
			SourceEngine:  sourceEngine,
			Reachable:     findings.ReachableUnknown,
		}
	}

	// Simulate the same AES finding appearing in both arm64 and x86_64 slices.
	arm64AES := mkFinding("AES", "symmetric", "evp_encryptinit_ex")
	x86AES := mkFinding("AES", "symmetric", "evp_encryptinit_ex")
	// A different finding that must survive deduplication.
	arm64RSA := mkFinding("RSA", "pke", "rsa_public_encrypt")

	raw := []findings.UnifiedFinding{arm64AES, x86AES, arm64RSA}
	got := deduplicateFindings(raw)

	if len(got) != 2 {
		t.Errorf("deduplicateFindings: got %d findings, want 2", len(got))
	}

	algSet := make(map[string]int)
	for _, f := range got {
		if f.Algorithm != nil {
			algSet[f.Algorithm.Name]++
		}
	}
	if algSet["AES"] != 1 {
		t.Errorf("AES should appear exactly once after dedup, got %d", algSet["AES"])
	}
	if algSet["RSA"] != 1 {
		t.Errorf("RSA should appear exactly once, got %d", algSet["RSA"])
	}
}

func TestDeduplicateFindings_Empty(t *testing.T) {
	if got := deduplicateFindings(nil); got != nil {
		t.Errorf("deduplicateFindings(nil) = %v, want nil", got)
	}
	if got := deduplicateFindings([]findings.UnifiedFinding{}); got != nil {
		t.Errorf("deduplicateFindings([]) = %v, want nil", got)
	}
}

func TestDeduplicateFindings_NilAlgorithm(t *testing.T) {
	// Findings with nil Algorithm should be deduped by rawIdentifier alone.
	f1 := findings.UnifiedFinding{RawIdentifier: "libssl.so.3"}
	f2 := findings.UnifiedFinding{RawIdentifier: "libssl.so.3"}
	f3 := findings.UnifiedFinding{RawIdentifier: "libcrypto.so.3"}

	got := deduplicateFindings([]findings.UnifiedFinding{f1, f2, f3})
	if len(got) != 2 {
		t.Errorf("deduplicateFindings with nil Algorithm: got %d, want 2", len(got))
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// writeTempFile creates a temporary file with the given content and registers
// it for cleanup. Returns the absolute path.
func writeTempFile(t *testing.T, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test.bin")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("writeTempFile: %v", err)
	}
	return path
}

// ---------------------------------------------------------------------------
// Size limit — Bug 3 regression tests
// ---------------------------------------------------------------------------

// writeTempFileSize creates a sparse file of exactly size bytes using
// os.Truncate so that it exercises the size-check path without actually
// allocating size bytes of RAM or disk (the OS keeps it sparse).
func writeTempFileSize(t *testing.T, size int64) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "big.bin")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create sparse file: %v", err)
	}
	if err := f.Truncate(size); err != nil {
		f.Close()
		t.Fatalf("truncate sparse file: %v", err)
	}
	f.Close()
	return path
}

// TestScan_SizeLimit verifies that Scan returns an error (not a panic or OOM)
// when the target file is larger than maxNativeBinarySize.
func TestScan_SizeLimit(t *testing.T) {
	// Create a sparse file that is 1 byte over the limit.
	path := writeTempFileSize(t, maxNativeBinarySize+1)

	_, err := Scan(context.Background(), path)
	if err == nil {
		t.Fatal("Scan: expected error for oversized file, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("Scan: error %q should mention 'exceeds'", err.Error())
	}
}

// TestScan_SizeLimitExact verifies that a file of exactly maxNativeBinarySize
// bytes is not rejected by the size check (boundary condition).
func TestScan_SizeLimitExact(t *testing.T) {
	// A file that is exactly at the limit must pass the size check.
	// We use a sparse file — it won't actually be read by a real engine,
	// but we only care that the size guard itself does not reject it.
	path := writeTempFileSize(t, maxNativeBinarySize)

	// DetectFormat will return "" for an all-zero sparse file, so Scan will
	// fall through the format switch and return no findings (not an error).
	// The important thing is that we do NOT get the "exceeds" error.
	_, err := Scan(context.Background(), path)
	if err != nil && strings.Contains(err.Error(), "exceeds") {
		t.Errorf("Scan: exact-limit file should not be rejected by size check: %v", err)
	}
}

// TestScanFatMachO_SizeLimit verifies that ScanFatMachO returns an error
// for oversized files before attempting to read them.
func TestScanFatMachO_SizeLimit(t *testing.T) {
	path := writeTempFileSize(t, maxNativeBinarySize+1)

	_, err := ScanFatMachO(context.Background(), path)
	if err == nil {
		t.Fatal("ScanFatMachO: expected error for oversized file, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("ScanFatMachO: error %q should mention 'exceeds'", err.Error())
	}
}

// ---------------------------------------------------------------------------
// Fuzz: IsFatMachOMagic
// ---------------------------------------------------------------------------

// FuzzIsFatMachOMagic verifies that IsFatMachOMagic never panics on arbitrary
// byte slices. Seeds cover the canonical magic values, known edge cases
// (Java class file, ELF, LE fat variant, too-short inputs), and a
// boundary-value archCount of exactly 30.
func FuzzIsFatMachOMagic(f *testing.F) {
	// Big-endian fat Mach-O with archCount=2 (real universal binary).
	f.Add([]byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x02})
	// Big-endian fat with archCount=30 (boundary: last accepted value).
	f.Add([]byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x1E})
	// Java class file (CAFEBABE + major version 61 = 0x3D, minor 0).
	f.Add([]byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x3D})
	// Little-endian fat variant with archCount=2.
	f.Add([]byte{0xBE, 0xBA, 0xFE, 0xCA, 0x02, 0x00, 0x00, 0x00})
	// LE fat with archCount=0 (must be rejected).
	f.Add([]byte{0xBE, 0xBA, 0xFE, 0xCA, 0x00, 0x00, 0x00, 0x00})
	// ELF magic — must return false.
	f.Add([]byte{0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00})
	// Too short (4 bytes).
	f.Add([]byte{0xCA, 0xFE, 0xBA, 0xBE})
	// Empty slice.
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		// Must never panic regardless of input.
		_ = IsFatMachOMagic(b)
	})
}

// ---------------------------------------------------------------------------
// Fuzz: DetectFormat
// ---------------------------------------------------------------------------

// FuzzDetectFormat writes fuzz-generated bytes to a temp file and calls
// DetectFormat, verifying the function never panics and always returns one
// of the four known format strings or an empty string.
func FuzzDetectFormat(f *testing.F) {
	// ELF magic.
	f.Add([]byte{0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00})
	// PE magic ("MZ").
	f.Add([]byte{'M', 'Z', 0x90, 0x00})
	// 64-bit LE Mach-O (0xCFFAEDFE).
	f.Add([]byte{0xCF, 0xFA, 0xED, 0xFE, 0x0C, 0x00, 0x00, 0x01})
	// Fat Mach-O with archCount=2.
	f.Add([]byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00})
	// Java class file — must NOT be detected as fat Mach-O.
	f.Add([]byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x3D})
	// Unrecognised ZIP header.
	f.Add([]byte{0x50, 0x4B, 0x03, 0x04})
	// Single byte (too short).
	f.Add([]byte{0x7F})
	// Empty file.
	f.Add([]byte{})

	validFormats := map[string]bool{
		"":           true,
		"elf":        true,
		"pe":         true,
		"macho":      true,
		"macho-fat":  true,
	}

	f.Fuzz(func(t *testing.T, content []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "fuzz.bin")
		if err := os.WriteFile(path, content, 0o600); err != nil {
			// Filesystem error is not a scanner bug — skip.
			t.Skip("could not write temp file:", err)
		}

		got := DetectFormat(path)

		if !validFormats[got] {
			t.Errorf("DetectFormat returned unexpected format %q", got)
		}
	})
}
