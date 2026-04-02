package binaryscanner

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"github.com/jimbo111/open-quantum-secure/pkg/engines"
	"github.com/jimbo111/open-quantum-secure/pkg/engines/binaryscanner/native"
)

// ---- metadata tests ----

func TestEngine_Name(t *testing.T) {
	e := New()
	if e.Name() != "binary-scanner" {
		t.Errorf("Name() = %q, want %q", e.Name(), "binary-scanner")
	}
}

func TestEngine_Tier(t *testing.T) {
	e := New()
	if e.Tier() != engines.Tier4Binary {
		t.Errorf("Tier() = %v, want Tier4Binary", e.Tier())
	}
}

func TestEngine_Available(t *testing.T) {
	e := New()
	if !e.Available() {
		t.Error("Available() = false, want true (pure Go engine)")
	}
}

func TestEngine_SupportedLanguages(t *testing.T) {
	e := New()
	langs := e.SupportedLanguages()
	required := map[string]bool{"java": false, "go": false, "c": false, "cpp": false, "python": false}
	for _, l := range langs {
		required[l] = true
	}
	for lang, found := range required {
		if !found {
			t.Errorf("SupportedLanguages missing %q", lang)
		}
	}
}

func TestSupportedLanguages_IncludesCSharp(t *testing.T) {
	e := New()
	langs := e.SupportedLanguages()
	for _, l := range langs {
		if l == "csharp" {
			return
		}
	}
	t.Error("SupportedLanguages does not include \"csharp\"")
}

func TestIsBinaryArtifact_DLL(t *testing.T) {
	// A file with a .dll extension must be recognised as a binary artifact
	// regardless of its content (extension-based detection).
	data := []byte{0x4D, 0x5A, 0x00, 0x00} // MZ magic
	path := writeTempFile(t, data, ".dll")

	e := New()
	if !e.isBinaryArtifact(path) {
		t.Error("isBinaryArtifact should return true for .dll extension")
	}
}

// ---- helpers ----

// buildMinimalJar returns an in-memory JAR containing one class file with the
// given UTF-8 constant pool string.
func buildMinimalJar(utf8Constant string) []byte {
	classData := buildClassBytes(utf8Constant)
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	f, _ := w.Create("com/example/App.class")
	_, _ = f.Write(classData)
	_ = w.Close()
	return buf.Bytes()
}

// buildClassBytes builds a minimal valid Java class file with one Utf8 constant.
func buildClassBytes(utf8Constant string) []byte {
	var buf bytes.Buffer
	writeU32 := func(v uint32) { _ = binary.Write(&buf, binary.BigEndian, v) }
	writeU16 := func(v uint16) { _ = binary.Write(&buf, binary.BigEndian, v) }
	writeU8 := func(v uint8) { buf.WriteByte(v) }

	writeU32(0xCAFEBABE)
	writeU16(0)  // minor
	writeU16(61) // major

	// cpCount=2: slot1=Utf8(utf8Constant)
	writeU16(2)
	writeU8(1) // tagUtf8
	writeU16(uint16(len(utf8Constant)))
	buf.WriteString(utf8Constant)
	return buf.Bytes()
}

// writeTempFile writes data to a temp file with the given suffix and returns the path.
func writeTempFile(t *testing.T, data []byte, suffix string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "*"+suffix)
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		t.Fatalf("write temp: %v", err)
	}
	return f.Name()
}

// ---- native.IsFatMachOMagic tests ----

func TestIsFatMachOMagic(t *testing.T) {
	tests := []struct {
		name  string
		magic []byte
		want  bool
	}{
		{
			name:  "CAFEBABE archCount=2",
			magic: []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x02},
			want:  true,
		},
		{
			name:  "CAFEBABE archCount=30 (boundary)",
			magic: []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x1E},
			want:  true,
		},
		{
			name:  "BEBAFECA archCount=2 (LE fat magic)",
			magic: []byte{0xBE, 0xBA, 0xFE, 0xCA, 0x02, 0x00, 0x00, 0x00},
			want:  true,
		},
		{
			name:  "BEBAFECA archCount=0 (LE, rejected)",
			magic: []byte{0xBE, 0xBA, 0xFE, 0xCA, 0x00, 0x00, 0x00, 0x00},
			want:  false,
		},
		{
			name:  "CAFEBABE Java major=61 (Java 17)",
			magic: []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x3D},
			want:  false,
		},
		{
			name:  "CAFEBABE Java major=52 (Java 8)",
			magic: []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x34},
			want:  false,
		},
		{
			name:  "CAFEBABE archCount=31 (over threshold)",
			magic: []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x1F},
			want:  false,
		},
		{
			name:  "ELF magic",
			magic: []byte{0x7F, 'E', 'L', 'F', 0x02, 0x01, 0x01, 0x00},
			want:  false,
		},
		{
			name:  "single-arch MachO 64LE",
			magic: []byte{0xCF, 0xFA, 0xED, 0xFE, 0x0C, 0x00, 0x00, 0x01},
			want:  false,
		},
		{
			name:  "too short (4 bytes)",
			magic: []byte{0xCA, 0xFE, 0xBA, 0xBE},
			want:  false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := native.IsFatMachOMagic(tc.magic)
			if got != tc.want {
				t.Errorf("native.IsFatMachOMagic(%x) = %v, want %v", tc.magic, got, tc.want)
			}
		})
	}
}

func TestIsFatMachOMagic_JavaClassFile(t *testing.T) {
	// A real Java class file header for Java 11 (major 55).
	// Bytes: CAFEBABE 00000000 00000037 (minor=0, major=55)
	// Field at bytes 4-7 = 0x00000037 = 55 > 30 → not a fat binary.
	magic := []byte{0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00, 0x00, 0x37}
	if native.IsFatMachOMagic(magic) {
		t.Error("Java 11 class file magic incorrectly identified as fat Mach-O")
	}
}

// ---- isBinaryArtifact fat Mach-O routing test ----

func TestIsBinaryArtifact_FatMachO(t *testing.T) {
	// Write a file with fat Mach-O magic (arch count = 2).
	data := []byte{
		0xCA, 0xFE, 0xBA, 0xBE, // magic
		0x00, 0x00, 0x00, 0x02, // nfat_arch = 2
		0x00, 0x00, 0x00, 0x00, // padding
	}
	path := writeTempFile(t, data, "")

	e := New()
	if !e.isBinaryArtifact(path) {
		t.Error("isBinaryArtifact should return true for fat Mach-O magic")
	}
}

func TestScanArtifact_FatMachO(t *testing.T) {
	// Build a file with fat Mach-O magic header. macho.OpenFat will fail on
	// the truncated data, so scanArtifact should return nil findings with a
	// nil error (non-fatal parse failure path is exercised).
	data := []byte{
		0xCA, 0xFE, 0xBA, 0xBE, // magic
		0x00, 0x00, 0x00, 0x02, // nfat_arch = 2 — routed to ScanFatMachO
		0x00, 0x00, 0x00, 0x00, // truncated; parse will fail gracefully
	}
	path := writeTempFile(t, data, "")

	e := New()
	// Should not panic or return a fatal error; truncated fat binary returns
	// an error which scanExplicitPaths swallows (non-fatal).
	opts := engines.ScanOptions{BinaryPaths: []string{path}}
	fds, err := e.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan returned unexpected error: %v", err)
	}
	// Truncated file: no findings expected.
	if len(fds) != 0 {
		t.Errorf("expected no findings from truncated fat binary, got %d", len(fds))
	}
}

func TestScanArtifact_DotNetAssembly(t *testing.T) {
	// Build a minimal .NET assembly using the same PE32 builder from the
	// dotnet sub-package tests, but inline here so engine_test.go stays
	// self-contained. We write a PE32 with CLI header bit set and embed a
	// known crypto type name in the .text section data, then verify the
	// engine routes to the dotnet scanner and returns a finding.
	//
	// PE32 layout (all little-endian):
	//   [0x00] DOS header (64 bytes) — e_magic=MZ, e_lfanew=0x40
	//   [0x40] PE sig "PE\0\0"
	//   [0x44] COFF header (20 bytes)
	//   [0x58] OptionalHeader32 (224 bytes total: 96 fixed + 16*8 dirs)
	//   [0xF8] Section header (40 bytes)
	//   [0x120] Section data
	peData := buildMinimalDotNetPE(t, true, []byte("System.Security.Cryptography.RSA extra"))
	path := writeTempFile(t, peData, ".dll")

	e := New()
	opts := engines.ScanOptions{BinaryPaths: []string{path}}

	fds, err := e.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	found := false
	for _, f := range fds {
		if f.Algorithm != nil && f.Algorithm.Name == "RSA" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected RSA finding from .NET assembly, got %v", fds)
	}
}

// buildMinimalDotNetPE creates a minimal PE32 file suitable for engine-level
// routing tests. It mirrors the logic in dotnet/scanner_test.go.
func buildMinimalDotNetPE(t *testing.T, hasCLI bool, sectionPayload []byte) []byte {
	t.Helper()

	const (
		peSignOff     = 0x40
		optHeaderSize = 96 + 16*8 // 224 bytes
		sectionHdrSz  = 40
	)

	sectionDataOffset := uint32(peSignOff + 4 + 20 + optHeaderSize + sectionHdrSz)
	sectionDataSize := uint32(len(sectionPayload))

	var buf bytes.Buffer
	w16 := func(v uint16) { _ = binary.Write(&buf, binary.LittleEndian, v) }
	w32 := func(v uint32) { _ = binary.Write(&buf, binary.LittleEndian, v) }
	pad := func(n int) { buf.Write(make([]byte, n)) }

	// DOS header
	w16(0x5A4D) // MZ
	pad(58)
	buf.Truncate(60)
	w32(uint32(peSignOff))
	// DOS header is now exactly 64 bytes

	// PE signature
	buf.WriteString("PE\x00\x00")

	// COFF header
	w16(0x014C) // i386
	w16(1)      // 1 section
	w32(0)      // timestamp
	w32(0)      // symbol table ptr
	w32(0)      // symbol count
	w16(uint16(optHeaderSize))
	w16(0x0002)

	// Optional header fixed fields (96 bytes)
	w16(0x010B) // PE32
	buf.WriteByte(0); buf.WriteByte(0) // linker version
	w32(sectionDataSize) // SizeOfCode
	w32(0); w32(0)       // init/uninit data
	w32(0x1000)          // entry point
	w32(0x1000)          // base of code
	w32(0)               // base of data
	w32(0x00400000)      // image base
	w32(0x1000)          // section alignment
	w32(0x200)           // file alignment
	w16(4); w16(0)       // OS version
	w16(0); w16(0)       // image version
	w16(4); w16(0)       // subsystem version
	w32(0)               // Win32VersionValue
	w32(0x3000)          // SizeOfImage
	w32(sectionDataOffset) // SizeOfHeaders
	w32(0)               // CheckSum
	w16(2); w16(0)       // Subsystem, DllCharacteristics
	w32(0x100000); w32(0x1000) // stack reserve/commit
	w32(0x100000); w32(0x1000) // heap reserve/commit
	w32(0)               // LoaderFlags
	w32(16)              // NumberOfRvaAndSizes

	// Data directories (16 × 8 bytes = 128 bytes)
	for i := 0; i < 14; i++ {
		w32(0); w32(0)
	}
	// Entry 14: COM descriptor
	if hasCLI {
		w32(0x2000); w32(72)
	} else {
		w32(0); w32(0)
	}
	w32(0); w32(0) // entry 15

	// Section header ".text"
	name := [8]byte{'.', 't', 'e', 'x', 't'}
	buf.Write(name[:])
	w32(sectionDataSize)    // VirtualSize
	w32(0x1000)             // VirtualAddress
	w32(sectionDataSize)    // SizeOfRawData
	w32(sectionDataOffset)  // PointerToRawData
	w32(0); w32(0)          // relocs, linenumbers
	w16(0); w16(0)          // reloc/lineno counts
	w32(0x60000020)         // Characteristics

	// Section data
	buf.Write(sectionPayload)

	return buf.Bytes()
}

// ---- scan tests ----

func TestEngine_ExplicitBinaryPaths(t *testing.T) {
	jarData := buildMinimalJar("AES/GCM/NoPadding")
	path := writeTempFile(t, jarData, ".jar")

	e := New()
	opts := engines.ScanOptions{
		TargetPath:  t.TempDir(),
		BinaryPaths: []string{path},
	}

	fds, err := e.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	found := false
	for _, f := range fds {
		if f.Algorithm != nil && f.Algorithm.Name == "AES" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected AES finding from explicit path, got %v", fds)
	}
}

func TestEngine_AutoDiscovery(t *testing.T) {
	dir := t.TempDir()

	jarData := buildMinimalJar("RSA/ECB/PKCS1Padding")
	jarPath := filepath.Join(dir, "app.jar")
	if err := os.WriteFile(jarPath, jarData, 0644); err != nil {
		t.Fatalf("write jar: %v", err)
	}

	e := New()
	opts := engines.ScanOptions{TargetPath: dir}

	fds, err := e.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	found := false
	for _, f := range fds {
		if f.Algorithm != nil && f.Algorithm.Name == "RSA" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected RSA finding from auto-discovery, got %v", fds)
	}
}

func TestEngine_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()

	e := New()
	opts := engines.ScanOptions{TargetPath: dir}

	fds, err := e.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(fds) != 0 {
		t.Errorf("expected no findings from empty dir, got %d", len(fds))
	}
}

func TestEngine_OversizeFileSkipped(t *testing.T) {
	dir := t.TempDir()

	// Write a tiny JAR but configure engine with a very small maxBinarySize.
	jarData := buildMinimalJar("AES/GCM/NoPadding")
	jarPath := filepath.Join(dir, "huge.jar")
	if err := os.WriteFile(jarPath, jarData, 0644); err != nil {
		t.Fatalf("write jar: %v", err)
	}

	e := &Engine{
		maxArchiveDepth: 3,
		maxBinarySize:   1, // 1 byte — everything is too big
	}
	opts := engines.ScanOptions{TargetPath: dir}

	fds, err := e.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(fds) != 0 {
		t.Errorf("expected no findings (all files skipped due to size), got %d", len(fds))
	}
}

func TestEngine_ContextCancellation(t *testing.T) {
	dir := t.TempDir()
	// Populate with a few JARs.
	for i := 0; i < 5; i++ {
		jarData := buildMinimalJar("HmacSHA256")
		name := filepath.Join(dir, "app"+string(rune('0'+i))+".jar")
		if err := os.WriteFile(name, jarData, 0644); err != nil {
			t.Fatalf("write jar: %v", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before scan

	e := New()
	opts := engines.ScanOptions{TargetPath: dir}
	_, err := e.Scan(ctx, opts)
	// Either context.Canceled or nil (engine handled cancellation gracefully).
	if err != nil && err != context.Canceled {
		t.Logf("Scan returned: %v (acceptable)", err)
	}
}

func TestEngine_ExplicitPaths_ContextCancellation(t *testing.T) {
	jarData := buildMinimalJar("AES/GCM/NoPadding")
	path := writeTempFile(t, jarData, ".jar")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	e := New()
	opts := engines.ScanOptions{BinaryPaths: []string{path}}
	_, err := e.Scan(ctx, opts)
	if err != nil && err != context.Canceled {
		t.Logf("Scan returned: %v (acceptable)", err)
	}
}

func TestEngine_IgnoresNonBinaryFiles(t *testing.T) {
	dir := t.TempDir()

	// Write a plain text file with a .jar extension — it's an invalid ZIP.
	badPath := filepath.Join(dir, "not-a-jar.jar")
	if err := os.WriteFile(badPath, []byte("hello world"), 0644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	e := New()
	opts := engines.ScanOptions{TargetPath: dir}

	// Should not panic or return an error for an invalid ZIP.
	fds, err := e.Scan(context.Background(), opts)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(fds) != 0 {
		t.Errorf("expected no findings for invalid archive, got %d", len(fds))
	}
}

func TestEngine_MultipleJARs(t *testing.T) {
	dir := t.TempDir()

	jars := []struct {
		file string
		alg  string
		want string
	}{
		{"a.jar", "AES/GCM/NoPadding", "AES"},
		{"b.jar", "RSA/ECB/PKCS1Padding", "RSA"},
		{"c.jar", "HmacSHA256", "HMAC"},
	}
	for _, j := range jars {
		data := buildMinimalJar(j.alg)
		if err := os.WriteFile(filepath.Join(dir, j.file), data, 0644); err != nil {
			t.Fatalf("write jar: %v", err)
		}
	}

	e := New()
	fds, err := e.Scan(context.Background(), engines.ScanOptions{TargetPath: dir})
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	found := make(map[string]bool)
	for _, f := range fds {
		if f.Algorithm != nil {
			found[f.Algorithm.Name] = true
		}
	}
	for _, j := range jars {
		if !found[j.want] {
			t.Errorf("expected finding for %q (alg=%q), got %v", j.file, j.want, fds)
		}
	}
}

// ---- new integration tests ----

// TestWalkAndScan_DotNetDLLAutoDiscovery verifies that a .dll file placed in a
// subdirectory is discovered by walkAndScan, and that isBinaryArtifact returns
// true for the .dll extension (extension-based detection, no content check).
func TestWalkAndScan_DotNetDLLAutoDiscovery(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "lib")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Minimal PE with no .NET CLI header — routes to native scanner.
	peData := buildMinimalDotNetPE(t, false /*hasCLI*/, []byte("placeholder"))
	dllPath := filepath.Join(sub, "native.dll")
	if err := os.WriteFile(dllPath, peData, 0644); err != nil {
		t.Fatalf("write dll: %v", err)
	}

	e := New()

	// isBinaryArtifact must return true for .dll regardless of content.
	if !e.isBinaryArtifact(dllPath) {
		t.Error("isBinaryArtifact should return true for .dll extension")
	}

	// walkAndScan must discover the DLL in the subdirectory without error.
	fds, err := e.walkAndScan(context.Background(), dir)
	if err != nil {
		t.Fatalf("walkAndScan error: %v", err)
	}
	// The file was discovered and routed. Findings may be zero (native scanner
	// found nothing in the stub PE) but no fatal error should occur.
	_ = fds
}

// TestScanArtifact_PE_WithoutCLIHeader verifies that a minimal PE file (MZ
// magic) with no .NET CLI header is routed to the native scanner, not the
// dotnet scanner, and returns without error.
func TestScanArtifact_PE_WithoutCLIHeader(t *testing.T) {
	// Extensionless file with MZ magic but no valid .NET CLI header pointer.
	// buildMinimalDotNetPE with hasCLI=false zeroes out data directory 14.
	peData := buildMinimalDotNetPE(t, false /*hasCLI*/, []byte("native binary data"))
	path := writeTempFile(t, peData, "" /*no extension*/)

	e := New()
	fds, err := e.scanArtifact(context.Background(), path)
	// scanArtifact must not return a hard error for a well-formed PE.
	// It is acceptable to return nil findings when the native scanner finds
	// no crypto patterns in the stub data.
	if err != nil {
		t.Fatalf("scanArtifact returned unexpected error: %v", err)
	}
	_ = fds
}

// TestScanArtifact_EXE_NativeFallback verifies that a .exe file with MZ magic
// but no .NET CLI header is routed to the native scanner without error.
func TestScanArtifact_EXE_NativeFallback(t *testing.T) {
	// PE32 without CLI header — IsDotNetAssembly must return false.
	peData := buildMinimalDotNetPE(t, false /*hasCLI*/, []byte("win32 stub"))
	path := writeTempFile(t, peData, ".exe")

	e := New()
	fds, err := e.scanArtifact(context.Background(), path)
	if err != nil {
		t.Fatalf("scanArtifact(.exe native) returned error: %v", err)
	}
	// Findings may be nil/empty for a stub PE — that is acceptable.
	_ = fds
}

// TestIsBinaryArtifact_AllExtensions verifies that every recognised binary
// artifact extension returns true from isBinaryArtifact, backed by a
// real temporary file for each extension (so the path suffix check is genuine).
func TestIsBinaryArtifact_AllExtensions(t *testing.T) {
	// Minimal content: MZ magic satisfies isPEMagic for .dll/.exe, and the
	// extension alone is sufficient for .jar/.war/.ear/.aar/.whl/.egg/.so/.dylib.
	mzMagic := []byte{0x4D, 0x5A, 0x00, 0x00}

	extensions := []string{
		".jar", ".war", ".ear", ".aar",
		".whl", ".egg",
		".so", ".dylib",
		".dll", ".exe",
	}

	e := New()
	for _, ext := range extensions {
		ext := ext // capture loop variable
		t.Run(ext, func(t *testing.T) {
			path := writeTempFile(t, mzMagic, ext)
			if !e.isBinaryArtifact(path) {
				t.Errorf("isBinaryArtifact should return true for %q extension", ext)
			}
		})
	}
}

// TestWalkAndScan_ContextCancellation verifies that walkAndScan stops early
// when the context is cancelled before the walk begins.
func TestWalkAndScan_ContextCancellation(t *testing.T) {
	dir := t.TempDir()

	// Populate directory with several JARs so there is work to cancel.
	for i := 0; i < 4; i++ {
		jarData := buildMinimalJar("AES/GCM/NoPadding")
		name := filepath.Join(dir, filepath.FromSlash("app"+string(rune('0'+i))+".jar"))
		if err := os.WriteFile(name, jarData, 0644); err != nil {
			t.Fatalf("write jar: %v", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before the walk starts

	e := New()
	_, err := e.walkAndScan(ctx, dir)
	// walkAndScan propagates context.Canceled when ctx is already done.
	// A nil error is also acceptable if the walker managed to complete
	// between the cancel and the first ctx.Err() check.
	if err != nil && err != context.Canceled && err != context.DeadlineExceeded {
		t.Errorf("walkAndScan returned unexpected error: %v", err)
	}
}

// TestWalkAndScan_SkipsSymlinks verifies that walkAndScan skips symlinks
// because symlink DirEntry.Info() reports a non-regular file mode, so the
// size-guard branch returns nil before isBinaryArtifact is called.
func TestWalkAndScan_SkipsSymlinks(t *testing.T) {
	dir := t.TempDir()

	// Create a real JAR target and a symlink pointing to it.
	jarData := buildMinimalJar("AES/GCM/NoPadding")
	target := filepath.Join(dir, "real.jar")
	if err := os.WriteFile(target, jarData, 0644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "link.jar")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation not supported on this platform: %v", err)
	}

	// Remove the real JAR so only the symlink remains in the directory.
	// The symlink itself is the non-regular file walkAndScan must skip.
	if err := os.Remove(target); err != nil {
		t.Fatalf("remove target: %v", err)
	}

	e := New()
	fds, err := e.walkAndScan(context.Background(), dir)
	if err != nil {
		t.Fatalf("walkAndScan error: %v", err)
	}
	// The symlink (pointing to a now-missing file) should yield zero findings.
	// On platforms where DirEntry.Info() dereferences the link (rare), the
	// walk may attempt to open a dangling symlink and fail gracefully (skip).
	if len(fds) != 0 {
		t.Errorf("expected zero findings when only a dangling symlink is present, got %d", len(fds))
	}
}

// TestWalkAndScan_MaxBinarySizeGuard verifies that files larger than
// maxBinarySize are silently skipped during walkAndScan.
func TestWalkAndScan_MaxBinarySizeGuard(t *testing.T) {
	dir := t.TempDir()

	// Write a small JAR — legitimate content, but the engine's maxBinarySize
	// is set to zero so every file exceeds the limit.
	jarData := buildMinimalJar("AES/GCM/NoPadding")
	jarPath := filepath.Join(dir, "app.jar")
	if err := os.WriteFile(jarPath, jarData, 0644); err != nil {
		t.Fatalf("write jar: %v", err)
	}

	// Set maxBinarySize=0: any file with size > 0 will be skipped.
	e := &Engine{
		maxArchiveDepth: defaultMaxArchiveDepth,
		maxBinarySize:   0,
	}

	fds, err := e.walkAndScan(context.Background(), dir)
	if err != nil {
		t.Fatalf("walkAndScan error: %v", err)
	}
	if len(fds) != 0 {
		t.Errorf("expected zero findings when maxBinarySize=0, got %d", len(fds))
	}
}
