package dotnet

import (
	"bytes"
	"context"
	"encoding/binary"
	"os"
	"testing"
)

// ---------------------------------------------------------------------------
// PE fixture builders
//
// We build minimal PE32 structures in memory to exercise the scanner without
// requiring actual .NET SDK tooling. The structures are intentionally minimal
// — only fields inspected by debug/pe and IsDotNetAssembly are populated.
// ---------------------------------------------------------------------------

// peBuilder accumulates PE file bytes.
type peBuilder struct {
	buf bytes.Buffer
}

func (b *peBuilder) writeU8(v uint8)  { b.buf.WriteByte(v) }
func (b *peBuilder) writeU16(v uint16) { _ = binary.Write(&b.buf, binary.LittleEndian, v) }
func (b *peBuilder) writeU32(v uint32) { _ = binary.Write(&b.buf, binary.LittleEndian, v) }
func (b *peBuilder) pad(n int)         { b.buf.Write(make([]byte, n)) }
func (b *peBuilder) bytes() []byte     { return b.buf.Bytes() }
func (b *peBuilder) len() int          { return b.buf.Len() }

// buildMinimalPE32 creates a minimal PE32 file. If hasCLI is true the COM
// descriptor data directory entry (index 14) has a non-zero VirtualAddress,
// marking the file as a .NET assembly. The returned bytes are valid enough for
// debug/pe to parse the optional header.
//
// Structure:
//   [0x00] DOS header (64 bytes) + stub (minimal)
//   [0x40] PE signature "PE\0\0"
//   [0x44] COFF file header (20 bytes)
//   [0x58] Optional header PE32 (96 bytes base + 128 bytes data directories)
//   [0xF8] Section table (1 section, 40 bytes)
//   [0x120] .text section data (section payload)
func buildMinimalPE32(t *testing.T, hasCLI bool, sectionPayload []byte) []byte {
	t.Helper()

	const (
		dosHeaderSize  = 64
		peSignOff      = 0x40 // e_lfanew — offset of PE signature
		coffHeaderSize = 20
		// OptionalHeader32 fixed fields = 96 bytes
		// DataDirectory  = 16 entries × 8 bytes = 128 bytes
		optHeaderSize = 96 + 16*8
		sectionSize   = 40 // IMAGE_SECTION_HEADER size
	)

	sectionDataOffset := uint32(peSignOff + 4 + coffHeaderSize + optHeaderSize + sectionSize)
	sectionDataSize := uint32(len(sectionPayload))

	b := &peBuilder{}

	// --- DOS header (64 bytes) ---
	b.writeU16(0x5A4D) // e_magic: MZ
	b.pad(58)          // fill unused DOS header fields
	// e_lfanew at offset 60 (little-endian uint32)
	_ = b.len() // should be 60
	b.buf.Truncate(60)
	b.writeU32(uint32(peSignOff)) // e_lfanew = 0x40
	b.pad(dosHeaderSize - 64)     // no-op (already 64 bytes)

	// --- PE signature (4 bytes) ---
	b.buf.WriteString("PE\x00\x00")

	// --- COFF File Header (20 bytes) ---
	b.writeU16(0x014C) // Machine: IMAGE_FILE_MACHINE_I386
	b.writeU16(1)      // NumberOfSections = 1
	b.writeU32(0)      // TimeDateStamp
	b.writeU32(0)      // PointerToSymbolTable
	b.writeU32(0)      // NumberOfSymbols
	b.writeU16(uint16(optHeaderSize)) // SizeOfOptionalHeader
	b.writeU16(0x0002) // Characteristics: IMAGE_FILE_EXECUTABLE_IMAGE

	// --- Optional Header (PE32) fixed fields (96 bytes) ---
	b.writeU16(0x010B) // Magic: PE32
	b.writeU8(0)       // MajorLinkerVersion
	b.writeU8(0)       // MinorLinkerVersion
	b.writeU32(sectionDataSize) // SizeOfCode
	b.writeU32(0)      // SizeOfInitializedData
	b.writeU32(0)      // SizeOfUninitializedData
	b.writeU32(0x1000) // AddressOfEntryPoint
	b.writeU32(0x1000) // BaseOfCode
	b.writeU32(0)      // BaseOfData (PE32 only)
	b.writeU32(0x00400000) // ImageBase
	b.writeU32(0x1000) // SectionAlignment
	b.writeU32(0x200)  // FileAlignment
	b.writeU16(4)      // MajorOSVersion
	b.writeU16(0)      // MinorOSVersion
	b.writeU16(0)      // MajorImageVersion
	b.writeU16(0)      // MinorImageVersion
	b.writeU16(4)      // MajorSubsystemVersion
	b.writeU16(0)      // MinorSubsystemVersion
	b.writeU32(0)      // Win32VersionValue
	b.writeU32(0x3000) // SizeOfImage
	b.writeU32(sectionDataOffset) // SizeOfHeaders
	b.writeU32(0)      // CheckSum
	b.writeU16(2)      // Subsystem: Windows GUI
	b.writeU16(0)      // DllCharacteristics
	b.writeU32(0x100000) // SizeOfStackReserve
	b.writeU32(0x1000)   // SizeOfStackCommit
	b.writeU32(0x100000) // SizeOfHeapReserve
	b.writeU32(0x1000)   // SizeOfHeapCommit
	b.writeU32(0)      // LoaderFlags
	b.writeU32(16)     // NumberOfRvaAndSizes

	// --- Data Directories (16 × 8 bytes = 128 bytes) ---
	// Entries 0-13: all zero
	for i := 0; i < 14; i++ {
		b.writeU32(0) // VirtualAddress
		b.writeU32(0) // Size
	}
	// Entry 14: IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
	if hasCLI {
		b.writeU32(0x2000) // non-zero VirtualAddress → .NET CLI header present
		b.writeU32(72)     // typical CLI header size
	} else {
		b.writeU32(0) // VirtualAddress = 0 → not .NET
		b.writeU32(0)
	}
	// Entry 15: zero
	b.writeU32(0)
	b.writeU32(0)

	// --- Section header ".text" (40 bytes) ---
	// Name (8 bytes, null-padded)
	name := [8]byte{'.', 't', 'e', 'x', 't'}
	b.buf.Write(name[:])
	b.writeU32(sectionDataSize) // VirtualSize
	b.writeU32(0x1000)          // VirtualAddress
	b.writeU32(sectionDataSize) // SizeOfRawData
	b.writeU32(sectionDataOffset) // PointerToRawData
	b.writeU32(0) // PointerToRelocations
	b.writeU32(0) // PointerToLinenumbers
	b.writeU16(0) // NumberOfRelocations
	b.writeU16(0) // NumberOfLinenumbers
	b.writeU32(0x60000020) // Characteristics: CODE | EXECUTE | READ

	// --- Section data ---
	b.buf.Write(sectionPayload)

	return b.bytes()
}

// writeTempPE writes PE bytes to a temp file with the given suffix.
func writeTempPE(t *testing.T, data []byte, suffix string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "*"+suffix)
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		t.Fatalf("write temp PE: %v", err)
	}
	return f.Name()
}

// ---------------------------------------------------------------------------
// IsDotNetAssembly tests
// ---------------------------------------------------------------------------

func TestIsDotNetAssembly_RegularPE(t *testing.T) {
	// PE32 without CLI header (hasCLI=false).
	data := buildMinimalPE32(t, false, []byte("hello"))
	path := writeTempPE(t, data, ".exe")

	if IsDotNetAssembly(path) {
		t.Error("IsDotNetAssembly = true for regular PE, want false")
	}
}

func TestIsDotNetAssembly_EmptyFile(t *testing.T) {
	path := writeTempPE(t, []byte{}, ".exe")

	if IsDotNetAssembly(path) {
		t.Error("IsDotNetAssembly = true for empty file, want false")
	}
}

func TestIsDotNetAssembly_TooSmall(t *testing.T) {
	// A file smaller than the minimum PE header is not a valid PE.
	path := writeTempPE(t, []byte{0x4D, 0x5A, 0x00, 0x00}, ".exe")

	if IsDotNetAssembly(path) {
		t.Error("IsDotNetAssembly = true for truncated PE, want false")
	}
}

func TestIsDotNetAssembly_WithCLIHeader(t *testing.T) {
	data := buildMinimalPE32(t, true, []byte("dummy section"))
	path := writeTempPE(t, data, ".dll")

	if !IsDotNetAssembly(path) {
		t.Error("IsDotNetAssembly = false for PE with CLI header, want true")
	}
}

func TestIsDotNetAssembly_MissingFile(t *testing.T) {
	if IsDotNetAssembly("/no/such/path/assembly.dll") {
		t.Error("IsDotNetAssembly = true for missing file, want false")
	}
}

// ---------------------------------------------------------------------------
// Scan tests
// ---------------------------------------------------------------------------

func TestScan_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before scan

	_, err := Scan(ctx, "/some/path.dll")
	if err == nil {
		t.Error("expected error on cancelled context, got nil")
	}
}

func TestScan_EmptyAssembly(t *testing.T) {
	// Valid PE with CLI header but no crypto type names in section data.
	sectionData := []byte("no crypto references here")
	data := buildMinimalPE32(t, true, sectionData)
	path := writeTempPE(t, data, ".dll")

	fds, err := Scan(context.Background(), path)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(fds) != 0 {
		t.Errorf("expected no findings for assembly with no crypto refs, got %d", len(fds))
	}
}

func TestScan_NotDotNet(t *testing.T) {
	// Regular PE without CLI header → Scan returns (nil, nil).
	sectionData := []byte("System.Security.Cryptography.Aes is just text here")
	data := buildMinimalPE32(t, false, sectionData)
	path := writeTempPE(t, data, ".exe")

	fds, err := Scan(context.Background(), path)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(fds) != 0 {
		t.Errorf("expected no findings for non-.NET PE, got %d", len(fds))
	}
}

func TestScan_CryptoReferences(t *testing.T) {
	// Embed known crypto type names in the section data.
	sectionData := []byte(
		"some preamble " +
			"System.Security.Cryptography.Aes" +
			" other data " +
			"System.Security.Cryptography.RSA" +
			" end",
	)
	data := buildMinimalPE32(t, true, sectionData)
	path := writeTempPE(t, data, ".dll")

	fds, err := Scan(context.Background(), path)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(fds) == 0 {
		t.Fatal("expected findings, got none")
	}

	found := make(map[string]bool)
	for _, f := range fds {
		if f.Algorithm != nil {
			found[f.Algorithm.Name] = true
		}
		if f.SourceEngine != sourceEngine {
			t.Errorf("SourceEngine = %q, want %q", f.SourceEngine, sourceEngine)
		}
		if f.Location.ArtifactType != artifactType {
			t.Errorf("ArtifactType = %q, want %q", f.Location.ArtifactType, artifactType)
		}
		if f.Confidence != "medium" {
			t.Errorf("Confidence = %q, want medium", f.Confidence)
		}
		if f.Location.File != path {
			t.Errorf("Location.File = %q, want %q", f.Location.File, path)
		}
	}

	if !found["AES"] {
		t.Error("expected AES finding, not found")
	}
	if !found["RSA"] {
		t.Error("expected RSA finding, not found")
	}
}

func TestScan_BouncyCastle(t *testing.T) {
	sectionData := []byte(
		"prefix " +
			"Org.BouncyCastle.Crypto.Engines.AesEngine" +
			" middle " +
			"Org.BouncyCastle.Crypto.Engines.RsaEngine" +
			" suffix",
	)
	data := buildMinimalPE32(t, true, sectionData)
	path := writeTempPE(t, data, ".dll")

	fds, err := Scan(context.Background(), path)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(fds) == 0 {
		t.Fatal("expected BouncyCastle findings, got none")
	}

	found := make(map[string]bool)
	for _, f := range fds {
		if f.Algorithm != nil {
			found[f.Algorithm.Name] = true
		}
	}
	if !found["AES"] {
		t.Error("expected AES finding from BouncyCastle AesEngine")
	}
	if !found["RSA"] {
		t.Error("expected RSA finding from BouncyCastle RsaEngine")
	}
}

func TestScan_PQCSafe(t *testing.T) {
	sectionData := []byte(
		"preamble " +
			"Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber" +
			" mid " +
			"Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium" +
			" end",
	)
	data := buildMinimalPE32(t, true, sectionData)
	path := writeTempPE(t, data, ".dll")

	fds, err := Scan(context.Background(), path)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(fds) == 0 {
		t.Fatal("expected PQC findings, got none")
	}

	algNames := make(map[string]bool)
	for _, f := range fds {
		if f.Algorithm != nil {
			algNames[f.Algorithm.Name] = true
		}
	}
	if !algNames["ML-KEM"] {
		t.Error("expected ML-KEM finding from Kyber type reference")
	}
	if !algNames["ML-DSA"] {
		t.Error("expected ML-DSA finding from Dilithium type reference")
	}
}

func TestScan_DeduplicatesIdenticalTypes(t *testing.T) {
	// The same type name appears three times in the section data — must
	// produce exactly one finding for that type.
	typeName := "System.Security.Cryptography.SHA256"
	sectionData := []byte(
		typeName + " first occurrence " +
			typeName + " second occurrence " +
			typeName + " third occurrence",
	)
	data := buildMinimalPE32(t, true, sectionData)
	path := writeTempPE(t, data, ".dll")

	fds, err := Scan(context.Background(), path)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}

	count := 0
	for _, f := range fds {
		if f.Algorithm != nil && f.Algorithm.Name == "SHA-256" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 SHA-256 finding after dedup, got %d", count)
	}
}

func TestScan_FindingFields(t *testing.T) {
	// Verify all fields of a finding are populated correctly.
	typeName := "System.Security.Cryptography.ECDsa"
	sectionData := []byte("data " + typeName + " end")
	data := buildMinimalPE32(t, true, sectionData)
	path := writeTempPE(t, data, ".dll")

	fds, err := Scan(context.Background(), path)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	if len(fds) == 0 {
		t.Fatal("expected at least one finding")
	}

	var found bool
	for _, f := range fds {
		if f.RawIdentifier == typeName {
			found = true
			if f.Algorithm == nil {
				t.Fatal("Algorithm is nil")
			}
			if f.Algorithm.Name != "ECDSA" {
				t.Errorf("Algorithm.Name = %q, want ECDSA", f.Algorithm.Name)
			}
			if f.Algorithm.Primitive != "signature" {
				t.Errorf("Algorithm.Primitive = %q, want signature", f.Algorithm.Primitive)
			}
			if f.Location.ArtifactType != artifactType {
				t.Errorf("ArtifactType = %q, want %q", f.Location.ArtifactType, artifactType)
			}
			if f.Confidence != "medium" {
				t.Errorf("Confidence = %q, want medium", f.Confidence)
			}
			if f.SourceEngine != sourceEngine {
				t.Errorf("SourceEngine = %q, want %q", f.SourceEngine, sourceEngine)
			}
			if f.Reachable != "unknown" {
				t.Errorf("Reachable = %q, want unknown", f.Reachable)
			}
		}
	}
	if !found {
		t.Errorf("finding with RawIdentifier=%q not found in results", typeName)
	}
}

func TestScan_NonPEFile(t *testing.T) {
	// A non-PE file should return a non-nil error (pe.Open fails).
	path := writeTempPE(t, []byte("this is not a PE file at all"), ".dll")

	_, err := Scan(context.Background(), path)
	if err == nil {
		t.Error("expected error for non-PE file, got nil")
	}
}

// ---------------------------------------------------------------------------
// searchCryptoTypes unit tests (internal)
// ---------------------------------------------------------------------------

func TestSearchCryptoTypes_EmptyData(t *testing.T) {
	result := searchCryptoTypes([]byte{}, "/fake/path.dll")
	if len(result) != 0 {
		t.Errorf("expected no findings for empty data, got %d", len(result))
	}
}

func TestSearchCryptoTypes_NoMatches(t *testing.T) {
	data := []byte("hello world no crypto here")
	result := searchCryptoTypes(data, "/fake/path.dll")
	if len(result) != 0 {
		t.Errorf("expected no findings, got %d", len(result))
	}
}

func TestSearchCryptoTypes_PartialNameNoMatch(t *testing.T) {
	// A partial type name must NOT produce a finding (avoids false positives).
	data := []byte("System.Security.Cryptography") // no specific type name
	result := searchCryptoTypes(data, "/fake/path.dll")
	if len(result) != 0 {
		t.Errorf("expected no findings for partial namespace, got %d", len(result))
	}
}

func TestSearchCryptoTypes_DeterministicOrder(t *testing.T) {
	// Run searchCryptoTypes twice on the same data and verify the order is
	// identical (sorted key iteration must be stable).
	data := []byte(
		"System.Security.Cryptography.SHA256 " +
			"System.Security.Cryptography.SHA512 " +
			"System.Security.Cryptography.MD5 " +
			"System.Security.Cryptography.AesGcm",
	)

	first := searchCryptoTypes(data, "/fake.dll")
	second := searchCryptoTypes(data, "/fake.dll")

	if len(first) != len(second) {
		t.Fatalf("different result counts: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].RawIdentifier != second[i].RawIdentifier {
			t.Errorf("result[%d] differs: %q vs %q",
				i, first[i].RawIdentifier, second[i].RawIdentifier)
		}
	}
}

// ---------------------------------------------------------------------------
// Fuzz: searchCryptoTypes
// ---------------------------------------------------------------------------

// FuzzSearchCryptoTypes verifies that searchCryptoTypes never panics on
// arbitrary byte input and always returns structurally valid findings.
// Seeds include known .NET type names to give the fuzzer a warm start on
// real matching paths, plus adversarial inputs (partial names, null bytes,
// very long strings).
func FuzzSearchCryptoTypes(f *testing.F) {
	// Known type names that produce findings — warm-start for matching paths.
	f.Add([]byte("System.Security.Cryptography.Aes"))
	f.Add([]byte("System.Security.Cryptography.RSA"))
	f.Add([]byte("System.Security.Cryptography.ECDsa"))
	f.Add([]byte("System.Security.Cryptography.SHA256"))
	f.Add([]byte("System.Security.Cryptography.MD5"))
	f.Add([]byte("Org.BouncyCastle.Crypto.Engines.AesEngine"))
	f.Add([]byte("Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber"))
	// Multiple type names in one buffer.
	f.Add([]byte("System.Security.Cryptography.Aes System.Security.Cryptography.RSA"))
	// Partial namespace prefix with no terminal type name — must not match.
	f.Add([]byte("System.Security.Cryptography"))
	// Binary noise mixed with a valid type name.
	f.Add(append([]byte{0x00, 0xFF, 0xDE, 0xAD}, []byte("System.Security.Cryptography.DES")...))
	// Empty input.
	f.Add([]byte{})
	// Null bytes only.
	f.Add([]byte{0x00, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Must never panic for any input.
		result := searchCryptoTypes(data, "/fuzz/target.dll")

		// Every returned finding must satisfy structural invariants.
		for i, fd := range result {
			if fd.Algorithm == nil {
				t.Errorf("result[%d]: Algorithm is nil", i)
				continue
			}
			if fd.Algorithm.Name == "" {
				t.Errorf("result[%d]: Algorithm.Name is empty", i)
			}
			if fd.Algorithm.Primitive == "" {
				t.Errorf("result[%d]: Algorithm.Primitive is empty", i)
			}
			if fd.RawIdentifier == "" {
				t.Errorf("result[%d]: RawIdentifier is empty", i)
			}
			if fd.SourceEngine != sourceEngine {
				t.Errorf("result[%d]: SourceEngine = %q, want %q",
					i, fd.SourceEngine, sourceEngine)
			}
			if fd.Location.ArtifactType != artifactType {
				t.Errorf("result[%d]: ArtifactType = %q, want %q",
					i, fd.Location.ArtifactType, artifactType)
			}
		}
	})
}
