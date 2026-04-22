package dotnet

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// Adversarial fixture tests for the .NET scanner. Since the scanner relies on
// debug/pe for PE parsing, the primary targets are:
//   - Malformed PE headers (bad e_lfanew, missing PE signature)
//   - Absent or corrupted COR20 (CLI) header
//   - Extremely large section payloads (> 200MB cap)

// writeAdvTempPE writes bytes to a temp file with the given suffix.
func writeAdvTempPE(t *testing.T, data []byte, suffix string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "adv"+suffix)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatalf("write temp PE: %v", err)
	}
	return p
}

// ---------------------------------------------------------------------------
// A-D1: Empty file — IsDotNetAssembly and Scan must both fail gracefully.
// ---------------------------------------------------------------------------

func TestAdversarial_DotNetEmptyFile(t *testing.T) {
	p := writeAdvTempPE(t, []byte{}, ".dll")
	if IsDotNetAssembly(p) {
		t.Error("IsDotNetAssembly returned true for empty file")
	}
	fds, err := Scan(context.Background(), p)
	if err == nil && fds == nil {
		// Acceptable: Scan returns (nil, nil) when file is not a valid PE,
		// although the current code returns an error from pe.Open.
	}
	// Primary invariant: no panic.
}

// ---------------------------------------------------------------------------
// A-D2: PE with MZ magic but e_lfanew pointing past EOF. pe.Open fails.
// ---------------------------------------------------------------------------

func TestAdversarial_DotNetBadLfanew(t *testing.T) {
	data := make([]byte, 64)
	data[0] = 'M'
	data[1] = 'Z'
	// e_lfanew = 0x7FFFFFFF (far past EOF)
	binary.LittleEndian.PutUint32(data[60:64], 0x7FFFFFFF)
	p := writeAdvTempPE(t, data, ".dll")

	if IsDotNetAssembly(p) {
		t.Error("IsDotNetAssembly returned true for invalid PE")
	}
	_, _ = Scan(context.Background(), p)
}

// ---------------------------------------------------------------------------
// A-D3: PE with a CLI header virtual address that exceeds the data directory
// count. The `hasCLIHeader` check is `if int(imageDirEntryCOMDescriptor) >=
// len(oh.DataDirectory)` which protects against OOB access. We need a PE
// where DataDirectory has fewer than 15 entries.
// ---------------------------------------------------------------------------

func TestAdversarial_DotNetShortDataDirectory(t *testing.T) {
	// buildMinimalPE32 always writes 16 data directory entries, so we can't
	// hit the "<15 entries" branch via helper — instead, build a PE with
	// NumberOfRvaAndSizes=8 (common in obsolete PE files).
	data := buildPEWithNRvaSizes(t, 8)
	p := writeAdvTempPE(t, data, ".dll")

	// hasCLIHeader's bounds check prevents OOB.
	if IsDotNetAssembly(p) {
		t.Error("IsDotNetAssembly returned true for PE with short data directory")
	}
}

// buildPEWithNRvaSizes builds a minimal PE with a custom NumberOfRvaAndSizes.
func buildPEWithNRvaSizes(t *testing.T, nrva uint32) []byte {
	t.Helper()

	const peSignOff = 0x40
	const coffHeaderSize = 20
	optHeaderSize := 96 + int(nrva)*8
	const sectionSize = 40

	sectionDataOffset := uint32(peSignOff + 4 + coffHeaderSize + optHeaderSize + sectionSize)

	b := &peBuilder{}
	// DOS header
	b.writeU16(0x5A4D)
	b.pad(58)
	b.buf.Truncate(60)
	b.writeU32(uint32(peSignOff))

	// PE sig
	b.buf.WriteString("PE\x00\x00")
	// COFF
	b.writeU16(0x014C)
	b.writeU16(1)
	b.writeU32(0)
	b.writeU32(0)
	b.writeU32(0)
	b.writeU16(uint16(optHeaderSize))
	b.writeU16(0x0002)
	// Optional header PE32
	b.writeU16(0x010B)
	b.writeU8(0)
	b.writeU8(0)
	b.writeU32(0x100)
	b.writeU32(0)
	b.writeU32(0)
	b.writeU32(0x1000)
	b.writeU32(0x1000)
	b.writeU32(0)
	b.writeU32(0x00400000)
	b.writeU32(0x1000)
	b.writeU32(0x200)
	b.writeU16(4)
	b.writeU16(0)
	b.writeU16(0)
	b.writeU16(0)
	b.writeU16(4)
	b.writeU16(0)
	b.writeU32(0)
	b.writeU32(0x3000)
	b.writeU32(sectionDataOffset)
	b.writeU32(0)
	b.writeU16(2)
	b.writeU16(0)
	b.writeU32(0x100000)
	b.writeU32(0x1000)
	b.writeU32(0x100000)
	b.writeU32(0x1000)
	b.writeU32(0)
	b.writeU32(nrva)

	// Write nrva data directory entries (each 8 bytes).
	for i := uint32(0); i < nrva; i++ {
		b.writeU32(0) // VirtualAddress
		b.writeU32(0) // Size
	}

	// Section header ".text"
	name := [8]byte{'.', 't', 'e', 'x', 't'}
	b.buf.Write(name[:])
	b.writeU32(0x100)
	b.writeU32(0x1000)
	b.writeU32(0x100)
	b.writeU32(sectionDataOffset)
	b.writeU32(0)
	b.writeU32(0)
	b.writeU16(0)
	b.writeU16(0)
	b.writeU32(0x60000020)

	// Section data — 256 bytes of padding
	b.buf.Write(make([]byte, 0x100))

	return b.bytes()
}

// ---------------------------------------------------------------------------
// A-D4: Section data contains embedded crypto type names AS SUBSTRINGS but
// the full FQN is not present. The byte-level substring search requires the
// full type name — partial matches should NOT produce findings.
// ---------------------------------------------------------------------------

func TestAdversarial_DotNetPartialTypeName(t *testing.T) {
	// "System.Security.Cryptography.Ae" (truncated) — should NOT match Aes.
	sectionData := []byte("prelude System.Security.Cryptography.Ae suffix")
	data := buildMinimalPE32(t, true, sectionData)
	p := writeAdvTempPE(t, data, ".dll")

	fds, err := Scan(context.Background(), p)
	if err != nil {
		t.Fatalf("Scan error: %v", err)
	}
	for _, f := range fds {
		if f.Algorithm != nil && f.Algorithm.Name == "AES" {
			t.Errorf("partial FQN must not match AES, got %+v", f)
		}
	}
}

// ---------------------------------------------------------------------------
// A-D5: Section data contains crypto type name at buffer boundary — must
// still match (not truncated).
// ---------------------------------------------------------------------------

func TestAdversarial_DotNetTypeNameAtBoundary(t *testing.T) {
	// Place type name at the END of section data.
	name := "System.Security.Cryptography.Aes"
	sectionData := append(make([]byte, 100), []byte(name)...)
	data := buildMinimalPE32(t, true, sectionData)
	p := writeAdvTempPE(t, data, ".dll")

	fds, err := Scan(context.Background(), p)
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
		t.Errorf("boundary type name should match, got %d findings", len(fds))
	}
}

// ---------------------------------------------------------------------------
// A-D6: PE section count = 0 — debug/pe allows this; section iteration is
// empty so no findings.
// ---------------------------------------------------------------------------

func TestAdversarial_DotNetZeroSections(t *testing.T) {
	// Build a PE with NumberOfSections=0. Manually.
	// Note: debug/pe may reject NumberOfSections=0; we just verify no panic.
	data := buildPEWithSectionCount(t, 0, true)
	p := writeAdvTempPE(t, data, ".dll")

	_, _ = Scan(context.Background(), p)
}

// buildPEWithSectionCount builds a minimal PE with variable section count.
func buildPEWithSectionCount(t *testing.T, sectionCount uint16, hasCLI bool) []byte {
	t.Helper()
	const peSignOff = 0x40
	const coffHeaderSize = 20
	optHeaderSize := 96 + 16*8
	const sectionSize = 40

	headerBytes := peSignOff + 4 + coffHeaderSize + optHeaderSize + int(sectionCount)*sectionSize
	sectionDataOffset := uint32(headerBytes)

	b := &peBuilder{}
	b.writeU16(0x5A4D)
	b.pad(58)
	b.buf.Truncate(60)
	b.writeU32(uint32(peSignOff))

	b.buf.WriteString("PE\x00\x00")
	b.writeU16(0x014C)
	b.writeU16(sectionCount)
	b.writeU32(0)
	b.writeU32(0)
	b.writeU32(0)
	b.writeU16(uint16(optHeaderSize))
	b.writeU16(0x0002)
	b.writeU16(0x010B)
	b.writeU8(0)
	b.writeU8(0)
	b.writeU32(0x100)
	b.writeU32(0)
	b.writeU32(0)
	b.writeU32(0x1000)
	b.writeU32(0x1000)
	b.writeU32(0)
	b.writeU32(0x00400000)
	b.writeU32(0x1000)
	b.writeU32(0x200)
	b.writeU16(4)
	b.writeU16(0)
	b.writeU16(0)
	b.writeU16(0)
	b.writeU16(4)
	b.writeU16(0)
	b.writeU32(0)
	b.writeU32(0x3000)
	b.writeU32(sectionDataOffset)
	b.writeU32(0)
	b.writeU16(2)
	b.writeU16(0)
	b.writeU32(0x100000)
	b.writeU32(0x1000)
	b.writeU32(0x100000)
	b.writeU32(0x1000)
	b.writeU32(0)
	b.writeU32(16)
	for i := 0; i < 14; i++ {
		b.writeU32(0)
		b.writeU32(0)
	}
	if hasCLI {
		b.writeU32(0x2000)
		b.writeU32(72)
	} else {
		b.writeU32(0)
		b.writeU32(0)
	}
	b.writeU32(0)
	b.writeU32(0)

	// Sections (none if count=0).
	for i := uint16(0); i < sectionCount; i++ {
		name := [8]byte{'.', 't', 'x', 't'}
		b.buf.Write(name[:])
		b.writeU32(0x100)
		b.writeU32(0x1000)
		b.writeU32(0x100)
		b.writeU32(sectionDataOffset)
		b.writeU32(0)
		b.writeU32(0)
		b.writeU16(0)
		b.writeU16(0)
		b.writeU32(0x60000020)
	}

	return b.bytes()
}

// ---------------------------------------------------------------------------
// A-D7: Missing PE signature — bytes 'M','Z' present but no "PE\x00\x00".
// ---------------------------------------------------------------------------

func TestAdversarial_DotNetMissingPESignature(t *testing.T) {
	data := make([]byte, 128)
	data[0] = 'M'
	data[1] = 'Z'
	binary.LittleEndian.PutUint32(data[60:64], 0x40)
	// At offset 0x40 we leave zero bytes — not "PE\x00\x00".
	p := writeAdvTempPE(t, data, ".dll")

	if IsDotNetAssembly(p) {
		t.Error("IsDotNetAssembly should not match without PE signature")
	}
	_, _ = Scan(context.Background(), p)
}

// ---------------------------------------------------------------------------
// A-D8: Context cancellation immediately returns an error.
// ---------------------------------------------------------------------------

func TestAdversarial_DotNetCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Scan(ctx, "/no/path/needed")
	if err == nil {
		t.Error("expected cancellation error")
	}
}
