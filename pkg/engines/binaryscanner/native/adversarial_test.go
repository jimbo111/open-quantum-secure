package native

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

// Adversarial fixture tests for the native binary scanner. These tests build
// byte-level malformed ELF / Mach-O / PE artifacts in-memory to probe the
// symbol-table and dynlib parsers for panics.
//
// Go's debug/elf, debug/macho, and debug/pe packages already have their own
// bounds checking and return error values — our job is to verify the Scanner
// treats those errors gracefully (not as panics and not as silent misses).

// ---------------------------------------------------------------------------
// A-N1: truncated ELF header — DetectFormat matches on the 4-byte magic, but
// elf.Open must fail cleanly when the header is truncated past the magic.
// ---------------------------------------------------------------------------

func TestAdversarial_TruncatedELFHeader(t *testing.T) {
	// Just the magic; everything else is missing.
	data := []byte{0x7F, 'E', 'L', 'F'}
	path := writeTempFile(t, data)

	// Scan must not panic.
	matches, err := ScanELFSymbols(path)
	if err == nil {
		t.Log("ScanELFSymbols accepted truncated ELF (returned no error)")
	}
	if len(matches) != 0 {
		t.Errorf("expected no matches, got %d", len(matches))
	}

	// End-to-end Scan must also not panic.
	_, _ = Scan(context.Background(), path)
}

// ---------------------------------------------------------------------------
// A-N2: ELF with plausible header but zero section count. elf.Open succeeds
// on many such inputs and returns empty symbol lists — verify non-panic.
// ---------------------------------------------------------------------------

func TestAdversarial_ELFZeroSections(t *testing.T) {
	// Minimal 64-byte ELF64 header with e_shnum=0, e_phnum=0.
	// Class=64bit (0x02), data=little-endian (0x01), OS ABI=SysV (0x00).
	hdr := make([]byte, 64)
	hdr[0] = 0x7F
	hdr[1] = 'E'
	hdr[2] = 'L'
	hdr[3] = 'F'
	hdr[4] = 0x02 // EI_CLASS = ELFCLASS64
	hdr[5] = 0x01 // EI_DATA  = ELFDATA2LSB
	hdr[6] = 0x01 // EI_VERSION
	binary.LittleEndian.PutUint16(hdr[16:18], 0x01) // e_type = ET_REL
	binary.LittleEndian.PutUint16(hdr[18:20], 0x3E) // e_machine = EM_X86_64
	binary.LittleEndian.PutUint32(hdr[20:24], 0x01) // e_version

	path := writeTempFile(t, hdr)

	// ScanELFSymbols should not panic regardless of elf.Open outcome.
	_, _ = ScanELFSymbols(path)
	// Full Scan path.
	_, _ = Scan(context.Background(), path)
}

// ---------------------------------------------------------------------------
// A-N3: ELF header with absurd section count. Go's elf.Open validates fields
// and typically rejects unreasonable values. Verify no panic even when
// Go's parser accepts and later iteration falls over.
// ---------------------------------------------------------------------------

func TestAdversarial_ELFMassiveSectionCount(t *testing.T) {
	hdr := make([]byte, 64)
	hdr[0] = 0x7F
	hdr[1] = 'E'
	hdr[2] = 'L'
	hdr[3] = 'F'
	hdr[4] = 0x02
	hdr[5] = 0x01
	hdr[6] = 0x01
	binary.LittleEndian.PutUint16(hdr[16:18], 0x01)
	binary.LittleEndian.PutUint16(hdr[18:20], 0x3E)
	binary.LittleEndian.PutUint32(hdr[20:24], 0x01)
	// e_shnum at offset 60, e_shentsize at offset 58, e_shoff at offset 40.
	binary.LittleEndian.PutUint64(hdr[40:48], 0x10000000) // e_shoff far past EOF
	binary.LittleEndian.PutUint16(hdr[58:60], 64)         // e_shentsize
	binary.LittleEndian.PutUint16(hdr[60:62], 0xFFFF)     // e_shnum = 65535

	path := writeTempFile(t, hdr)
	_, _ = ScanELFSymbols(path)
	_, _ = Scan(context.Background(), path)
}

// ---------------------------------------------------------------------------
// A-N4: PE stub file — just "MZ" and some junk. pe.Open typically fails here;
// Scan must treat the error gracefully.
// ---------------------------------------------------------------------------

func TestAdversarial_MinimalPEStub(t *testing.T) {
	data := make([]byte, 64)
	data[0] = 'M'
	data[1] = 'Z'
	// leave rest as zeros
	path := writeTempFile(t, data)

	_, _ = ScanPESymbols(path)
	_, _ = Scan(context.Background(), path)
}

// ---------------------------------------------------------------------------
// A-N5: PE file where e_lfanew (offset to PE header) points past EOF. pe.Open
// returns an error; Scan must not panic.
// ---------------------------------------------------------------------------

func TestAdversarial_PEBadLfanew(t *testing.T) {
	data := make([]byte, 64)
	data[0] = 'M'
	data[1] = 'Z'
	// e_lfanew at offset 60 — point far past EOF.
	binary.LittleEndian.PutUint32(data[60:64], 0x10000000)
	path := writeTempFile(t, data)

	_, _ = ScanPESymbols(path)
	_, _ = Scan(context.Background(), path)
}

// ---------------------------------------------------------------------------
// A-N6: Mach-O header where ncmds exceeds remaining bytes. The parser should
// fail on the unreadable load commands but must not panic.
// ---------------------------------------------------------------------------

func TestAdversarial_MachOMassiveNcmds(t *testing.T) {
	// 32-byte Mach-O 64 header with ncmds=0xFFFFFFFF.
	hdr := make([]byte, 32)
	// 0xFEEDFACF (big-endian layout: FE ED FA CF) for 64-bit BE. Easier to do LE:
	// 0xCFFAEDFE (LE): magic bytes are CF FA ED FE.
	hdr[0] = 0xCF
	hdr[1] = 0xFA
	hdr[2] = 0xED
	hdr[3] = 0xFE
	// cputype(4), cpusubtype(4), filetype(4), ncmds(4), sizeofcmds(4), flags(4), reserved(4).
	binary.LittleEndian.PutUint32(hdr[16:20], 0xFFFFFFFF) // ncmds
	binary.LittleEndian.PutUint32(hdr[20:24], 0x1000)     // sizeofcmds
	path := writeTempFile(t, hdr)

	_, _ = ScanMachOSymbols(path)
	_, _ = Scan(context.Background(), path)
}

// ---------------------------------------------------------------------------
// A-N7: Mach-O header with ncmds=0 — valid, no load commands, no symtab.
// Scanner should return no matches and no error.
// ---------------------------------------------------------------------------

func TestAdversarial_MachOZeroNcmds(t *testing.T) {
	hdr := make([]byte, 32)
	hdr[0] = 0xCF
	hdr[1] = 0xFA
	hdr[2] = 0xED
	hdr[3] = 0xFE
	// cputype + cpusubtype + filetype are set sanely but not required.
	binary.LittleEndian.PutUint32(hdr[4:8], 0x01000007) // cputype=CPU_TYPE_X86_64
	binary.LittleEndian.PutUint32(hdr[12:16], 0x2)      // filetype=MH_EXECUTE
	// ncmds=0 (offset 16), sizeofcmds=0 (offset 20).
	path := writeTempFile(t, hdr)

	matches, err := ScanMachOSymbols(path)
	if err != nil {
		t.Logf("ScanMachOSymbols error on zero-ncmds Mach-O: %v", err)
	}
	if len(matches) != 0 {
		t.Errorf("expected no matches, got %d", len(matches))
	}
	_, _ = Scan(context.Background(), path)
}

// ---------------------------------------------------------------------------
// A-N8: Fat Mach-O header with archCount=0 — DetectFormat rejects (archCount
// must be > 0 per IsFatMachOMagic). Verify the format detector handles it.
// ---------------------------------------------------------------------------

func TestAdversarial_FatMachOZeroArchCount(t *testing.T) {
	// 0xCAFEBABE + archCount=0 (big-endian).
	hdr := make([]byte, 8)
	hdr[0] = 0xCA
	hdr[1] = 0xFE
	hdr[2] = 0xBA
	hdr[3] = 0xBE
	// archCount = 0 (big-endian) at bytes 4-7
	// already zero

	if IsFatMachOMagic(hdr) {
		t.Error("IsFatMachOMagic should reject archCount=0")
	}

	// DetectFormat should also reject this.
	path := writeTempFile(t, hdr)
	got := DetectFormat(path)
	if got == "macho-fat" {
		t.Errorf("DetectFormat should not classify archCount=0 as fat Mach-O, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// A-N9: Fat Mach-O header with archCount=31 (just above the threshold of 30).
// Per the IsFatMachOMagic heuristic, this must be rejected to avoid
// misidentifying Java class files.
// ---------------------------------------------------------------------------

func TestAdversarial_FatMachOJustAboveThreshold(t *testing.T) {
	hdr := make([]byte, 8)
	hdr[0] = 0xCA
	hdr[1] = 0xFE
	hdr[2] = 0xBA
	hdr[3] = 0xBE
	// archCount = 31 (big-endian)
	hdr[7] = 31

	if IsFatMachOMagic(hdr) {
		t.Error("IsFatMachOMagic should reject archCount > 30 (Java class file protection)")
	}
}

// ---------------------------------------------------------------------------
// A-N10: File containing ONLY the fat magic (archCount bytes missing).
// IsFatMachOMagic checks len(b) >= 8 — a 4-byte slice must return false.
// ---------------------------------------------------------------------------

func TestAdversarial_FatMachOMissingArchCount(t *testing.T) {
	hdr := []byte{0xCA, 0xFE, 0xBA, 0xBE}
	if IsFatMachOMagic(hdr) {
		t.Error("IsFatMachOMagic should require 8 bytes")
	}
}

// ---------------------------------------------------------------------------
// A-N11: An empty binary — ScanConstants must return nil without panic.
// ---------------------------------------------------------------------------

func TestAdversarial_EmptyBinaryScanConstants(t *testing.T) {
	matches := ScanConstants(nil)
	if matches != nil {
		t.Errorf("expected nil for empty input, got %v", matches)
	}
	matches = ScanConstants([]byte{})
	if matches != nil {
		t.Errorf("expected nil for empty slice, got %v", matches)
	}
}

// ---------------------------------------------------------------------------
// A-N12: Single pattern that appears at both very start and end of a buffer.
// Dedup logic in deduplicateMatches must keep only one entry per algorithm.
// ---------------------------------------------------------------------------

func TestAdversarial_ScanConstantsDedupAcrossAlgorithms(t *testing.T) {
	// Build data = AES Sbox + filler + AES RCON (two AES patterns).
	data := append([]byte{}, cryptoConstants[0].pattern...) // AES S-box
	data = append(data, make([]byte, 32)...)                // filler
	data = append(data, cryptoConstants[2].pattern...)      // AES RCON

	matches := ScanConstants(data)
	aesCount := 0
	for _, m := range matches {
		if m.Algorithm == "AES" {
			aesCount++
		}
	}
	if aesCount != 1 {
		t.Errorf("expected dedup to collapse AES matches to 1, got %d", aesCount)
	}
}

// ---------------------------------------------------------------------------
// A-N13: DetectFormat on a file whose first byte is 0x7F but bytes 1-3 are
// NOT "ELF". Must not return "elf".
// ---------------------------------------------------------------------------

func TestAdversarial_DetectFormat_PartialELF(t *testing.T) {
	tests := map[string][]byte{
		"0x7F only":            {0x7F, 0x00, 0x00, 0x00},
		"0x7F+E no LF":         {0x7F, 'E', 0x00, 0x00},
		"0x7F+EL no F":         {0x7F, 'E', 'L', 0x00},
		"wrong case":           {0x7F, 'e', 'L', 'F'},
		"short 0x7F 1 byte":    {0x7F},
	}
	dir := t.TempDir()
	for name, data := range tests {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(dir, name)
			if err := os.WriteFile(p, data, 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			got := DetectFormat(p)
			if got == "elf" {
				t.Errorf("DetectFormat(%v) = elf, want !=elf", data)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// A-N14: Scan on a non-existent file — must return an error, not panic.
// ---------------------------------------------------------------------------

func TestAdversarial_ScanNonexistentFile(t *testing.T) {
	_, err := Scan(context.Background(), "/this/path/does/not/exist/nowhere.bin")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

// ---------------------------------------------------------------------------
// A-N15: ScanDynamicLibraries on a format the function does not recognise.
// Returns (nil, nil) — no crash.
// ---------------------------------------------------------------------------

func TestAdversarial_ScanDynLibsUnknownFormat(t *testing.T) {
	data := []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}
	path := writeTempFile(t, data)

	libs, err := ScanDynamicLibraries(path)
	if err != nil {
		t.Errorf("unexpected error on unknown format: %v", err)
	}
	if libs != nil {
		t.Errorf("expected nil libs, got %v", libs)
	}
}

// ---------------------------------------------------------------------------
// A-N16: matchLibrary with empty string — must not match anything.
// ---------------------------------------------------------------------------

func TestAdversarial_MatchLibraryEmpty(t *testing.T) {
	_, ok := matchLibrary("")
	if ok {
		t.Error("matchLibrary should not match empty string")
	}
}

// ---------------------------------------------------------------------------
// A-N17: lookupSymbol on only-underscores — normalisation strips them all;
// an empty key must not match.
// ---------------------------------------------------------------------------

func TestAdversarial_LookupOnlyUnderscores(t *testing.T) {
	_, ok := lookupSymbol("____")
	if ok {
		t.Error("lookupSymbol must not match an all-underscore name")
	}
	_, ok = lookupSymbol("")
	if ok {
		t.Error("lookupSymbol must not match the empty string")
	}
}
