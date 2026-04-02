package native

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"strings"
)

// DynLibMatch describes a crypto-related dynamic library dependency found in
// a binary.
type DynLibMatch struct {
	// Library is the raw library name as found in the binary (e.g. "libssl.so.3").
	Library string
	// Algorithm is the representative algorithm associated with this library.
	Algorithm string
	// Primitive is the primitive class (e.g. "symmetric", "hash").
	Primitive string
}

// cryptoLib describes a known cryptographic shared library.
type cryptoLib struct {
	// prefix is the canonical prefix to match against the lowercased library name.
	prefix    string
	algorithm string
	primitive string
}

// knownCryptoLibs is the catalogue of recognisable crypto libraries.
// Matching is done by checking whether the lowercased library name contains
// the prefix field as a substring, allowing version suffixes like ".so.3" or
// ".1.1".
var knownCryptoLibs = []cryptoLib{
	// Linux / Unix shared objects
	{prefix: "libssl", algorithm: "TLS", primitive: "protocol"},
	{prefix: "libcrypto", algorithm: "AES", primitive: "symmetric"},
	{prefix: "libgcrypt", algorithm: "AES", primitive: "symmetric"},
	{prefix: "libgnutls", algorithm: "TLS", primitive: "protocol"},
	{prefix: "libmbedcrypto", algorithm: "AES", primitive: "symmetric"},
	{prefix: "libboringssl", algorithm: "AES", primitive: "symmetric"},
	{prefix: "libnss3", algorithm: "RSA", primitive: "pke"},
	{prefix: "libnspr4", algorithm: "RSA", primitive: "pke"},
	{prefix: "libk5crypto", algorithm: "AES", primitive: "symmetric"},
	{prefix: "libsodium", algorithm: "ChaCha20", primitive: "symmetric"},
	// Windows DLLs / kernel modules
	{prefix: "bcrypt.dll", algorithm: "AES", primitive: "symmetric"},
	{prefix: "ncrypt.dll", algorithm: "RSA", primitive: "pke"},
	{prefix: "cng.sys", algorithm: "AES", primitive: "symmetric"},
	{prefix: "advapi32.dll", algorithm: "AES", primitive: "symmetric"},
	// macOS frameworks
	{prefix: "security.framework", algorithm: "AES", primitive: "symmetric"},
	{prefix: "commoncrypto", algorithm: "AES", primitive: "symmetric"},
	// Additional common crypto libraries
	{prefix: "libssl3", algorithm: "TLS", primitive: "protocol"},
	{prefix: "libcrypto3", algorithm: "AES", primitive: "symmetric"},
	{prefix: "openssl", algorithm: "AES", primitive: "symmetric"},
}

// matchLibrary checks whether libName (already lowercased) is a known crypto
// library. Returns the matched cryptoLib and true on a hit.
func matchLibrary(libNameLower string) (cryptoLib, bool) {
	for _, cl := range knownCryptoLibs {
		if strings.Contains(libNameLower, cl.prefix) {
			return cl, true
		}
	}
	return cryptoLib{}, false
}

// ScanDynamicLibraries detects the binary format at path, then reads its
// dynamic library dependency list and matches against knownCryptoLibs.
func ScanDynamicLibraries(path string) ([]DynLibMatch, error) {
	format := DetectFormat(path)
	switch format {
	case "elf":
		return scanELFDynLibs(path)
	case "pe":
		return scanPEDynLibs(path)
	case "macho":
		return scanMachODynLibs(path)
	default:
		return nil, nil
	}
}

// scanELFDynLibs extracts DT_NEEDED entries from the ELF dynamic section.
func scanELFDynLibs(path string) ([]DynLibMatch, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	libs, err := f.ImportedLibraries()
	if err != nil {
		return nil, nil //nolint:nilerr
	}

	return matchLibraryList(libs), nil
}

// scanPEDynLibs extracts the imported DLL names from a PE binary.
func scanPEDynLibs(path string) ([]DynLibMatch, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	libs, err := f.ImportedLibraries()
	if err != nil {
		return nil, nil //nolint:nilerr
	}

	return matchLibraryList(libs), nil
}

// scanMachODynLibs reads LC_LOAD_DYLIB commands from a Mach-O binary.
func scanMachODynLibs(path string) ([]DynLibMatch, error) {
	f, err := macho.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return matchLibraryList(collectMachODylibs(f)), nil
}

// scanMachOFileDynLibs extracts LC_LOAD_DYLIB crypto libraries from an
// already-opened *macho.File. This helper is shared by scanMachODynLibs
// (single-arch) and ScanFatMachO (fat binary architecture slices).
func scanMachOFileDynLibs(f *macho.File) []DynLibMatch {
	return matchLibraryList(collectMachODylibs(f))
}

// collectMachODylibs returns the raw dylib names from LC_LOAD_DYLIB load
// commands in f.
func collectMachODylibs(f *macho.File) []string {
	var libs []string
	for _, load := range f.Loads {
		if dylib, ok := load.(*macho.Dylib); ok {
			libs = append(libs, dylib.Name)
		}
	}
	return libs
}

// matchLibraryList converts a slice of raw library names into DynLibMatch
// entries for those recognised as cryptographic.
func matchLibraryList(libs []string) []DynLibMatch {
	var matches []DynLibMatch
	for _, lib := range libs {
		lower := strings.ToLower(lib)
		if cl, ok := matchLibrary(lower); ok {
			matches = append(matches, DynLibMatch{
				Library:   lib,
				Algorithm: cl.algorithm,
				Primitive: cl.primitive,
			})
		}
	}
	return matches
}
