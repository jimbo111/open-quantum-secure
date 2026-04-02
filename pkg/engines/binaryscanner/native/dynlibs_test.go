package native

import (
	"testing"
)

// ---------------------------------------------------------------------------
// matchLibrary unit tests
// ---------------------------------------------------------------------------

func TestMatchLibrary_KnownCryptoLibraries(t *testing.T) {
	tests := []struct {
		input     string // library name as it appears in binary
		wantMatch bool
		wantAlg   string
	}{
		// Linux versioned shared objects
		{input: "libssl.so.3", wantMatch: true, wantAlg: "TLS"},
		{input: "libssl.so.1.1", wantMatch: true, wantAlg: "TLS"},
		{input: "libcrypto.so.3", wantMatch: true, wantAlg: "AES"},
		{input: "libcrypto.so.1.1", wantMatch: true, wantAlg: "AES"},
		{input: "libgcrypt.so.20", wantMatch: true, wantAlg: "AES"},
		{input: "libgnutls.so.30", wantMatch: true, wantAlg: "TLS"},
		{input: "libmbedcrypto.so.7", wantMatch: true, wantAlg: "AES"},
		{input: "libnss3.so", wantMatch: true, wantAlg: "RSA"},
		{input: "libnspr4.so", wantMatch: true, wantAlg: "RSA"},
		{input: "libk5crypto.so.3", wantMatch: true, wantAlg: "AES"},
		{input: "libsodium.so.23", wantMatch: true, wantAlg: "ChaCha20"},
		// Windows DLLs
		{input: "bcrypt.dll", wantMatch: true, wantAlg: "AES"},
		{input: "BCRYPT.DLL", wantMatch: true, wantAlg: "AES"}, // case-insensitive
		{input: "ncrypt.dll", wantMatch: true, wantAlg: "RSA"},
		{input: "advapi32.dll", wantMatch: true, wantAlg: "AES"},
		// macOS
		{input: "/System/Library/Frameworks/Security.framework/Security", wantMatch: true, wantAlg: "AES"},
		// BoringSSL (embedded, referenced by soname in some builds)
		{input: "libboringssl.so", wantMatch: true, wantAlg: "AES"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			lower := tc.input
			// Normalise to lowercase for matchLibrary (same as production code).
			import_lower := make([]byte, len(lower))
			for i := 0; i < len(lower); i++ {
				c := lower[i]
				if c >= 'A' && c <= 'Z' {
					c += 32
				}
				import_lower[i] = c
			}
			cl, ok := matchLibrary(string(import_lower))
			if ok != tc.wantMatch {
				t.Errorf("matchLibrary(%q) match=%v, want %v", tc.input, ok, tc.wantMatch)
				return
			}
			if ok && cl.algorithm != tc.wantAlg {
				t.Errorf("matchLibrary(%q) algorithm=%q, want %q", tc.input, cl.algorithm, tc.wantAlg)
			}
		})
	}
}

func TestMatchLibrary_NonCryptoLibraries(t *testing.T) {
	nonCrypto := []string{
		"libc.so.6",
		"libpthread.so.0",
		"libm.so.6",
		"libz.so.1",
		"libstdc++.so.6",
		"libdl.so.2",
		"librt.so.1",
		"kernel32.dll",
		"user32.dll",
		"gdi32.dll",
		"ntdll.dll",
		"libxml2.so.2",
		"libpng16.so.16",
	}

	for _, lib := range nonCrypto {
		t.Run(lib, func(t *testing.T) {
			_, ok := matchLibrary(lib)
			if ok {
				t.Errorf("non-crypto library %q should not match", lib)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// matchLibraryList
// ---------------------------------------------------------------------------

func TestMatchLibraryList_MixedInput(t *testing.T) {
	libs := []string{
		"libssl.so.3",    // crypto
		"libc.so.6",      // not crypto
		"libcrypto.so.3", // crypto
		"libpthread.so.0", // not crypto
	}

	matches := matchLibraryList(libs)
	if len(matches) != 2 {
		t.Errorf("expected 2 matches, got %d: %v", len(matches), matches)
	}

	algSet := make(map[string]bool)
	for _, m := range matches {
		algSet[m.Algorithm] = true
	}
	if !algSet["TLS"] {
		t.Error("expected TLS match from libssl.so.3")
	}
	if !algSet["AES"] {
		t.Error("expected AES match from libcrypto.so.3")
	}
}

func TestMatchLibraryList_Empty(t *testing.T) {
	matches := matchLibraryList(nil)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for nil input, got %d", len(matches))
	}

	matches = matchLibraryList([]string{})
	if len(matches) != 0 {
		t.Errorf("expected 0 matches for empty input, got %d", len(matches))
	}
}

func TestMatchLibraryList_PreservesRawName(t *testing.T) {
	libs := []string{"libssl.so.3"}
	matches := matchLibraryList(libs)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Library != "libssl.so.3" {
		t.Errorf("raw library name = %q, want %q", matches[0].Library, "libssl.so.3")
	}
}

// ---------------------------------------------------------------------------
// knownCryptoLibs catalogue completeness
// ---------------------------------------------------------------------------

func TestKnownCryptoLibs_HasMinimumEntries(t *testing.T) {
	if len(knownCryptoLibs) < 10 {
		t.Errorf("knownCryptoLibs has %d entries, want at least 10", len(knownCryptoLibs))
	}
}
