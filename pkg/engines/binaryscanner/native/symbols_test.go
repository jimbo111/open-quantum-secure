package native

import (
	"testing"
)

// ---------------------------------------------------------------------------
// normalizeSymbol
// ---------------------------------------------------------------------------

func TestNormalizeSymbol(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "EVP_EncryptInit_ex", want: "evp_encryptinit_ex"},
		{input: "_EVP_EncryptInit_ex", want: "evp_encryptinit_ex"},
		{input: "__AES_encrypt", want: "aes_encrypt"},
		{input: "BCryptEncrypt", want: "bcryptencrypt"},
		{input: "_BCryptEncrypt", want: "bcryptencrypt"},
		{input: "CCCrypt", want: "cccrypt"},
		{input: "gcry_cipher_open", want: "gcry_cipher_open"},
		{input: "nettle_sha256_digest", want: "nettle_sha256_digest"},
		{input: "SHA256_Init", want: "sha256_init"},
		{input: "unknown_function_xyz", want: "unknown_function_xyz"},
		{input: "", want: ""},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := normalizeSymbol(tc.input)
			if got != tc.want {
				t.Errorf("normalizeSymbol(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// lookupSymbol — known symbols accepted
// ---------------------------------------------------------------------------

func TestLookupSymbol_KnownOpenSSLSymbol(t *testing.T) {
	sym, ok := lookupSymbol("EVP_EncryptInit_ex")
	if !ok {
		t.Fatal("expected EVP_EncryptInit_ex to be found in symbolDB")
	}
	if sym.library != "openssl" {
		t.Errorf("library = %q, want %q", sym.library, "openssl")
	}
	if sym.algorithm != "AES" {
		t.Errorf("algorithm = %q, want %q", sym.algorithm, "AES")
	}
}

func TestLookupSymbol_LeadingUnderscoreStripped(t *testing.T) {
	// Symbols with a leading underscore (common on macOS/COFF) must still match.
	sym, ok := lookupSymbol("_EVP_EncryptInit_ex")
	if !ok {
		t.Fatal("expected _EVP_EncryptInit_ex to match after normalisation")
	}
	if sym.library != "openssl" {
		t.Errorf("library = %q, want %q", sym.library, "openssl")
	}
}

func TestLookupSymbol_UnknownSymbolRejected(t *testing.T) {
	_, ok := lookupSymbol("printf")
	if ok {
		t.Error("printf should not be in symbolDB")
	}
	_, ok = lookupSymbol("malloc")
	if ok {
		t.Error("malloc should not be in symbolDB")
	}
	_, ok = lookupSymbol("completely_random_symbol_xyz")
	if ok {
		t.Error("random symbol should not be in symbolDB")
	}
}

// ---------------------------------------------------------------------------
// Library family coverage
// ---------------------------------------------------------------------------

func TestLookupSymbol_OpenSSLEVPFamily(t *testing.T) {
	evpSymbols := []string{
		"EVP_EncryptInit_ex",
		"EVP_DigestInit_ex",
		"EVP_PKEY_CTX_new",
		"EVP_aes_256_gcm",
		"EVP_sha256",
		"EVP_MD_CTX_new",
		"EVP_CIPHER_CTX_new",
		"EVP_SignInit",
		"EVP_VerifyInit",
		"EVP_PKEY_keygen",
	}
	for _, name := range evpSymbols {
		t.Run(name, func(t *testing.T) {
			sym, ok := lookupSymbol(name)
			if !ok {
				t.Errorf("%q not found in symbolDB", name)
				return
			}
			if sym.library != "openssl" {
				t.Errorf("%q: library = %q, want openssl", name, sym.library)
			}
		})
	}
}

func TestLookupSymbol_OpenSSLLowLevelFamily(t *testing.T) {
	lowLevel := []string{
		"AES_encrypt",
		"SHA256_Init",
		"RSA_public_encrypt",
		"EC_KEY_new",
		"DH_generate_parameters",
		"DES_ecb_encrypt",
		"MD5_Init",
		"BN_CTX_new",
	}
	for _, name := range lowLevel {
		t.Run(name, func(t *testing.T) {
			_, ok := lookupSymbol(name)
			if !ok {
				t.Errorf("low-level symbol %q not found in symbolDB", name)
			}
		})
	}
}

func TestLookupSymbol_LibgcryptFamily(t *testing.T) {
	gcryptSymbols := []string{
		"gcry_cipher_open",
		"gcry_md_open",
		"gcry_pk_encrypt",
		"gcry_pk_sign",
	}
	for _, name := range gcryptSymbols {
		t.Run(name, func(t *testing.T) {
			sym, ok := lookupSymbol(name)
			if !ok {
				t.Errorf("libgcrypt symbol %q not found", name)
				return
			}
			if sym.library != "libgcrypt" {
				t.Errorf("%q: library = %q, want libgcrypt", name, sym.library)
			}
		})
	}
}

func TestLookupSymbol_NettleFamily(t *testing.T) {
	nettleSymbols := []string{
		"nettle_aes256_encrypt",
		"nettle_sha256_digest",
	}
	for _, name := range nettleSymbols {
		t.Run(name, func(t *testing.T) {
			sym, ok := lookupSymbol(name)
			if !ok {
				t.Errorf("nettle symbol %q not found", name)
				return
			}
			if sym.library != "nettle" {
				t.Errorf("%q: library = %q, want nettle", name, sym.library)
			}
		})
	}
}

func TestLookupSymbol_BCryptFamily(t *testing.T) {
	bcryptSymbols := []string{
		"BCryptEncrypt",
		"BCryptDecrypt",
		"BCryptGenerateKeyPair",
		"BCryptCreateHash",
		"BCryptSignHash",
	}
	for _, name := range bcryptSymbols {
		t.Run(name, func(t *testing.T) {
			sym, ok := lookupSymbol(name)
			if !ok {
				t.Errorf("BCrypt symbol %q not found", name)
				return
			}
			if sym.library != "bcrypt" {
				t.Errorf("%q: library = %q, want bcrypt", name, sym.library)
			}
		})
	}
}

func TestLookupSymbol_CommonCryptoFamily(t *testing.T) {
	ccSymbols := []string{
		"CCCrypt",
		"CCHmac",
		"CCKeyDerivationPBKDF",
	}
	for _, name := range ccSymbols {
		t.Run(name, func(t *testing.T) {
			sym, ok := lookupSymbol(name)
			if !ok {
				t.Errorf("CommonCrypto symbol %q not found", name)
				return
			}
			if sym.library != "commoncrypto" {
				t.Errorf("%q: library = %q, want commoncrypto", name, sym.library)
			}
		})
	}
}

func TestLookupSymbol_SecurityFrameworkFamily(t *testing.T) {
	secSymbols := []string{
		"SecKeyCreateSignature",
		"SecKeyCreateEncryptedData",
	}
	for _, name := range secSymbols {
		t.Run(name, func(t *testing.T) {
			sym, ok := lookupSymbol(name)
			if !ok {
				t.Errorf("Security.framework symbol %q not found", name)
				return
			}
			if sym.library != "security.framework" {
				t.Errorf("%q: library = %q, want security.framework", name, sym.library)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// symbolDB completeness
// ---------------------------------------------------------------------------

func TestSymbolDB_HasMinimumEntries(t *testing.T) {
	if len(symbolDB) < 40 {
		t.Errorf("symbolDB has %d entries, want at least 40", len(symbolDB))
	}
}
