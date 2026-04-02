package native

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"strings"
)

// SymbolMatch describes a crypto symbol found in a binary's symbol table.
type SymbolMatch struct {
	// Name is the normalised symbol name (lowercase, leading underscores stripped).
	Name string
	// Library is the source library family (e.g. "openssl", "bcrypt").
	Library string
	// Algorithm is the canonical algorithm name implied by this symbol.
	Algorithm string
	// Primitive is the primitive class (e.g. "symmetric", "hash").
	Primitive string
	// IsDynamic is true when the symbol appears in the dynamic symbol table
	// (.dynsym / import table), confirming runtime linkage.
	IsDynamic bool
}

// knownSymbol holds a mapping from a normalised symbol name to its
// semantic description.
type knownSymbol struct {
	library   string
	algorithm string
	primitive string
}

// symbolDB is the canonical database of recognisable crypto function names.
// Keys are lowercase with leading underscores removed.
var symbolDB = map[string]knownSymbol{
	// --- OpenSSL EVP high-level API ---
	"evp_encryptinit_ex":     {library: "openssl", algorithm: "AES", primitive: "symmetric"},
	"evp_digestinit_ex":      {library: "openssl", algorithm: "SHA-256", primitive: "hash"},
	"evp_pkey_ctx_new":       {library: "openssl", algorithm: "RSA", primitive: "pke"},
	"evp_aes_256_gcm":        {library: "openssl", algorithm: "AES-256-GCM", primitive: "symmetric"},
	"evp_sha256":             {library: "openssl", algorithm: "SHA-256", primitive: "hash"},
	"evp_md_ctx_new":         {library: "openssl", algorithm: "SHA-256", primitive: "hash"},
	"evp_cipher_ctx_new":     {library: "openssl", algorithm: "AES", primitive: "symmetric"},
	"evp_signinit":           {library: "openssl", algorithm: "RSA", primitive: "signature"},
	"evp_verifyinit":         {library: "openssl", algorithm: "RSA", primitive: "signature"},
	"evp_pkey_keygen":        {library: "openssl", algorithm: "RSA", primitive: "pke"},
	// --- OpenSSL low-level API ---
	"aes_encrypt":            {library: "openssl", algorithm: "AES", primitive: "symmetric"},
	"sha256_init":            {library: "openssl", algorithm: "SHA-256", primitive: "hash"},
	"rsa_public_encrypt":     {library: "openssl", algorithm: "RSA", primitive: "pke"},
	"ec_key_new":             {library: "openssl", algorithm: "EC", primitive: "key-exchange"},
	"dh_generate_parameters": {library: "openssl", algorithm: "DH", primitive: "key-exchange"},
	"des_ecb_encrypt":        {library: "openssl", algorithm: "DES", primitive: "symmetric"},
	"md5_init":               {library: "openssl", algorithm: "MD5", primitive: "hash"},
	"bn_ctx_new":             {library: "openssl", algorithm: "RSA", primitive: "pke"},
	// --- libgcrypt ---
	"gcry_cipher_open":  {library: "libgcrypt", algorithm: "AES", primitive: "symmetric"},
	"gcry_md_open":      {library: "libgcrypt", algorithm: "SHA-256", primitive: "hash"},
	"gcry_pk_encrypt":   {library: "libgcrypt", algorithm: "RSA", primitive: "pke"},
	"gcry_pk_sign":      {library: "libgcrypt", algorithm: "RSA", primitive: "signature"},
	// --- Nettle ---
	"nettle_aes256_encrypt": {library: "nettle", algorithm: "AES-256", primitive: "symmetric"},
	"nettle_sha256_digest":  {library: "nettle", algorithm: "SHA-256", primitive: "hash"},
	// --- BCrypt (Windows CNG) ---
	"bcryptencrypt":          {library: "bcrypt", algorithm: "AES", primitive: "symmetric"},
	"bcryptdecrypt":          {library: "bcrypt", algorithm: "AES", primitive: "symmetric"},
	"bcryptgeneratekeypair":  {library: "bcrypt", algorithm: "RSA", primitive: "pke"},
	"bcryptcreatehash":       {library: "bcrypt", algorithm: "SHA-256", primitive: "hash"},
	"bcryptsignhash":         {library: "bcrypt", algorithm: "RSA", primitive: "signature"},
	// --- CommonCrypto / Security.framework (Apple) ---
	"cccrypt":                      {library: "commoncrypto", algorithm: "AES", primitive: "symmetric"},
	"cchmac":                       {library: "commoncrypto", algorithm: "HMAC", primitive: "mac"},
	"cckeyderivationpbkdf":         {library: "commoncrypto", algorithm: "PBKDF2", primitive: "kdf"},
	"seckeycreatesignature":        {library: "security.framework", algorithm: "RSA", primitive: "signature"},
	"seckeycreatencrypteddata":     {library: "security.framework", algorithm: "RSA", primitive: "pke"},
	"seckeycreateencrypteddata":    {library: "security.framework", algorithm: "RSA", primitive: "pke"},
	// --- Additional OpenSSL EVP ---
	"evp_encryptupdate":            {library: "openssl", algorithm: "AES", primitive: "symmetric"},
	"evp_encryptfinal_ex":          {library: "openssl", algorithm: "AES", primitive: "symmetric"},
	"evp_decryptinit_ex":           {library: "openssl", algorithm: "AES", primitive: "symmetric"},
	"evp_decryptupdate":            {library: "openssl", algorithm: "AES", primitive: "symmetric"},
	"evp_decryptfinal_ex":          {library: "openssl", algorithm: "AES", primitive: "symmetric"},
	"evp_digestupdate":             {library: "openssl", algorithm: "SHA-256", primitive: "hash"},
	"evp_digestfinal_ex":           {library: "openssl", algorithm: "SHA-256", primitive: "hash"},
	// --- Additional OpenSSL low-level ---
	"sha1_init":                    {library: "openssl", algorithm: "SHA-1", primitive: "hash"},
	"sha512_init":                  {library: "openssl", algorithm: "SHA-512", primitive: "hash"},
	"rsa_private_decrypt":          {library: "openssl", algorithm: "RSA", primitive: "pke"},
	"ecdsa_sign":                   {library: "openssl", algorithm: "ECDSA", primitive: "signature"},
	"ecdsa_verify":                 {library: "openssl", algorithm: "ECDSA", primitive: "signature"},
	// --- libsodium ---
	"crypto_secretbox_easy":        {library: "libsodium", algorithm: "ChaCha20-Poly1305", primitive: "ae"},
	"crypto_sign_ed25519":          {library: "libsodium", algorithm: "Ed25519", primitive: "signature"},
	"crypto_box_curve25519xsalsa20poly1305": {library: "libsodium", algorithm: "Curve25519", primitive: "key-exchange"},
}

// normalizeSymbol converts a raw symbol name into the canonical lookup form:
// lowercase with leading underscores stripped.
func normalizeSymbol(name string) string {
	return strings.ToLower(strings.TrimLeft(name, "_"))
}

// lookupSymbol searches symbolDB for the normalised form of name.
// Returns the knownSymbol and true on a hit.
func lookupSymbol(name string) (knownSymbol, bool) {
	norm := normalizeSymbol(name)
	sym, ok := symbolDB[norm]
	return sym, ok
}

// ScanELFSymbols opens an ELF binary at path and searches both the static
// (.symtab) and dynamic (.dynsym) symbol tables for known crypto symbols.
func ScanELFSymbols(path string) ([]SymbolMatch, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var matches []SymbolMatch

	// .symtab — static symbols; not always present in stripped binaries.
	syms, err := f.Symbols()
	if err == nil {
		for _, s := range syms {
			if sym, ok := lookupSymbol(s.Name); ok {
				matches = append(matches, SymbolMatch{
					Name:      normalizeSymbol(s.Name),
					Library:   sym.library,
					Algorithm: sym.algorithm,
					Primitive: sym.primitive,
					IsDynamic: false,
				})
			}
		}
	}

	// .dynsym — dynamic symbols; present in almost all linked binaries.
	dynSyms, err := f.DynamicSymbols()
	if err == nil {
		for _, s := range dynSyms {
			if sym, ok := lookupSymbol(s.Name); ok {
				matches = append(matches, SymbolMatch{
					Name:      normalizeSymbol(s.Name),
					Library:   sym.library,
					Algorithm: sym.algorithm,
					Primitive: sym.primitive,
					IsDynamic: true,
				})
			}
		}
	}

	return matches, nil
}

// ScanPESymbols opens a PE (Windows) binary at path and searches the import
// directory for known crypto function names.
func ScanPESymbols(path string) ([]SymbolMatch, error) {
	f, err := pe.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	imports, err := f.ImportedSymbols()
	if err != nil {
		// Non-fatal: binary may have no imports (static linkage).
		return nil, nil //nolint:nilerr
	}

	var matches []SymbolMatch
	for _, imp := range imports {
		// pe.ImportedSymbols returns "FunctionName:DLL.dll" format.
		funcName := imp
		if idx := strings.Index(imp, ":"); idx >= 0 {
			funcName = imp[:idx]
		}
		if sym, ok := lookupSymbol(funcName); ok {
			matches = append(matches, SymbolMatch{
				Name:      normalizeSymbol(funcName),
				Library:   sym.library,
				Algorithm: sym.algorithm,
				Primitive: sym.primitive,
				IsDynamic: true, // PE imports are always dynamic
			})
		}
	}

	return matches, nil
}

// ScanMachOSymbols opens a Mach-O binary at path and searches the symbol
// table for known crypto function names.
func ScanMachOSymbols(path string) ([]SymbolMatch, error) {
	f, err := macho.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return scanMachOFile(f), nil
}

// scanMachOFile searches the symbol table of an already-opened *macho.File for
// known crypto function names. This helper is shared by ScanMachOSymbols (for
// single-arch files) and ScanFatMachO (for fat binary architecture slices).
func scanMachOFile(f *macho.File) []SymbolMatch {
	if f.Symtab == nil {
		return nil
	}

	var matches []SymbolMatch
	for _, s := range f.Symtab.Syms {
		if sym, ok := lookupSymbol(s.Name); ok {
			matches = append(matches, SymbolMatch{
				Name:      normalizeSymbol(s.Name),
				Library:   sym.library,
				Algorithm: sym.algorithm,
				Primitive: sym.primitive,
				IsDynamic: false,
			})
		}
	}

	return matches
}
