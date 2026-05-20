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

	// --- liboqs (the canonical PQC reference implementation) ---
	// Generic API — algorithm is chosen at runtime via OQS_KEM_new(method_name).
	// Presence of these symbols proves PQC capability but not which algorithm is used;
	// the per-algorithm symbols below pin specific FIPS-203/204/205 / Falcon / HQC variants.
	"oqs_kem_new":              {library: "liboqs", algorithm: "ML-KEM", primitive: "kem"},
	"oqs_kem_keypair":          {library: "liboqs", algorithm: "ML-KEM", primitive: "kem"},
	"oqs_kem_encaps":           {library: "liboqs", algorithm: "ML-KEM", primitive: "kem"},
	"oqs_kem_decaps":           {library: "liboqs", algorithm: "ML-KEM", primitive: "kem"},
	"oqs_sig_new":              {library: "liboqs", algorithm: "ML-DSA", primitive: "signature"},
	"oqs_sig_keypair":          {library: "liboqs", algorithm: "ML-DSA", primitive: "signature"},
	"oqs_sig_sign":             {library: "liboqs", algorithm: "ML-DSA", primitive: "signature"},
	"oqs_sig_verify":           {library: "liboqs", algorithm: "ML-DSA", primitive: "signature"},
	// liboqs per-algorithm constructors (FIPS 203 ML-KEM)
	"oqs_kem_ml_kem_512_new":   {library: "liboqs", algorithm: "ML-KEM-512", primitive: "kem"},
	"oqs_kem_ml_kem_768_new":   {library: "liboqs", algorithm: "ML-KEM-768", primitive: "kem"},
	"oqs_kem_ml_kem_1024_new":  {library: "liboqs", algorithm: "ML-KEM-1024", primitive: "kem"},
	// FIPS 204 ML-DSA
	"oqs_sig_ml_dsa_44_new":    {library: "liboqs", algorithm: "ML-DSA-44", primitive: "signature"},
	"oqs_sig_ml_dsa_65_new":    {library: "liboqs", algorithm: "ML-DSA-65", primitive: "signature"},
	"oqs_sig_ml_dsa_87_new":    {library: "liboqs", algorithm: "ML-DSA-87", primitive: "signature"},
	// FIPS 205 SLH-DSA (subset; SHA2 fast / small + SHAKE)
	"oqs_sig_slh_dsa_sha2_128s_new":  {library: "liboqs", algorithm: "SLH-DSA-SHA2-128s", primitive: "signature"},
	"oqs_sig_slh_dsa_sha2_128f_new":  {library: "liboqs", algorithm: "SLH-DSA-SHA2-128f", primitive: "signature"},
	"oqs_sig_slh_dsa_sha2_192s_new":  {library: "liboqs", algorithm: "SLH-DSA-SHA2-192s", primitive: "signature"},
	"oqs_sig_slh_dsa_sha2_192f_new":  {library: "liboqs", algorithm: "SLH-DSA-SHA2-192f", primitive: "signature"},
	"oqs_sig_slh_dsa_sha2_256s_new":  {library: "liboqs", algorithm: "SLH-DSA-SHA2-256s", primitive: "signature"},
	"oqs_sig_slh_dsa_sha2_256f_new":  {library: "liboqs", algorithm: "SLH-DSA-SHA2-256f", primitive: "signature"},
	"oqs_sig_slh_dsa_shake_128s_new": {library: "liboqs", algorithm: "SLH-DSA-SHAKE-128s", primitive: "signature"},
	"oqs_sig_slh_dsa_shake_128f_new": {library: "liboqs", algorithm: "SLH-DSA-SHAKE-128f", primitive: "signature"},
	// FIPS 206 (draft) Falcon / FN-DSA
	"oqs_sig_falcon_512_new":   {library: "liboqs", algorithm: "Falcon-512", primitive: "signature"},
	"oqs_sig_falcon_1024_new":  {library: "liboqs", algorithm: "Falcon-1024", primitive: "signature"},
	// 5th NIST PQC standard — HQC (selected March 2025)
	"oqs_kem_hqc_128_new":      {library: "liboqs", algorithm: "HQC-128", primitive: "kem"},
	"oqs_kem_hqc_192_new":      {library: "liboqs", algorithm: "HQC-192", primitive: "kem"},
	"oqs_kem_hqc_256_new":      {library: "liboqs", algorithm: "HQC-256", primitive: "kem"},
	// Pre-FIPS-203 Kyber draft names (still appear in older OQS-OpenSSL provider builds)
	"oqs_kem_kyber_512_new":    {library: "liboqs", algorithm: "Kyber-512", primitive: "kem"},
	"oqs_kem_kyber_768_new":    {library: "liboqs", algorithm: "Kyber-768", primitive: "kem"},
	"oqs_kem_kyber_1024_new":   {library: "liboqs", algorithm: "Kyber-1024", primitive: "kem"},

	// --- OQS-OpenSSL / oqs-provider (OpenSSL 3+ PQC provider) ---
	// Provider-style entry points; presence proves PQC provider loaded.
	"oqs_provider_init":        {library: "oqs-provider", algorithm: "ML-KEM", primitive: "kem"},

	// --- OpenSSL 3.5+ native PQC (built-in, no provider needed) ---
	// EVP_PKEY_* generic functions appear on every OpenSSL binary; specific PQC
	// algorithm names ("ML-KEM-768", "ML-DSA-65", "SLH-DSA-SHA2-128s") are passed
	// as runtime strings to EVP_PKEY_CTX_new_from_name, so they are picked up by
	// the constant/string scanner (native/constants.go) rather than the symbol DB.
	// We still pin the OpenSSL-3.5 high-level KEM and SIGNATURE entry points so
	// any OQS binding shows up as PQC-capable.
	"evp_pkey_encapsulate_init": {library: "openssl", algorithm: "ML-KEM", primitive: "kem"},
	"evp_pkey_decapsulate_init": {library: "openssl", algorithm: "ML-KEM", primitive: "kem"},
	"evp_pkey_encapsulate":      {library: "openssl", algorithm: "ML-KEM", primitive: "kem"},
	"evp_pkey_decapsulate":      {library: "openssl", algorithm: "ML-KEM", primitive: "kem"},
	"evp_signature_fetch":       {library: "openssl", algorithm: "ML-DSA", primitive: "signature"},
	"evp_kem_fetch":             {library: "openssl", algorithm: "ML-KEM", primitive: "kem"},

	// --- AWS-LC PQC (BoringSSL fork shipping ML-KEM + ML-DSA since 2025) ---
	"aws_lc_mlkem_keygen":      {library: "aws-lc", algorithm: "ML-KEM", primitive: "kem"},
	"aws_lc_mlkem_encaps":      {library: "aws-lc", algorithm: "ML-KEM", primitive: "kem"},
	"aws_lc_mlkem_decaps":      {library: "aws-lc", algorithm: "ML-KEM", primitive: "kem"},
	"aws_lc_mldsa_keygen":      {library: "aws-lc", algorithm: "ML-DSA", primitive: "signature"},
	"aws_lc_mldsa_sign":        {library: "aws-lc", algorithm: "ML-DSA", primitive: "signature"},
	"aws_lc_mldsa_verify":      {library: "aws-lc", algorithm: "ML-DSA", primitive: "signature"},

	// --- BoringSSL ML-KEM (Google, used in Chrome's X25519MLKEM768 deployment) ---
	"ml_kem_768_keypair":       {library: "boringssl", algorithm: "ML-KEM-768", primitive: "kem"},
	"ml_kem_768_encap":         {library: "boringssl", algorithm: "ML-KEM-768", primitive: "kem"},
	"ml_kem_768_decap":         {library: "boringssl", algorithm: "ML-KEM-768", primitive: "kem"},
	"ml_kem_1024_keypair":      {library: "boringssl", algorithm: "ML-KEM-1024", primitive: "kem"},
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
