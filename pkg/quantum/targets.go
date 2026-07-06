package quantum

import "strings"

// MigrationTarget defines the PQC replacement for a classical algorithm.
type MigrationTarget struct {
	Algorithm string // e.g. "ML-DSA-65", "ML-KEM-768", "AES-256"
	Standard  string // e.g. "FIPS 204", "FIPS 203", ""
}

// migrationTargets maps classical algorithm families to their PQC replacements.
// Keyed by uppercase base name. Entries with empty Standard are not PQC but
// are quantum-resistant upgrades (e.g. AES-128 → AES-256).
var migrationTargets = map[string]MigrationTarget{
	// Asymmetric signing → ML-DSA (FIPS 204)
	"RSA":          {Algorithm: "ML-DSA-65", Standard: "FIPS 204"},
	"RSASSA-PKCS1": {Algorithm: "ML-DSA-65", Standard: "FIPS 204"},
	"RSASSA-PSS":   {Algorithm: "ML-DSA-65", Standard: "FIPS 204"},
	"DSA":          {Algorithm: "ML-DSA-65", Standard: "FIPS 204"},
	"ECDSA":        {Algorithm: "ML-DSA-65", Standard: "FIPS 204"}, // ML-DSA-65 floor, not -44 (review A1)
	"EDDSA":        {Algorithm: "ML-DSA-65", Standard: "FIPS 204"},
	"ED25519":      {Algorithm: "ML-DSA-65", Standard: "FIPS 204"}, // ML-DSA-65 floor, not -44 (review A1)
	"ED448":        {Algorithm: "ML-DSA-87", Standard: "FIPS 204"},
	"KCDSA":        {Algorithm: "ML-DSA-65", Standard: "FIPS 204"},
	"EC-KCDSA":     {Algorithm: "ML-DSA-65", Standard: "FIPS 204"},

	// Asymmetric encryption/key exchange → ML-KEM (FIPS 203)
	"RSAES-PKCS1":    {Algorithm: "ML-KEM-768", Standard: "FIPS 203"},
	"RSAES-OAEP":     {Algorithm: "ML-KEM-768", Standard: "FIPS 203"},
	"ECDH":           {Algorithm: "ML-KEM-768", Standard: "FIPS 203"},
	"ECDHE":          {Algorithm: "ML-KEM-768", Standard: "FIPS 203"},
	"X25519":         {Algorithm: "ML-KEM-768", Standard: "FIPS 203"},
	"X448":           {Algorithm: "ML-KEM-1024", Standard: "FIPS 203"},
	"DH":             {Algorithm: "ML-KEM-768", Standard: "FIPS 203"},
	"FFDH":           {Algorithm: "ML-KEM-768", Standard: "FIPS 203"},
	"DIFFIE-HELLMAN": {Algorithm: "ML-KEM-768", Standard: "FIPS 203"},
	"ELGAMAL":        {Algorithm: "ML-KEM-768", Standard: "FIPS 203"},
	"ECIES":          {Algorithm: "ML-KEM-768", Standard: "FIPS 203"},
	"MQV":            {Algorithm: "ML-KEM-768", Standard: "FIPS 203"},
	"ECMQV":          {Algorithm: "ML-KEM-768", Standard: "FIPS 203"},

	// Deprecated → direct replacements (not PQC, but modern)
	"MD5":        {Algorithm: "SHA-256", Standard: ""},
	"MD4":        {Algorithm: "SHA-256", Standard: ""},
	"MD2":        {Algorithm: "SHA-256", Standard: ""},
	"SHA-1":      {Algorithm: "SHA-256", Standard: ""},
	"SHA1":       {Algorithm: "SHA-256", Standard: ""},
	"DES":        {Algorithm: "AES-256-GCM", Standard: ""},
	"3DES":       {Algorithm: "AES-256-GCM", Standard: ""},
	"DES-EDE3":   {Algorithm: "AES-256-GCM", Standard: ""},
	"TRIPLE-DES": {Algorithm: "AES-256-GCM", Standard: ""},
	"TDEA":       {Algorithm: "AES-256-GCM", Standard: ""},
	"RC2":        {Algorithm: "AES-256-GCM", Standard: ""},
	"RC4":        {Algorithm: "AES-256-GCM", Standard: ""},
	"RC5":        {Algorithm: "AES-256-GCM", Standard: ""},
	"BLOWFISH":   {Algorithm: "AES-256-GCM", Standard: ""},
	"HAS-160":    {Algorithm: "SHA-256", Standard: ""},

	// Pre-standard PQC → current NIST names
	"DILITHIUM": {Algorithm: "ML-DSA-65", Standard: "FIPS 204"},
	"KYBER":     {Algorithm: "ML-KEM-768", Standard: "FIPS 203"},
	"SPHINCS+":  {Algorithm: "SLH-DSA-SHA2-128f", Standard: "FIPS 205"},
	"SPHINCS":   {Algorithm: "SLH-DSA-SHA2-128f", Standard: "FIPS 205"},
	// No "FALCON" entry: Falcon's replacement standard (FIPS 206/FN-DSA) is
	// still pending finalization — unlike Kyber/Dilithium/SPHINCS+ above,
	// whose FIPS standards are already final — so Falcon is RiskSafe (HQC
	// pattern, no migration target needed) rather than RiskDeprecated. See
	// the Falcon branch in classify.go's ClassifyAlgorithm.

	// Chinese/Russian national standards (review finding B2).
	// SM2 is dual-purpose (signature + key exchange), same as RSA above; the
	// key-agree/kem/pke override in classifyVulnerable redirects this FIPS 204
	// default to ML-KEM-768/FIPS 203 when used for key exchange.
	"SM2":          {Algorithm: "ML-DSA-65", Standard: "FIPS 204"},
	"GOST":         {Algorithm: "ML-DSA-65", Standard: "FIPS 204"},
	"GOST R 34.10": {Algorithm: "ML-DSA-65", Standard: "FIPS 204"},
}

// LookupTarget returns the PQC migration target for a given algorithm base name.
// Returns empty MigrationTarget if no mapping exists.
func LookupTarget(baseName string) MigrationTarget {
	if t, ok := migrationTargets[strings.ToUpper(baseName)]; ok {
		return t
	}
	return MigrationTarget{}
}

// LookupTargetForKeySize returns a size-appropriate target for algorithms
// where the replacement depends on the classical security level.
func LookupTargetForKeySize(baseName string, keySize int) MigrationTarget {
	upper := strings.ToUpper(baseName)

	// RSA: key size determines ML-DSA level. ML-DSA-65 is the floor — RSA
	// below the 3072-bit tier used to fall through to ML-DSA-44, which
	// contradicted classify.go's recommendation text (review finding A1).
	switch upper {
	case "RSA", "RSASSA-PKCS1", "RSASSA-PSS":
		if keySize >= 4096 {
			return MigrationTarget{Algorithm: "ML-DSA-87", Standard: "FIPS 204"}
		}
		return MigrationTarget{Algorithm: "ML-DSA-65", Standard: "FIPS 204"}
	}

	// ECDSA/ECDH: curve size determines level. ML-DSA-65 is the floor (same
	// A1 fix as RSA above); a dedicated tier steps up to ML-DSA-87 for
	// P-521-class curves (>= 521 bits), which previously shared the P-384
	// tier's ML-DSA-65/ML-KEM-1024 target despite being NIST security level 5.
	switch upper {
	case "ECDSA":
		if keySize >= 521 {
			return MigrationTarget{Algorithm: "ML-DSA-87", Standard: "FIPS 204"}
		}
		return MigrationTarget{Algorithm: "ML-DSA-65", Standard: "FIPS 204"}
	case "ECDH", "ECDHE":
		if keySize >= 384 {
			return MigrationTarget{Algorithm: "ML-KEM-1024", Standard: "FIPS 203"}
		}
		return MigrationTarget{Algorithm: "ML-KEM-768", Standard: "FIPS 203"}
	}

	// Symmetric: AES-128 → AES-256
	if upper == "AES" && keySize > 0 && keySize < 256 {
		return MigrationTarget{Algorithm: "AES-256", Standard: ""}
	}

	return LookupTarget(baseName)
}
