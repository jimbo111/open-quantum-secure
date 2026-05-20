package constraints

import (
	"sort"
	"strings"
)

// AlgorithmSizeProfile holds byte sizes for a cryptographic algorithm's key artifacts.
// Fields are zero when not applicable (e.g. KEM has no SignatureBytes).
type AlgorithmSizeProfile struct {
	PublicKeyBytes    int
	PrivateKeyBytes   int
	SignatureBytes    int
	CiphertextBytes   int
	SharedSecretBytes int
}

// algorithmSizes is the static lookup table with FIPS 203/204/205 and classical algorithms.
var algorithmSizes = map[string]AlgorithmSizeProfile{
	// FIPS 204 — ML-DSA (signatures)
	"ML-DSA-44": {PublicKeyBytes: 1312, PrivateKeyBytes: 2560, SignatureBytes: 2420},
	"ML-DSA-65": {PublicKeyBytes: 1952, PrivateKeyBytes: 4032, SignatureBytes: 3309},
	"ML-DSA-87": {PublicKeyBytes: 2592, PrivateKeyBytes: 4896, SignatureBytes: 4627},

	// FIPS 203 — ML-KEM (key encapsulation)
	"ML-KEM-512":  {PublicKeyBytes: 800, PrivateKeyBytes: 1632, CiphertextBytes: 768, SharedSecretBytes: 32},
	"ML-KEM-768":  {PublicKeyBytes: 1184, PrivateKeyBytes: 2400, CiphertextBytes: 1088, SharedSecretBytes: 32},
	"ML-KEM-1024": {PublicKeyBytes: 1568, PrivateKeyBytes: 3168, CiphertextBytes: 1568, SharedSecretBytes: 32},

	// FIPS 205 — SLH-DSA (signatures)
	"SLH-DSA-128s": {PublicKeyBytes: 32, PrivateKeyBytes: 64, SignatureBytes: 7856},
	"SLH-DSA-128f": {PublicKeyBytes: 32, PrivateKeyBytes: 64, SignatureBytes: 17088},
	"SLH-DSA-192s": {PublicKeyBytes: 48, PrivateKeyBytes: 96, SignatureBytes: 16224},
	"SLH-DSA-192f": {PublicKeyBytes: 48, PrivateKeyBytes: 96, SignatureBytes: 35664},
	"SLH-DSA-256s": {PublicKeyBytes: 64, PrivateKeyBytes: 128, SignatureBytes: 29792},
	"SLH-DSA-256f": {PublicKeyBytes: 64, PrivateKeyBytes: 128, SignatureBytes: 49856},

	// Classical — RSA
	"RSA-2048": {PublicKeyBytes: 294, SignatureBytes: 256},
	"RSA-3072": {PublicKeyBytes: 422, SignatureBytes: 384},
	"RSA-4096": {PublicKeyBytes: 550, SignatureBytes: 512},

	// Classical — ECDSA
	"ECDSA-P256": {PublicKeyBytes: 65, SignatureBytes: 72},
	"ECDSA-P384": {PublicKeyBytes: 97, SignatureBytes: 104},

	// Classical — ECDH
	"ECDH-P256": {PublicKeyBytes: 65, SharedSecretBytes: 32},
	"ECDH-P384": {PublicKeyBytes: 97, SharedSecretBytes: 48},

	// Classical — Edwards curves
	"Ed25519": {PublicKeyBytes: 32, SignatureBytes: 64},
	"Ed448":   {PublicKeyBytes: 57, SignatureBytes: 114},

	// K-PQC Round 4 Finalists
	"SMAUG-T-128": {PublicKeyBytes: 672, CiphertextBytes: 768, SharedSecretBytes: 32},
	"SMAUG-T-192": {PublicKeyBytes: 992, CiphertextBytes: 1120, SharedSecretBytes: 32},
	"SMAUG-T-256": {PublicKeyBytes: 1312, CiphertextBytes: 1440, SharedSecretBytes: 32},
	"HAETAE-2":    {PublicKeyBytes: 1312, SignatureBytes: 2512},
	"HAETAE-3":    {PublicKeyBytes: 1952, SignatureBytes: 3504},
	"HAETAE-5":    {PublicKeyBytes: 2592, SignatureBytes: 4128},
	"AIMer-128f":  {PublicKeyBytes: 32, SignatureBytes: 5472},
	"AIMer-128s":  {PublicKeyBytes: 32, SignatureBytes: 2816},
	"AIMer-192f":  {PublicKeyBytes: 48, SignatureBytes: 11456},
	"AIMer-192s":  {PublicKeyBytes: 48, SignatureBytes: 7424},
	"AIMer-256f":  {PublicKeyBytes: 64, SignatureBytes: 17312},
	"AIMer-256s":  {PublicKeyBytes: 64, SignatureBytes: 12288},
	"NTRU+-576":   {PublicKeyBytes: 864, CiphertextBytes: 864, SharedSecretBytes: 32},
	"NTRU+-768":   {PublicKeyBytes: 1152, CiphertextBytes: 1152, SharedSecretBytes: 32},
	"NTRU+-864":   {PublicKeyBytes: 1312, CiphertextBytes: 1312, SharedSecretBytes: 32},
	"NTRU+-1277":  {PublicKeyBytes: 1920, CiphertextBytes: 1920, SharedSecretBytes: 32},

	// Korean legacy algorithms (KCMVP)
	"KCDSA-2048": {PublicKeyBytes: 256, SignatureBytes: 256},
	"KCDSA-3072": {PublicKeyBytes: 384, SignatureBytes: 384},
}

// sortedAlgoKeys holds algorithmSizes keys sorted by length descending, then
// alphabetically ascending. Initialized in init() for deterministic prefix matching.
var sortedAlgoKeys []string

// sortedMigrationKeys holds migrationMap keys sorted by length descending, then
// alphabetically ascending. Initialized in init() for deterministic prefix matching.
var sortedMigrationKeys []string

func init() {
	// Build sortedAlgoKeys: longest key first, alphabetical tie-break.
	sortedAlgoKeys = make([]string, 0, len(algorithmSizes))
	for k := range algorithmSizes {
		sortedAlgoKeys = append(sortedAlgoKeys, k)
	}
	sort.Slice(sortedAlgoKeys, func(i, j int) bool {
		li, lj := len(sortedAlgoKeys[i]), len(sortedAlgoKeys[j])
		if li != lj {
			return li > lj
		}
		return sortedAlgoKeys[i] < sortedAlgoKeys[j]
	})
}

// migrationMap maps classical algorithm prefixes to their recommended PQC
// replacements. Targets are aligned with NIST IR 8547 §3 Cat-N strength
// mapping (matching the equivalent classical-bit security to ML-DSA / ML-KEM
// parameter sets):
//
//	Classical strength      | ML-DSA      | ML-KEM
//	------------------------|-------------|------------
//	≤ Category 1 (≤128-bit) | ML-DSA-44   | ML-KEM-512
//	Category 3   (~192-bit) | ML-DSA-65   | ML-KEM-768
//	Category 5   (256-bit)  | ML-DSA-87   | ML-KEM-1024
//
// Specific curve / RSA-size mappings (FIPS 204 / 203 selection criteria):
//
//	ECDSA-P256 / Ed25519 ≈ Cat-3  → ML-DSA-65
//	ECDSA-P384            ≈ Cat-3 → ML-DSA-65 (or ML-DSA-87 for headroom)
//	ECDSA-P521 / Ed448    ≈ Cat-5 → ML-DSA-87
//	RSA-2048              ≈ Cat-1 → ML-DSA-65 / ML-KEM-768 (Cat-3 floor)
//	RSA-3072              ≈ Cat-3 → ML-DSA-65 / ML-KEM-768
//	RSA-4096+             ≈ Cat-5 → ML-DSA-87 / ML-KEM-1024
//
// Note ordering: the FIRST target is the recommended default; callers that
// pick `MigrationTargets[0]` get the standards-aligned baseline.
var migrationMap = map[string][]string{
	// Signature algorithms — RSA + EC + EdDSA.
	"RSA":     {"ML-DSA-65", "ML-DSA-87"},
	"ECDSA":   {"ML-DSA-65", "ML-DSA-87"},
	"Ed25519": {"ML-DSA-65"},
	"Ed448":   {"ML-DSA-87"},
	"DSA":     {"ML-DSA-65", "ML-DSA-87"},
	"KCDSA":   {"HAETAE-3", "ML-DSA-65"},

	// Key-agreement / KEM transitions.
	"ECDH":         {"ML-KEM-768", "ML-KEM-1024"},
	"ECDHE":        {"ML-KEM-768", "ML-KEM-1024"},
	"DH":           {"ML-KEM-768", "ML-KEM-1024"},
	"Diffie-Hellman": {"ML-KEM-768", "ML-KEM-1024"},
	"FFDH":         {"ML-KEM-768", "ML-KEM-1024"},
	"X25519":       {"ML-KEM-768"},
	"X448":         {"ML-KEM-1024"},

	// RSA encryption (PKE) — distinct from RSA signing.
	"RSA-OAEP":          {"ML-KEM-768", "ML-KEM-1024"},
	"RSAES-OAEP":        {"ML-KEM-768", "ML-KEM-1024"},
	"RSAES":             {"ML-KEM-768", "ML-KEM-1024"},
	"RSAES-PKCS1":       {"ML-KEM-768", "ML-KEM-1024"},
	"RSAES-PKCS1-v1_5":  {"ML-KEM-768", "ML-KEM-1024"},

	// Symmetric / hash — Grover halves the security margin. Migrate to a
	// larger primitive in the same family (NOT a PQC swap, but documented
	// here so `--impact-graph` produces a recommendation).
	"AES-128": {"AES-256"},
	"AES":     {"AES-256"},
	"SHA-1":   {"SHA-256", "SHA-3-256"},
	"SHA1":    {"SHA-256", "SHA-3-256"},
	"MD5":     {"SHA-256", "SHA-3-256"},
	"MD4":     {"SHA-256", "SHA-3-256"},
}

func init() {
	// Build sortedMigrationKeys: longest key first, alphabetical tie-break.
	sortedMigrationKeys = make([]string, 0, len(migrationMap))
	for k := range migrationMap {
		sortedMigrationKeys = append(sortedMigrationKeys, k)
	}
	sort.Slice(sortedMigrationKeys, func(i, j int) bool {
		li, lj := len(sortedMigrationKeys[i]), len(sortedMigrationKeys[j])
		if li != lj {
			return li > lj
		}
		return sortedMigrationKeys[i] < sortedMigrationKeys[j]
	})
}

// Lookup returns the AlgorithmSizeProfile for the given identifier.
// It first tries an exact case-sensitive match, then falls back to a
// case-insensitive prefix match (e.g. "RSA" matches "RSA-2048").
// The prefix fallback iterates sortedAlgoKeys (longest match first) for
// deterministic results.
func Lookup(identifier string) (AlgorithmSizeProfile, bool) {
	if p, ok := algorithmSizes[identifier]; ok {
		return p, true
	}
	upper := strings.ToUpper(identifier)
	for _, k := range sortedAlgoKeys {
		kUpper := strings.ToUpper(k)
		// Match when the identifier starts with the DB key (e.g. "RSA-2048-SHA256" → "RSA-2048"),
		// or when the DB key starts with the identifier (e.g. "RSA" → "RSA-2048").
		if strings.HasPrefix(upper, kUpper) || strings.HasPrefix(kUpper, upper) {
			return algorithmSizes[k], true
		}
	}
	return AlgorithmSizeProfile{}, false
}

// MigrationTargets returns the recommended PQC target algorithm names for a classical
// algorithm. The identifier is matched by exact key then by case-insensitive prefix.
// The prefix fallback iterates sortedMigrationKeys (longest match first) for
// deterministic results. Returns nil when no migration path is known.
func MigrationTargets(from string) []string {
	if targets, ok := migrationMap[from]; ok {
		out := make([]string, len(targets))
		copy(out, targets)
		return out
	}
	upper := strings.ToUpper(from)
	for _, k := range sortedMigrationKeys {
		if strings.HasPrefix(upper, strings.ToUpper(k)) {
			targets := migrationMap[k]
			out := make([]string, len(targets))
			copy(out, targets)
			return out
		}
	}
	return nil
}
