package quantum

import (
	"sort"
	"strings"
)

// Risk represents the quantum risk level of a cryptographic algorithm.
type Risk string

const (
	RiskVulnerable Risk = "quantum-vulnerable" // Broken by Shor's algorithm (RSA, ECDSA, ECDH, etc.)
	RiskWeakened   Risk = "quantum-weakened"    // Weakened by Grover's (AES-128, SHA-1, etc.)
	RiskSafe       Risk = "quantum-safe"        // PQC algorithms (ML-KEM, ML-DSA, etc.)
	RiskResistant  Risk = "quantum-resistant"    // Symmetric with sufficient key size (AES-256, SHA-3-256+)
	RiskDeprecated Risk = "deprecated"           // Classically broken regardless of quantum (MD5, DES, SHA-1)
	RiskUnknown    Risk = "unknown"
)

// Severity maps quantum risk to severity level for policy/reporting.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// Classification holds the quantum risk assessment for a single finding.
type Classification struct {
	Risk            Risk     `json:"quantumRisk"`
	Severity        Severity `json:"severity"`
	Recommendation  string   `json:"recommendation,omitempty"`
	HNDLRisk        string   `json:"hndlRisk,omitempty"`        // "immediate", "deferred", or "" for non-asymmetric
	MigrationEffort string   `json:"migrationEffort,omitempty"` // "simple", "moderate", or "complex"
	TargetAlgorithm string   `json:"targetAlgorithm,omitempty"` // PQC replacement (e.g. "ML-DSA-65", "ML-KEM-768")
	TargetStandard  string   `json:"targetStandard,omitempty"`  // NIST standard (e.g. "FIPS 204", "FIPS 203")
}

// HNDL risk levels for Harvest Now, Decrypt Later attacks.
const (
	HNDLImmediate = "immediate" // Key exchange — data encrypted now can be decrypted when quantum computers arrive (2030 deadline)
	HNDLDeferred  = "deferred"  // Signatures — only future signatures at risk, not past data (2035 deadline)
)

// pqcSafeFamilies are NIST post-quantum standard families and K-PQC Round 4 finalists.
var pqcSafeFamilies = map[string]bool{
	"ML-KEM":  true, // FIPS 203
	"ML-DSA":  true, // FIPS 204
	"SLH-DSA": true, // FIPS 205
	"HQC":     true, // NIST PQC 5th standard (selected March 2025), draft expected 2026
	"XMSS":    true,
	"LMS":     true,
	// K-PQC Round 4 finalists
	"SMAUG-T": true, // KEM, lattice-based
	"HAETAE":  true, // Signature, lattice-based
	"AIMer":   true, // Signature, AES-based MPC-in-the-head
	"NTRU+":   true, // KEM, NTRU variant
}

// kpqcEliminatedCandidates are K-PQC candidates eliminated in earlier rounds.
// These are quantum-vulnerable despite being post-quantum candidates.
var kpqcEliminatedCandidates = map[string]bool{
	"GCKSign": true,
	"NCC-Sign": true,
	"SOLMAE":  true,
	"TiGER":   true,
	"PALOMA":  true,
	"REDOG":   true,
}

// Pre-sorted keys for deterministic longest-prefix matching in extractBaseName.
var (
	pqcSafeFamiliesSorted           []string
	quantumVulnerableFamiliesSorted []string
	kpqcEliminatedCandidatesSorted  []string
	deprecatedAlgorithmsSorted      []string
)

func init() {
	pqcSafeFamiliesSorted = sortedMapKeys(pqcSafeFamilies)
	quantumVulnerableFamiliesSorted = sortedMapKeys(quantumVulnerableFamilies)
	kpqcEliminatedCandidatesSorted = sortedMapKeys(kpqcEliminatedCandidates)
	// Sort deprecated algorithms by length descending so that longer keys (e.g.
	// "SHA-1") are checked before shorter ones (e.g. "SHA1") when both would
	// match the same input via EqualFold. This makes extractBaseName deterministic
	// regardless of map iteration order.
	deprecatedAlgorithmsSorted = sortedMapKeys(deprecatedAlgorithms)
}

// sortedMapKeys returns map keys sorted by length descending (longest match first).
func sortedMapKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return len(keys[i]) > len(keys[j])
	})
	return keys
}

// quantumVulnerableFamilies are asymmetric algorithms broken by Shor's algorithm.
var quantumVulnerableFamilies = map[string]bool{
	"RSA": true, "RSASSA-PKCS1": true, "RSASSA-PSS": true,
	"RSAES-PKCS1": true, "RSAES-OAEP": true,
	"DSA": true, "ECDSA": true, "ECDH": true, "ECDHE": true,
	"EdDSA": true, "Ed25519": true, "Ed448": true,
	"X25519": true, "X448": true,
	"FFDH": true, "DH": true, "Diffie-Hellman": true,
	"ElGamal": true, "ECIES": true, "MQV": true, "ECMQV": true,
	"KCDSA": true, "EC-KCDSA": true,
}

// deprecatedAlgorithms are classically broken regardless of quantum computing.
var deprecatedAlgorithms = map[string]bool{
	"MD5": true, "MD4": true, "MD2": true,
	"SHA-1": true, "SHA1": true,
	"DES": true, "3DES": true, "DES-EDE3": true, "Triple-DES": true, "TDEA": true,
	"RC2": true, "RC4": true, "RC5": true,
	"Blowfish": true,
	"HAS-160": true,
}

// ClassifyAlgorithm assesses the quantum risk of a cryptographic algorithm.
func ClassifyAlgorithm(name, primitive string, keySize int) Classification {
	upperName := strings.ToUpper(name)
	baseName := extractBaseName(name)

	// 1. Check deprecated first (classically broken)
	if deprecatedAlgorithms[baseName] || deprecatedAlgorithms[name] {
		t := LookupTargetForKeySize(baseName, keySize)
		return Classification{
			Risk:            RiskDeprecated,
			Severity:        SeverityCritical,
			Recommendation:  deprecatedRecommendation(baseName),
			TargetAlgorithm: t.Algorithm,
			TargetStandard:  t.Standard,
		}
	}

	// 2. Check PQC-safe families
	// HQC: NIST-selected 5th PQC standard (March 2025). Carry a recommendation
	// because the standard is still in draft and not yet CNSA 2.0 approved.
	if baseName == "HQC" {
		return Classification{
			Risk:           RiskSafe,
			Severity:       SeverityInfo,
			Recommendation: "HQC is a NIST-selected PQC KEM (code-based). Provides non-lattice backup to ML-KEM. Standard expected 2027.",
		}
	}
	if pqcSafeFamilies[baseName] {
		return Classification{
			Risk:     RiskSafe,
			Severity: SeverityInfo,
		}
	}

	// 2a. Check K-PQC eliminated candidates (quantum-vulnerable)
	if kpqcEliminatedCandidates[baseName] {
		t := LookupTarget(baseName)
		return Classification{
			Risk:            RiskVulnerable,
			Severity:        SeverityMedium,
			Recommendation:  "K-PQC eliminated candidate. Migrate to SMAUG-T (KEM) or HAETAE (signature).",
			TargetAlgorithm: t.Algorithm,
			TargetStandard:  t.Standard,
		}
	}

	// 3. Check quantum-vulnerable asymmetric algorithms (Shor's)
	if quantumVulnerableFamilies[baseName] {
		return classifyVulnerable(baseName, primitive, keySize)
	}

	// 4. Check by primitive type
	switch normalizePrimitive(primitive) {
	case "signature":
		if !pqcSafeFamilies[baseName] {
			t := LookupTarget(baseName)
			return Classification{
				Risk:            RiskVulnerable,
				Severity:        SeverityHigh,
				HNDLRisk:        HNDLDeferred,
				Recommendation:  "HNDL risk: DEFERRED — unrecognized signature algorithm. Review for quantum safety.",
				TargetAlgorithm: t.Algorithm,
				TargetStandard:  t.Standard,
			}
		}
	case "pke", "key-agree", "kem":
		if !pqcSafeFamilies[baseName] {
			t := LookupTarget(baseName)
			return Classification{
				Risk:            RiskVulnerable,
				Severity:        SeverityCritical,
				HNDLRisk:        HNDLImmediate,
				Recommendation:  "HNDL risk: IMMEDIATE — unrecognized key exchange algorithm. Review for quantum safety.",
				TargetAlgorithm: t.Algorithm,
				TargetStandard:  t.Standard,
			}
		}
	case "rng":
		return Classification{Risk: RiskResistant, Severity: SeverityInfo, Recommendation: "CSPRNG is quantum-resistant."}
	case "hash", "xof", "mac", "kdf":
		return classifySymmetric(baseName, upperName, keySize, true)
	case "symmetric", "block-cipher", "stream-cipher", "ae", "aead":
		return classifySymmetric(baseName, upperName, keySize, false)
	}

	// 5. Heuristic: check name patterns
	if isLikelySymmetric(upperName) {
		return classifySymmetric(baseName, upperName, keySize, false)
	}
	if isLikelyHash(upperName) {
		return classifySymmetric(baseName, upperName, keySize, true)
	}

	return Classification{
		Risk:     RiskUnknown,
		Severity: SeverityLow,
	}
}

// classifyVulnerable returns classification for known quantum-vulnerable algorithms.
func classifyVulnerable(baseName, primitive string, keySize int) Classification {
	p := normalizePrimitive(primitive)
	t := LookupTargetForKeySize(baseName, keySize)
	// Override target when algorithm is used for encryption/KEM — LookupTarget
	// defaults RSA to signing, but RSA encryption should target ML-KEM.
	if (p == "key-agree" || p == "kem" || p == "pke") && t.Standard == "FIPS 204" {
		t = MigrationTarget{Algorithm: "ML-KEM-768", Standard: "FIPS 203"}
	}
	switch p {
	case "key-agree", "kem", "pke":
		return Classification{
			Risk:            RiskVulnerable,
			Severity:        SeverityCritical,
			HNDLRisk:        HNDLImmediate,
			Recommendation:  "HNDL risk: IMMEDIATE — encrypted data can be harvested now and decrypted when quantum computers arrive. Migrate to ML-KEM (FIPS 203). Transition: use a classical+ML-KEM-768 hybrid key exchange (deployed in TLS 1.3). CNSA 2.0 deadline: 2030.",
			TargetAlgorithm: t.Algorithm,
			TargetStandard:  t.Standard,
		}
	case "signature":
		return Classification{
			Risk:            RiskVulnerable,
			Severity:        SeverityHigh,
			HNDLRisk:        HNDLDeferred,
			Recommendation:  "HNDL risk: DEFERRED — only future signatures are at risk (past signatures remain valid). Migrate to ML-DSA (FIPS 204) or SLH-DSA (FIPS 205). Transition: use a composite classical+ML-DSA-65 signature (IETF draft) for backward compatibility. CNSA 2.0 deadline: 2035.",
			TargetAlgorithm: t.Algorithm,
			TargetStandard:  t.Standard,
		}
	default:
		// Unknown primitive for vulnerable algorithm — assume immediate (conservative).
		return Classification{
			Risk:            RiskVulnerable,
			Severity:        SeverityHigh,
			HNDLRisk:        HNDLImmediate,
			Recommendation:  vulnerableRecommendation(baseName),
			TargetAlgorithm: t.Algorithm,
			TargetStandard:  t.Standard,
		}
	}
}

// classifySymmetric classifies symmetric/hash algorithms based on key/output size.
func classifySymmetric(baseName, upperName string, keySize int, isHash bool) Classification {
	// SEED special handling: 128-bit only cipher (KCMVP approved)
	// SEED-ECB without MAC is deprecated (insecure mode)
	if strings.ToUpper(baseName) == "SEED" {
		if strings.Contains(upperName, "ECB") {
			return Classification{
				Risk:           RiskDeprecated,
				Severity:       SeverityCritical,
				Recommendation: "SEED-ECB is deprecated (no authentication, ECB mode is insecure). Migrate to ARIA-256-GCM or AES-256-GCM.",
			}
		}
		// SEED is 128-bit only — quantum-weakened
		return Classification{
			Risk:           RiskWeakened,
			Severity:       SeverityLow,
			Recommendation: "SEED is 128-bit only (~64-bit effective under Grover's algorithm). Migrate to ARIA-256-GCM or AES-256-GCM.",
		}
	}

	// LSH variant classification: LSH-256-* variants → quantum-weakened, LSH-512-* → quantum-resistant
	upperBase := strings.ToUpper(baseName)
	if strings.HasPrefix(upperBase, "LSH") {
		size := hashOutputSize(baseName, upperName, keySize)
		if size >= 512 {
			return Classification{
				Risk:     RiskResistant,
				Severity: SeverityInfo,
			}
		}
		if size > 0 && size < 256 {
			return Classification{
				Risk:           RiskWeakened,
				Severity:       SeverityLow,
				Recommendation: "LSH output < 256 bits is quantum-weakened. Use LSH-512 variants for quantum safety.",
			}
		}
		if size == 256 {
			return Classification{
				Risk:           RiskWeakened,
				Severity:       SeverityLow,
				Recommendation: "LSH-256 provides ~128-bit quantum security. Consider LSH-512 for higher margin.",
			}
		}
	}

	quantumResistantHash := map[string]bool{
		"SHA-3": true, "SHA3": true, "BLAKE2": true, "BLAKE2B": true,
		"BLAKE2S": true, "BLAKE3": true, "ARGON2": true, "SCRYPT": true,
		"HKDF": true, "PBKDF2": true,
		"SHA-2": true, "SHA-256": true, "SHA-384": true, "SHA-512": true,
		"SHA256": true, "SHA384": true, "SHA512": true,
		"LSH": true, // Korean standard
	}

	if isHash {
		// Hash functions: output size matters (Grover halves effective security)
		effectiveSize := hashOutputSize(baseName, upperName, keySize)
		if effectiveSize > 0 && effectiveSize < 256 {
			return Classification{
				Risk:            RiskWeakened,
				Severity:        SeverityLow,
				Recommendation:  "Consider upgrading to SHA-256+ or SHA-3 for quantum margin",
				TargetAlgorithm: "SHA-256",
			}
		}
		if quantumResistantHash[strings.ToUpper(baseName)] {
			return Classification{
				Risk:     RiskResistant,
				Severity: SeverityInfo,
			}
		}
		// Unknown hash — default to resistant if >= 256
		if effectiveSize >= 256 {
			return Classification{
				Risk:     RiskResistant,
				Severity: SeverityInfo,
			}
		}
		return Classification{
			Risk:     RiskUnknown,
			Severity: SeverityLow,
		}
	}

	// Symmetric ciphers: key size matters (Grover halves effective security).
	// If keySize is 0 (unknown), try to infer from algorithm name.
	effectiveKeySize := keySize
	if effectiveKeySize == 0 {
		effectiveKeySize = symmetricKeySize(upperName)
	}

	if effectiveKeySize > 0 {
		if effectiveKeySize < 128 {
			return Classification{
				Risk:            RiskWeakened,
				Severity:        SeverityMedium,
				Recommendation:  "Key size too small. Upgrade to 256-bit key for quantum safety.",
				TargetAlgorithm: "AES-256",
			}
		}
		if effectiveKeySize < 256 {
			return Classification{
				Risk:            RiskWeakened,
				Severity:        SeverityLow,
				Recommendation:  "128-bit symmetric is weakened by Grover's algorithm (~64-bit effective). Consider 256-bit.",
				TargetAlgorithm: "AES-256",
			}
		}
		// 256-bit+ is quantum-resistant
		return Classification{
			Risk:     RiskResistant,
			Severity: SeverityInfo,
		}
	}

	// No key size at all (not provided, not parseable from name).
	// Known symmetric families with unknown key size → RiskUnknown (conservative).
	// We can't assume 256-bit when it might be 128-bit.
	return Classification{
		Risk:           RiskUnknown,
		Severity:       SeverityLow,
		Recommendation: "Key size could not be determined. Verify >= 256-bit key for quantum safety.",
	}
}

// extractBaseName gets the algorithm family name from a full identifier.
// "AES-256-GCM" → "AES", "RSA-2048" → "RSA", "SHA-256" → "SHA-256"
// Korean multi-part names: "SMAUG-T-128" → "SMAUG-T", "HAETAE-2" → "HAETAE",
// "AIMer-128f" → "AIMer", "NTRU+-576" → "NTRU+", "EC-KCDSA" → "EC-KCDSA", "HAS-160" → "HAS-160"
func extractBaseName(name string) string {
	upper := strings.ToUpper(name)

	// Korean multi-part names that must be matched as complete base names
	koreanMultiPartNames := []string{
		"SMAUG-T", "NTRU+", "EC-KCDSA", "HAS-160", "NCC-Sign",
	}
	for _, kn := range koreanMultiPartNames {
		if strings.HasPrefix(upper, strings.ToUpper(kn)) {
			// Preserve original casing from the list
			return kn
		}
	}

	// Handle known multi-part names first (sorted by length desc for longest match)
	for _, prefix := range pqcSafeFamiliesSorted {
		if strings.HasPrefix(upper, strings.ToUpper(prefix)) {
			return prefix
		}
	}
	for _, alg := range deprecatedAlgorithmsSorted {
		if strings.EqualFold(name, alg) {
			return alg
		}
	}
	for _, family := range quantumVulnerableFamiliesSorted {
		if strings.HasPrefix(upper, strings.ToUpper(family)) {
			return family
		}
	}
	for _, candidate := range kpqcEliminatedCandidatesSorted {
		if strings.EqualFold(name, candidate) || strings.HasPrefix(upper, strings.ToUpper(candidate)+"-") {
			return candidate
		}
	}

	// Default: take first segment before '-' or '_'
	parts := strings.FieldsFunc(name, func(r rune) bool {
		return r == '-' || r == '_'
	})
	if len(parts) > 0 {
		return parts[0]
	}
	return name
}

// hashOutputSize infers the hash output size in bits.
func hashOutputSize(baseName, upperName string, keySize int) int {
	if keySize > 0 {
		return keySize
	}
	// Infer from name
	switch {
	case strings.Contains(upperName, "512"):
		return 512
	case strings.Contains(upperName, "384"):
		return 384
	case strings.Contains(upperName, "256"):
		return 256
	case strings.Contains(upperName, "224"):
		return 224
	case strings.Contains(upperName, "160"):
		return 160
	case strings.Contains(upperName, "128"):
		return 128
	case strings.EqualFold(baseName, "MD5"):
		return 128
	case strings.EqualFold(baseName, "SHA-1") || strings.EqualFold(baseName, "SHA1"):
		return 160
	case strings.EqualFold(baseName, "HAS-160"):
		return 160
	}
	return 0
}

// symmetricKeySize infers symmetric cipher key size from the algorithm name.
// "AES-256-GCM" → 256, "AES-128" → 128, "CHACHA20" → 256, "AES" → 0 (unknown).
func symmetricKeySize(upperName string) int {
	// ChaCha20 always uses 256-bit keys.
	if strings.Contains(upperName, "CHACHA20") {
		return 256
	}
	// Check for common key size markers in the name.
	switch {
	case strings.Contains(upperName, "256"):
		return 256
	case strings.Contains(upperName, "192"):
		return 192
	case strings.Contains(upperName, "128"):
		return 128
	}
	return 0
}

func normalizePrimitive(p string) string {
	switch strings.ToLower(p) {
	case "pke", "public-key", "public_key":
		return "pke"
	case "kem", "key-encapsulation":
		return "kem"
	case "key-agree", "key-exchange", "key_exchange", "keyexchange", "dh":
		return "key-agree"
	case "signature", "sign", "digital-signature":
		return "signature"
	case "asymmetric":
		return "pke"
	case "hash", "digest":
		return "hash"
	case "mac", "hmac":
		return "mac"
	case "kdf", "key-derivation":
		return "kdf"
	case "symmetric", "block-cipher", "block_cipher", "stream-cipher", "stream_cipher":
		return "symmetric"
	case "ae", "aead":
		return "ae"
	case "xof":
		return "xof"
	case "rng", "prng", "csprng", "random":
		return "rng"
	}
	return strings.ToLower(p)
}

func isLikelySymmetric(upper string) bool {
	prefixes := []string{"AES", "CHACHA", "CAMELLIA", "ARIA", "SEED", "LEA", "ASCON", "TWOFISH", "SERPENT"}
	for _, p := range prefixes {
		if strings.HasPrefix(upper, p) {
			return true
		}
	}
	return false
}

func isLikelyHash(upper string) bool {
	prefixes := []string{"SHA", "BLAKE", "MD5", "MD4", "RIPEMD", "WHIRLPOOL", "LSH", "HMAC", "HKDF", "PBKDF", "ARGON", "SCRYPT", "BCRYPT"}
	for _, p := range prefixes {
		if strings.HasPrefix(upper, p) {
			return true
		}
	}
	return false
}

func deprecatedRecommendation(name string) string {
	switch strings.ToUpper(name) {
	case "MD5", "MD4", "MD2":
		return "MD5 is cryptographically broken. Migrate to SHA-256 or SHA-3."
	case "SHA-1", "SHA1":
		return "SHA-1 is deprecated (collision attacks). Migrate to SHA-256 or SHA-3."
	case "DES", "3DES", "DES-EDE3", "TRIPLE-DES", "TDEA":
		return "DES/3DES is deprecated. Migrate to AES-256-GCM."
	case "RC2", "RC4", "RC5":
		return "RC ciphers are broken. Migrate to AES-256-GCM or ChaCha20-Poly1305."
	case "BLOWFISH":
		return "Blowfish has a 64-bit block size (birthday attacks). Migrate to AES-256."
	case "HAS-160":
		return "HAS-160 is deprecated (equivalent to SHA-1). Migrate to SHA-256 or LSH-256."
	}
	return "This algorithm is deprecated. Migrate to a modern alternative."
}

// ClassifyEffort returns the base migration effort for a classification result.
// isConfig should be true when the finding originates from a config file
// (e.g., SourceEngine == "config-scanner"). Blast-radius upgrade (simple→moderate,
// moderate→complex) is applied separately in the orchestrator after BlastRadius is set.
//
// Rules:
//   - Safe / resistant / unknown: no effort (not actionable)
//   - Deprecated: simple — remove the algorithm
//   - Weakened hash (output < 256 bits): simple
//   - Weakened symmetric in config: simple (cipher-suite swap)
//   - Weakened symmetric in source: moderate (code change)
//   - Asymmetric signature: moderate
//   - Key exchange / KEM / PKE in config: moderate
//   - Key exchange / KEM / PKE in source: complex
func ClassifyEffort(c Classification, primitive string, isConfig bool) string {
	switch c.Risk {
	case RiskSafe, RiskResistant, RiskUnknown:
		return ""
	}

	p := normalizePrimitive(primitive)

	switch c.Risk {
	case RiskDeprecated:
		return "simple"

	case RiskWeakened:
		switch p {
		case "hash", "xof", "mac", "kdf":
			return "simple"
		}
		if isConfig {
			return "simple"
		}
		return "moderate"

	case RiskVulnerable:
		if p == "signature" {
			return "moderate"
		}
		if p == "key-agree" || p == "kem" || p == "pke" {
			if isConfig {
				return "moderate"
			}
			return "complex"
		}
		// Unknown primitive for a vulnerable asymmetric algorithm — conservative.
		return "complex"
	}

	return ""
}

// UpgradeEffort bumps effort up one level: simple→moderate, moderate→complex.
// Returns the input unchanged if it is already "complex" or empty.
func UpgradeEffort(effort string) string {
	switch effort {
	case "simple":
		return "moderate"
	case "moderate":
		return "complex"
	}
	return effort
}

func vulnerableRecommendation(name string) string {
	switch strings.ToUpper(name) {
	case "RSA", "RSASSA-PKCS1", "RSASSA-PSS":
		return "RSA is quantum-vulnerable (Shor's algorithm). Migrate to ML-DSA-65 (FIPS 204) for signatures. Transition: use RSA-3072+ML-DSA-65 composite signature (IETF draft) for backward compatibility."
	case "RSAES-PKCS1", "RSAES-OAEP":
		return "RSA encryption is quantum-vulnerable (Shor's algorithm). Migrate to ML-KEM-768 (FIPS 203). Transition: use X25519+ML-KEM-768 hybrid key exchange (deployed in TLS 1.3). CNSA 2.0 deadline: 2030."
	case "ECDSA":
		return "ECDSA is quantum-vulnerable. Migrate to ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205). Transition: use ECDSA-P256+ML-DSA-65 composite signature (IETF draft) for backward compatibility."
	case "KCDSA", "EC-KCDSA":
		return "Migrate to HAETAE or ML-DSA (FIPS 204). Korean PQC transition deadline: 2028 (KS X 3262)."
	case "ECDH", "ECDHE":
		return "HNDL risk: IMMEDIATE. Key exchange is quantum-vulnerable. Migrate to ML-KEM-768 (FIPS 203). Transition: use ECDH-P256+ML-KEM-768 hybrid key exchange (deployed in TLS 1.3). CNSA 2.0 deadline: 2030."
	case "X25519":
		return "HNDL risk: IMMEDIATE. Key exchange is quantum-vulnerable. Migrate to ML-KEM-768 (FIPS 203). Transition: use X25519+ML-KEM-768 hybrid (deployed in Chrome, Firefox, BoringSSL). CNSA 2.0 deadline: 2030."
	case "X448", "DH", "FFDH", "DIFFIE-HELLMAN":
		return "HNDL risk: IMMEDIATE. Key exchange is quantum-vulnerable. Migrate to ML-KEM-768 (FIPS 203). Transition: use X25519+ML-KEM-768 hybrid key exchange (deployed in TLS 1.3). CNSA 2.0 deadline: 2030."
	case "EDDSA":
		return "EdDSA is quantum-vulnerable. Migrate to ML-DSA-65 (FIPS 204) or SLH-DSA (FIPS 205). Transition: use Ed25519+ML-DSA-65 composite signature (IETF draft) for backward compatibility."
	case "ED25519":
		return "Ed25519 (EdDSA) is quantum-vulnerable. Migrate to ML-DSA-65 (FIPS 204). Transition: use Ed25519+ML-DSA-65 composite signature (IETF draft) for backward compatibility."
	case "ED448":
		return "Ed448 (EdDSA) is quantum-vulnerable. Migrate to ML-DSA-87 (FIPS 204). Transition: use Ed448+ML-DSA-87 composite signature (IETF draft) for backward compatibility."
	case "DSA":
		return "DSA is quantum-vulnerable. Migrate to ML-DSA-65 (FIPS 204). DSA has no hybrid path — replace directly. See NIST PQC standards (FIPS 203/204/205)."
	}
	return "This algorithm is quantum-vulnerable. Migrate to NIST PQC standards (FIPS 203/204/205)."
}
