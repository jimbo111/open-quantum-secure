// Package migration generates language-specific PQC migration code snippets.
// Given a file path, a classical algorithm name, its cryptographic primitive,
// and the recommended PQC target algorithm, GenerateSnippet returns a
// ready-to-use before/after code example for the detected language.
package migration

import (
	"path/filepath"
	"strings"
)

// Snippet holds a generated migration code example for a single finding.
type Snippet struct {
	// Language is the target language or config format: "go", "python", "java",
	// "rust", "javascript", "typescript", "c", "cpp", "csharp", "swift", or "config".
	Language string

	// Before contains a short classical-algorithm code example (3-5 lines).
	Before string

	// After contains the PQC replacement code example, including necessary
	// import lines (3-5 lines).
	After string

	// Explanation is a single sentence summarising the migration.
	Explanation string
}

// primitive constants used for matching. We keep these unexported so callers
// work only through the public API.
const (
	primitiveSigning    = "signing"
	primitiveSignature  = "signature"
	primitiveKEM        = "kem"
	primitiveKeyExchange = "key-exchange"
	primitiveKeyAgree   = "key-agree"
)

// isSigning reports whether p looks like a digital-signature primitive.
func isSigning(p string) bool {
	p = strings.ToLower(p)
	return p == primitiveSigning || p == primitiveSignature
}

// isKEM reports whether p looks like a key-encapsulation / key-exchange
// primitive.
func isKEM(p string) bool {
	p = strings.ToLower(p)
	return p == primitiveKEM || p == primitiveKeyExchange || p == primitiveKeyAgree
}

// isSafePQC reports whether alg is already a PQC-safe algorithm name. These
// must never generate a migration snippet regardless of the primitive hint.
func isSafePQC(alg string) bool {
	upper := strings.ToUpper(alg)
	// Prefix-based check covers all variants (ML-DSA-44/65/87, ML-KEM-512/768/1024,
	// SLH-DSA-*, HQC-*, etc.) as well as the bare family names.
	for _, prefix := range []string{
		"ML-DSA", "ML-KEM", "SLH-DSA",
		"DILITHIUM", "KYBER",           // pre-standard aliases
		"XMSS", "LMS", "SPHINCS+",
		"HQC",
	} {
		if upper == prefix || strings.HasPrefix(upper, prefix+"-") {
			return true
		}
	}
	return false
}

// familyFromTargetAlg infers snippet family ("sign" or "kem") from the PQC target
// algorithm. ML-KEM → "kem", ML-DSA/SLH-DSA → "sign". Returns "" when the target
// does not map to a known PQC family.
//
// Used by GenerateSnippet as an override: when the primitive hint disagrees with
// the classical algorithm's hardcoded family (e.g. quantum pkg recommends ML-KEM
// for RSA used as encryption, but classicalAlgFamily("RSA") returns "sign"), the
// target-derived family wins so the emitted code matches the recommended algorithm.
func familyFromTargetAlg(targetAlg string) string {
	upper := strings.ToUpper(targetAlg)
	switch {
	case strings.HasPrefix(upper, "ML-KEM") || strings.HasPrefix(upper, "MLKEM"):
		return "kem"
	case strings.HasPrefix(upper, "ML-DSA") || strings.HasPrefix(upper, "MLDSA"),
		strings.HasPrefix(upper, "SLH-DSA") || strings.HasPrefix(upper, "SLHDSA"):
		return "sign"
	}
	return ""
}

// pqcStdSuffix returns a parenthetical FIPS standard suffix for a PQC target,
// or an empty string when the target is unknown. Used to build explanation
// strings without hardcoding the standard number — so SLH-DSA targets render
// as "(FIPS 205)" instead of the incorrect "(FIPS 204)".
func pqcStdSuffix(targetAlg string) string {
	std := fipsStandardFor(targetAlg)
	if std == "" {
		return ""
	}
	return " (" + std + ")"
}

// fipsStandardFor returns the NIST FIPS publication that standardises targetAlg.
// ML-KEM → FIPS 203, ML-DSA → FIPS 204, SLH-DSA → FIPS 205. Returns "" otherwise.
func fipsStandardFor(targetAlg string) string {
	upper := strings.ToUpper(targetAlg)
	switch {
	case strings.HasPrefix(upper, "ML-KEM") || strings.HasPrefix(upper, "MLKEM"):
		return "FIPS 203"
	case strings.HasPrefix(upper, "ML-DSA") || strings.HasPrefix(upper, "MLDSA"):
		return "FIPS 204"
	case strings.HasPrefix(upper, "SLH-DSA") || strings.HasPrefix(upper, "SLHDSA"):
		return "FIPS 205"
	}
	return ""
}

// classicalAlgFamily maps an arbitrary classical algorithm name (case-insensitive)
// to a canonical two-value family: "sign" or "kem".
// Returns "" when the algorithm is already PQC-safe or is unrecognised.
func classicalAlgFamily(alg string) string {
	switch strings.ToUpper(alg) {
	// Signing
	case "RSA", "RSASSA-PKCS1", "RSASSA-PSS",
		"DSA", "ECDSA", "EDDSA", "ED25519", "ED448",
		"KCDSA", "EC-KCDSA":
		return "sign"

	// Key encapsulation / key exchange
	case "ECDH", "ECDHE", "X25519", "X448",
		"DH", "FFDH", "DIFFIE-HELLMAN",
		"RSAES-PKCS1", "RSAES-OAEP",
		"ELGAMAL", "ECIES", "MQV", "ECMQV":
		return "kem"

	// Pre-standard PQC names — no migration needed, they already map to PQC.
	// Also catches DILITHIUM / KYBER / ML-DSA / ML-KEM / SLH-DSA etc.
	default:
		return ""
	}
}

// extractBaseAlg strips key-size or curve suffixes from compound algorithm names.
// "RSA-2048" → "RSA", "ECDSA-P256" → "ECDSA", "AES-256-GCM" → "AES",
// "X25519" → "X25519" (no hyphen-digit boundary).
func extractBaseAlg(alg string) string {
	// Find the first hyphen followed by a digit — everything before it is the base.
	for i := 0; i < len(alg)-1; i++ {
		if alg[i] == '-' && alg[i+1] >= '0' && alg[i+1] <= '9' {
			return alg[:i]
		}
	}
	// Also handle "ECDSA-P256" — hyphen followed by 'P' + digits
	for i := 0; i < len(alg)-2; i++ {
		if alg[i] == '-' && (alg[i+1] == 'P' || alg[i+1] == 'p') && alg[i+2] >= '0' && alg[i+2] <= '9' {
			return alg[:i]
		}
	}
	return alg
}

// langFromExt maps a file extension (dot included, lower-cased) to a language
// token. Config-like extensions all collapse to "config".
func langFromExt(ext string) string {
	switch ext {
	case ".go":
		return "go"
	case ".py":
		return "python"
	case ".java":
		return "java"
	case ".rs":
		return "rust"
	case ".js":
		return "javascript"
	case ".ts", ".tsx":
		return "typescript"
	case ".c", ".h":
		return "c"
	case ".cpp", ".cc", ".cxx", ".hpp":
		return "cpp"
	case ".cs":
		return "csharp"
	case ".swift":
		return "swift"
	case ".yml", ".yaml", ".conf", ".nginx", ".cnf", ".cfg",
		".properties", ".toml", ".json", ".xml", ".ini", ".hcl", ".env":
		return "config"
	default:
		return ""
	}
}

// GenerateSnippet returns a language-specific PQC migration snippet.
//
// Parameters:
//   - filePath     – path of the source file (extension determines language)
//   - classicalAlg – detected classical algorithm name, e.g. "RSA", "ECDSA",
//     "X25519"
//   - primitive     – cryptographic primitive hint, e.g. "signature",
//     "key-exchange" (may be empty)
//   - targetAlg     – recommended PQC algorithm, e.g. "ML-DSA-65",
//     "ML-KEM-768"
//
// Returns nil when:
//   - the file extension is not recognised
//   - the algorithm is already PQC-safe (classicalAlgFamily returns "")
//   - no snippet exists for the language/primitive combination
func GenerateSnippet(filePath, classicalAlg, primitive, targetAlg string) *Snippet {
	lang := langFromExt(strings.ToLower(filepath.Ext(filePath)))
	if lang == "" {
		// Extensionless server config files are common on Debian/Ubuntu
		// (e.g. /etc/nginx/sites-available/default, /etc/haproxy/haproxy).
		// Detect them by path so configSnippet can still run.
		if isExtensionlessConfigPath(filePath) {
			lang = "config"
		} else {
			return nil
		}
	}

	// Bail out immediately for PQC-safe algorithms — no migration needed.
	if isSafePQC(classicalAlg) {
		return nil
	}

	// Normalize compound names like "RSA-2048" or "ECDSA-P256" to base form
	// for family lookup. Take first segment before any hyphen-digit boundary.
	baseAlg := extractBaseAlg(classicalAlg)
	family := classicalAlgFamily(baseAlg)
	if family == "" {
		// Resolve ambiguity using the primitive hint when the algorithm name
		// alone is not enough (e.g. generic "RSA" used for encryption vs.
		// signing). We also allow the caller to override via primitive.
		if isSigning(primitive) {
			family = "sign"
		} else if isKEM(primitive) {
			family = "kem"
		} else {
			return nil
		}
	}

	// targetAlg may be empty when the caller omits it; fall back to
	// sensible defaults per family so snippets are always useful.
	target := targetAlg
	if target == "" {
		if family == "sign" {
			target = "ML-DSA-65"
		} else {
			target = "ML-KEM-768"
		}
	}

	// Target-derived family overrides classical family when they disagree.
	// Prevents the bug where RSA (classicalAlgFamily="sign") paired with a
	// KEM target (e.g. ML-KEM-768, picked by pkg/quantum for RSA used in
	// encryption/KEM context) produced signing code calling oqs.Signature
	// on a KEM algorithm — runtime-invalid and misleading.
	if tf := familyFromTargetAlg(target); tf != "" && tf != family {
		family = tf
	}

	switch lang {
	case "go":
		return goSnippet(classicalAlg, primitive, family, target)
	case "python":
		return pythonSnippet(family, target)
	case "java":
		return javaSnippet(family, target)
	case "rust":
		return rustSnippet(family, target)
	case "javascript", "typescript":
		return jsSnippet(lang, family, target)
	case "c", "cpp":
		return cSnippet(lang, family, target)
	case "csharp":
		return csharpSnippet(family, target)
	case "swift":
		return swiftSnippet(family, target)
	case "config":
		return configSnippet(filePath, classicalAlg, family)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Go snippets
// ---------------------------------------------------------------------------

func goSnippet(classicalAlg, primitive, family, targetAlg string) *Snippet {
	algUpper := strings.ToUpper(classicalAlg)

	// TLS-context hint: if primitive or alg suggests TLS, add note about
	// crypto/tls native support available since Go 1.24.
	isTLS := strings.Contains(strings.ToLower(primitive), "tls") ||
		algUpper == "ECDHE" || algUpper == "X25519"

	switch family {
	case "sign":
		before := `import "crypto/rsa"

priv, _ := rsa.GenerateKey(rand.Reader, 2048)
sig, _ := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest)`

		after := `import "github.com/open-quantum-safe/liboqs-go/oqs"

signer := oqs.Signature{}
_ = signer.Init("` + targetAlg + `", nil)
pub, _ := signer.GenerateKeyPair()
sig, _ := signer.Sign(message)
isValid, _ := signer.Verify(message, sig, pub)`

		return &Snippet{
			Language:    "go",
			Before:      before,
			After:       after,
			Explanation: "Replace RSA/ECDSA signing with " + targetAlg + pqcStdSuffix(targetAlg) + " via liboqs-go.",
		}

	case "kem":
		var note string
		if isTLS {
			note = "\n// Go 1.24+: crypto/tls supports X25519MLKEM768 natively via tls.CurveID."
		}

		before := `import "crypto/elliptic"

priv, _ := ecdh.P256().GenerateKey(rand.Reader)
shared, _ := priv.ECDH(peerPub)`

		after := `import "github.com/open-quantum-safe/liboqs-go/oqs"` + note + `

kem := oqs.KeyEncapsulation{}
_ = kem.Init("` + targetAlg + `", nil)
pub, _ := kem.GenerateKeyPair()
ciphertext, sharedSecret, _ := kem.EncapSecret(pub)`

		return &Snippet{
			Language:    "go",
			Before:      before,
			After:       after,
			Explanation: "Replace ECDH/X25519 key exchange with " + targetAlg + pqcStdSuffix(targetAlg) + " via liboqs-go.",
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Python snippets
// ---------------------------------------------------------------------------

func pythonSnippet(family, targetAlg string) *Snippet {
	switch family {
	case "sign":
		before := `from cryptography.hazmat.primitives.asymmetric import rsa, padding

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())`

		after := `import oqs  # pip install liboqs-python

with oqs.Signature("` + targetAlg + `") as signer:
    public_key = signer.generate_keypair()
    signature = signer.sign(message)
    valid = signer.verify(message, signature, public_key)`

		return &Snippet{
			Language:    "python",
			Before:      before,
			After:       after,
			Explanation: "Replace RSA/ECDSA signing with " + targetAlg + pqcStdSuffix(targetAlg) + " via liboqs-python.",
		}

	case "kem":
		before := `from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

private_key = X25519PrivateKey.generate()
shared_key = private_key.exchange(peer_public_key)`

		after := `import oqs  # pip install liboqs-python

with oqs.KeyEncapsulation("` + targetAlg + `") as kem:
    public_key = kem.generate_keypair()
    ciphertext, shared_secret = kem.encap_secret(public_key)`

		return &Snippet{
			Language:    "python",
			Before:      before,
			After:       after,
			Explanation: "Replace ECDH key exchange with " + targetAlg + pqcStdSuffix(targetAlg) + " via liboqs-python.",
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Java snippets
// ---------------------------------------------------------------------------

// javaBCAlgName strips the numeric variant suffix from a canonical PQC target
// for the Bouncy Castle JCA algorithm name: "ML-DSA-65" → "ML-DSA",
// "ML-KEM-768" → "ML-KEM".
func javaBCAlgName(targetAlg string) string {
	bcAlg := targetAlg
	if idx := strings.LastIndex(targetAlg, "-"); idx > 0 {
		prefix := targetAlg[:idx]
		// Only strip the numeric suffix (e.g. "-65", "-768").
		suffix := targetAlg[idx+1:]
		allDigits := len(suffix) > 0
		for _, c := range suffix {
			if c < '0' || c > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			bcAlg = prefix
		}
	}
	return bcAlg
}

// javaParamSpecClass builds the Bouncy Castle org.bouncycastle.jcajce.spec
// parameter-set class simple name from a JCA algorithm name, e.g.
// "ML-DSA" -> "MLDSAParameterSpec", "ML-KEM" -> "MLKEMParameterSpec".
// Verified against the Bouncy Castle 1.83+ javadoc for MLDSAParameterSpec /
// MLKEMParameterSpec; the same hyphen-stripped-plus-suffix convention is used
// consistently across BC's other jcajce.spec PQC parameter classes.
func javaParamSpecClass(bcAlg string) string {
	return strings.ReplaceAll(bcAlg, "-", "") + "ParameterSpec"
}

// javaParamSpecField converts a canonical target algorithm (e.g. "ML-DSA-65")
// into the corresponding Bouncy Castle parameter-set static field name (e.g.
// "ml_dsa_65") — confirmed fields: ml_dsa_44/65/87, ml_kem_768/1024.
func javaParamSpecField(targetAlg string) string {
	return strings.ReplaceAll(strings.ToLower(targetAlg), "-", "_")
}

func javaSnippet(family, targetAlg string) *Snippet {
	bcAlg := javaBCAlgName(targetAlg)
	specClass := javaParamSpecClass(bcAlg)
	specField := javaParamSpecField(targetAlg)
	initCall := specClass + "." + specField

	switch family {
	case "sign":
		before := `import java.security.KeyPairGenerator;

KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
kpg.initialize(2048);
KeyPair kp = kpg.generateKeyPair();`

		after := `import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jcajce.spec.` + specClass + `;
import java.security.KeyPairGenerator;

Security.addProvider(new BouncyCastleProvider());
KeyPairGenerator kpg = KeyPairGenerator.getInstance("` + bcAlg + `", "BC");
kpg.initialize(` + initCall + `);
KeyPair kp = kpg.generateKeyPair();`

		return &Snippet{
			Language:    "java",
			Before:      before,
			After:       after,
			Explanation: "Replace RSA/ECDSA with " + targetAlg + pqcStdSuffix(targetAlg) + " using Bouncy Castle's standard \"BC\" provider.",
		}

	case "kem":
		before := `import javax.crypto.KeyAgreement;

KeyAgreement ka = KeyAgreement.getInstance("ECDH");
ka.init(privateKey);
ka.doPhase(peerPublicKey, true);
byte[] sharedSecret = ka.generateSecret();`

		after := `import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jcajce.spec.` + specClass + `;
import java.security.KeyPairGenerator;

Security.addProvider(new BouncyCastleProvider());
KeyPairGenerator kpg = KeyPairGenerator.getInstance("` + bcAlg + `", "BC");
kpg.initialize(` + initCall + `);
KeyPair kp = kpg.generateKeyPair();`

		return &Snippet{
			Language:    "java",
			Before:      before,
			After:       after,
			Explanation: "Replace ECDH key agreement with " + targetAlg + pqcStdSuffix(targetAlg) + " using Bouncy Castle's standard \"BC\" provider.",
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Rust snippets
// ---------------------------------------------------------------------------

func rustSnippet(family, targetAlg string) *Snippet {
	// Map canonical target algorithm to the oqs-rust enum variant.
	// "ML-DSA-44" → "MlDsa44", "ML-KEM-768" → "MlKem768"
	oqsVariant := toOQSVariant(targetAlg)

	switch family {
	case "sign":
		before := `use rsa::{RsaPrivateKey, pkcs1v15::SigningKey};

let priv_key = RsaPrivateKey::new(&mut rng, 2048)?;
let signing_key = SigningKey::<Sha256>::new(priv_key);
let sig = signing_key.sign(message);`

		after := `use oqs::sig::{Sig, Algorithm};

let sig = Sig::new(Algorithm::` + oqsVariant + `)?;
let (pk, sk) = sig.keypair()?;
let signature = sig.sign(message, &sk)?;
sig.verify(message, &signature, &pk)?;`

		return &Snippet{
			Language:    "rust",
			Before:      before,
			After:       after,
			Explanation: "Replace RSA/ECDSA signing with " + targetAlg + pqcStdSuffix(targetAlg) + " via the oqs crate.",
		}

	case "kem":
		before := `use x25519_dalek::{EphemeralSecret, PublicKey};

let secret = EphemeralSecret::random_from_rng(rng);
let public = PublicKey::from(&secret);
let shared = secret.diffie_hellman(&peer_public);`

		after := `use oqs::kem::{Kem, Algorithm};

let kem = Kem::new(Algorithm::` + oqsVariant + `)?;
let (pk, sk) = kem.keypair()?;
let (ciphertext, shared_secret) = kem.encapsulate(&pk)?;`

		return &Snippet{
			Language:    "rust",
			Before:      before,
			After:       after,
			Explanation: "Replace X25519/ECDH key exchange with " + targetAlg + pqcStdSuffix(targetAlg) + " via the oqs crate.",
		}
	}
	return nil
}

// toOQSVariant converts a NIST algorithm name to the oqs-rust enum variant
// naming convention (PascalCase, hyphens removed).
// Examples:
//
//	"ML-DSA-44"  → "MlDsa44"
//	"ML-KEM-768" → "MlKem768"
//	"SLH-DSA-SHA2-128f" → "SlhDsaSha2128f"
func toOQSVariant(alg string) string {
	parts := strings.Split(alg, "-")
	var b strings.Builder
	for _, p := range parts {
		if len(p) == 0 {
			continue
		}
		// If first char is a letter, Title-case the part; otherwise keep as-is
		// (handles numeric-only parts like "768").
		if p[0] >= 'A' && p[0] <= 'Z' {
			b.WriteByte(p[0])
			b.WriteString(strings.ToLower(p[1:]))
		} else if p[0] >= 'a' && p[0] <= 'z' {
			b.WriteByte(p[0] - 32) // ASCII upper
			b.WriteString(p[1:])
		} else {
			b.WriteString(p)
		}
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// Config snippets
// ---------------------------------------------------------------------------

// configServerType returns one of "nginx", "apache", "haproxy", "ssh", or
// "generic" based on whether the file name or path contains a recognisable
// keyword (case-insensitive). Paths that match none of the known servers
// return "generic" — they must NOT silently default to nginx (B5): a
// generic-guidance snippet is the only safe thing to emit for a server we
// can't identify, since nginx directives are wrong syntax for anything else.
func configServerType(filePath string) string {
	lower := strings.ToLower(filepath.ToSlash(filePath))
	base := strings.ToLower(filepath.Base(filePath))
	switch {
	case strings.Contains(lower, "haproxy"):
		return "haproxy"
	case strings.Contains(lower, "apache") || strings.Contains(lower, "httpd"):
		return "apache"
	case strings.Contains(lower, "nginx"):
		return "nginx"
	case base == "sshd_config" || base == "ssh_config" ||
		strings.Contains(lower, "/sshd_config.d/") || strings.Contains(lower, "/ssh/"):
		return "ssh"
	default:
		return "generic"
	}
}

// isExtensionlessConfigPath reports whether filePath looks like a server
// configuration file even though it has no file extension (e.g.
// /etc/nginx/sites-available/default, /etc/ssh/sshd_config).
func isExtensionlessConfigPath(filePath string) bool {
	if filepath.Ext(filePath) != "" {
		return false
	}
	lower := strings.ToLower(filepath.ToSlash(filePath))
	base := strings.ToLower(filepath.Base(filePath))
	if base == "sshd_config" || base == "ssh_config" {
		return true
	}
	for _, marker := range []string{"/nginx/", "/apache/", "/apache2/", "/httpd/", "/haproxy/", "/ssh/"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// configSnippet generates a server-specific PQC migration snippet for config
// files. The filePath is used to detect whether the target is nginx, Apache,
// HAProxy, or OpenSSH (configServerType); paths matching none of those get a
// generic guidance snippet rather than defaulting to any one server's syntax
// (B5 — SSH and unrecognised configs must never receive nginx directives).
func configSnippet(filePath, classicalAlg, family string) *Snippet {
	_ = strings.ToUpper(classicalAlg) // kept for future per-alg branching

	server := configServerType(filePath)

	// Signing certificate / key config — checked first so that RSA (which is
	// also a TLS algorithm) maps to the certificate snippet, not the curve
	// snippet.
	if family == "sign" {
		switch server {
		case "apache":
			before := `# Apache TLS curves (classical only)
SSLCertificateFile    /etc/ssl/certs/server-rsa.crt
SSLCertificateKeyFile /etc/ssl/private/server-rsa.key`

			after := `SSLCertificateFile    /etc/ssl/certs/server-mldsa.crt
SSLCertificateKeyFile /etc/ssl/private/server-mldsa.key
# Generate with: openssl genpkey -algorithm ML-DSA-65`

			return &Snippet{
				Language:    "config",
				Before:      before,
				After:       after,
				Explanation: "Replace RSA/ECDSA TLS certificate with an ML-DSA-65 certificate (FIPS 204).",
			}

		case "haproxy":
			before := `# Classical RSA certificate bundle (cert + key in one file per HAProxy convention)
bind *:443 ssl crt /etc/haproxy/certs/server-rsa.pem`

			after := `# Replace with ML-DSA certificate bundle
bind *:443 ssl crt /etc/haproxy/certs/server-mldsa.pem
# Generate with: openssl genpkey -algorithm ML-DSA-65`

			return &Snippet{
				Language:    "config",
				Before:      before,
				After:       after,
				Explanation: "Replace RSA/ECDSA TLS certificate with an ML-DSA-65 certificate (FIPS 204) in the HAProxy bind directive.",
			}

		case "nginx":
			before := `# Certificate key type (classical RSA)
ssl_certificate     /etc/ssl/certs/server-rsa.crt;
ssl_certificate_key /etc/ssl/private/server-rsa.key;`

			after := `# Certificate key type — replace RSA cert with ML-DSA certificate
ssl_certificate     /etc/ssl/certs/server-mldsa.crt;
ssl_certificate_key /etc/ssl/private/server-mldsa.key;
# Generate with: openssl genpkey -algorithm ML-DSA-65`

			return &Snippet{
				Language:    "config",
				Before:      before,
				After:       after,
				Explanation: "Replace RSA/ECDSA TLS certificate with an ML-DSA-65 certificate (FIPS 204).",
			}

		default: // "ssh" (host-key signature algorithms have no NIST-standard
			// PQC replacement shipping yet) and "generic" — no server-specific
			// directive can be assumed safely, so fall through to generic guidance.
			return genericConfigSnippet(family, "ML-DSA-65")
		}
	}

	// TLS cipher / curve configuration for key-exchange algorithms.
	if family == "kem" {
		switch server {
		case "apache":
			before := `# Apache TLS curves (classical only)
SSLOpenSSLConfCmd Curves prime256v1:secp384r1`

			after := `# Apache TLS curves — add PQC hybrid key exchange
SSLOpenSSLConfCmd Curves X25519MLKEM768:prime256v1:secp384r1`

			return &Snippet{
				Language:    "config",
				Before:      before,
				After:       after,
				Explanation: "Add X25519MLKEM768 to Apache TLS curve list to enable PQC hybrid key exchange (FIPS 203).",
			}

		case "haproxy":
			before := `bind *:443 ssl crt /etc/haproxy/certs/ curves secp256r1:secp384r1`

			after := `bind *:443 ssl crt /etc/haproxy/certs/ curves X25519MLKEM768:secp256r1:secp384r1`

			return &Snippet{
				Language:    "config",
				Before:      before,
				After:       after,
				Explanation: "Add X25519MLKEM768 to HAProxy TLS curve list to enable PQC hybrid key exchange (FIPS 203).",
			}

		case "nginx":
			before := `# TLS curve preference (classical only)
ssl_ecdh_curve secp384r1:prime256v1;`

			after := `# TLS curve preference — add X25519MLKEM768 for PQC hybrid key exchange
ssl_ecdh_curve X25519MLKEM768:secp384r1:prime256v1;`

			return &Snippet{
				Language:    "config",
				Before:      before,
				After:       after,
				Explanation: "Add X25519MLKEM768 to TLS curve list to enable PQC hybrid key exchange (FIPS 203).",
			}

		case "ssh":
			// mlkem768x25519-sha256: OpenSSH 9.9+ (default since 10.0), hybrid
			// ML-KEM-768/X25519, FIPS 203. sntrup761x25519-sha512: OpenSSH
			// 8.5+ (default since 9.0), hybrid Streamlined NTRU Prime/X25519 —
			// listed second as a fallback for servers/clients predating 9.9.
			before := `# sshd_config / ssh_config (classical key exchange only)
KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256`

			after := `# mlkem768x25519-sha256: OpenSSH 9.9+ (default since 10.0), FIPS 203 hybrid.
# sntrup761x25519-sha512: OpenSSH 8.5+ (default since 9.0), fallback for older peers.
KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512`

			return &Snippet{
				Language:    "config",
				Before:      before,
				After:       after,
				Explanation: "Add mlkem768x25519-sha256 (OpenSSH 9.9+, FIPS 203) and sntrup761x25519-sha512 (OpenSSH 8.5+) hybrid post-quantum key exchange to KexAlgorithms.",
			}

		default: // "generic" — no server-specific directive can be assumed safely.
			return genericConfigSnippet(family, "ML-KEM-768")
		}
	}

	return nil
}

// genericConfigSnippet returns server-agnostic migration guidance for config
// paths where configServerType could not identify a known server (or, for
// the "sign" family, identified "ssh" — SSH host-key signatures have no
// shipping NIST-standard PQC replacement, so no specific directive is safe to
// assume). defaultTarget names the algorithm to recommend when the caller
// didn't already bake one into an existing directive example.
func genericConfigSnippet(family, defaultTarget string) *Snippet {
	if family == "sign" {
		before := `# Classical certificate/key configuration (directive names vary by server)
# e.g. certificate_file = /etc/ssl/certs/server-rsa.crt`

		after := `# Replace the classical certificate with an ` + defaultTarget + pqcStdSuffix(defaultTarget) + ` certificate.
# Generate with: openssl genpkey -algorithm ` + defaultTarget + `
# This config format was not recognised — consult your server's documentation
# for its certificate/key directive name; do not assume another server's syntax.`

		return &Snippet{
			Language:    "config",
			Before:      before,
			After:       after,
			Explanation: "Replace the classical certificate with an " + defaultTarget + pqcStdSuffix(defaultTarget) + " certificate — unrecognised config format, apply to your server's certificate directive.",
		}
	}

	before := `# Classical TLS/key-exchange configuration (directive names vary by server)
# e.g. key_exchange_curves = secp256r1`

	after := `# Add a PQC hybrid key-exchange group, e.g. X25519MLKEM768` + pqcStdSuffix("ML-KEM-768") + `.
# This config format was not recognised — consult your server's documentation
# for its cipher/curve/key-exchange directive name; do not assume another server's syntax.`

	return &Snippet{
		Language:    "config",
		Before:      before,
		After:       after,
		Explanation: "Add a PQC hybrid key-exchange group (e.g. X25519MLKEM768, FIPS 203) — unrecognised config format, apply to your server's cipher/curve directive.",
	}
}

// ---------------------------------------------------------------------------
// JavaScript / TypeScript snippets
// ---------------------------------------------------------------------------

// nodeKeyType converts a canonical target algorithm ("ML-DSA-65") into the
// node:crypto asymmetricKeyType string ("ml-dsa-65"). Verified against the
// Node.js 24.7+ crypto docs, which name ML-DSA/ML-KEM key types this way.
func nodeKeyType(targetAlg string) string {
	return strings.ToLower(targetAlg)
}

// jsSnippet returns Node.js migration snippets for the given family.
// lang is "javascript" or "typescript" and is reflected in Snippet.Language.
func jsSnippet(lang, family, targetAlg string) *Snippet {
	keyType := nodeKeyType(targetAlg)

	switch family {
	case "sign":
		before := `const { createSign } = require('crypto');

const sign = createSign('RSA-SHA256');
sign.update(message);
const signature = sign.sign(privateKey);`

		after := `// Node.js 24.7+: node:crypto has native ML-DSA sign()/verify() (OpenSSL 3.5+).
// Browsers or older Node: use @noble/post-quantum (npm install @noble/post-quantum).
const { generateKeyPairSync, sign, verify } = require('node:crypto');

const { publicKey, privateKey } = generateKeyPairSync('` + keyType + `');
const signature = sign(null, message, privateKey);
const isValid = verify(null, message, publicKey, signature);`

		return &Snippet{
			Language:    lang,
			Before:      before,
			After:       after,
			Explanation: "Replace RSA/ECDSA signing with " + targetAlg + pqcStdSuffix(targetAlg) + " via node:crypto (Node.js 24.7+).",
		}

	case "kem":
		before := `const { createECDH } = require('crypto');

const ecdh = createECDH('prime256v1');
ecdh.generateKeys();
const sharedSecret = ecdh.computeSecret(peerPublicKey);`

		after := `// Node.js 24.7+: node:crypto has native ML-KEM encapsulate()/decapsulate() (OpenSSL 3.5+).
// Browsers or older Node: use @noble/post-quantum (npm install @noble/post-quantum).
const { generateKeyPairSync, encapsulate, decapsulate } = require('node:crypto');

const { publicKey, privateKey } = generateKeyPairSync('` + keyType + `');
const { ciphertext, sharedSecret } = encapsulate(publicKey);
const recovered = decapsulate(privateKey, ciphertext);`

		return &Snippet{
			Language:    lang,
			Before:      before,
			After:       after,
			Explanation: "Replace ECDH key exchange with " + targetAlg + pqcStdSuffix(targetAlg) + " via node:crypto (Node.js 24.7+).",
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// C / C++ snippets
// ---------------------------------------------------------------------------

// cSnippet returns OpenSSL-based C/C++ migration snippets for the given family.
// lang is "c" or "cpp" and is reflected in Snippet.Language.
func cSnippet(lang, family, targetAlg string) *Snippet {
	switch family {
	case "sign":
		before := `EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
EVP_PKEY_keygen_init(ctx);
EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
EVP_PKEY *pkey = NULL;
EVP_PKEY_keygen(ctx, &pkey);`

		after := `/* OpenSSL 3.5+: ML-DSA is available natively. */
/* For OpenSSL < 3.5, load oqs-provider: OSSL_PROVIDER_load(NULL, "oqsprovider") */
EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "` + targetAlg + `", NULL);
EVP_PKEY_keygen_init(ctx);
EVP_PKEY *pkey = NULL;
EVP_PKEY_keygen(ctx, &pkey);`

		return &Snippet{
			Language:    lang,
			Before:      before,
			After:       after,
			Explanation: "Replace RSA/ECDSA key generation with " + targetAlg + pqcStdSuffix(targetAlg) + " via OpenSSL 3.5+ or oqs-provider.",
		}

	case "kem":
		before := `EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
EVP_PKEY_keygen_init(ctx);
EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1);
EVP_PKEY *pkey = NULL;
EVP_PKEY_keygen(ctx, &pkey);`

		after := `/* OpenSSL 3.5+: ML-KEM and X25519MLKEM768 hybrid are available natively. */
/* For OpenSSL < 3.5, load oqs-provider: OSSL_PROVIDER_load(NULL, "oqsprovider") */
/* Use "X25519MLKEM768" as the name for the hybrid key exchange variant. */
EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "` + targetAlg + `", NULL);
EVP_PKEY_keygen_init(ctx);
EVP_PKEY *pkey = NULL;
EVP_PKEY_keygen(ctx, &pkey);`

		return &Snippet{
			Language:    lang,
			Before:      before,
			After:       after,
			Explanation: "Replace ECDH/X25519 key exchange with " + targetAlg + pqcStdSuffix(targetAlg) + " via OpenSSL 3.5+ or oqs-provider.",
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// C# snippets
// ---------------------------------------------------------------------------

// csharpAlgorithmVariant converts a canonical target algorithm ("ML-DSA-65")
// into the .NET 10 MLDsaAlgorithm/MLKemAlgorithm enum member name
// ("MLDsa65"/"MLKem768"). Verified against the MLDsaAlgorithm/MLKemAlgorithm
// static members documented for System.Security.Cryptography in .NET 10
// (MLDsa44/65/87, MLKem512/768/1024).
func csharpAlgorithmVariant(targetAlg string) string {
	parts := strings.Split(targetAlg, "-")
	var b strings.Builder
	for i, p := range parts {
		if p == "" {
			continue
		}
		if i == 0 || (p[0] >= '0' && p[0] <= '9') {
			// "ML" prefix and numeric suffixes ("65", "768") pass through
			// unchanged; only the middle family segment gets Title-cased.
			b.WriteString(strings.ToUpper(p[:1]) + p[1:])
			continue
		}
		b.WriteString(strings.ToUpper(p[:1]) + strings.ToLower(p[1:]))
	}
	return b.String()
}

func csharpSnippet(family, targetAlg string) *Snippet {
	variant := csharpAlgorithmVariant(targetAlg)

	switch family {
	case "sign":
		before := `using var rsa = RSA.Create(2048);
byte[] signature = rsa.SignData(
    message, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);`

		after := `// .NET 10+: System.Security.Cryptography.MLDsa is built in ([Experimental] —
// requires Linux+OpenSSL 3.5+ or Windows with CNG PQC support; not macOS yet).
// Pre-.NET-10 or macOS: use BouncyCastle.Cryptography instead
// (Org.BouncyCastle.Pqc.Crypto.MLDsa / MLDsaParameters.ml_dsa_65).
using System.Security.Cryptography;

using MLDsa key = MLDsa.GenerateKey(MLDsaAlgorithm.` + variant + `);
byte[] signature = new byte[key.Algorithm.SignatureSizeInBytes];
key.SignData(message, signature);
bool isValid = key.VerifyData(message, signature);`

		return &Snippet{
			Language:    "csharp",
			Before:      before,
			After:       after,
			Explanation: "Replace RSA/ECDSA signing with " + targetAlg + pqcStdSuffix(targetAlg) + " via .NET 10's native MLDsa class.",
		}

	case "kem":
		before := `using var ecdh = ECDiffieHellman.Create();
byte[] publicKey = ecdh.PublicKey.ExportSubjectPublicKeyInfo();
byte[] sharedSecret = ecdh.DeriveKeyFromHash(
    peerPublicKey, HashAlgorithmName.SHA256);`

		after := `// .NET 10+: System.Security.Cryptography.MLKem is built in and stable
// (Linux+OpenSSL 3.5+ or Windows with CNG PQC support; not macOS yet).
// Pre-.NET-10 or macOS: use BouncyCastle.Cryptography instead
// (Org.BouncyCastle.Pqc.Crypto.MLKem / MLKemParameters.ml_kem_768).
using System.Security.Cryptography;

using MLKem privateKey = MLKem.GenerateKey(MLKemAlgorithm.` + variant + `);
using MLKem publicKey = MLKem.ImportEncapsulationKey(MLKemAlgorithm.` + variant + `, privateKey.ExportEncapsulationKey());
publicKey.Encapsulate(out byte[] ciphertext, out byte[] sharedSecret);
byte[] sharedSecret2 = privateKey.Decapsulate(ciphertext);`

		return &Snippet{
			Language:    "csharp",
			Before:      before,
			After:       after,
			Explanation: "Replace ECDH key exchange with " + targetAlg + pqcStdSuffix(targetAlg) + " via .NET 10's native MLKem class.",
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Swift snippets
// ---------------------------------------------------------------------------

// pqcStandard returns the FIPS standard label for a target algorithm name.
//
// Delegates to fipsStandardFor so the SLH-DSA → FIPS 205 correction lands
// in every snippet that previously called pqcStandard (swiftSnippet was the
// last consumer; previously labelled SLH-DSA targets as "FIPS 204"). Kept
// as a thin alias so callers don't all need to be rewritten.
func pqcStandard(targetAlg string) string {
	return fipsStandardFor(targetAlg)
}

// swiftMLDSAType picks the CryptoKit ML-DSA type for a target algorithm.
// CryptoKit (iOS 26/macOS 26) exposes only MLDSA65 and MLDSA87 — there is no
// MLDSA44 type — so an ML-DSA-44 target renders the nearest available type
// (MLDSA65) with a note explaining the substitution.
func swiftMLDSAType(targetAlg string) (typeName, note string) {
	if strings.Contains(targetAlg, "87") {
		return "MLDSA87", ""
	}
	if strings.Contains(targetAlg, "44") {
		return "MLDSA65", "// CryptoKit has no MLDSA44 type; using MLDSA65 (the nearest available parameter set).\n"
	}
	return "MLDSA65", ""
}

// swiftMLKEMType picks the CryptoKit ML-KEM type for a target algorithm.
// CryptoKit (iOS 26/macOS 26) exposes only MLKEM768 and MLKEM1024 — there is
// no MLKEM512 type — so an ML-KEM-512 target renders the nearest available
// type (MLKEM768) with a note explaining the substitution.
func swiftMLKEMType(targetAlg string) (typeName, note string) {
	if strings.Contains(targetAlg, "1024") {
		return "MLKEM1024", ""
	}
	if strings.Contains(targetAlg, "512") {
		return "MLKEM768", "// CryptoKit has no MLKEM512 type; using MLKEM768 (the nearest available parameter set).\n"
	}
	return "MLKEM768", ""
}

// swiftSnippet returns Apple CryptoKit migration snippets for the given
// family. iOS 26 / macOS 26 CryptoKit has native ML-KEM/ML-DSA types; older
// OS versions or non-Apple platforms fall back to swift-crypto (a
// CryptoKit-API-compatible package covering Linux/older-OS backends) or
// liboqs-swift.
func swiftSnippet(family, targetAlg string) *Snippet {
	switch family {
	case "sign":
		before := `import CryptoKit

let privateKey = Curve25519.Signing.PrivateKey()
let signature = try privateKey.signature(for: data)
let isValid = publicKey.isValidSignature(signature, for: data)`

		mldsaType, note := swiftMLDSAType(targetAlg)

		after := `// iOS 26+ / macOS 26+: CryptoKit has native ML-DSA signing.
// Older OS or Linux: use swift-crypto (CryptoKit-API-compatible) or liboqs-swift.
` + note + `import CryptoKit

let signingKey = ` + mldsaType + `.PrivateKey()
let signature = try signingKey.signature(for: data)
let isValid = signingKey.publicKey.isValidSignature(signature, for: data)
// Target algorithm: ` + targetAlg + pqcStdSuffix(targetAlg)

		return &Snippet{
			Language:    "swift",
			Before:      before,
			After:       after,
			Explanation: "Replace Curve25519 signing with " + targetAlg + pqcStdSuffix(targetAlg) + " via Apple CryptoKit (iOS 26+/macOS 26+).",
		}

	case "kem":
		before := `import CryptoKit

let privateKey = Curve25519.KeyAgreement.PrivateKey()
let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: peerPublicKey)`

		mlkemType, note := swiftMLKEMType(targetAlg)

		after := `// iOS 26+ / macOS 26+: CryptoKit has native ML-KEM key encapsulation.
// Older OS or Linux: use swift-crypto (CryptoKit-API-compatible) or liboqs-swift.
` + note + `import CryptoKit

let privateKey = ` + mlkemType + `.PrivateKey()
let (ciphertext, sharedSecret) = privateKey.publicKey.encapsulate()
let recovered = try privateKey.decapsulate(ciphertext)
// Target algorithm: ` + targetAlg + pqcStdSuffix(targetAlg)

		return &Snippet{
			Language:    "swift",
			Before:      before,
			After:       after,
			Explanation: "Replace Curve25519 key agreement with " + targetAlg + pqcStdSuffix(targetAlg) + " via Apple CryptoKit (iOS 26+/macOS 26+).",
		}
	}
	return nil
}
