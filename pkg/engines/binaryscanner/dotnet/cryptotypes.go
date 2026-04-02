// Package dotnet scans .NET assemblies (PE files with a CLI header) for
// cryptographic API references. It searches section data for known fully-
// qualified .NET crypto type names and reports each match as a UnifiedFinding.
package dotnet

// cryptoTypeEntry describes a single .NET crypto type.
type cryptoTypeEntry struct {
	algorithm string
	primitive string
	pqcSafe   bool
}

// cryptoTypes maps fully-qualified .NET type names to their cryptographic
// metadata. The keys are the exact strings that appear in .NET assembly
// metadata and string heaps, enabling byte-level search.
//
// Entries cover:
//   - System.Security.Cryptography (BCL built-ins)
//   - BouncyCastle for .NET (Org.BouncyCastle.*)
//   - Post-quantum candidates via BouncyCastle PQC namespace
var cryptoTypes = map[string]cryptoTypeEntry{
	// ---- System.Security.Cryptography — symmetric ----
	"System.Security.Cryptography.Aes": {
		algorithm: "AES",
		primitive: "symmetric",
	},
	"System.Security.Cryptography.AesGcm": {
		algorithm: "AES-GCM",
		primitive: "ae",
	},
	"System.Security.Cryptography.AesCcm": {
		algorithm: "AES-CCM",
		primitive: "ae",
	},
	"System.Security.Cryptography.TripleDES": {
		algorithm: "3DES",
		primitive: "symmetric",
	},
	"System.Security.Cryptography.TripleDESCryptoServiceProvider": {
		algorithm: "3DES",
		primitive: "symmetric",
	},
	"System.Security.Cryptography.DES": {
		algorithm: "DES",
		primitive: "symmetric",
	},
	"System.Security.Cryptography.DESCryptoServiceProvider": {
		algorithm: "DES",
		primitive: "symmetric",
	},
	"System.Security.Cryptography.RC2": {
		algorithm: "RC2",
		primitive: "symmetric",
	},
	"System.Security.Cryptography.RC2CryptoServiceProvider": {
		algorithm: "RC2",
		primitive: "symmetric",
	},

	// ---- System.Security.Cryptography — asymmetric / PKE ----
	"System.Security.Cryptography.RSA": {
		algorithm: "RSA",
		primitive: "pke",
	},
	"System.Security.Cryptography.RSACryptoServiceProvider": {
		algorithm: "RSA",
		primitive: "pke",
	},
	"System.Security.Cryptography.RSACng": {
		algorithm: "RSA",
		primitive: "pke",
	},

	// ---- System.Security.Cryptography — signatures ----
	"System.Security.Cryptography.DSA": {
		algorithm: "DSA",
		primitive: "signature",
	},
	"System.Security.Cryptography.DSACng": {
		algorithm: "DSA",
		primitive: "signature",
	},
	"System.Security.Cryptography.ECDsa": {
		algorithm: "ECDSA",
		primitive: "signature",
	},
	"System.Security.Cryptography.ECDsaCng": {
		algorithm: "ECDSA",
		primitive: "signature",
	},

	// ---- System.Security.Cryptography — key exchange ----
	"System.Security.Cryptography.ECDiffieHellman": {
		algorithm: "ECDH",
		primitive: "key-exchange",
	},
	"System.Security.Cryptography.ECDiffieHellmanCng": {
		algorithm: "ECDH",
		primitive: "key-exchange",
	},

	// ---- System.Security.Cryptography — hash ----
	"System.Security.Cryptography.SHA1": {
		algorithm: "SHA-1",
		primitive: "hash",
	},
	"System.Security.Cryptography.SHA256": {
		algorithm: "SHA-256",
		primitive: "hash",
	},
	"System.Security.Cryptography.SHA384": {
		algorithm: "SHA-384",
		primitive: "hash",
	},
	"System.Security.Cryptography.SHA512": {
		algorithm: "SHA-512",
		primitive: "hash",
	},
	"System.Security.Cryptography.MD5": {
		algorithm: "MD5",
		primitive: "hash",
	},

	// ---- System.Security.Cryptography — MAC ----
	"System.Security.Cryptography.HMACSHA1": {
		algorithm: "HMAC-SHA-1",
		primitive: "mac",
	},
	"System.Security.Cryptography.HMACSHA256": {
		algorithm: "HMAC-SHA-256",
		primitive: "mac",
	},
	"System.Security.Cryptography.HMACSHA384": {
		algorithm: "HMAC-SHA-384",
		primitive: "mac",
	},
	"System.Security.Cryptography.HMACSHA512": {
		algorithm: "HMAC-SHA-512",
		primitive: "mac",
	},
	"System.Security.Cryptography.HMACMD5": {
		algorithm: "HMAC-MD5",
		primitive: "mac",
	},

	// ---- System.Security.Cryptography — KDF ----
	"System.Security.Cryptography.Rfc2898DeriveBytes": {
		algorithm: "PBKDF2",
		primitive: "kdf",
	},

	// ---- System.Security.Cryptography — protocols / PKI ----
	"System.Security.Cryptography.Pkcs.SignedCms": {
		algorithm: "CMS",
		primitive: "protocol",
	},
	"System.Security.Cryptography.X509Certificates.X509Certificate2": {
		algorithm: "X.509",
		primitive: "protocol",
	},

	// ---- System.Security.Cryptography — RNG ----
	"System.Security.Cryptography.RandomNumberGenerator": {
		algorithm: "RNG",
		primitive: "rng",
	},

	// ---- BouncyCastle for .NET — symmetric ----
	"Org.BouncyCastle.Crypto.Engines.AesEngine": {
		algorithm: "AES",
		primitive: "symmetric",
	},
	"Org.BouncyCastle.Crypto.Engines.DesEngine": {
		algorithm: "DES",
		primitive: "symmetric",
	},

	// ---- BouncyCastle for .NET — asymmetric / PKE ----
	"Org.BouncyCastle.Crypto.Engines.RsaEngine": {
		algorithm: "RSA",
		primitive: "pke",
	},

	// ---- BouncyCastle for .NET — hash ----
	"Org.BouncyCastle.Crypto.Digests.Sha256Digest": {
		algorithm: "SHA-256",
		primitive: "hash",
	},

	// ---- BouncyCastle for .NET — signatures ----
	"Org.BouncyCastle.Crypto.Signers.Ed25519Signer": {
		algorithm: "Ed25519",
		primitive: "signature",
	},

	// ---- BouncyCastle PQC — post-quantum safe ----
	"Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber": {
		algorithm: "ML-KEM",
		primitive: "kem",
		pqcSafe:   true,
	},
	"Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium": {
		algorithm: "ML-DSA",
		primitive: "signature",
		pqcSafe:   true,
	},
}
