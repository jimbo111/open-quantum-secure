package keyfile

import (
	"bytes"
	"crypto/dsa" //nolint:staticcheck // read-only inventory of legacy DSA material
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
	"github.com/jimbo111/open-quantum-secure/pkg/quantum"
)

// privateKeyRawID marks key material whose mere presence in a repository is a
// finding: an attacker with repo access holds the key, and the classifier
// additionally scores the algorithm's quantum risk from Algorithm.Name.
const privateKeyRawID = "private-key committed to repository"

// scanPEM walks every PEM block in data, tracking the line number of each
// BEGIN marker so findings carry accurate locations.
func scanPEM(path string, data []byte) []findings.UnifiedFinding {
	var out []findings.UnifiedFinding
	line := 1
	rest := data
	for i := 0; i < 10000; i++ { // hard cap against pathological inputs
		block, next := pem.Decode(rest)
		if block == nil {
			break
		}
		consumed := rest[:len(rest)-len(next)]
		blockLine := line
		if idx := bytes.Index(consumed, []byte("-----BEGIN ")); idx >= 0 {
			blockLine = line + bytes.Count(consumed[:idx], []byte("\n"))
		}
		if f := findingForPEMBlock(path, blockLine, block); f != nil {
			out = append(out, *f)
		}
		line += bytes.Count(consumed, []byte("\n"))
		rest = next
	}
	return out
}

// findingForPEMBlock maps one decoded PEM block to a finding, or nil when the
// block type is unrecognized or unparseable.
func findingForPEMBlock(path string, line int, block *pem.Block) *findings.UnifiedFinding {
	encrypted := block.Type == "ENCRYPTED PRIVATE KEY" || block.Headers["DEK-Info"] != ""

	switch block.Type {
	case "CERTIFICATE", "TRUSTED CERTIFICATE":
		return certificateFinding(path, line, block.Bytes)

	case "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST":
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return nil
		}
		name, size, curve := publicKeyInfo(csr.PublicKey)
		if name == "" {
			return nil
		}
		f := newFinding(path, line, &findings.Algorithm{
			Name: name, Primitive: "signature", KeySize: size, Curve: curve,
		}, fmt.Sprintf("certificate-request cn=%q", csr.Subject.CommonName), findings.ConfidenceHigh)
		return &f

	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil
		}
		return publicKeyFinding(path, line, pub)

	case "RSA PUBLIC KEY":
		pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil
		}
		return publicKeyFinding(path, line, pub)

	case "ENCRYPTED PRIVATE KEY":
		// PKCS#8 encrypted envelope — inner algorithm is opaque.
		f := newFinding(path, line, nil, "encrypted-private-key committed to repository", findings.ConfidenceMedium)
		return &f

	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil
		}
		return privateKeyFinding(path, line, key)

	case "RSA PRIVATE KEY":
		if encrypted {
			return encryptedKeyFinding(path, line, "RSA", "asymmetric")
		}
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil
		}
		return privateKeyFinding(path, line, key)

	case "EC PRIVATE KEY":
		if encrypted {
			return encryptedKeyFinding(path, line, "ECDSA", "signature")
		}
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil
		}
		return privateKeyFinding(path, line, key)

	case "DSA PRIVATE KEY":
		if encrypted {
			return encryptedKeyFinding(path, line, "DSA", "signature")
		}
		if bits := dsaPrivateKeyBits(block.Bytes); bits > 0 {
			f := newFinding(path, line, &findings.Algorithm{
				Name: "DSA", Primitive: "signature", KeySize: bits,
			}, privateKeyRawID, findings.ConfidenceHigh)
			return &f
		}
		return encryptedKeyFinding(path, line, "DSA", "signature")

	case "OPENSSH PRIVATE KEY":
		return opensshPrivateKeyFinding(path, line, block.Bytes)
	}

	// Unknown block type carrying DEK-Info: still evidence of an encrypted key.
	if encrypted {
		f := newFinding(path, line, nil, "encrypted-private-key committed to repository", findings.ConfidenceMedium)
		return &f
	}
	return nil
}

// scanDERCertificate handles raw DER files (.der, and binary .cer/.crt).
func scanDERCertificate(path string, data []byte) []findings.UnifiedFinding {
	if f := certificateFinding(path, 1, data); f != nil {
		return []findings.UnifiedFinding{*f}
	}
	return nil
}

// certificateFinding parses one DER certificate and emits a finding carrying
// the subject-key algorithm, size, subject CN, and expiry.
func certificateFinding(path string, line int, der []byte) *findings.UnifiedFinding {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		// Possibly a PQC certificate Go cannot parse — fall back to the raw
		// signature-algorithm OID.
		if name := pqcSigAlgNameFromDER(der); name != "" {
			f := newFinding(path, line, &findings.Algorithm{Name: name, Primitive: "signature"},
				"certificate (PQC signature algorithm)", findings.ConfidenceMediumHigh)
			return &f
		}
		return nil
	}

	name, size, curve := publicKeyInfo(cert.PublicKey)
	if name == "" {
		// Unknown public key algorithm — try the signature OID (PQC certs
		// surface as UnknownSignatureAlgorithm in Go's x509).
		if pqc := pqcSigAlgNameFromDER(der); pqc != "" {
			name = pqc
		} else if cert.PublicKeyAlgorithm != x509.UnknownPublicKeyAlgorithm {
			name = cert.PublicKeyAlgorithm.String()
		}
	}

	rawID := fmt.Sprintf("certificate cn=%q not-after=%s", cert.Subject.CommonName, cert.NotAfter.Format("2006-01-02"))
	if name == "" {
		f := newFinding(path, line, nil, rawID+" (unknown algorithm)", findings.ConfidenceMedium)
		return &f
	}
	f := newFinding(path, line, &findings.Algorithm{
		Name: name, Primitive: "signature", KeySize: size, Curve: curve,
	}, rawID, findings.ConfidenceHigh)
	return &f
}

// certificateASN mirrors the top-level X.509 Certificate SEQUENCE just enough
// to extract the outer signature-algorithm OID without full parsing.
type certificateASN struct {
	TBSCertificate     asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// pqcSigAlgNameFromDER extracts the certificate's signature-algorithm OID and
// resolves it against the PQC OID table. Returns "" when unknown.
func pqcSigAlgNameFromDER(der []byte) string {
	var c certificateASN
	if _, err := asn1.Unmarshal(der, &c); err != nil {
		return ""
	}
	return quantum.LookupPQCSigAlgName(c.SignatureAlgorithm.Algorithm.String())
}

// publicKeyFinding emits a finding for a parsed public key value.
func publicKeyFinding(path string, line int, pub any) *findings.UnifiedFinding {
	name, size, curve := publicKeyInfo(pub)
	if name == "" {
		return nil
	}
	f := newFinding(path, line, &findings.Algorithm{
		Name: name, Primitive: primitiveFor(name), KeySize: size, Curve: curve,
	}, "public-key", findings.ConfidenceHigh)
	return &f
}

// privateKeyFinding emits a finding for a parsed private key value.
func privateKeyFinding(path string, line int, key any) *findings.UnifiedFinding {
	var pub any
	switch k := key.(type) {
	case *rsa.PrivateKey:
		pub = &k.PublicKey
	case *ecdsa.PrivateKey:
		pub = &k.PublicKey
	case ed25519.PrivateKey:
		pub = k.Public()
	case *ecdh.PrivateKey:
		pub = k.PublicKey()
	default:
		return nil
	}
	name, size, curve := publicKeyInfo(pub)
	if name == "" {
		return nil
	}
	f := newFinding(path, line, &findings.Algorithm{
		Name: name, Primitive: primitiveFor(name), KeySize: size, Curve: curve,
	}, privateKeyRawID, findings.ConfidenceHigh)
	return &f
}

// encryptedKeyFinding emits a finding for an encrypted private key whose
// algorithm is determinable from the PEM type but whose size is opaque.
func encryptedKeyFinding(path string, line int, algName, primitive string) *findings.UnifiedFinding {
	f := newFinding(path, line, &findings.Algorithm{Name: algName, Primitive: primitive},
		"encrypted-private-key committed to repository", findings.ConfidenceHigh)
	return &f
}

// publicKeyInfo returns the algorithm name, key size in bits, and curve name
// for a stdlib public key value. Empty name means unrecognized.
func publicKeyInfo(pub any) (name string, size int, curve string) {
	switch p := pub.(type) {
	case *rsa.PublicKey:
		return "RSA", p.N.BitLen(), ""
	case *ecdsa.PublicKey:
		if params := p.Params(); params != nil {
			return "ECDSA", params.BitSize, params.Name
		}
		return "ECDSA", 0, ""
	case ed25519.PublicKey:
		return "Ed25519", 256, ""
	case *ecdh.PublicKey:
		if p.Curve() == ecdh.X25519() {
			return "X25519", 256, "X25519"
		}
		return "ECDH", ecdhCurveBits(p.Curve()), fmt.Sprintf("%v", p.Curve())
	case *dsa.PublicKey:
		return "DSA", p.P.BitLen(), ""
	}
	return "", 0, ""
}

// primitiveFor maps an algorithm name to the UnifiedFinding primitive label.
func primitiveFor(name string) string {
	switch name {
	case "RSA":
		return "asymmetric"
	case "X25519", "ECDH":
		return "key-agree"
	default:
		return "signature"
	}
}

func ecdhCurveBits(c ecdh.Curve) int {
	switch c {
	case ecdh.P256():
		return 256
	case ecdh.P384():
		return 384
	case ecdh.P521():
		return 521
	case ecdh.X25519():
		return 256
	}
	return 0
}

// opensslDSAKey mirrors OpenSSL's traditional DSA private key ASN.1 layout.
type opensslDSAKey struct {
	Version int
	P, Q, G *big.Int
	Y, X    *big.Int
}

// dsaPrivateKeyBits returns the modulus bit length of an OpenSSL-format DSA
// private key, or 0 on parse failure.
func dsaPrivateKeyBits(der []byte) int {
	var k opensslDSAKey
	if _, err := asn1.Unmarshal(der, &k); err != nil || k.P == nil {
		return 0
	}
	return k.P.BitLen()
}
