package ctlookup

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"time"
)

// crtShEntry is a single JSON record from the crt.sh search API
// (https://crt.sh/?q=<hostname>&output=json).
type crtShEntry struct {
	IssuerCAID     int    `json:"issuer_ca_id"`
	IssuerName     string `json:"issuer_name"`
	CommonName     string `json:"common_name"`
	NameValue      string `json:"name_value"`
	ID             int64  `json:"id"`
	EntryTimestamp string `json:"entry_timestamp"`
	NotBefore      string `json:"not_before"`
	NotAfter       string `json:"not_after"`
	SerialNumber   string `json:"serial_number"`
}

// certRecord holds normalised metadata for one certificate.
type certRecord struct {
	Serial          string
	NotBefore       time.Time
	NotAfter        time.Time
	IssuerName      string
	CommonName      string
	NameValue       string
	SigAlgorithm    string // family name compatible with quantum.ClassifyAlgorithm ("RSA", "ECDSA", etc.)
	PubKeyAlgorithm string // same family; may differ from SigAlgorithm for cross-signed certs
	PubKeySize      int    // bits; 0 when unavailable
	PubKeyCurve     string // curve name for ECDSA (e.g. "P-256"); empty otherwise
	CertID          int64  // crt.sh internal cert ID
}

// parseCrtShJSON unmarshals a crt.sh JSON response body into crtShEntry records.
// An empty body or null JSON array yields nil without error.
func parseCrtShJSON(data []byte) ([]crtShEntry, error) {
	if len(data) == 0 {
		return nil, nil
	}
	var entries []crtShEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("ctlookup: parse crt.sh JSON: %w", err)
	}
	return entries, nil
}

// crtShTimeLayouts lists timestamp formats used by crt.sh, in preference order.
var crtShTimeLayouts = []string{
	"2006-01-02T15:04:05",
	"2006-01-02T15:04:05.999",
	"2006-01-02 15:04:05",
	"2006-01-02",
}

func parseTime(s string) time.Time {
	for _, l := range crtShTimeLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// entryToRecord converts a crtShEntry (no DER cert) into a partial certRecord.
// SigAlgorithm and PubKey fields are empty until enriched by x509ToRecord.
func entryToRecord(e crtShEntry) certRecord {
	return certRecord{
		Serial:     e.SerialNumber,
		NotBefore:  parseTime(e.NotBefore),
		NotAfter:   parseTime(e.NotAfter),
		IssuerName: e.IssuerName,
		CommonName: e.CommonName,
		NameValue:  e.NameValue,
		CertID:     e.ID,
	}
}

// x509ToRecord extracts algorithm metadata from a parsed x509 certificate.
// It is authoritative: when a DER cert is available it is always preferred over
// the partial JSON-only entryToRecord.
func x509ToRecord(cert *x509.Certificate) certRecord {
	rec := certRecord{
		Serial:     cert.SerialNumber.Text(16),
		NotBefore:  cert.NotBefore,
		NotAfter:   cert.NotAfter,
		IssuerName: cert.Issuer.String(),
		CommonName: cert.Subject.CommonName,
		NameValue:  cert.Subject.CommonName,
	}
	rec.SigAlgorithm = sigAlgoName(cert.SignatureAlgorithm)
	rec.PubKeyAlgorithm, rec.PubKeySize, rec.PubKeyCurve = pubKeyDetails(cert.PublicKey)
	return rec
}

// sigAlgoName maps an x509.SignatureAlgorithm to a family name recognised by
// quantum.ClassifyAlgorithm (e.g. "RSA", "ECDSA", "Ed25519").
func sigAlgoName(alg x509.SignatureAlgorithm) string {
	switch alg {
	case x509.SHA1WithRSA, x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA,
		x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS,
		x509.MD2WithRSA, x509.MD5WithRSA:
		return "RSA"
	case x509.ECDSAWithSHA1, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
		return "ECDSA"
	case x509.PureEd25519:
		return "Ed25519"
	case x509.DSAWithSHA1, x509.DSAWithSHA256:
		return "DSA"
	default:
		return alg.String()
	}
}

// pubKeyDetails returns the algorithm family name, key size in bits, and curve
// name (ECDSA only) for a certificate public key.
func pubKeyDetails(pub interface{}) (algo string, bits int, curve string) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen(), ""
	case *ecdsa.PublicKey:
		return "ECDSA", k.Curve.Params().BitSize, k.Curve.Params().Name
	case ed25519.PublicKey:
		return "Ed25519", 256, ""
	default:
		return "unknown", 0, ""
	}
}
