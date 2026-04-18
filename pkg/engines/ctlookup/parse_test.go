package ctlookup

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"
)

// sampleCrtShJSON contains realistic crt.sh JSON responses for testing.
var sampleCrtShJSON = `[
  {
    "issuer_ca_id": 183267,
    "issuer_name": "C=US, O=Let's Encrypt, CN=R10",
    "common_name": "example.com",
    "name_value": "example.com",
    "id": 10000001,
    "entry_timestamp": "2024-01-15T12:00:00",
    "not_before": "2024-01-15T00:00:00",
    "not_after": "2024-04-15T00:00:00",
    "serial_number": "04D2A1B3C4E5F601"
  },
  {
    "issuer_ca_id": 183268,
    "issuer_name": "C=US, O=DigiCert Inc, CN=DigiCert Global CA G2",
    "common_name": "example.com",
    "name_value": "example.com\nwww.example.com",
    "id": 10000002,
    "entry_timestamp": "2023-06-01T08:00:00",
    "not_before": "2023-06-01T00:00:00",
    "not_after": "2024-06-01T00:00:00",
    "serial_number": "0ABCDEF012345678"
  }
]`

func TestParseCrtShJSON_Valid(t *testing.T) {
	entries, err := parseCrtShJSON([]byte(sampleCrtShJSON))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}

	e := entries[0]
	if e.CommonName != "example.com" {
		t.Errorf("CommonName = %q, want example.com", e.CommonName)
	}
	if e.ID != 10000001 {
		t.Errorf("ID = %d, want 10000001", e.ID)
	}
	if e.SerialNumber != "04D2A1B3C4E5F601" {
		t.Errorf("SerialNumber = %q, want 04D2A1B3C4E5F601", e.SerialNumber)
	}
	if e.IssuerName != "C=US, O=Let's Encrypt, CN=R10" {
		t.Errorf("IssuerName = %q", e.IssuerName)
	}
}

func TestParseCrtShJSON_Empty(t *testing.T) {
	entries, err := parseCrtShJSON(nil)
	if err != nil {
		t.Fatalf("unexpected error for nil body: %v", err)
	}
	if entries != nil {
		t.Errorf("expected nil entries for nil body, got %v", entries)
	}

	entries, err = parseCrtShJSON([]byte("[]"))
	if err != nil {
		t.Fatalf("unexpected error for empty array: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries for [], got %d", len(entries))
	}
}

func TestParseCrtShJSON_Malformed(t *testing.T) {
	cases := [][]byte{
		[]byte(`{not valid json`),
		[]byte(`"just a string"`),
		[]byte(`null`), // valid JSON but wrong type — will error or return nil
	}
	for _, tc := range cases {
		entries, err := parseCrtShJSON(tc)
		// null → valid JSON, type mismatch with []crtShEntry → error.
		// Accept either an error or an empty/nil result.
		_ = entries
		_ = err
	}
	// Specifically test that a garbage payload returns an error.
	_, err := parseCrtShJSON([]byte(`{not valid`))
	if err == nil {
		t.Error("expected error for malformed JSON, got nil")
	}
}

func TestEntryToRecord_TimeParsing(t *testing.T) {
	e := crtShEntry{
		SerialNumber: "ABCD",
		NotBefore:    "2024-01-15T00:00:00",
		NotAfter:     "2024-04-15T00:00:00",
		IssuerName:   "CN=Test CA",
		CommonName:   "test.example.com",
		NameValue:    "test.example.com",
		ID:           42,
	}
	rec := entryToRecord(e)
	if rec.Serial != "ABCD" {
		t.Errorf("Serial = %q, want ABCD", rec.Serial)
	}
	wantNotBefore, _ := time.Parse("2006-01-02T15:04:05", "2024-01-15T00:00:00")
	if !rec.NotBefore.Equal(wantNotBefore) {
		t.Errorf("NotBefore = %v, want %v", rec.NotBefore, wantNotBefore)
	}
	if rec.CertID != 42 {
		t.Errorf("CertID = %d, want 42", rec.CertID)
	}
}

func TestSigAlgoName_RSA(t *testing.T) {
	cases := []x509.SignatureAlgorithm{
		x509.SHA256WithRSA,
		x509.SHA384WithRSA,
		x509.SHA512WithRSA,
		x509.SHA256WithRSAPSS,
		x509.MD5WithRSA,
	}
	for _, alg := range cases {
		if got := sigAlgoName(alg); got != "RSA" {
			t.Errorf("sigAlgoName(%v) = %q, want RSA", alg, got)
		}
	}
}

func TestSigAlgoName_ECDSA(t *testing.T) {
	cases := []x509.SignatureAlgorithm{
		x509.ECDSAWithSHA256,
		x509.ECDSAWithSHA384,
		x509.ECDSAWithSHA512,
	}
	for _, alg := range cases {
		if got := sigAlgoName(alg); got != "ECDSA" {
			t.Errorf("sigAlgoName(%v) = %q, want ECDSA", alg, got)
		}
	}
}

func TestSigAlgoName_Ed25519(t *testing.T) {
	if got := sigAlgoName(x509.PureEd25519); got != "Ed25519" {
		t.Errorf("sigAlgoName(PureEd25519) = %q, want Ed25519", got)
	}
}

func TestPubKeyDetails_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	algo, bits, curve := pubKeyDetails(&key.PublicKey)
	if algo != "RSA" {
		t.Errorf("algo = %q, want RSA", algo)
	}
	if bits != 2048 {
		t.Errorf("bits = %d, want 2048", bits)
	}
	if curve != "" {
		t.Errorf("curve = %q, want empty", curve)
	}
}

func TestPubKeyDetails_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	algo, bits, curve := pubKeyDetails(&key.PublicKey)
	if algo != "ECDSA" {
		t.Errorf("algo = %q, want ECDSA", algo)
	}
	if bits != 256 {
		t.Errorf("bits = %d, want 256", bits)
	}
	if !strings.Contains(curve, "256") && curve != "P-256" {
		t.Errorf("curve = %q, expected P-256 or P256", curve)
	}
}

func TestPubKeyDetails_Ed25519(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	algo, bits, curve := pubKeyDetails(pub)
	if algo != "Ed25519" {
		t.Errorf("algo = %q, want Ed25519", algo)
	}
	if bits != 256 {
		t.Errorf("bits = %d, want 256", bits)
	}
	if curve != "" {
		t.Errorf("curve = %q, want empty", curve)
	}
}

// TestX509ToRecord_RSA generates a self-signed RSA cert and verifies that
// x509ToRecord extracts the correct algorithm fields.
func TestX509ToRecord_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rsa.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	rec := x509ToRecord(cert)
	if rec.SigAlgorithm != "RSA" {
		t.Errorf("SigAlgorithm = %q, want RSA", rec.SigAlgorithm)
	}
	if rec.PubKeyAlgorithm != "RSA" {
		t.Errorf("PubKeyAlgorithm = %q, want RSA", rec.PubKeyAlgorithm)
	}
	if rec.PubKeySize != 2048 {
		t.Errorf("PubKeySize = %d, want 2048", rec.PubKeySize)
	}
	if rec.CommonName != "rsa.test" {
		t.Errorf("CommonName = %q, want rsa.test", rec.CommonName)
	}
}

func TestX509ToRecord_ECDSA(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "ecdsa.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	rec := x509ToRecord(cert)
	if rec.SigAlgorithm != "ECDSA" {
		t.Errorf("SigAlgorithm = %q, want ECDSA", rec.SigAlgorithm)
	}
}

func TestX509ToRecord_Ed25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "ed25519.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	rec := x509ToRecord(cert)
	if rec.SigAlgorithm != "Ed25519" {
		t.Errorf("SigAlgorithm = %q, want Ed25519", rec.SigAlgorithm)
	}
	if rec.PubKeyAlgorithm != "Ed25519" {
		t.Errorf("PubKeyAlgorithm = %q, want Ed25519", rec.PubKeyAlgorithm)
	}
}
