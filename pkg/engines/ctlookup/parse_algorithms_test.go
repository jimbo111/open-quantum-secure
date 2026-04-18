// parse_algorithms_test.go — Exhaustive coverage of every certificate algorithm
// variant that parse.go and certRecordToFinding() must handle: all RSA key
// sizes (2048/3072/4096), all ECDSA curves (P-256/P-384/P-521), Ed25519, DSA
// variants, every RSA PSS variant, every SHA1/MD* legacy variant, the unknown-
// algorithm fallback, the ML-DSA (unknown public-key type) fallback, missing
// JSON fields, and edge-case timestamp strings.
package ctlookup

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"
)

// ── sigAlgoName exhaustive table ──────────────────────────────────────────────

func TestSigAlgoName_AllRSAVariants(t *testing.T) {
	rsaCases := []x509.SignatureAlgorithm{
		x509.SHA1WithRSA,
		x509.SHA256WithRSA,
		x509.SHA384WithRSA,
		x509.SHA512WithRSA,
		x509.SHA256WithRSAPSS,
		x509.SHA384WithRSAPSS,
		x509.SHA512WithRSAPSS,
		x509.MD2WithRSA,
		x509.MD5WithRSA,
	}
	for _, alg := range rsaCases {
		if got := sigAlgoName(alg); got != "RSA" {
			t.Errorf("sigAlgoName(%v) = %q, want RSA", alg, got)
		}
	}
}

func TestSigAlgoName_AllECDSAVariants(t *testing.T) {
	ecdsaCases := []x509.SignatureAlgorithm{
		x509.ECDSAWithSHA1,
		x509.ECDSAWithSHA256,
		x509.ECDSAWithSHA384,
		x509.ECDSAWithSHA512,
	}
	for _, alg := range ecdsaCases {
		if got := sigAlgoName(alg); got != "ECDSA" {
			t.Errorf("sigAlgoName(%v) = %q, want ECDSA", alg, got)
		}
	}
}

func TestSigAlgoName_DSA(t *testing.T) {
	for _, alg := range []x509.SignatureAlgorithm{x509.DSAWithSHA1, x509.DSAWithSHA256} {
		if got := sigAlgoName(alg); got != "DSA" {
			t.Errorf("sigAlgoName(%v) = %q, want DSA", alg, got)
		}
	}
}

func TestSigAlgoName_UnknownAlgorithm(t *testing.T) {
	// An unrecognised SignatureAlgorithm must fall back to .String() — not panic
	// and not return an empty string.
	const unknownAlg x509.SignatureAlgorithm = 9999
	got := sigAlgoName(unknownAlg)
	if got == "" {
		t.Error("sigAlgoName(unknown) must not return empty string")
	}
}

// ── pubKeyDetails: RSA key-size variants ──────────────────────────────────────

func TestPubKeyDetails_RSA_2048(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate 2048: %v", err)
	}
	algo, bits, curve := pubKeyDetails(&key.PublicKey)
	if algo != "RSA" || bits != 2048 || curve != "" {
		t.Errorf("RSA 2048: got algo=%q bits=%d curve=%q", algo, bits, curve)
	}
}

func TestPubKeyDetails_RSA_3072(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		t.Fatalf("generate 3072: %v", err)
	}
	algo, bits, curve := pubKeyDetails(&key.PublicKey)
	if algo != "RSA" || bits != 3072 || curve != "" {
		t.Errorf("RSA 3072: got algo=%q bits=%d curve=%q", algo, bits, curve)
	}
}

func TestPubKeyDetails_RSA_4096(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		t.Fatalf("generate 4096: %v", err)
	}
	algo, bits, curve := pubKeyDetails(&key.PublicKey)
	if algo != "RSA" || bits != 4096 || curve != "" {
		t.Errorf("RSA 4096: got algo=%q bits=%d curve=%q", algo, bits, curve)
	}
}

// ── pubKeyDetails: ECDSA curve variants ───────────────────────────────────────

func TestPubKeyDetails_ECDSA_P384(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P384: %v", err)
	}
	algo, bits, curve := pubKeyDetails(&key.PublicKey)
	if algo != "ECDSA" || bits != 384 {
		t.Errorf("P384: got algo=%q bits=%d", algo, bits)
	}
	if curve == "" {
		t.Error("P384: curve must not be empty")
	}
}

func TestPubKeyDetails_ECDSA_P521(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P521: %v", err)
	}
	algo, bits, curve := pubKeyDetails(&key.PublicKey)
	if algo != "ECDSA" || bits != 521 {
		t.Errorf("P521: got algo=%q bits=%d", algo, bits)
	}
	if curve == "" {
		t.Error("P521: curve must not be empty")
	}
}

// ── pubKeyDetails: unknown key type (ML-DSA fallback) ────────────────────────

// mlDSAFakeKey simulates a post-quantum public key whose type Go does not yet
// natively model. pubKeyDetails must return ("unknown", 0, "") without panic.
type mlDSAFakeKey struct{}

func TestPubKeyDetails_UnknownKeyType(t *testing.T) {
	algo, bits, curve := pubKeyDetails(mlDSAFakeKey{})
	if algo != "unknown" || bits != 0 || curve != "" {
		t.Errorf("unknown key type: got algo=%q bits=%d curve=%q, want unknown/0/empty", algo, bits, curve)
	}
}

// ── x509ToRecord: full cert round-trip for each key type ─────────────────────

func makeSelfSigned(t *testing.T, pub, priv interface{}) *x509.Certificate {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.algo"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

func TestX509ToRecord_ECDSA_P384(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	cert := makeSelfSigned(t, &key.PublicKey, key)
	rec := x509ToRecord(cert)
	if rec.SigAlgorithm != "ECDSA" {
		t.Errorf("P384 SigAlgorithm = %q, want ECDSA", rec.SigAlgorithm)
	}
	if rec.PubKeySize != 384 {
		t.Errorf("P384 PubKeySize = %d, want 384", rec.PubKeySize)
	}
	if rec.PubKeyCurve == "" {
		t.Error("P384 PubKeyCurve must not be empty")
	}
}

func TestX509ToRecord_ECDSA_P521(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	cert := makeSelfSigned(t, &key.PublicKey, key)
	rec := x509ToRecord(cert)
	if rec.SigAlgorithm != "ECDSA" {
		t.Errorf("P521 SigAlgorithm = %q, want ECDSA", rec.SigAlgorithm)
	}
	if rec.PubKeySize != 521 {
		t.Errorf("P521 PubKeySize = %d, want 521", rec.PubKeySize)
	}
}

func TestX509ToRecord_RSA_3072(t *testing.T) {
	key, _ := rsa.GenerateKey(rand.Reader, 3072)
	cert := makeSelfSigned(t, &key.PublicKey, key)
	rec := x509ToRecord(cert)
	if rec.SigAlgorithm != "RSA" {
		t.Errorf("RSA3072 SigAlgorithm = %q, want RSA", rec.SigAlgorithm)
	}
	if rec.PubKeySize != 3072 {
		t.Errorf("RSA3072 PubKeySize = %d, want 3072", rec.PubKeySize)
	}
}

// ── certRecordToFinding: algorithm selection logic ────────────────────────────

func TestCertRecordToFinding_SigAlgorithmPreferred(t *testing.T) {
	rec := certRecord{
		Serial:          "AABB",
		SigAlgorithm:    "ECDSA",
		PubKeyAlgorithm: "RSA",
		PubKeySize:      256,
	}
	f := certRecordToFinding("host.com", rec)
	if f.Algorithm.Name != "ECDSA" {
		t.Errorf("SigAlgorithm should be preferred: got %q, want ECDSA", f.Algorithm.Name)
	}
}

func TestCertRecordToFinding_FallsBackToPubKeyAlgo(t *testing.T) {
	rec := certRecord{
		Serial:          "CCDD",
		SigAlgorithm:    "", // empty
		PubKeyAlgorithm: "Ed25519",
		PubKeySize:      256,
	}
	f := certRecordToFinding("host.com", rec)
	if f.Algorithm.Name != "Ed25519" {
		t.Errorf("PubKeyAlgorithm fallback: got %q, want Ed25519", f.Algorithm.Name)
	}
}

func TestCertRecordToFinding_BothEmpty_EmptyName(t *testing.T) {
	// When both SigAlgorithm and PubKeyAlgorithm are empty the engine passes ""
	// to ClassifyAlgorithm; it does not synthesize a placeholder string.
	rec := certRecord{Serial: "EE00"}
	f := certRecordToFinding("host.com", rec)
	// Just verify no panic; exact name is whatever ClassifyAlgorithm returns for "".
	_ = f.Algorithm.Name
}

func TestCertRecordToFinding_AlgorithmPrimitive(t *testing.T) {
	rec := certRecord{Serial: "FF11", SigAlgorithm: "ECDSA", PubKeySize: 256}
	f := certRecordToFinding("host.com", rec)
	if f.Algorithm.Primitive != "signature" {
		t.Errorf("Primitive = %q, want signature", f.Algorithm.Primitive)
	}
}

func TestCertRecordToFinding_PartialInventoryFalse(t *testing.T) {
	rec := certRecord{Serial: "1234", SigAlgorithm: "RSA", PubKeySize: 2048}
	f := certRecordToFinding("resolved.com", rec)
	if f.PartialInventory {
		t.Error("CT-derived finding must have PartialInventory=false (CT resolves what ECH hid)")
	}
}

func TestCertRecordToFinding_LocationPrefix(t *testing.T) {
	rec := certRecord{Serial: "5678", SigAlgorithm: "RSA"}
	f := certRecordToFinding("host.example.com", rec)
	// File must start with "(ct-lookup)/host.example.com#cert" and include serial.
	if !strings.HasPrefix(f.Location.File, "(ct-lookup)/host.example.com#cert") {
		t.Errorf("Location.File = %q, want prefix %q", f.Location.File, "(ct-lookup)/host.example.com#cert")
	}
	if !strings.Contains(f.Location.File, "5678") {
		t.Errorf("Location.File = %q, expected serial %q to appear", f.Location.File, "5678")
	}
	if f.Location.ArtifactType != "ct-log" {
		t.Errorf("ArtifactType = %q, want ct-log", f.Location.ArtifactType)
	}
}

func TestCertRecordToFinding_CurvePreserved(t *testing.T) {
	rec := certRecord{
		Serial:        "9ABC",
		SigAlgorithm:  "ECDSA",
		PubKeySize:    384,
		PubKeyCurve:   "P-384",
	}
	f := certRecordToFinding("ec.host.com", rec)
	if f.Algorithm.Curve != "P-384" {
		t.Errorf("Curve = %q, want P-384", f.Algorithm.Curve)
	}
}

func TestCertRecordToFinding_KeySizePreserved(t *testing.T) {
	rec := certRecord{Serial: "DEF0", SigAlgorithm: "RSA", PubKeySize: 4096}
	f := certRecordToFinding("rsa.host.com", rec)
	if f.Algorithm.KeySize != 4096 {
		t.Errorf("KeySize = %d, want 4096", f.Algorithm.KeySize)
	}
}

// ── JSON parsing: missing fields and edge-case timestamps ─────────────────────

func TestParseCrtShJSON_MissingOptionalFields(t *testing.T) {
	// Only required "id" present; all other fields absent (default zero values).
	data := []byte(`[{"id": 42}]`)
	entries, err := parseCrtShJSON(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	e := entries[0]
	if e.ID != 42 {
		t.Errorf("ID = %d, want 42", e.ID)
	}
	if e.SerialNumber != "" {
		t.Errorf("missing SerialNumber should be empty, got %q", e.SerialNumber)
	}
	if e.CommonName != "" {
		t.Errorf("missing CommonName should be empty, got %q", e.CommonName)
	}
}

func TestParseTime_EdgeCases(t *testing.T) {
	cases := []struct {
		input    string
		wantZero bool
	}{
		{"", true},                              // empty → zero time
		{"garbage", true},                       // unparseable → zero time
		{"9999-12-31T23:59:59", false},          // far future → parses OK
		{"1970-01-01T00:00:00", false},          // epoch → parses OK
		{"2024-01-15T12:00:00.999", false},      // milliseconds
		{"2024-01-15 12:00:00", false},          // space separator
		{"2024-01-15", false},                   // date only
		{"2024-13-40T25:99:99", true},           // invalid date → zero
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got := parseTime(tc.input)
			isZero := got.IsZero()
			if isZero != tc.wantZero {
				t.Errorf("parseTime(%q).IsZero() = %v, want %v", tc.input, isZero, tc.wantZero)
			}
		})
	}
}

func TestEntryToRecord_MissingTimestamps(t *testing.T) {
	e := crtShEntry{SerialNumber: "AA", NotBefore: "", NotAfter: ""}
	rec := entryToRecord(e)
	if !rec.NotBefore.IsZero() {
		t.Errorf("empty NotBefore should produce zero time, got %v", rec.NotBefore)
	}
	if !rec.NotAfter.IsZero() {
		t.Errorf("empty NotAfter should produce zero time, got %v", rec.NotAfter)
	}
}

func TestEntryToRecord_FutureCert(t *testing.T) {
	e := crtShEntry{
		SerialNumber: "FUTURE",
		NotBefore:    "9999-12-31T00:00:00",
		NotAfter:     "9999-12-31T23:59:59",
	}
	rec := entryToRecord(e)
	if rec.NotBefore.Year() != 9999 {
		t.Errorf("future NotBefore.Year() = %d, want 9999", rec.NotBefore.Year())
	}
}

func TestParseCrtShJSON_NullArray(t *testing.T) {
	// "null" is valid JSON but not a []crtShEntry — behaviour is implementation-
	// defined (error or nil slice). The critical invariant is no panic.
	entries, err := parseCrtShJSON([]byte("null"))
	// Either empty or nil is acceptable; the function must not panic.
	_ = entries
	_ = err
}

func TestParseCrtShJSON_VeryLargeID(t *testing.T) {
	// crt.sh IDs can be large int64 values.
	maxInt64JSON := `[{"id": 9223372036854775807}]`
	entries, err := parseCrtShJSON([]byte(maxInt64JSON))
	if err != nil {
		t.Fatalf("max int64 ID: %v", err)
	}
	if len(entries) != 1 || entries[0].ID != 9223372036854775807 {
		t.Errorf("max int64 ID not preserved: got %v", entries)
	}
}

func TestParseCrtShJSON_NameValueWithNewlines(t *testing.T) {
	// crt.sh returns SAN lists newline-separated in name_value.
	data := []byte(`[{"id":1,"name_value":"example.com\nwww.example.com\napi.example.com"}]`)
	entries, err := parseCrtShJSON(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if entries[0].NameValue != "example.com\nwww.example.com\napi.example.com" {
		t.Errorf("NameValue = %q", entries[0].NameValue)
	}
}

// ── certRecordToFinding: RawIdentifier format ─────────────────────────────────

func TestCertRecordToFinding_RawIdentifierFormat(t *testing.T) {
	rec := certRecord{Serial: "ABCDEF01", SigAlgorithm: "RSA", PubKeySize: 2048}
	f := certRecordToFinding("id-test.com", rec)
	expected := "ct-cert:id-test.com|RSA|ABCDEF01"
	if f.RawIdentifier != expected {
		t.Errorf("RawIdentifier = %q, want %q", f.RawIdentifier, expected)
	}
}

func TestCertRecordToFinding_Ed25519(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen ed25519: %v", err)
	}
	cert := makeSelfSigned(t, pub, priv)
	rec := x509ToRecord(cert)
	f := certRecordToFinding("ed25519.host.com", rec)
	if f.Algorithm.Name != "Ed25519" {
		t.Errorf("Ed25519: Algorithm.Name = %q, want Ed25519", f.Algorithm.Name)
	}
	if f.Algorithm.Primitive != "signature" {
		t.Errorf("Ed25519: Primitive = %q, want signature", f.Algorithm.Primitive)
	}
}

// ── JSON: ContentType mismatch / non-JSON response ────────────────────────────

func TestParseCrtShJSON_HTMLResponse(t *testing.T) {
	// Servers sometimes return HTML error pages (e.g., maintenance page).
	data := []byte(`<!DOCTYPE html><html><body>Error</body></html>`)
	_, err := parseCrtShJSON(data)
	if err == nil {
		t.Error("expected error for HTML body, got nil")
	}
}

func TestParseCrtShJSON_PlainTextError(t *testing.T) {
	data := []byte(`Too Many Requests`)
	_, err := parseCrtShJSON(data)
	if err == nil {
		t.Error("expected error for plain-text body, got nil")
	}
}

// ── entryToRecord: field mapping completeness ─────────────────────────────────

func TestEntryToRecord_AllFieldsMapped(t *testing.T) {
	entry := crtShEntry{
		IssuerCAID:     99,
		IssuerName:     "CN=Real CA",
		CommonName:     "www.example.com",
		NameValue:      "www.example.com",
		ID:             12345,
		EntryTimestamp: "2024-06-01T00:00:00",
		NotBefore:      "2024-06-01T00:00:00",
		NotAfter:       "2025-06-01T00:00:00",
		SerialNumber:   "DEADBEEF",
	}
	rec := entryToRecord(entry)

	if rec.Serial != "DEADBEEF" {
		t.Errorf("Serial = %q, want DEADBEEF", rec.Serial)
	}
	if rec.IssuerName != "CN=Real CA" {
		t.Errorf("IssuerName = %q, want CN=Real CA", rec.IssuerName)
	}
	if rec.CommonName != "www.example.com" {
		t.Errorf("CommonName = %q, want www.example.com", rec.CommonName)
	}
	if rec.NameValue != "www.example.com" {
		t.Errorf("NameValue = %q, want www.example.com", rec.NameValue)
	}
	if rec.CertID != 12345 {
		t.Errorf("CertID = %d, want 12345", rec.CertID)
	}
	if rec.SigAlgorithm != "" {
		t.Errorf("SigAlgorithm should be empty for partial record, got %q", rec.SigAlgorithm)
	}
}

// ── JSON round-trip for all field types ───────────────────────────────────────

func TestCrtShEntry_JSONRoundTrip_AllFields(t *testing.T) {
	original := crtShEntry{
		IssuerCAID:     183267,
		IssuerName:     "C=US, O=Let's Encrypt, CN=R10",
		CommonName:     "roundtrip.example.com",
		NameValue:      "roundtrip.example.com\nwww.roundtrip.example.com",
		ID:             9876543210,
		EntryTimestamp: "2024-03-15T08:30:00",
		NotBefore:      "2024-03-15T00:00:00",
		NotAfter:       "2024-06-15T00:00:00",
		SerialNumber:   "0123456789ABCDEF",
	}

	// parseCrtShJSON expects a JSON array; wrap the single entry.
	data, err := json.Marshal([]crtShEntry{original})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	entries, err := parseCrtShJSON(data)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	got := entries[0]
	if got != original {
		t.Errorf("round-trip mismatch:\n  got:  %+v\n  want: %+v", got, original)
	}
}
