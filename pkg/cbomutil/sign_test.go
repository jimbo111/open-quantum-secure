package cbomutil

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// minimalCBOM is a representative CycloneDX CBOM payload used across tests.
const minimalCBOM = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "serialNumber": "urn:uuid:test-0000-0000-0000-000000000001",
  "version": 1,
  "components": []
}`

func TestSignVerifyRoundTrip(t *testing.T) {
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	signed, err := Sign([]byte(minimalCBOM), priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Structural checks.
	if len(signed.CBOM) == 0 {
		t.Error("CBOM field is empty")
	}
	if signed.Signature == "" {
		t.Error("Signature field is empty")
	}
	if signed.PublicKey == "" {
		t.Error("PublicKey field is empty")
	}
	if signed.SignedAt == "" {
		t.Error("SignedAt field is empty")
	}
	if signed.Digest == "" {
		t.Error("Digest field is empty")
	}

	ok, err := Verify(signed)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("Verify returned false for a freshly signed CBOM")
	}
}

func TestSignVerifyRoundTrip_JSONMarshalUnmarshal(t *testing.T) {
	// Simulate the full envelope-over-wire lifecycle: sign -> JSON encode ->
	// JSON decode -> verify. This catches any json.RawMessage re-encoding issues.
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	signed, err := Sign([]byte(minimalCBOM), priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	data, err := json.Marshal(signed)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}

	var decoded SignedCBOM
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	ok, err := Verify(&decoded)
	if err != nil {
		t.Fatalf("Verify after marshal/unmarshal: %v", err)
	}
	if !ok {
		t.Fatal("Verify returned false after marshal/unmarshal round-trip")
	}
}

func TestVerifyFailsTamperedCBOM(t *testing.T) {
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	signed, err := Sign([]byte(minimalCBOM), priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Tamper both CBOM content AND digest (simulates a full content swap).
	// The signature was over the original digest, so verification must fail.
	tampered := strings.Replace(string(signed.CBOM), "CycloneDX", "TamperedDX", 1)
	signed.CBOM = json.RawMessage(tampered)
	signed.Digest = "0000000000000000000000000000000000000000000000000000000000000000"

	ok, err := Verify(signed)
	if err == nil && ok {
		t.Fatal("Verify returned (true, nil) for a tampered CBOM+digest — expected rejection")
	}
}

func TestVerifyFailsWrongPublicKey(t *testing.T) {
	// Sign with key A, then swap in key B's public key.
	_, privA, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair A: %v", err)
	}
	pubB, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair B: %v", err)
	}

	signed, err := Sign([]byte(minimalCBOM), privA)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Swap public key to an unrelated key.
	signed.PublicKey = base64.StdEncoding.EncodeToString(pubB)

	ok, err := Verify(signed)
	if err == nil && ok {
		t.Fatal("Verify returned (true, nil) with wrong public key — expected rejection")
	}
}

func TestVerifyFailsTamperedDigest(t *testing.T) {
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	signed, err := Sign([]byte(minimalCBOM), priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Tamper only the Digest field, leave CBOM + Signature intact.
	// The signature was over the original digest, so verification must fail.
	signed.Digest = strings.Repeat("a", 64)

	ok, err := Verify(signed)
	if err == nil && ok {
		t.Fatal("Verify returned (true, nil) for tampered digest — expected rejection")
	}
}

func TestSignRejectsEmptyCBOM(t *testing.T) {
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	_, err = Sign([]byte{}, priv)
	if err == nil {
		t.Fatal("Sign accepted empty cbomJSON — expected error")
	}
}

func TestSignRejectsInvalidPrivateKey(t *testing.T) {
	_, err := Sign([]byte(minimalCBOM), ed25519.PrivateKey([]byte("tooshort")))
	if err == nil {
		t.Fatal("Sign accepted invalid private key — expected error")
	}
}

func TestVerifyRejectsNilInput(t *testing.T) {
	_, err := Verify(nil)
	if err == nil {
		t.Fatal("Verify accepted nil SignedCBOM — expected error")
	}
}

func TestVerifyRejectsInvalidBase64PublicKey(t *testing.T) {
	signed := &SignedCBOM{
		CBOM:      json.RawMessage(minimalCBOM),
		PublicKey: "not-valid-base64!!!",
		Signature: base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
		Digest:    strings.Repeat("a", 64),
	}
	_, err := Verify(signed)
	if err == nil {
		t.Fatal("Verify accepted invalid base64 public key — expected error")
	}
}

func TestVerifyRejectsInvalidBase64Signature(t *testing.T) {
	pub, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	signed := &SignedCBOM{
		CBOM:      json.RawMessage(minimalCBOM),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Signature: "not-valid-base64!!!",
		Digest:    strings.Repeat("a", 64),
	}
	_, err = Verify(signed)
	if err == nil {
		t.Fatal("Verify accepted invalid base64 signature — expected error")
	}
}

func TestGenerateKeyPairProducesValidKeys(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Errorf("public key length: got %d, want %d", len(pub), ed25519.PublicKeySize)
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Errorf("private key length: got %d, want %d", len(priv), ed25519.PrivateKeySize)
	}

	// Sanity: keys produced by the helper must sign/verify correctly.
	msg := []byte("test message")
	sig := ed25519.Sign(priv, msg)
	if !ed25519.Verify(pub, msg, sig) {
		t.Error("generated key pair fails basic sign/verify")
	}
}

func TestSignedCBOMPublicKeyMatchesPrivateKey(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	signed, err := Sign([]byte(minimalCBOM), priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	embeddedPubBytes, err := base64.StdEncoding.DecodeString(signed.PublicKey)
	if err != nil {
		t.Fatalf("decode embedded public key: %v", err)
	}

	if string(embeddedPubBytes) != string(pub) {
		t.Error("embedded public key does not match the public key derived from the private key")
	}
}

func TestSignedCBOMDigestMatchesCBOMContent(t *testing.T) {
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	cbomBytes := []byte(minimalCBOM)
	signed, err := Sign(cbomBytes, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Recompute digest independently and compare against the envelope field.
	sum := sha256.Sum256(cbomBytes)
	expected := hex.EncodeToString(sum[:])
	if signed.Digest != expected {
		t.Errorf("Digest mismatch: got %s, want %s", signed.Digest, expected)
	}
}

// TestSignEphemeralKeyPairPattern exercises the intended MVP usage pattern:
// generate a fresh key pair per scan, sign, embed public key, verify.
func TestSignEphemeralKeyPairPattern(t *testing.T) {
	cbomBytes := []byte(minimalCBOM)

	// Step 1: generate ephemeral key pair (done once per scan).
	_, priv, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	// Step 2: sign the CBOM output.
	envelope, err := Sign(cbomBytes, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// Step 3: serialize the envelope to JSON (what gets written to disk/stdout).
	envelopeJSON, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}

	// Step 4 (consumer side): parse the envelope and verify.
	var parsed SignedCBOM
	if err := json.Unmarshal(envelopeJSON, &parsed); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}

	ok, err := Verify(&parsed)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("end-to-end ephemeral key pattern: Verify returned false")
	}
}

// Benchmark signs a ~300-byte CBOM to confirm signing adds negligible latency.
func BenchmarkSign(b *testing.B) {
	_, priv, err := GenerateKeyPair()
	if err != nil {
		b.Fatalf("GenerateKeyPair: %v", err)
	}
	cbomBytes := []byte(minimalCBOM)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Sign(cbomBytes, priv); err != nil {
			b.Fatalf("Sign: %v", err)
		}
	}
}

func BenchmarkVerify(b *testing.B) {
	_, priv, err := GenerateKeyPair()
	if err != nil {
		b.Fatalf("GenerateKeyPair: %v", err)
	}
	signed, err := Sign([]byte(minimalCBOM), priv)
	if err != nil {
		b.Fatalf("Sign: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Verify(signed); err != nil {
			b.Fatalf("Verify: %v", err)
		}
	}
}

// FuzzSign verifies that Sign+Verify never panics on arbitrary input.
func FuzzSign(f *testing.F) {
	f.Add([]byte(minimalCBOM))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"bomFormat":"CycloneDX"}`))

	_, priv, err := GenerateKeyPair()
	if err != nil {
		f.Fatalf("GenerateKeyPair: %v", err)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) == 0 {
			return // empty input is a documented error, not a panic
		}
		signed, err := Sign(data, priv)
		if err != nil {
			return // non-panic error is fine
		}
		ok, err := Verify(signed)
		if err != nil || !ok {
			t.Errorf("round-trip failed for input len=%d: ok=%v err=%v", len(data), ok, err)
		}
	})
}

// Prevent compiler from optimizing away rand.Reader.
var _ = rand.Reader
