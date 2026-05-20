// Package cbomutil provides utilities for CBOM signing and verification.
package cbomutil

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// SignedCBOM wraps a CycloneDX CBOM with a detached Ed25519 signature.
// The envelope is self-contained: consumers can verify provenance using
// only the fields in this struct (no external key distribution required
// for MVP ephemeral-key mode).
type SignedCBOM struct {
	// CBOM is the original CycloneDX CBOM JSON, preserved byte-for-byte
	// so the digest is reproducible.
	CBOM json.RawMessage `json:"cbom"`

	// Signature is the base64-standard-encoded Ed25519 signature over
	// SHA-256(CBOM bytes).
	Signature string `json:"signature"`

	// PublicKey is the base64-standard-encoded Ed25519 public key (32 bytes).
	PublicKey string `json:"publicKey"`

	// SignedAt is the RFC3339 UTC timestamp of when the signature was created.
	SignedAt string `json:"signedAt"`

	// Digest is the lowercase hex-encoded SHA-256 of the CBOM content.
	// Consumers can cross-check this against the raw CBOM bytes before
	// trusting the signature.
	Digest string `json:"digest"`
}

// GenerateKeyPair generates a fresh Ed25519 key pair suitable for signing a
// single CBOM. The returned private key must be kept confidential; the public
// key is embedded in the SignedCBOM envelope for self-contained verification.
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("cbomutil: generate Ed25519 key pair: %w", err)
	}
	return pub, priv, nil
}

// Sign signs cbomJSON with the given Ed25519 private key and returns a
// SignedCBOM envelope. The signature covers SHA-256(canonical(cbomJSON))
// so that integrity and authenticity can be verified independently.
//
// cbomJSON must be the complete, serialized CycloneDX CBOM document as
// returned by output.WriteCBOM. Sign canonicalises the input through
// json.Compact (whitespace-stripped form) before hashing so that the
// digest survives downstream JSON pretty-printing of the envelope (e.g.
// json.MarshalIndent). The canonical bytes are what get stored in the
// SignedCBOM.CBOM field.
func Sign(cbomJSON []byte, privateKey ed25519.PrivateKey) (*SignedCBOM, error) {
	if len(cbomJSON) == 0 {
		return nil, errors.New("cbomutil: cbomJSON must not be empty")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("cbomutil: invalid private key length: got %d, want %d",
			len(privateKey), ed25519.PrivateKeySize)
	}

	// Canonicalise the CBOM bytes by stripping all insignificant whitespace.
	// This makes the digest stable across JSON pretty-print round-trips of
	// the envelope (json.MarshalIndent re-indents inner json.RawMessage
	// values).
	canonical, err := canonicaliseJSON(cbomJSON)
	if err != nil {
		return nil, fmt.Errorf("cbomutil: canonicalise CBOM: %w", err)
	}

	// Compute SHA-256 digest over the canonical bytes.
	sum := sha256.Sum256(canonical)
	digest := hex.EncodeToString(sum[:])

	// Sign the SHA-256 digest (not raw bytes) — Ed25519's small signing
	// surface keeps the envelope compact and signature verification cheap.
	sig := ed25519.Sign(privateKey, sum[:])

	pub := privateKey.Public().(ed25519.PublicKey)

	return &SignedCBOM{
		CBOM:      json.RawMessage(canonical),
		Signature: base64.StdEncoding.EncodeToString(sig),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		SignedAt:  time.Now().UTC().Format(time.RFC3339),
		Digest:    digest,
	}, nil
}

// canonicaliseJSON returns the JSON-encoded src with insignificant whitespace
// stripped (json.Compact). Used by Sign and Verify to obtain a stable byte
// representation that survives MarshalIndent re-formatting.
func canonicaliseJSON(src []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := json.Compact(&buf, src); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Verify checks the Ed25519 signature of a SignedCBOM against its embedded
// public key AND cross-checks the embedded Digest field against the actual
// CBOM bytes. It returns (true, nil) only when both checks succeed.
//
// Both checks are required: signing only the digest leaves the CBOM payload
// unauthenticated. Without the CBOM↔digest comparison, an attacker can
// substitute the entire `cbom` field while keeping digest+signature+publicKey
// intact and Verify would still return true. (json.RawMessage.UnmarshalJSON
// preserves source bytes verbatim, so digest equality survives a Marshal /
// Unmarshal round-trip; whitespace drift only occurs if a downstream consumer
// deserialises into a struct and re-marshals, which is out of scope here.)
//
// Note: Verify does NOT check SignedAt for expiry. Callers that need
// freshness guarantees must enforce that separately.
func Verify(signed *SignedCBOM) (bool, error) {
	if signed == nil {
		return false, errors.New("cbomutil: signed CBOM must not be nil")
	}
	if len(signed.CBOM) == 0 {
		return false, errors.New("cbomutil: signed CBOM has empty cbom field")
	}

	// Decode public key.
	pubBytes, err := base64.StdEncoding.DecodeString(signed.PublicKey)
	if err != nil {
		return false, fmt.Errorf("cbomutil: decode public key: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return false, fmt.Errorf("cbomutil: invalid public key length: got %d, want %d",
			len(pubBytes), ed25519.PublicKeySize)
	}
	pub := ed25519.PublicKey(pubBytes)

	// Decode signature.
	sigBytes, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil {
		return false, fmt.Errorf("cbomutil: decode signature: %w", err)
	}
	if len(sigBytes) != ed25519.SignatureSize {
		return false, fmt.Errorf("cbomutil: invalid signature length: got %d, want %d",
			len(sigBytes), ed25519.SignatureSize)
	}

	// Decode the stored digest.
	digestBytes, err := hex.DecodeString(signed.Digest)
	if err != nil {
		return false, fmt.Errorf("cbomutil: decode digest: %w", err)
	}
	if len(digestBytes) != sha256.Size {
		return false, fmt.Errorf("cbomutil: invalid digest length: got %d, want %d",
			len(digestBytes), sha256.Size)
	}

	// Cross-check the stored digest against the actual CBOM bytes. Without
	// this, an attacker can swap the entire CBOM payload while keeping the
	// signed digest intact. The CBOM bytes are canonicalised (whitespace-
	// stripped) before hashing so that envelope pretty-print round-trips
	// (json.MarshalIndent) don't break verification.
	canonical, err := canonicaliseJSON(signed.CBOM)
	if err != nil {
		return false, fmt.Errorf("cbomutil: canonicalise CBOM: %w", err)
	}
	recomputed := sha256.Sum256(canonical)
	if !bytes.Equal(recomputed[:], digestBytes) {
		return false, nil
	}

	// Verify Ed25519 signature over the SHA-256 digest.
	if !ed25519.Verify(pub, digestBytes, sigBytes) {
		return false, nil
	}

	return true, nil
}
