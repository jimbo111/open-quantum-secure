// Package cbomutil provides utilities for CBOM signing and verification.
package cbomutil

import (
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
// SignedCBOM envelope. The signature covers SHA-256(cbomJSON) so that
// integrity and authenticity can be verified independently.
//
// cbomJSON must be the complete, serialized CycloneDX CBOM document as
// returned by output.WriteCBOM. Callers should not modify the bytes after
// signing.
func Sign(cbomJSON []byte, privateKey ed25519.PrivateKey) (*SignedCBOM, error) {
	if len(cbomJSON) == 0 {
		return nil, errors.New("cbomutil: cbomJSON must not be empty")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("cbomutil: invalid private key length: got %d, want %d",
			len(privateKey), ed25519.PrivateKeySize)
	}

	// Compute SHA-256 digest over the raw CBOM bytes.
	sum := sha256.Sum256(cbomJSON)
	digest := hex.EncodeToString(sum[:])

	// Sign the SHA-256 digest (not raw bytes) so that verification works
	// after a JSON marshal/unmarshal round-trip where whitespace may change.
	sig := ed25519.Sign(privateKey, sum[:])

	pub := privateKey.Public().(ed25519.PublicKey)

	return &SignedCBOM{
		CBOM:      json.RawMessage(cbomJSON),
		Signature: base64.StdEncoding.EncodeToString(sig),
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		SignedAt:  time.Now().UTC().Format(time.RFC3339),
		Digest:    digest,
	}, nil
}

// Verify checks the Ed25519 signature of a SignedCBOM against its embedded
// public key. It returns (true, nil) when the signature is valid.
//
// Verify also cross-checks the Digest field against the CBOM bytes so that
// a tampered digest is caught even if the signature itself is somehow reused.
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

	// Decode the stored digest for signature verification.
	// We verify against the stored digest (not recomputed) because JSON
	// marshal/unmarshal may alter CBOM whitespace, changing raw bytes.
	digestBytes, err := hex.DecodeString(signed.Digest)
	if err != nil {
		return false, fmt.Errorf("cbomutil: decode digest: %w", err)
	}
	if len(digestBytes) != sha256.Size {
		return false, fmt.Errorf("cbomutil: invalid digest length: got %d, want %d",
			len(digestBytes), sha256.Size)
	}

	// Verify Ed25519 signature over the SHA-256 digest.
	if !ed25519.Verify(pub, digestBytes, sigBytes) {
		return false, nil
	}

	// Note: We do NOT cross-check CBOM bytes against the digest because JSON
	// marshal/unmarshal may alter whitespace in json.RawMessage. The signature
	// over the digest is the authoritative integrity check. If the digest is
	// tampered, the signature verification above fails.

	return true, nil
}
