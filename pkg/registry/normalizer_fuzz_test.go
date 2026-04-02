package registry

import "testing"

func FuzzNormalize(f *testing.F) {
	f.Add("AES-256-GCM", 256, "GCM")
	f.Add("RSA", 0, "")
	f.Add("", 0, "")
	f.Add("unknown-algorithm", 128, "CBC")
	f.Add("SHA-3-256", 0, "")
	f.Add("ECDSA-P256", 256, "")
	f.Add("ChaCha20-Poly1305", 0, "")

	f.Fuzz(func(t *testing.T, raw string, keySize int, mode string) {
		reg := Load()
		// Must never panic regardless of input.
		_ = reg.Normalize(raw, keySize, mode)
	})
}
