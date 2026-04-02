package quantum

import "testing"

func FuzzClassifyAlgorithm(f *testing.F) {
	f.Add("AES", "symmetric", 256)
	f.Add("RSA", "asymmetric", 2048)
	f.Add("", "", 0)
	f.Add("ML-KEM", "kem", 768)
	f.Add("SHA-256", "hash", 0)
	f.Add("3DES", "symmetric", 168)
	f.Add("MD5", "hash", 0)
	f.Add("ECDSA", "signature", 256)

	f.Fuzz(func(t *testing.T, name, primitive string, keySize int) {
		// ClassifyAlgorithm must never panic regardless of input.
		_ = ClassifyAlgorithm(name, primitive, keySize)
	})
}
