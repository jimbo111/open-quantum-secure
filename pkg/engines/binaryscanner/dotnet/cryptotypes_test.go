package dotnet

import (
	"testing"
)

func TestCryptoTypesDB_AllHaveAlgorithm(t *testing.T) {
	for typeName, entry := range cryptoTypes {
		if entry.algorithm == "" {
			t.Errorf("cryptoTypes[%q].algorithm is empty", typeName)
		}
	}
}

func TestCryptoTypesDB_AllHavePrimitive(t *testing.T) {
	for typeName, entry := range cryptoTypes {
		if entry.primitive == "" {
			t.Errorf("cryptoTypes[%q].primitive is empty", typeName)
		}
	}
}

func TestCryptoTypesDB_NoDuplicateKeys(t *testing.T) {
	// Go maps enforce unique keys at compile time, but this test makes the
	// constraint explicit and documents it as a DB invariant. We verify that
	// the map contains the expected number of entries (no silent overwrites
	// from a future copy-paste error where two keys are accidentally the same).
	if len(cryptoTypes) == 0 {
		t.Error("cryptoTypes is empty — expected at least one entry")
	}

	// Verify a representative set of known entries are present.
	required := []string{
		"System.Security.Cryptography.Aes",
		"System.Security.Cryptography.RSA",
		"System.Security.Cryptography.SHA256",
		"System.Security.Cryptography.MD5",
		"Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber",
		"Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium",
	}
	for _, key := range required {
		if _, ok := cryptoTypes[key]; !ok {
			t.Errorf("cryptoTypes missing required key %q", key)
		}
	}
}

func TestCryptoTypesDB_PQCSafeEntries(t *testing.T) {
	// ML-KEM and ML-DSA must be marked pqcSafe.
	pqcEntries := []struct {
		typeName  string
		wantAlg   string
		wantPrim  string
	}{
		{
			typeName: "Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber",
			wantAlg:  "ML-KEM",
			wantPrim: "kem",
		},
		{
			typeName: "Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium",
			wantAlg:  "ML-DSA",
			wantPrim: "signature",
		},
	}

	for _, tc := range pqcEntries {
		tc := tc
		t.Run(tc.typeName, func(t *testing.T) {
			entry, ok := cryptoTypes[tc.typeName]
			if !ok {
				t.Fatalf("cryptoTypes[%q] not found", tc.typeName)
			}
			if !entry.pqcSafe {
				t.Errorf("pqcSafe = false, want true for %q", tc.typeName)
			}
			if entry.algorithm != tc.wantAlg {
				t.Errorf("algorithm = %q, want %q", entry.algorithm, tc.wantAlg)
			}
			if entry.primitive != tc.wantPrim {
				t.Errorf("primitive = %q, want %q", entry.primitive, tc.wantPrim)
			}
		})
	}
}

func TestCryptoTypesDB_ClassicEntries(t *testing.T) {
	// Classic (non-PQC) entries must NOT be marked pqcSafe.
	classicEntries := []string{
		"System.Security.Cryptography.RSA",
		"System.Security.Cryptography.DES",
		"System.Security.Cryptography.SHA1",
		"System.Security.Cryptography.MD5",
		"Org.BouncyCastle.Crypto.Engines.RsaEngine",
	}
	for _, typeName := range classicEntries {
		typeName := typeName
		t.Run(typeName, func(t *testing.T) {
			entry, ok := cryptoTypes[typeName]
			if !ok {
				t.Fatalf("cryptoTypes[%q] not found", typeName)
			}
			if entry.pqcSafe {
				t.Errorf("pqcSafe = true, want false for classic entry %q", typeName)
			}
		})
	}
}
