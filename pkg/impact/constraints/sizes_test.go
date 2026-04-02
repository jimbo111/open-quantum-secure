package constraints

import (
	"testing"
)

func TestLookup_Exact(t *testing.T) {
	tests := []struct {
		id      string
		wantPK  int
		wantSig int
		wantCT  int
		wantSS  int
		wantOK  bool
	}{
		{"ML-DSA-44", 1312, 2420, 0, 0, true},
		{"ML-DSA-65", 1952, 3309, 0, 0, true},
		{"ML-DSA-87", 2592, 4627, 0, 0, true},
		{"ML-KEM-512", 800, 0, 768, 32, true},
		{"ML-KEM-768", 1184, 0, 1088, 32, true},
		{"ML-KEM-1024", 1568, 0, 1568, 32, true},
		{"SLH-DSA-128s", 32, 7856, 0, 0, true},
		{"SLH-DSA-128f", 32, 17088, 0, 0, true},
		{"SLH-DSA-192s", 48, 16224, 0, 0, true},
		{"SLH-DSA-192f", 48, 35664, 0, 0, true},
		{"SLH-DSA-256s", 64, 29792, 0, 0, true},
		{"SLH-DSA-256f", 64, 49856, 0, 0, true},
		{"RSA-2048", 294, 256, 0, 0, true},
		{"RSA-3072", 422, 384, 0, 0, true},
		{"RSA-4096", 550, 512, 0, 0, true},
		{"ECDSA-P256", 65, 72, 0, 0, true},
		{"ECDSA-P384", 97, 104, 0, 0, true},
		{"ECDH-P256", 65, 0, 0, 32, true},
		{"ECDH-P384", 97, 0, 0, 48, true},
		{"Ed25519", 32, 64, 0, 0, true},
		{"Ed448", 57, 114, 0, 0, true},
		{"UNKNOWN", 0, 0, 0, 0, false},
	}

	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			p, ok := Lookup(tc.id)
			if ok != tc.wantOK {
				t.Fatalf("Lookup(%q) ok=%v want %v", tc.id, ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if p.PublicKeyBytes != tc.wantPK {
				t.Errorf("PublicKeyBytes=%d want %d", p.PublicKeyBytes, tc.wantPK)
			}
			if p.SignatureBytes != tc.wantSig {
				t.Errorf("SignatureBytes=%d want %d", p.SignatureBytes, tc.wantSig)
			}
			if p.CiphertextBytes != tc.wantCT {
				t.Errorf("CiphertextBytes=%d want %d", p.CiphertextBytes, tc.wantCT)
			}
			if p.SharedSecretBytes != tc.wantSS {
				t.Errorf("SharedSecretBytes=%d want %d", p.SharedSecretBytes, tc.wantSS)
			}
		})
	}
}

func TestLookup_PrefixFallback(t *testing.T) {
	tests := []struct {
		prefix string
		wantOK bool
	}{
		{"RSA", true},
		{"ML-DSA", true},
		{"ML-KEM", true},
		{"SLH-DSA", true},
		{"ECDSA", true},
		{"UNKNOWN-PREFIX", false},
	}

	for _, tc := range tests {
		t.Run(tc.prefix, func(t *testing.T) {
			_, ok := Lookup(tc.prefix)
			if ok != tc.wantOK {
				t.Errorf("Lookup(%q) ok=%v want %v", tc.prefix, ok, tc.wantOK)
			}
		})
	}
}

// TestLookup_PrefixDeterministic verifies that Lookup("RSA") always returns the
// same profile regardless of map iteration order.
func TestLookup_PrefixDeterministic(t *testing.T) {
	var first AlgorithmSizeProfile
	for i := 0; i < 100; i++ {
		p, ok := Lookup("RSA")
		if !ok {
			t.Fatalf("Lookup(\"RSA\") returned not-found on iteration %d", i)
		}
		if i == 0 {
			first = p
			continue
		}
		if p != first {
			t.Fatalf("Lookup(\"RSA\") returned different profiles on iteration %d: got %+v, first was %+v", i, p, first)
		}
	}
}

// TestLookup_PrefixReturnsLongestMatch verifies that "RSA-30" matches RSA-3072
// (longest prefix) and not RSA-2048.
func TestLookup_PrefixReturnsLongestMatch(t *testing.T) {
	p, ok := Lookup("RSA-30")
	if !ok {
		t.Fatal("Lookup(\"RSA-30\") returned not-found, want RSA-3072")
	}
	// RSA-3072 has SignatureBytes=384; RSA-2048 has SignatureBytes=256.
	if p.SignatureBytes != 384 {
		t.Errorf("Lookup(\"RSA-30\").SignatureBytes = %d, want 384 (RSA-3072)", p.SignatureBytes)
	}
}

func TestLookup_PrivateKeyBytes(t *testing.T) {
	tests := []struct {
		id   string
		want int
	}{
		// FIPS 203 — ML-KEM decapsulation keys
		{"ML-KEM-512", 1632},
		{"ML-KEM-768", 2400},
		{"ML-KEM-1024", 3168},
		// FIPS 205 — SLH-DSA private keys
		{"SLH-DSA-128s", 64},
		{"SLH-DSA-128f", 64},
		{"SLH-DSA-192s", 96},
		{"SLH-DSA-192f", 96},
		{"SLH-DSA-256s", 128},
		{"SLH-DSA-256f", 128},
		// FIPS 204 — ML-DSA (already had private keys)
		{"ML-DSA-44", 2560},
		{"ML-DSA-65", 4032},
		{"ML-DSA-87", 4896},
	}

	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			p, ok := Lookup(tc.id)
			if !ok {
				t.Fatalf("Lookup(%q) not found", tc.id)
			}
			if p.PrivateKeyBytes != tc.want {
				t.Errorf("PrivateKeyBytes=%d want %d", p.PrivateKeyBytes, tc.want)
			}
		})
	}
}

// TestLookup_IdentifierLongerThanKey checks the previously-broken direction of the
// prefix check. Identifiers such as "RSA-2048-SHA256" and "ECDSA-P256-SHA256"
// must match the DB key they start with, not the other way around.
func TestLookup_IdentifierLongerThanKey(t *testing.T) {
	tests := []struct {
		id          string
		wantOK      bool
		wantPKBytes int // spot-check to ensure we got the right profile
	}{
		// Exact match still works.
		{"RSA-2048", true, 294},
		// Identifier longer than DB key — this was the broken direction.
		{"RSA-2048-SHA256", true, 294},
		{"ECDSA-P256-SHA256", true, 65},
		// Unknown algorithm returns false.
		{"UNKNOWN-ALGO", false, 0},
	}

	for _, tc := range tests {
		t.Run(tc.id, func(t *testing.T) {
			p, ok := Lookup(tc.id)
			if ok != tc.wantOK {
				t.Fatalf("Lookup(%q) ok=%v want %v", tc.id, ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if p.PublicKeyBytes != tc.wantPKBytes {
				t.Errorf("Lookup(%q).PublicKeyBytes=%d want %d", tc.id, p.PublicKeyBytes, tc.wantPKBytes)
			}
		})
	}
}

func TestMigrationTargets_ReturnsCopy(t *testing.T) {
	original := MigrationTargets("RSA")
	if len(original) == 0 {
		t.Fatal("MigrationTargets(RSA) returned empty")
	}
	// Mutate the returned slice.
	original[0] = "CORRUPTED"

	// Second call should still return the original value.
	second := MigrationTargets("RSA")
	if second[0] == "CORRUPTED" {
		t.Error("MigrationTargets returns shared slice — mutation leaked to global state")
	}
}

func TestMigrationTargets(t *testing.T) {
	tests := []struct {
		from    string
		want    []string
		wantNil bool
	}{
		{"RSA", []string{"ML-DSA-65", "ML-DSA-87"}, false},
		{"RSA-2048", []string{"ML-DSA-65", "ML-DSA-87"}, false},
		{"ECDSA", []string{"ML-DSA-44", "ML-DSA-65"}, false},
		{"ECDSA-P256", []string{"ML-DSA-44", "ML-DSA-65"}, false},
		{"ECDH", []string{"ML-KEM-768"}, false},
		{"Ed25519", []string{"ML-DSA-44"}, false},
		{"Ed448", []string{"ML-DSA-44"}, false},
		{"UNKNOWN", nil, true},
	}

	for _, tc := range tests {
		t.Run(tc.from, func(t *testing.T) {
			got := MigrationTargets(tc.from)
			if tc.wantNil {
				if got != nil {
					t.Errorf("MigrationTargets(%q)=%v want nil", tc.from, got)
				}
				return
			}
			if len(got) != len(tc.want) {
				t.Fatalf("MigrationTargets(%q)=%v want %v", tc.from, got, tc.want)
			}
			for i, v := range tc.want {
				if got[i] != v {
					t.Errorf("MigrationTargets(%q)[%d]=%q want %q", tc.from, i, got[i], v)
				}
			}
		})
	}
}
