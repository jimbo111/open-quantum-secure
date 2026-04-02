package configscanner

import (
	"testing"
)

func TestMatchCryptoParams_KoreanAlgorithms(t *testing.T) {
	tests := []struct {
		name     string
		key      string
		value    string
		wantAlgo string
		wantSize int
		wantMode string
	}{
		// ARIA variants
		{"aria-256-gcm", "algorithm", "aria-256-gcm", "ARIA", 256, "GCM"},
		{"aria-128-gcm", "algorithm", "aria-128-gcm", "ARIA", 128, "GCM"},
		{"aria-256-cbc", "algorithm", "aria-256-cbc", "ARIA", 256, "CBC"},
		{"aria-128-cbc", "algorithm", "aria-128-cbc", "ARIA", 128, "CBC"},
		{"aria-192", "algorithm", "aria-192", "ARIA", 192, ""},
		{"aria-256", "algorithm", "aria-256", "ARIA", 256, ""},
		{"aria-128", "algorithm", "aria-128", "ARIA", 128, ""},
		{"aria bare", "algorithm", "aria", "ARIA", 0, ""},

		// SEED
		{"seed-cbc", "algorithm", "seed-cbc", "SEED", 128, "CBC"},
		{"seed bare", "algorithm", "seed", "SEED", 128, ""},

		// LEA variants
		{"lea-256-gcm", "algorithm", "lea-256-gcm", "LEA", 256, "GCM"},
		{"lea-128-gcm", "algorithm", "lea-128-gcm", "LEA", 128, "GCM"},
		{"lea-256", "algorithm", "lea-256", "LEA", 256, ""},
		{"lea bare", "algorithm", "lea", "LEA", 0, ""},

		// KCDSA / EC-KCDSA (must be separate)
		{"ec-kcdsa", "algorithm", "ec-kcdsa", "EC-KCDSA", 0, ""},
		{"eckcdsa", "algorithm", "eckcdsa", "EC-KCDSA", 0, ""},
		{"kcdsa", "algorithm", "kcdsa", "KCDSA", 0, ""},

		// Hashes
		{"has-160", "algorithm", "has-160", "HAS-160", 0, ""},
		{"has160", "algorithm", "has160", "HAS-160", 0, ""},
		{"lsh-512", "algorithm", "lsh-512", "LSH-512", 0, ""},
		{"lsh-256", "algorithm", "lsh-256", "LSH-256", 0, ""},

		// K-PQC finalists
		{"smaug-t", "algorithm", "smaug-t", "SMAUG-T", 0, ""},
		{"haetae", "algorithm", "haetae", "HAETAE", 0, ""},
		{"aimer", "algorithm", "aimer", "AIMer", 0, ""},
		{"ntru+", "algorithm", "ntru+", "NTRU+", 0, ""},
		{"ntruplus", "algorithm", "ntruplus", "NTRU+", 0, ""},

		// cipher key pattern
		{"cipher aria", "cipher", "aria", "ARIA", 0, ""},
		{"cipher seed", "cipher", "seed", "SEED", 128, ""},
		{"cipher lea", "cipher", "lea", "LEA", 0, ""},

		// hash key pattern
		{"hash has-160", "hash", "has-160", "HAS-160", 0, ""},
		{"hash lsh-512", "hash", "lsh-512", "LSH-512", 0, ""},

		// signature key pattern
		{"sig haetae", "signature", "haetae", "HAETAE", 0, ""},
		{"sig aimer", "signature", "aimer", "AIMer", 0, ""},
		{"sig ec-kcdsa", "signature", "ec-kcdsa", "EC-KCDSA", 0, ""},
		{"sig kcdsa", "signature", "kcdsa", "KCDSA", 0, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kvPairs := []KeyValue{{Key: tt.key, Value: tt.value, Line: 1}}
			results := matchCryptoParams("test.yml", kvPairs)

			if len(results) == 0 {
				t.Fatalf("expected match for key=%q value=%q, got none", tt.key, tt.value)
			}
			r := results[0]
			if r.Algorithm == nil {
				t.Fatal("expected algorithm, got nil")
			}
			if r.Algorithm.Name != tt.wantAlgo {
				t.Errorf("Algorithm.Name = %q, want %q", r.Algorithm.Name, tt.wantAlgo)
			}
			if tt.wantSize > 0 && r.Algorithm.KeySize != tt.wantSize {
				t.Errorf("Algorithm.KeySize = %d, want %d", r.Algorithm.KeySize, tt.wantSize)
			}
			if tt.wantMode != "" && r.Algorithm.Mode != tt.wantMode {
				t.Errorf("Algorithm.Mode = %q, want %q", r.Algorithm.Mode, tt.wantMode)
			}
		})
	}
}

func TestMatchCryptoParams_KoreanNoFalsePositives(t *testing.T) {
	// "lea" should NOT match in words like "clear" or "plea"
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{"clear should not match lea", "algorithm", "clear"},
		{"plea should not match lea", "algorithm", "plea"},
		{"description should not match des", "algorithm", "description"},
		{"seeder should not match seed", "algorithm", "seeder"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kvPairs := []KeyValue{{Key: tt.key, Value: tt.value, Line: 1}}
			results := matchCryptoParams("test.yml", kvPairs)
			if len(results) > 0 {
				t.Errorf("false positive: key=%q value=%q matched %q", tt.key, tt.value, results[0].Algorithm.Name)
			}
		})
	}
}

func TestMatchCryptoParams_ARIANotAES(t *testing.T) {
	// "aria-256-gcm" should match ARIA, not AES
	kvPairs := []KeyValue{{Key: "algorithm", Value: "aria-256-gcm", Line: 1}}
	results := matchCryptoParams("test.yml", kvPairs)

	if len(results) == 0 {
		t.Fatal("expected match for aria-256-gcm")
	}
	if results[0].Algorithm.Name != "ARIA" {
		t.Errorf("aria-256-gcm should match ARIA, got %q", results[0].Algorithm.Name)
	}
}

func TestMatchCryptoParams_CaseInsensitive(t *testing.T) {
	// Korean algorithm names should be case-insensitive
	kvPairs := []KeyValue{{Key: "algorithm", Value: "ARIA-256-GCM", Line: 1}}
	results := matchCryptoParams("test.yml", kvPairs)

	if len(results) == 0 {
		t.Fatal("expected case-insensitive match for ARIA-256-GCM")
	}
	if results[0].Algorithm.Name != "ARIA" {
		t.Errorf("expected ARIA, got %q", results[0].Algorithm.Name)
	}
}
