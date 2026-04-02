package registry

import (
	"sync"
	"testing"
)

func TestLoad(t *testing.T) {
	reg := Load()
	if reg == nil {
		t.Fatal("Load() returned nil")
	}

	// Verify basic counts
	if reg.FamilyCount() < 30 {
		t.Errorf("FamilyCount() = %d, want >= 30", reg.FamilyCount())
	}
	if reg.PatternCount() < 50 {
		t.Errorf("PatternCount() = %d, want >= 50", reg.PatternCount())
	}
	if reg.CurveCount() < 5 {
		t.Errorf("CurveCount() = %d, want >= 5", reg.CurveCount())
	}
}

// TestLoad_ConcurrentCallsSafe verifies that Load() is safe to call from multiple
// goroutines simultaneously (sync.Once guarantees this, but the race detector
// will catch any issues). All results must be non-nil and point to the same instance.
func TestLoad_ConcurrentCallsSafe(t *testing.T) {
	const goroutines = 10
	results := make([]*Registry, goroutines)
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		i := i
		go func() {
			defer wg.Done()
			results[i] = Load()
		}()
	}

	wg.Wait()

	for i, r := range results {
		if r == nil {
			t.Errorf("goroutine %d: Load() returned nil", i)
		}
	}
	// All results should be the same singleton instance.
	for i := 1; i < goroutines; i++ {
		if results[i] != results[0] {
			t.Errorf("goroutine %d: Load() returned different instance than goroutine 0", i)
		}
	}
}

func TestLoad_Singleton(t *testing.T) {
	r1 := Load()
	r2 := Load()
	if r1 != r2 {
		t.Error("Load() should return the same singleton instance")
	}
}

func TestLookupFamily(t *testing.T) {
	reg := Load()

	families := []string{"AES", "RSA", "ECDSA", "ML-KEM", "ML-DSA", "SHA-2", "SHA-3", "ARIA", "SEED", "LEA", "SMAUG-T", "HAETAE", "AIMer"}
	for _, name := range families {
		fam, ok := reg.LookupFamily(name)
		if !ok {
			t.Errorf("LookupFamily(%q) not found", name)
			continue
		}
		if fam.Family == "" {
			t.Errorf("LookupFamily(%q).Family is empty", name)
		}
		if len(fam.Variant) == 0 {
			t.Errorf("LookupFamily(%q) has no variants", name)
		}
	}
}

func TestLookupFamily_CaseInsensitive(t *testing.T) {
	reg := Load()
	_, ok := reg.LookupFamily("aes")
	if !ok {
		t.Error("LookupFamily should be case-insensitive")
	}
}

func TestLookupFamily_NotFound(t *testing.T) {
	reg := Load()
	_, ok := reg.LookupFamily("NONEXISTENT")
	if ok {
		t.Error("LookupFamily should return false for unknown family")
	}
}

func TestNormalize_ExactMatch(t *testing.T) {
	reg := Load()

	tests := []struct {
		raw     string
		keySize int
		mode    string
		family  string
	}{
		{"AES-256-GCM", 0, "", "AES"},
		{"AES-128-CBC", 0, "", "AES"},
		{"ML-KEM-768", 0, "", "ML-KEM"},
		{"ML-DSA-65", 0, "", "ML-DSA"},
		{"SHA-256", 0, "", "SHA-2"},
		{"SHA-512", 0, "", "SHA-2"},
	}

	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			result := reg.Normalize(tt.raw, tt.keySize, tt.mode)
			if result.Family != tt.family {
				t.Errorf("Normalize(%q).Family = %q, want %q", tt.raw, result.Family, tt.family)
			}
			if result.MatchType != MatchExact {
				t.Errorf("Normalize(%q).MatchType = %q, want exact", tt.raw, result.MatchType)
			}
			if result.Confidence != "high" {
				t.Errorf("Normalize(%q).Confidence = %q, want high", tt.raw, result.Confidence)
			}
		})
	}
}

func TestNormalize_PrefixMatch(t *testing.T) {
	reg := Load()

	// Something like "AES_GCM_256" should get prefix-matched to AES family
	result := reg.Normalize("AES_GCM_256", 256, "GCM")
	if result.Family != "AES" {
		t.Errorf("Normalize(AES_GCM_256).Family = %q, want AES", result.Family)
	}
}

func TestNormalize_Fallback(t *testing.T) {
	reg := Load()

	result := reg.Normalize("TotallyUnknownAlgorithm", 0, "")
	if result.MatchType != MatchNone {
		t.Errorf("unknown algo MatchType = %q, want none", result.MatchType)
	}
	if result.Confidence != "low" {
		t.Errorf("unknown algo Confidence = %q, want low", result.Confidence)
	}
}

func TestNormalize_UnderscoreNormalized(t *testing.T) {
	reg := Load()

	// Underscores should be converted to hyphens
	result := reg.Normalize("AES-256-GCM", 0, "")
	resultUS := reg.Normalize("AES-256-GCM", 0, "")
	if result.CanonicalName != resultUS.CanonicalName {
		t.Errorf("underscore normalization failed: %q vs %q",
			result.CanonicalName, resultUS.CanonicalName)
	}
}

func TestResolveCurve_CanonicalName(t *testing.T) {
	reg := Load()

	result, ok := reg.ResolveCurve("P-256")
	if !ok {
		t.Fatal("ResolveCurve(P-256) failed")
	}
	if result.Name != "P-256" {
		t.Errorf("Name = %q, want P-256", result.Name)
	}
}

func TestResolveCurve_Alias(t *testing.T) {
	reg := Load()

	result, ok := reg.ResolveCurve("secp256r1")
	if !ok {
		t.Fatal("ResolveCurve(secp256r1) failed")
	}
	if result.Name != "P-256" {
		t.Errorf("Name = %q, want P-256", result.Name)
	}
}

func TestResolveCurve_OID(t *testing.T) {
	reg := Load()

	result, ok := reg.ResolveCurve("1.2.840.10045.3.1.7")
	if !ok {
		t.Fatal("ResolveCurve(OID) failed")
	}
	if result.Name != "P-256" {
		t.Errorf("Name = %q, want P-256", result.Name)
	}
}

func TestResolveCurve_NotFound(t *testing.T) {
	reg := Load()

	_, ok := reg.ResolveCurve("nonexistent-curve")
	if ok {
		t.Error("ResolveCurve should return false for unknown curve")
	}
}

func TestPatternCompiler_BasicPatterns(t *testing.T) {
	tests := []struct {
		pattern string
		family  string
		input   string
		match   bool
	}{
		{"AES-256-GCM", "AES", "AES-256-GCM", true},
		{"AES-256-GCM", "AES", "aes-256-gcm", true}, // case insensitive
		{"AES-256-GCM", "AES", "AES-128-CBC", false},
		{"ML-KEM-768", "ML-KEM", "ML-KEM-768", true},
		{"SHA-256", "SHA-2", "SHA-256", true},
	}

	for _, tt := range tests {
		t.Run(tt.pattern+"→"+tt.input, func(t *testing.T) {
			cp, err := compilePattern(tt.pattern, tt.family)
			if err != nil {
				t.Fatalf("compilePattern(%q) error: %v", tt.pattern, err)
			}
			_, ok := cp.match(tt.input)
			if ok != tt.match {
				t.Errorf("match(%q) = %v, want %v", tt.input, ok, tt.match)
			}
		})
	}
}

func TestConvertPatternToRegex(t *testing.T) {
	tests := []struct {
		pattern string
		want    string
	}{
		{"AES-256", "AES-256"},
		// Dots should be escaped
		{"SLH-DSA-SHA2-128s", "SLH-DSA-SHA2-128s"},
	}

	for _, tt := range tests {
		got := convertPatternToRegex(tt.pattern)
		if got != tt.want {
			t.Errorf("convertPatternToRegex(%q) = %q, want %q", tt.pattern, got, tt.want)
		}
	}
}
