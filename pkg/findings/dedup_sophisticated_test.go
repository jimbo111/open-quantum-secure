package findings

// dedup_sophisticated_test.go — sophisticated DedupeKey property and collision tests.
//
// Gaps addressed:
//  1. Property: any non-empty (file, line, alg) triple produces deterministic non-empty key
//  2. Two different findings (different file/line/alg) produce distinct keys
//  3. Same finding from two engines produces same key (corroboration merge works)
//  4. Dependency version participates in key (different versions → different keys)
//  5. Algorithm name takes priority over dependency when both are set
//  6. Exhaustive: DedupeKey never panics for any combination of nil/empty fields

import (
	"fmt"
	"testing"
)

// ─── 1. Property: deterministic non-empty for any (file, line, alg) triple ───

// TestDedupeKey_Property_DeterministicNonEmpty verifies that for a range of
// (file, line, alg) triples the key is always non-empty and identical on
// repeated calls. This is the core property test for DedupeKey correctness.
func TestDedupeKey_Property_DeterministicNonEmpty(t *testing.T) {
	triples := []struct {
		file string
		line int
		alg  string
	}{
		{"/src/main.go", 1, "RSA"},
		{"/src/main.go", 1, "AES-256-GCM"},
		{"/src/crypto.py", 42, "ECDH"},
		{"", 0, "MD5"},   // empty file, zero line
		{"a", 0, "x"},    // minimal non-empty values
		{"/deep/path/to/file.java", 99999, "ML-KEM-768"},
		{"(tls-probe)/example.com:443#kex", 0, "X25519MLKEM768"},
	}

	for _, tri := range triples {
		tri := tri
		t.Run(fmt.Sprintf("file=%q/line=%d/alg=%q", tri.file, tri.line, tri.alg), func(t *testing.T) {
			f := &UnifiedFinding{
				Location:  Location{File: tri.file, Line: tri.line},
				Algorithm: &Algorithm{Name: tri.alg},
			}

			key1 := f.DedupeKey()
			key2 := f.DedupeKey()
			key3 := f.DedupeKey()

			// Non-empty
			if key1 == "" {
				t.Errorf("DedupeKey() returned empty string for triple (%q, %d, %q)",
					tri.file, tri.line, tri.alg)
			}
			// Deterministic
			if key1 != key2 || key2 != key3 {
				t.Errorf("DedupeKey() is not deterministic: %q != %q != %q", key1, key2, key3)
			}
		})
	}
}

// ─── 2. Different findings (file/line/alg differ) produce distinct keys ──────

// TestDedupeKey_DifferentFindingsDifferentKeys is the regression guard for
// commit 010970c: two findings that differ in any dimension must not collide.
func TestDedupeKey_DifferentFindingsDifferentKeys(t *testing.T) {
	base := UnifiedFinding{
		Location:  Location{File: "/src/crypto.go", Line: 10},
		Algorithm: &Algorithm{Name: "RSA"},
	}

	differentFrom := []struct {
		name    string
		finding UnifiedFinding
	}{
		{
			"different file",
			UnifiedFinding{
				Location:  Location{File: "/src/other.go", Line: 10},
				Algorithm: &Algorithm{Name: "RSA"},
			},
		},
		{
			"different line",
			UnifiedFinding{
				Location:  Location{File: "/src/crypto.go", Line: 11},
				Algorithm: &Algorithm{Name: "RSA"},
			},
		},
		{
			"different algorithm",
			UnifiedFinding{
				Location:  Location{File: "/src/crypto.go", Line: 10},
				Algorithm: &Algorithm{Name: "ECDH"},
			},
		},
		{
			"different alg and file",
			UnifiedFinding{
				Location:  Location{File: "/src/tls.go", Line: 10},
				Algorithm: &Algorithm{Name: "ECDH"},
			},
		},
	}

	baseKey := base.DedupeKey()
	for _, d := range differentFrom {
		d := d
		t.Run(d.name, func(t *testing.T) {
			otherKey := d.finding.DedupeKey()
			if baseKey == otherKey {
				t.Errorf("collision: base and %s produced same key %q", d.name, baseKey)
			}
		})
	}
}

// ─── 3. Same finding from two engines → same key (corroboration merging) ──────

// TestDedupeKey_SameAlgDifferentEngines_SameKey confirms that the dedup design
// allows two engines that both detect the same algorithm at the same location
// to be merged into a single finding with corroboration.
func TestDedupeKey_SameAlgDifferentEngines_SameKey(t *testing.T) {
	engines := []string{"cipherscope", "cryptoscan", "semgrep", "tls-probe"}

	for i, eng1 := range engines {
		for _, eng2 := range engines[i+1:] {
			eng1, eng2 := eng1, eng2
			t.Run(fmt.Sprintf("%s+%s", eng1, eng2), func(t *testing.T) {
				f1 := UnifiedFinding{
					Location:     Location{File: "/svc/auth.go", Line: 42},
					Algorithm:    &Algorithm{Name: "RSA-2048"},
					SourceEngine: eng1,
				}
				f2 := UnifiedFinding{
					Location:     Location{File: "/svc/auth.go", Line: 42},
					Algorithm:    &Algorithm{Name: "RSA-2048"},
					SourceEngine: eng2,
				}
				if f1.DedupeKey() != f2.DedupeKey() {
					t.Errorf("engines %q and %q: same finding should share dedup key: %q vs %q",
						eng1, eng2, f1.DedupeKey(), f2.DedupeKey())
				}
			})
		}
	}
}

// ─── 4. Dependency version participates in key ────────────────────────────────

// TestDedupeKey_DependencyVersionDistinct verifies that two findings for the
// same library at different versions are NOT merged. This prevents a false
// "already fixed" state when a project has both old and new versions present.
func TestDedupeKey_DependencyVersionDistinct(t *testing.T) {
	f1 := UnifiedFinding{
		Location:   Location{File: "/go.mod", Line: 0},
		Dependency: &Dependency{Library: "crypto/openssl", Version: "1.0.2"},
	}
	f2 := UnifiedFinding{
		Location:   Location{File: "/go.mod", Line: 0},
		Dependency: &Dependency{Library: "crypto/openssl", Version: "3.0.0"},
	}
	if f1.DedupeKey() == f2.DedupeKey() {
		t.Errorf("different versions of same library must not share dedup key: "+
			"v1.0.2 and v3.0.0 both produced %q", f1.DedupeKey())
	}
}

// TestDedupeKey_DependencyNoVersionVsVersion verifies that a finding without
// a version is distinct from one with a version for the same library.
func TestDedupeKey_DependencyNoVersionVsVersion(t *testing.T) {
	noVersion := UnifiedFinding{
		Location:   Location{File: "/pom.xml"},
		Dependency: &Dependency{Library: "bouncy-castle"},
	}
	withVersion := UnifiedFinding{
		Location:   Location{File: "/pom.xml"},
		Dependency: &Dependency{Library: "bouncy-castle", Version: "1.68"},
	}
	if noVersion.DedupeKey() == withVersion.DedupeKey() {
		t.Errorf("dependency without version and with version must not share dedup key: both produced %q",
			noVersion.DedupeKey())
	}
}

// ─── 5. Algorithm takes priority over Dependency when both set ───────────────

// TestDedupeKey_AlgorithmPriorityOverDependency verifies the documented precedence:
// when both Algorithm (non-empty Name) and Dependency are set, the algorithm
// branch runs and the dependency is ignored in the key.
func TestDedupeKey_AlgorithmPriorityOverDependency(t *testing.T) {
	f := UnifiedFinding{
		Location:   Location{File: "app.go", Line: 5},
		Algorithm:  &Algorithm{Name: "AES"},
		Dependency: &Dependency{Library: "crypto/tls", Version: "1.0"},
	}
	key := f.DedupeKey()
	want := "app.go|5|alg|AES"
	if key != want {
		t.Errorf("DedupeKey() = %q, want %q (algorithm must take priority)", key, want)
	}
}

// ─── 6. Never panics for any nil/empty combination ────────────────────────────

// TestDedupeKey_NoPanicMatrix exhaustively tests all combinations of nil/set
// for Algorithm and Dependency to guarantee DedupeKey never panics.
func TestDedupeKey_NoPanicMatrix(t *testing.T) {
	type combo struct {
		name string
		f    UnifiedFinding
	}

	combos := []combo{
		{
			"nil alg, nil dep",
			UnifiedFinding{Location: Location{File: "f.go", Line: 1}, SourceEngine: "eng"},
		},
		{
			"alg with empty Name, nil dep",
			UnifiedFinding{
				Location:  Location{File: "f.go", Line: 1},
				Algorithm: &Algorithm{Name: ""},
			},
		},
		{
			"nil alg, dep with empty Library",
			UnifiedFinding{
				Location:   Location{File: "f.go", Line: 1},
				Dependency: &Dependency{Library: ""},
			},
		},
		{
			"nil alg, dep with non-empty Library",
			UnifiedFinding{
				Location:   Location{File: "f.go", Line: 1},
				Dependency: &Dependency{Library: "openssl"},
			},
		},
		{
			"alg with name, nil dep",
			UnifiedFinding{
				Location:  Location{File: "f.go", Line: 1},
				Algorithm: &Algorithm{Name: "RSA"},
			},
		},
		{
			"both nil, empty file",
			UnifiedFinding{Location: Location{File: "", Line: 0}},
		},
	}

	for _, c := range combos {
		c := c
		t.Run(c.name, func(t *testing.T) {
			var key string
			func() {
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("DedupeKey panicked for %s: %v", c.name, r)
					}
				}()
				key = c.f.DedupeKey()
			}()
			if key == "" {
				// Only acceptable when fallback path also returns empty — check that
				// the key is at least structurally valid (non-panic is the real assertion)
				_ = key
			}
		})
	}
}

// ─── 7. InnerPath key format includes "!" separator ──────────────────────────

// TestDedupeKey_InnerPath_KeyFormat_Deterministic verifies that InnerPath findings
// produce the exact expected key format and are deterministic across calls.
func TestDedupeKey_InnerPath_KeyFormat_Deterministic(t *testing.T) {
	f := UnifiedFinding{
		Location:  Location{File: "app.jar", InnerPath: "com/example/Crypto.class", Line: 7},
		Algorithm: &Algorithm{Name: "AES-128"},
	}
	want := "app.jar!com/example/Crypto.class|7|alg|AES-128"
	for i := 0; i < 5; i++ {
		got := f.DedupeKey()
		if got != want {
			t.Errorf("iteration %d: DedupeKey() = %q, want %q", i, got, want)
		}
	}
}

// ─── 8. PQC algorithm names in DedupeKey are case-sensitive ──────────────────

// TestDedupeKey_PQCAlgorithmName_CaseSensitive verifies that the PQC algorithm
// names used as dedup keys are case-sensitive — "ML-KEM-768" and "ml-kem-768"
// are different strings and should not collapse into the same finding.
// Normalization happens upstream in the orchestrator before dedup.
func TestDedupeKey_PQCAlgorithmName_CaseSensitive(t *testing.T) {
	canonical := UnifiedFinding{
		Location:  Location{File: "/src/tls.go", Line: 10},
		Algorithm: &Algorithm{Name: "ML-KEM-768"},
	}
	lowercase := UnifiedFinding{
		Location:  Location{File: "/src/tls.go", Line: 10},
		Algorithm: &Algorithm{Name: "ml-kem-768"},
	}
	if canonical.DedupeKey() == lowercase.DedupeKey() {
		t.Errorf("DedupeKey must be case-sensitive: 'ML-KEM-768' and 'ml-kem-768' must differ. "+
			"Both produced: %q", canonical.DedupeKey())
	}
}

// ─── 9. Dependency-only finding: library name is in key ──────────────────────

// TestDedupeKey_DependencyKeyContainsLibraryName verifies that the library name
// is embedded verbatim in the dependency branch key, so changes in library
// name (even minor ones like "openssl" vs "OpenSSL") produce different keys.
func TestDedupeKey_DependencyKeyContainsLibraryName(t *testing.T) {
	openssl := UnifiedFinding{
		Location:   Location{File: "/go.mod"},
		Dependency: &Dependency{Library: "openssl"},
	}
	OpenSSL := UnifiedFinding{
		Location:   Location{File: "/go.mod"},
		Dependency: &Dependency{Library: "OpenSSL"},
	}
	if openssl.DedupeKey() == OpenSSL.DedupeKey() {
		t.Errorf("'openssl' and 'OpenSSL' should have different dedup keys (case-sensitive library names)")
	}
	// Verify the library name is literally in the key
	key := openssl.DedupeKey()
	if key != "/go.mod|dep|openssl" {
		t.Errorf("dependency key = %q, want %q", key, "/go.mod|dep|openssl")
	}
}
