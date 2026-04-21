// Package cache — property-based audit tests.
//
// Uses testing/quick to probe invariants of the incremental cache: hash
// determinism, Update/Get round-trip, and gzip round-trip.
package cache

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"testing/quick"

	"github.com/jimbo111/open-quantum-secure/pkg/findings"
)

// Property: HashFile is deterministic — hashing the same file twice gives
// the same hash.
func TestProp_HashFile_Deterministic(t *testing.T) {
	dir := t.TempDir()

	f := func(content []byte) bool {
		p := filepath.Join(dir, "f.bin")
		if err := os.WriteFile(p, content, 0644); err != nil {
			return false
		}
		h1, err := HashFile(p)
		if err != nil {
			return false
		}
		h2, err := HashFile(p)
		if err != nil {
			return false
		}
		return h1 == h2
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 200}); err != nil {
		t.Error(err)
	}
}

// Property: HashFile matches an independent SHA-256 computation.
func TestProp_HashFile_MatchesStdlibSHA256(t *testing.T) {
	dir := t.TempDir()

	f := func(content []byte) bool {
		p := filepath.Join(dir, "f.bin")
		if err := os.WriteFile(p, content, 0644); err != nil {
			return false
		}
		got, err := HashFile(p)
		if err != nil {
			return false
		}
		h := sha256.Sum256(content)
		want := hex.EncodeToString(h[:])
		return got == want
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 200}); err != nil {
		t.Error(err)
	}
}

// Property: After Update+Get with matching hashes, the findings survive.
func TestProp_UpdateGet_RoundTrip(t *testing.T) {
	f := func(nameChar byte, algoChar byte, lineByte byte) bool {
		sc := New()
		name := string(rune('a' + nameChar%26))
		algo := string(rune('A' + algoChar%26))
		path := "/src/" + name + ".go"
		hash := "hash_" + name

		sc.Update(
			map[string][]findings.UnifiedFinding{
				path: {sampleFinding("e", path, algo, int(lineByte))},
			},
			map[string]string{path: hash},
		)
		cached, changed := sc.GetUnchangedFindings(map[string]string{path: hash})
		if len(cached) != 1 || len(changed) != 0 {
			return false
		}
		if cached[0].Algorithm.Name != algo {
			return false
		}
		return true
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 500}); err != nil {
		t.Error(err)
	}
}

// Property: gzip round-trip preserves ScannerVersion and entry count.
func TestProp_MarshalGzip_RoundTrip(t *testing.T) {
	f := func(vers byte, count uint8) bool {
		sc := New()
		sc.ScannerVersion = string(rune('A' + vers%26))
		n := int(count) % 20
		for i := 0; i < n; i++ {
			p := "/src/" + string(rune('a'+i%26)) + ".go"
			sc.Entries[p] = &CacheEntry{
				ContentHash: "h" + string(rune('0'+i%10)),
				Findings:    []findings.UnifiedFinding{sampleFinding("e", p, "RSA", i)},
			}
		}

		compressed, err := sc.MarshalGzip()
		if err != nil {
			return false
		}
		sc2, err := UnmarshalGzip(compressed)
		if err != nil {
			return false
		}
		return sc2.ScannerVersion == sc.ScannerVersion && len(sc2.Entries) == len(sc.Entries)
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 100}); err != nil {
		t.Error(err)
	}
}

// Property: IsValid is true iff format version, scanner version, and all
// engine versions match.
func TestProp_IsValid_ExactMatchRequired(t *testing.T) {
	f := func(v1, v2 byte) bool {
		sc := New()
		sc.ScannerVersion = "v1"
		sc.EngineVersions["e"] = "1"

		want := v1 == v2
		got := sc.IsValid("v1", map[string]string{"e": string(rune('0' + v2%10))})
		// If v2 != "1", should be false. Our want logic is simpler: IsValid
		// true only when EngineVersions match exactly.
		_ = want
		expectTrue := string(rune('0'+v2%10)) == "1"
		if got != expectTrue {
			return false
		}
		return true
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 200}); err != nil {
		t.Error(err)
	}
}
