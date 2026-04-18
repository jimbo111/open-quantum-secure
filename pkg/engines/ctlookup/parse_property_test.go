// parse_property_test.go — Property-based tests using seed-based pseudo-random
// inputs. Asserts invariants that must hold for all well-formed inputs rather
// than only the handful of hand-crafted examples in parse_test.go.
package ctlookup

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"testing"
	"time"
)

// randEntry builds a crtShEntry from a seeded RNG. All generated values are
// valid JSON strings so marshal→parse must be a lossless round-trip.
func randEntry(rng *rand.Rand) crtShEntry {
	tsFmts := []string{
		"2024-01-15T12:00:00",
		"2023-06-01T08:00:00",
		"2024-03-20 09:30:00",
		"2024-01-01",
	}
	ts := tsFmts[rng.Intn(len(tsFmts))]
	return crtShEntry{
		IssuerCAID:     rng.Intn(999999),
		IssuerName:     fmt.Sprintf("CN=Test CA %d", rng.Intn(50)),
		CommonName:     fmt.Sprintf("prop%05d.example.com", rng.Intn(99999)),
		NameValue:      fmt.Sprintf("prop%05d.example.com", rng.Intn(99999)),
		ID:             rng.Int63n(1e12),
		EntryTimestamp: ts,
		NotBefore:      ts,
		NotAfter:       ts,
		SerialNumber:   fmt.Sprintf("%016X", rng.Uint64()),
	}
}

// TestParseProperty_MarshalRoundTrip verifies that for 200 seed-generated
// crtShEntry values, marshal(entry) → parseCrtShJSON → entries[0] preserves
// the identity (ID, SerialNumber, CommonName) and name (NameValue, IssuerName)
// fields exactly.
func TestParseProperty_MarshalRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for i := 0; i < 200; i++ {
		original := randEntry(rng)
		data, err := json.Marshal([]crtShEntry{original})
		if err != nil {
			t.Fatalf("iteration %d: marshal: %v", i, err)
		}
		entries, err := parseCrtShJSON(data)
		if err != nil {
			t.Fatalf("iteration %d: parseCrtShJSON: %v", i, err)
		}
		if len(entries) != 1 {
			t.Fatalf("iteration %d: expected 1 entry, got %d", i, len(entries))
		}
		got := entries[0]
		if got.ID != original.ID {
			t.Errorf("iteration %d: ID mismatch: got %d, want %d", i, got.ID, original.ID)
		}
		if got.SerialNumber != original.SerialNumber {
			t.Errorf("iteration %d: SerialNumber mismatch: got %q, want %q", i, got.SerialNumber, original.SerialNumber)
		}
		if got.CommonName != original.CommonName {
			t.Errorf("iteration %d: CommonName mismatch: got %q, want %q", i, got.CommonName, original.CommonName)
		}
		if got.NameValue != original.NameValue {
			t.Errorf("iteration %d: NameValue mismatch: got %q, want %q", i, got.NameValue, original.NameValue)
		}
		if got.IssuerName != original.IssuerName {
			t.Errorf("iteration %d: IssuerName mismatch: got %q, want %q", i, got.IssuerName, original.IssuerName)
		}
		if got.IssuerCAID != original.IssuerCAID {
			t.Errorf("iteration %d: IssuerCAID mismatch: got %d, want %d", i, got.IssuerCAID, original.IssuerCAID)
		}
	}
}

// TestParseProperty_MultiEntryRoundTrip verifies that arrays of N entries
// (N ∈ {0, 1, 5, 20}) round-trip without element reordering or count change.
func TestParseProperty_MultiEntryRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 5, 20} {
		rng := rand.New(rand.NewSource(int64(n + 7)))
		originals := make([]crtShEntry, n)
		for i := range originals {
			originals[i] = randEntry(rng)
		}
		data, err := json.Marshal(originals)
		if err != nil {
			t.Fatalf("n=%d: marshal: %v", n, err)
		}
		entries, err := parseCrtShJSON(data)
		if err != nil {
			t.Fatalf("n=%d: parseCrtShJSON: %v", n, err)
		}
		if len(entries) != n {
			t.Fatalf("n=%d: got %d entries, want %d", n, len(entries), n)
		}
		for i, orig := range originals {
			if entries[i].ID != orig.ID {
				t.Errorf("n=%d element %d: ID %d != %d", n, i, entries[i].ID, orig.ID)
			}
		}
	}
}

// TestCacheProperty_PutGetReturnsStoredValue verifies that for any ASCII hostname,
// cache.Get(cache.Put(k,v)) == v. Uses sequential keys so there are no duplicates
// and the capacity (512) is never saturated.
func TestCacheProperty_PutGetReturnsStoredValue(t *testing.T) {
	c := newCTCache(512, time.Hour)
	rng := rand.New(rand.NewSource(99))

	type kv struct {
		key    string
		serial string
	}
	const nKeys = 100
	pairs := make([]kv, nKeys)
	for i := range pairs {
		pairs[i] = kv{
			key:    fmt.Sprintf("prophost%04d.example.com", i),
			serial: fmt.Sprintf("%016X", rng.Uint64()),
		}
	}

	for _, p := range pairs {
		c.put(p.key, []certRecord{{Serial: p.serial, SigAlgorithm: "ECDSA", PubKeySize: 256}})
	}

	for _, p := range pairs {
		recs, ok := c.get(p.key)
		if !ok {
			t.Errorf("cache miss for key %q (should be a cache hit)", p.key)
			continue
		}
		if len(recs) == 0 {
			t.Errorf("key %q: empty records slice", p.key)
			continue
		}
		if recs[0].Serial != p.serial {
			t.Errorf("key %q: serial %q != stored %q", p.key, recs[0].Serial, p.serial)
		}
	}
}
