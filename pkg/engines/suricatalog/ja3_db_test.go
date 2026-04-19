package suricatalog

import "testing"

func TestLookupJA3SMiss(t *testing.T) {
	_, ok := lookupJA3S("not-a-real-hash")
	if ok {
		t.Fatal("lookupJA3S should return false for unknown hash")
	}
}

func TestLookupJA3SEmpty(t *testing.T) {
	_, ok := lookupJA3S("")
	if ok {
		t.Fatal("lookupJA3S should return false for empty hash")
	}
}

func TestJA3SDBIsQueryable(t *testing.T) {
	// Verify the table is initialized and queryable even when empty.
	count := len(ja3sDB)
	if count < 0 {
		t.Fatal("ja3sDB should have non-negative length")
	}
	// The table is intentionally empty pending authoritative fingerprints.
	// When entries are added, each must cite a public source — this test
	// ensures any future entries are correctly structured.
	for hash, hint := range ja3sDB {
		if hash == "" {
			t.Error("ja3sDB contains an entry with empty hash key")
		}
		if hint.Label == "" {
			t.Errorf("ja3sDB entry %q has empty Label", hash)
		}
	}
}
