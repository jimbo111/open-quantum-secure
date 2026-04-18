package ctlookup

import (
	"testing"
	"time"
)

func TestCache_PutGet(t *testing.T) {
	c := newCTCache(10, time.Hour)
	recs := []certRecord{{Serial: "abc", SigAlgorithm: "RSA", PubKeySize: 2048}}
	c.put("example.com", recs)

	got, ok := c.get("example.com")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if len(got) != 1 || got[0].Serial != "abc" {
		t.Errorf("got %+v, want serial=abc", got)
	}
}

func TestCache_Miss(t *testing.T) {
	c := newCTCache(10, time.Hour)
	_, ok := c.get("nothere.com")
	if ok {
		t.Error("expected cache miss for unknown key")
	}
}

func TestCache_TTLExpiry(t *testing.T) {
	c := newCTCache(10, 10*time.Millisecond)
	c.put("example.com", []certRecord{{Serial: "xyz"}})

	time.Sleep(20 * time.Millisecond)

	_, ok := c.get("example.com")
	if ok {
		t.Error("expected cache miss after TTL expiry")
	}
}

func TestCache_LRUEviction(t *testing.T) {
	// Capacity of 2 — inserting a 3rd entry evicts the LRU (first inserted).
	c := newCTCache(2, time.Hour)
	c.put("a.com", []certRecord{{Serial: "1"}})
	c.put("b.com", []certRecord{{Serial: "2"}})

	// Access a.com to make it recently used.
	c.get("a.com")

	// Insert a 3rd entry; b.com is now LRU and should be evicted.
	c.put("c.com", []certRecord{{Serial: "3"}})

	if _, ok := c.get("b.com"); ok {
		t.Error("b.com should have been evicted (LRU)")
	}
	if _, ok := c.get("a.com"); !ok {
		t.Error("a.com should still be present (recently accessed)")
	}
	if _, ok := c.get("c.com"); !ok {
		t.Error("c.com should be present (just inserted)")
	}
}

func TestCache_UpdateRefreshesExpiry(t *testing.T) {
	c := newCTCache(10, 30*time.Millisecond)
	c.put("example.com", []certRecord{{Serial: "v1"}})

	time.Sleep(20 * time.Millisecond)

	// Re-insert before TTL expires; should reset the expiry.
	c.put("example.com", []certRecord{{Serial: "v2"}})

	time.Sleep(20 * time.Millisecond)

	// 40ms have passed total, but the last put was at 20ms so expiry is at 50ms.
	// The entry should still be alive.
	got, ok := c.get("example.com")
	if !ok {
		t.Fatal("expected cache hit after update")
	}
	if len(got) == 0 || got[0].Serial != "v2" {
		t.Errorf("got serial=%q, want v2", got[0].Serial)
	}
}

func TestCache_EmptySlice(t *testing.T) {
	// Storing an empty slice is valid (hostname with no CT results).
	c := newCTCache(10, time.Hour)
	c.put("empty.com", nil)
	recs, ok := c.get("empty.com")
	if !ok {
		t.Fatal("expected cache hit for nil-value entry")
	}
	if recs != nil {
		t.Errorf("expected nil records, got %v", recs)
	}
}
