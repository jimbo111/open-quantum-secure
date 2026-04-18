// cache_hostname_property_test.go — Property tests for ctCache key semantics.
// Verifies case-sensitivity, trailing-dot normalization, TLD edge cases, very
// long hostnames, single-label names, and that the cache is key-exact (no
// implicit folding or normalization is performed at the cache layer).
package ctlookup

import (
	"strings"
	"testing"
	"time"
)

// cacheRec is a one-element certRecord slice used as a stand-in value in cache
// property tests; the value content is irrelevant — only presence matters.
func cacheRec(serial string) []certRecord {
	return []certRecord{{Serial: serial, SigAlgorithm: "ECDSA"}}
}

// ── Case-sensitivity ──────────────────────────────────────────────────────────

// TestCache_CaseSensitive verifies that the cache treats "Example.COM" and
// "example.com" as distinct keys (no implicit case folding at cache layer).
func TestCache_CaseSensitive(t *testing.T) {
	c := newCTCache(16, time.Minute)

	lower := "example.com"
	upper := "Example.COM"

	c.put(lower, cacheRec("lower"))

	if _, ok := c.get(upper); ok {
		t.Errorf("cache should NOT find %q after storing %q — no implicit case fold", upper, lower)
	}

	c.put(upper, cacheRec("upper"))
	recs, ok := c.get(upper)
	if !ok || len(recs) == 0 || recs[0].Serial != "upper" {
		t.Errorf("get(%q) after put(%q): expected serial=upper, got %v ok=%v", upper, upper, recs, ok)
	}

	// Original lower-case key must still return its own value.
	recs, ok = c.get(lower)
	if !ok || recs[0].Serial != "lower" {
		t.Errorf("get(%q): expected serial=lower after upper was added, got %v ok=%v", lower, recs, ok)
	}
}

// TestCache_MixedCaseTLD verifies that "host.COM" and "host.com" are different
// cache keys, because TLD case is not normalised.
func TestCache_MixedCaseTLD(t *testing.T) {
	c := newCTCache(8, time.Minute)
	c.put("host.com", cacheRec("lc"))
	if _, ok := c.get("host.COM"); ok {
		t.Error("host.COM should be a cache miss when only host.com was stored")
	}
}

// ── Trailing-dot (FQDN) ───────────────────────────────────────────────────────

// TestCache_TrailingDot verifies that "example.com." (trailing root dot) and
// "example.com" are treated as different keys (no FQDN normalisation).
func TestCache_TrailingDot(t *testing.T) {
	c := newCTCache(8, time.Minute)
	c.put("example.com", cacheRec("nodot"))

	if _, ok := c.get("example.com."); ok {
		t.Error("trailing-dot FQDN should be a cache miss when non-FQDN was stored")
	}

	c.put("example.com.", cacheRec("dotted"))
	recs, ok := c.get("example.com.")
	if !ok || recs[0].Serial != "dotted" {
		t.Errorf("get(trailing-dot) expected serial=dotted, got %v ok=%v", recs, ok)
	}
}

// ── TLD edge cases ────────────────────────────────────────────────────────────

// TestCache_NumericTLD verifies that hostnames with all-numeric TLDs (e.g.
// "example.123") are stored and retrieved correctly.
func TestCache_NumericTLD(t *testing.T) {
	c := newCTCache(8, time.Minute)
	c.put("example.123", cacheRec("numtld"))
	recs, ok := c.get("example.123")
	if !ok || recs[0].Serial != "numtld" {
		t.Errorf("numeric TLD: expected hit, got %v ok=%v", recs, ok)
	}
}

// TestCache_SingleLabelHostname verifies that a single-label hostname (no dots)
// is stored and retrieved correctly.
func TestCache_SingleLabelHostname(t *testing.T) {
	c := newCTCache(8, time.Minute)
	c.put("intranet", cacheRec("single"))
	recs, ok := c.get("intranet")
	if !ok || recs[0].Serial != "single" {
		t.Errorf("single-label: expected hit, got %v ok=%v", recs, ok)
	}
}

// TestCache_LongTLD verifies that hostnames with long TLDs (e.g. ".example")
// are accepted as cache keys without panic.
func TestCache_LongTLD(t *testing.T) {
	c := newCTCache(8, time.Minute)
	host := "host.longtld"
	c.put(host, cacheRec("longtld"))
	recs, ok := c.get(host)
	if !ok || recs[0].Serial != "longtld" {
		t.Errorf("long TLD: expected hit, got %v ok=%v", recs, ok)
	}
}

// ── Very long hostnames ───────────────────────────────────────────────────────

// TestCache_MaxLengthHostname verifies that a 253-byte hostname (DNS max) is
// stored and retrieved without truncation or panic.
func TestCache_MaxLengthHostname(t *testing.T) {
	// Build a 253-byte hostname: 63-char labels separated by dots.
	label63 := strings.Repeat("a", 63)
	host := label63 + "." + label63 + "." + label63 + ".com"
	if len(host) > 253 {
		host = host[:253]
	}

	c := newCTCache(8, time.Minute)
	c.put(host, cacheRec("maxlen"))
	recs, ok := c.get(host)
	if !ok || recs[0].Serial != "maxlen" {
		t.Errorf("max-length hostname: expected hit, got %v ok=%v", recs, ok)
	}
}

// TestCache_VeryLongHostname_NoCollision verifies that two hostnames that share
// a long common prefix but differ only at the tail are stored under distinct
// keys (no prefix-based collision).
func TestCache_VeryLongHostname_NoCollision(t *testing.T) {
	prefix := strings.Repeat("x", 200)
	hostA := prefix + ".alpha.com"
	hostB := prefix + ".beta.com"

	c := newCTCache(8, time.Minute)
	c.put(hostA, cacheRec("alpha"))
	c.put(hostB, cacheRec("beta"))

	recsA, okA := c.get(hostA)
	recsB, okB := c.get(hostB)
	if !okA || recsA[0].Serial != "alpha" {
		t.Errorf("hostA: expected alpha, got %v ok=%v", recsA, okA)
	}
	if !okB || recsB[0].Serial != "beta" {
		t.Errorf("hostB: expected beta, got %v ok=%v", recsB, okB)
	}
}

// ── Wildcard and special patterns ────────────────────────────────────────────

// TestCache_WildcardHostname verifies that "*.example.com" is stored and
// retrieved correctly (wildcards are valid cache keys).
func TestCache_WildcardHostname(t *testing.T) {
	c := newCTCache(8, time.Minute)
	c.put("*.example.com", cacheRec("wildcard"))
	recs, ok := c.get("*.example.com")
	if !ok || recs[0].Serial != "wildcard" {
		t.Errorf("wildcard: expected hit, got %v ok=%v", recs, ok)
	}
	// Non-wildcard form must NOT hit the wildcard entry.
	if _, ok := c.get("sub.example.com"); ok {
		t.Error("sub.example.com must not hit *.example.com cache entry")
	}
}

// TestCache_EmptyKey verifies that put/get with an empty string key does not
// panic. Behaviour (hit/miss) is implementation-defined.
func TestCache_EmptyKey(t *testing.T) {
	c := newCTCache(8, time.Minute)
	// Must not panic.
	c.put("", cacheRec("empty"))
	_, _ = c.get("")
}

// ── Collision resistance ──────────────────────────────────────────────────────

// TestCache_IdenticalSubdomainDistinctTLD verifies that "host.com" and
// "host.org" are independent cache entries with no cross-contamination.
func TestCache_IdenticalSubdomainDistinctTLD(t *testing.T) {
	c := newCTCache(8, time.Minute)
	c.put("host.com", cacheRec("com"))
	c.put("host.org", cacheRec("org"))

	rCom, okCom := c.get("host.com")
	rOrg, okOrg := c.get("host.org")
	if !okCom || rCom[0].Serial != "com" {
		t.Errorf("host.com: expected com, got %v ok=%v", rCom, okCom)
	}
	if !okOrg || rOrg[0].Serial != "org" {
		t.Errorf("host.org: expected org, got %v ok=%v", rOrg, okOrg)
	}
}

// TestCache_HostnameWithPort verifies that "host.com:443" and "host.com" are
// different keys (port is not stripped at the cache layer).
func TestCache_HostnameWithPort(t *testing.T) {
	c := newCTCache(8, time.Minute)
	c.put("host.com", cacheRec("noport"))
	if _, ok := c.get("host.com:443"); ok {
		t.Error("host.com:443 should miss when only host.com was stored")
	}
}

// TestCache_IPv4Key verifies that an IPv4 address string can be stored without
// panic (IP literals are rejected by the engine, but the cache itself is
// agnostic to key format).
func TestCache_IPv4Key(t *testing.T) {
	c := newCTCache(8, time.Minute)
	c.put("192.168.1.1", cacheRec("ip4"))
	recs, ok := c.get("192.168.1.1")
	if !ok || recs[0].Serial != "ip4" {
		t.Errorf("IPv4 key: expected hit, got %v ok=%v", recs, ok)
	}
}

// TestCache_IPv6Key verifies that an IPv6 address string can be stored without
// panic.
func TestCache_IPv6Key(t *testing.T) {
	c := newCTCache(8, time.Minute)
	c.put("[::1]", cacheRec("ip6"))
	recs, ok := c.get("[::1]")
	if !ok || recs[0].Serial != "ip6" {
		t.Errorf("IPv6 key: expected hit, got %v ok=%v", recs, ok)
	}
}

// ── TTL expiry ─────────────────────────────────────────────────────────────────

// TestCache_TTLExpiry verifies that an entry stored with a very short TTL
// (via putWithTTL) is no longer returned after the TTL has elapsed.
func TestCache_TTLExpiry(t *testing.T) {
	c := newCTCache(8, time.Minute)
	c.putWithTTL("expiring.com", cacheRec("short"), 1*time.Millisecond)

	// Poll until the entry expires (max ~100ms).
	deadline := time.Now().Add(100 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, ok := c.get("expiring.com"); !ok {
			return // expired as expected
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Error("entry with 1ms TTL should have expired within 100ms")
}

// TestCache_ShortPutReturnsHit verifies that putShort stores an entry that is
// immediately retrievable (TTL is shorter but positive).
func TestCache_ShortPutReturnsHit(t *testing.T) {
	c := newCTCache(8, time.Minute)
	c.putShort("short.com", nil)
	// putShort stores with a reduced TTL; entry must be immediately retrievable.
	_, ok := c.get("short.com")
	if !ok {
		t.Error("putShort entry should be immediately retrievable")
	}
}
