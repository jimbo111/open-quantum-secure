package ctlookup

import (
	"container/list"
	"sync"
	"time"
)

const (
	defaultCacheSize     = 256
	defaultCacheTTL      = 24 * time.Hour
	defaultEmptyCacheTTL = 15 * time.Minute // short TTL for empty results (often transient: 429 or outage)
)

type cacheEntry struct {
	key    string
	value  []certRecord
	expiry time.Time
}

// ctCache is a thread-safe LRU cache with per-entry TTL, keyed by hostname.
// Entries expire after defaultCacheTTL (24 h) — cert algorithms for a given
// hostname rarely change faster than that.
// Eviction: when at capacity, the least-recently-used entry is removed.
type ctCache struct {
	mu    sync.Mutex
	cap   int
	ttl   time.Duration
	items map[string]*list.Element
	order *list.List
}

func newCTCache(cap int, ttl time.Duration) *ctCache {
	return &ctCache{
		cap:   cap,
		ttl:   ttl,
		items: make(map[string]*list.Element, cap),
		order: list.New(),
	}
}

// get returns cached records for the key. Returns (nil, false) when the key is
// absent or the entry has expired (expired entries are evicted on access).
func (c *ctCache) get(key string) ([]certRecord, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.items[key]
	if !ok {
		return nil, false
	}
	entry := el.Value.(*cacheEntry)
	if time.Now().After(entry.expiry) {
		c.order.Remove(el)
		delete(c.items, key)
		return nil, false
	}
	c.order.MoveToFront(el)
	return entry.value, true
}

// putShort stores records under key with the short (empty-result) TTL.
// Use when value is empty to avoid caching transient misses for 24 hours.
func (c *ctCache) putShort(key string, value []certRecord) {
	c.putWithTTL(key, value, defaultEmptyCacheTTL)
}

// put stores records under key, evicting the LRU entry when at capacity.
// Updating an existing key refreshes its TTL and moves it to the front.
func (c *ctCache) put(key string, value []certRecord) {
	c.putWithTTL(key, value, c.ttl)
}

func (c *ctCache) putWithTTL(key string, value []certRecord, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		entry := el.Value.(*cacheEntry)
		entry.value = value
		entry.expiry = time.Now().Add(ttl)
		c.order.MoveToFront(el)
		return
	}
	if c.order.Len() >= c.cap {
		oldest := c.order.Back()
		if oldest != nil {
			c.order.Remove(oldest)
			delete(c.items, oldest.Value.(*cacheEntry).key)
		}
	}
	entry := &cacheEntry{key: key, value: value, expiry: time.Now().Add(ttl)}
	el := c.order.PushFront(entry)
	c.items[key] = el
}
