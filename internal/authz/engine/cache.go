package engine

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// Defaults of the cache (SPEC 12.1 and 12.2).
const (
	DefaultTTL      = 30 * time.Second
	DefaultMaxBytes = 64 << 20
)

type cacheKey struct{ user, org uuid.UUID }

type cacheEntry struct {
	snap *snapshot
	used atomic.Int64 // unix nanos of the last use, coarse (updated at most once per second)
}

// cache is the in-process snapshot cache: byte budget with LRU eviction. Readers take a read lock only to
// find the entry; the snapshot itself is immutable.
type cache struct {
	mu    sync.RWMutex
	m     map[cacheKey]*cacheEntry
	bytes int64
	max   int64
}

func newCache(max int64) *cache {
	if max <= 0 {
		max = DefaultMaxBytes
	}
	return &cache{m: map[cacheKey]*cacheEntry{}, max: max}
}

// get returns the snapshot when present and not past its validUntil.
func (c *cache) get(k cacheKey, now time.Time) *snapshot {
	c.mu.RLock()
	en := c.m[k]
	c.mu.RUnlock()
	if en == nil || !now.Before(en.snap.validUntil) {
		return nil
	}
	if n := now.UnixNano(); n-en.used.Load() > int64(time.Second) {
		en.used.Store(n)
	}
	return en.snap
}

func (c *cache) put(k cacheKey, s *snapshot, now time.Time) {
	en := &cacheEntry{snap: s}
	en.used.Store(now.UnixNano())
	c.mu.Lock()
	defer c.mu.Unlock()
	if old := c.m[k]; old != nil {
		c.bytes -= old.snap.bytes
	}
	c.m[k] = en
	c.bytes += s.bytes
	if c.bytes > c.max {
		c.evictLocked(k)
	}
}

// evictLocked drops the least recently used entries (never the one just inserted) down to 90 % of the
// budget. It runs only when the budget is exceeded, so its O(n log n) cost is amortised.
func (c *cache) evictLocked(keep cacheKey) {
	type kv struct {
		k    cacheKey
		used int64
	}
	all := make([]kv, 0, len(c.m))
	for k, en := range c.m {
		if k != keep {
			all = append(all, kv{k, en.used.Load()})
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].used < all[j].used })
	target := c.max / 10 * 9
	for _, x := range all {
		if c.bytes <= target {
			return
		}
		c.bytes -= c.m[x.k].snap.bytes
		delete(c.m, x.k)
	}
}

func (c *cache) evictIf(pred func(cacheKey) bool) {
	c.mu.Lock()
	for k, en := range c.m {
		if pred(k) {
			c.bytes -= en.snap.bytes
			delete(c.m, k)
		}
	}
	c.mu.Unlock()
}

func (c *cache) len() (n int, bytes int64) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.m), c.bytes
}
