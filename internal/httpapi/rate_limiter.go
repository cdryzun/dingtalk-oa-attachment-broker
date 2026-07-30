package httpapi

import (
	"net/netip"
	"sync"
	"time"
)

const (
	maxRateLimitEntries  = 4096
	overflowRateLimitKey = "__overflow__"
)

type rateLimitEntry struct {
	windowStart time.Time
	lastSeen    time.Time
	count       int
}

type rateLimiter struct {
	mu       sync.Mutex
	limit    int
	now      func() time.Time
	entries  map[string]rateLimitEntry
	requests uint64
}

func newRateLimiter(limit int, now func() time.Time) *rateLimiter {
	return &rateLimiter{
		limit:   limit,
		now:     now,
		entries: map[string]rateLimitEntry{overflowRateLimitKey: {}},
	}
}

func (limiter *rateLimiter) Allow(key string) bool {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	key = normalizedRateLimitKey(key)
	if _, exists := limiter.entries[key]; !exists && len(limiter.entries) >= maxRateLimitEntries {
		key = overflowRateLimitKey
	}

	now := limiter.now()
	entry := limiter.entries[key]
	if entry.windowStart.IsZero() || now.Sub(entry.windowStart) >= time.Minute {
		entry.windowStart = now
		entry.count = 0
	}
	entry.lastSeen = now
	entry.count++
	limiter.entries[key] = entry
	limiter.requests++
	if limiter.requests%1000 == 0 {
		limiter.prune(now.Add(-10 * time.Minute))
	}
	return entry.count <= limiter.limit
}

func (limiter *rateLimiter) prune(before time.Time) {
	for key, entry := range limiter.entries {
		if key != overflowRateLimitKey && entry.lastSeen.Before(before) {
			delete(limiter.entries, key)
		}
	}
}

func normalizedRateLimitKey(key string) string {
	address, err := netip.ParseAddr(key)
	if err != nil {
		return key
	}
	address = address.Unmap()
	if address.Is6() {
		return netip.PrefixFrom(address, 64).Masked().String()
	}
	return address.String()
}
