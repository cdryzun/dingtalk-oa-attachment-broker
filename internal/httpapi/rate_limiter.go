package httpapi

import (
	"sync"
	"time"
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
		entries: make(map[string]rateLimitEntry),
	}
}

func (limiter *rateLimiter) Allow(key string) bool {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()

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
		if entry.lastSeen.Before(before) {
			delete(limiter.entries, key)
		}
	}
}
