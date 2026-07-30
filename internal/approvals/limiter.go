package approvals

import (
	"sync"
	"time"
)

const searchRateWindow = time.Minute

type searchRateState struct {
	windowStarted time.Time
	requests      int
}

type searchRateLimiter struct {
	mu     sync.Mutex
	limit  int
	now    func() time.Time
	states map[string]searchRateState
}

func newSearchRateLimiter(limit int, now func() time.Time) *searchRateLimiter {
	return &searchRateLimiter{
		limit:  limit,
		now:    now,
		states: make(map[string]searchRateState),
	}
}

func (limiter *searchRateLimiter) Allow(userID string) bool {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()

	now := limiter.now()
	state := limiter.states[userID]
	if state.windowStarted.IsZero() ||
		now.Before(state.windowStarted) ||
		now.Sub(state.windowStarted) >= searchRateWindow {
		state = searchRateState{windowStarted: now}
	}
	if state.requests >= limiter.limit {
		return false
	}
	state.requests++
	limiter.states[userID] = state
	if len(limiter.states) > 1024 {
		limiter.prune(now)
	}
	return true
}

func (limiter *searchRateLimiter) prune(now time.Time) {
	for userID, state := range limiter.states {
		if now.Before(state.windowStarted) ||
			now.Sub(state.windowStarted) >= searchRateWindow {
			delete(limiter.states, userID)
		}
	}
}
