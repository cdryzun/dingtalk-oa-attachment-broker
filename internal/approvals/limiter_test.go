package approvals

import (
	"testing"
	"time"
)

func TestSearchRateLimiterBoundsEachUserAndResetsWindow(t *testing.T) {
	now := searchNow
	limiter := newSearchRateLimiter(2, func() time.Time { return now })
	if !limiter.Allow("user-one") || !limiter.Allow("user-one") {
		t.Fatal("first two requests were unexpectedly denied")
	}
	if limiter.Allow("user-one") {
		t.Fatal("third request was unexpectedly allowed")
	}
	if !limiter.Allow("user-two") {
		t.Fatal("another user was unexpectedly denied")
	}

	now = now.Add(searchRateWindow)
	if !limiter.Allow("user-one") {
		t.Fatal("request after window reset was unexpectedly denied")
	}
}

func TestSearchRateLimiterPrunesExpiredUsers(t *testing.T) {
	now := searchNow
	limiter := newSearchRateLimiter(1, func() time.Time { return now })
	for index := 0; index < 1025; index++ {
		if !limiter.Allow(time.Unix(int64(index), 0).String()) {
			t.Fatalf("user %d was unexpectedly denied", index)
		}
	}
	now = now.Add(searchRateWindow)
	if !limiter.Allow("current-user") {
		t.Fatal("current user was unexpectedly denied")
	}
	if len(limiter.states) > 2 {
		t.Errorf("rate limiter retained %d expired users", len(limiter.states))
	}
}
