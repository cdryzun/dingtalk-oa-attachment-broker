package dingtalk

import (
	"context"
	"fmt"
	"sync"
	"time"
)

const appTokenFetchTimeout = 30 * time.Second
const appTokenRefreshFailureBackoff = time.Minute

type appTokenFetcher func(context.Context) (string, time.Duration, error)

type tokenRefresh struct {
	done  chan struct{}
	token string
	err   error
}

type appTokenCache struct {
	mu             sync.Mutex
	token          string
	expiresAt      time.Time
	refresh        *tokenRefresh
	refreshRetryAt time.Time
	fetch          appTokenFetcher
	now            func() time.Time
	refreshBefore  time.Duration
}

func newAppTokenCache(
	fetch appTokenFetcher,
	now func() time.Time,
	refreshBefore time.Duration,
) *appTokenCache {
	return &appTokenCache{
		fetch:         fetch,
		now:           now,
		refreshBefore: refreshBefore,
	}
}

func (cache *appTokenCache) Token(ctx context.Context) (string, error) {
	cache.mu.Lock()
	now := cache.now()
	if cache.token != "" && cache.expiresAt.After(now) &&
		(cache.expiresAt.After(now.Add(cache.refreshBefore)) || cache.refreshRetryAt.After(now)) {
		token := cache.token
		cache.mu.Unlock()
		return token, nil
	}
	if cache.refresh != nil {
		refresh := cache.refresh
		cache.mu.Unlock()
		return waitForTokenRefresh(ctx, refresh)
	}

	refresh := &tokenRefresh{done: make(chan struct{})}
	cache.refresh = refresh
	cache.mu.Unlock()
	go cache.fetchToken(refresh)
	return waitForTokenRefresh(ctx, refresh)
}

func (cache *appTokenCache) fetchToken(refresh *tokenRefresh) {
	ctx, cancel := context.WithTimeout(context.Background(), appTokenFetchTimeout)
	defer cancel()
	token, ttl, err := cache.fetch(ctx)

	cache.mu.Lock()
	now := cache.now()
	if err == nil && token != "" && ttl > 0 {
		cache.token = token
		cache.expiresAt = now.Add(ttl)
		cache.refreshRetryAt = time.Time{}
		refresh.token = token
	} else if cache.token != "" && cache.expiresAt.After(now) {
		refresh.token = cache.token
		cache.refreshRetryAt = now.Add(appTokenRefreshFailureBackoff)
	} else {
		if err == nil {
			err = fmt.Errorf("app token endpoint returned an invalid token lifetime")
		}
		refresh.token = token
		refresh.err = err
	}
	cache.refresh = nil
	close(refresh.done)
	cache.mu.Unlock()
}

func waitForTokenRefresh(ctx context.Context, refresh *tokenRefresh) (string, error) {
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-refresh.done:
		return refresh.token, refresh.err
	}
}
