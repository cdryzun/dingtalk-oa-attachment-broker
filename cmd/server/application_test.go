package main

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/postgres"
)

func TestMaintainRetentionPrunesAuditAndAuthenticationState(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	pruner := &recordingRetentionPruner{
		cancel: cancel,
		result: postgres.AuthenticationPruneResult{
			DeviceAuthorizations: 2,
			Sessions:             3,
		},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	auditRetention := 180 * 24 * time.Hour
	authRetention := 7 * 24 * time.Hour
	startedAt := time.Now()

	maintainRetention(ctx, pruner, auditRetention, authRetention, logger)

	pruner.mu.Lock()
	defer pruner.mu.Unlock()
	if pruner.auditCalls != 1 {
		t.Errorf("audit prune calls = %d; want 1", pruner.auditCalls)
	}
	if pruner.authCalls != 1 {
		t.Errorf("authentication prune calls = %d; want 1", pruner.authCalls)
	}
	assertCutoffWithin(t, pruner.auditCutoff, startedAt.Add(-auditRetention))
	assertCutoffWithin(t, pruner.authCutoff, startedAt.Add(-authRetention))
}

type recordingRetentionPruner struct {
	mu          sync.Mutex
	cancel      context.CancelFunc
	result      postgres.AuthenticationPruneResult
	auditCalls  int
	authCalls   int
	auditCutoff time.Time
	authCutoff  time.Time
}

func (pruner *recordingRetentionPruner) PruneAudit(
	_ context.Context,
	cutoff time.Time,
) (int64, error) {
	pruner.mu.Lock()
	defer pruner.mu.Unlock()
	pruner.auditCalls++
	pruner.auditCutoff = cutoff
	return 1, nil
}

func (pruner *recordingRetentionPruner) PruneAuthenticationState(
	_ context.Context,
	cutoff time.Time,
) (postgres.AuthenticationPruneResult, error) {
	pruner.mu.Lock()
	defer pruner.mu.Unlock()
	pruner.authCalls++
	pruner.authCutoff = cutoff
	pruner.cancel()
	return pruner.result, nil
}

func assertCutoffWithin(t *testing.T, got, want time.Time) {
	t.Helper()
	const tolerance = time.Second
	if got.Before(want.Add(-tolerance)) || got.After(want.Add(tolerance)) {
		t.Errorf("cutoff = %s; want within %s of %s", got, tolerance, want)
	}
}
