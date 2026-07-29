package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/approvals"
	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/attachments"
	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/auth"
	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/config"
	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/dingtalk"
	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/httpapi"
	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/postgres"
)

const retentionPruneInterval = 24 * time.Hour

type application struct {
	handler        http.Handler
	metricsHandler http.Handler
	close          func()
	maintenance    func(context.Context)
}

type applicationBuilder func(
	context.Context,
	config.Config,
	*slog.Logger,
) (*application, error)

func productionApplication(
	ctx context.Context,
	cfg config.Config,
	logger *slog.Logger,
) (*application, error) {
	store, err := postgres.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("open PostgreSQL store: %w", err)
	}
	closeStore := true
	defer func() {
		if closeStore {
			store.Close()
		}
	}()

	dingTalkClient, err := dingtalk.NewClient(dingtalk.Options{
		ClientID:        cfg.DingTalkClientID,
		ClientSecret:    cfg.DingTalkClientSecret,
		APIEndpoint:     cfg.DingTalkAPIEndpoint,
		OAPIBaseURL:     cfg.DingTalkOAPIBaseURL,
		UpstreamTimeout: cfg.UpstreamTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("create DingTalk client: %w", err)
	}
	downloader, err := attachments.NewSecureDownloader(
		cfg.DownloadTimeout,
		cfg.DownloadMaxBytes,
	)
	if err != nil {
		return nil, fmt.Errorf("create secure attachment downloader: %w", err)
	}
	authService, err := auth.NewService(auth.Options{
		Repository:       store,
		IdentityProvider: dingTalkClient,
		Hasher:           auth.NewHasher(cfg.TokenPepper),
		PublicBaseURL:    cfg.PublicBaseURL,
		AuthorizeURL:     cfg.DingTalkOAuthAuthorizeURL,
		ClientID:         cfg.DingTalkClientID,
		CorpID:           cfg.DingTalkCorpID,
		DeviceCodeTTL:    cfg.DeviceCodeTTL,
		AccessTokenTTL:   cfg.AccessTokenTTL,
		RefreshTokenTTL:  cfg.RefreshTokenTTL,
		PollInterval:     cfg.AuthPollInterval,
	})
	if err != nil {
		return nil, fmt.Errorf("create authentication service: %w", err)
	}
	attachmentService := attachments.NewService(attachments.Options{
		Approvals:            dingTalkClient,
		Downloader:           downloader,
		Audit:                store,
		AdministratorUserIDs: cfg.AdminUserIDs,
		DownloadConcurrency:  cfg.DownloadConcurrencyPerUser,
	})
	approvalSearchService, err := approvals.NewService(approvals.Options{
		Provider:             dingTalkClient,
		Audit:                store,
		AdministratorUserIDs: cfg.AdminUserIDs,
		CursorSigningKey:     []byte(cfg.TokenPepper),
		DetailConcurrency:    cfg.ApprovalSearchConcurrency,
		RequestsPerMinute:    cfg.ApprovalSearchRate,
	})
	if err != nil {
		return nil, fmt.Errorf("create approval search service: %w", err)
	}
	handler, err := httpapi.NewHandler(httpapi.Options{
		Auth:              authService,
		Attachments:       attachmentService,
		ApprovalSearch:    approvalSearchService,
		Readiness:         store,
		Logger:            logger,
		ReadinessTimeout:  cfg.ReadinessTimeout,
		RequestsPerMinute: cfg.RequestsPerMinute,
		TrustedProxyCIDRs: cfg.TrustedProxyCIDRs,
	})
	if err != nil {
		return nil, fmt.Errorf("create HTTP handler: %w", err)
	}

	closeStore = false
	return &application{
		handler:        handler,
		metricsHandler: handler.MetricsHandler(),
		close:          store.Close,
		maintenance: func(maintenanceContext context.Context) {
			maintainRetention(
				maintenanceContext,
				store,
				cfg.AuditRetention,
				cfg.AuthRecordRetention,
				logger,
			)
		},
	}, nil
}

type retentionPruner interface {
	PruneAudit(context.Context, time.Time) (int64, error)
	PruneAuthenticationState(
		context.Context,
		time.Time,
	) (postgres.AuthenticationPruneResult, error)
}

func maintainRetention(
	ctx context.Context,
	pruner retentionPruner,
	auditRetention time.Duration,
	authRecordRetention time.Duration,
	logger *slog.Logger,
) {
	prune := func() {
		pruneContext, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		now := time.Now()
		deletedAuditEvents, auditErr := pruner.PruneAudit(
			pruneContext,
			now.Add(-auditRetention),
		)
		if auditErr != nil {
			if ctx.Err() == nil {
				logger.WarnContext(
					ctx,
					"audit retention prune failed",
					"error",
					auditErr,
				)
			}
		}
		deletedAuthenticationState, authErr := pruner.PruneAuthenticationState(
			pruneContext,
			now.Add(-authRecordRetention),
		)
		if authErr != nil {
			if ctx.Err() == nil {
				logger.WarnContext(
					ctx,
					"authentication state retention prune failed",
					"error",
					authErr,
				)
			}
		}
		if auditErr == nil && authErr == nil {
			logger.InfoContext(
				ctx,
				"retention prune completed",
				"deletedAuditEvents",
				deletedAuditEvents,
				"deletedDeviceAuthorizations",
				deletedAuthenticationState.DeviceAuthorizations,
				"deletedSessions",
				deletedAuthenticationState.Sessions,
			)
		}
	}

	prune()
	ticker := time.NewTicker(retentionPruneInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			prune()
		}
	}
}
