package attachments

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/domain"
)

const auditWriteTimeout = 5 * time.Second

type ApprovalProvider interface {
	Approval(context.Context, string) (domain.Approval, error)
	DownloadURL(context.Context, string, string) (*url.URL, error)
}

type DownloadOpener interface {
	Open(context.Context, *url.URL) (*Download, error)
}

type AuditRepository interface {
	RecordAudit(context.Context, domain.AuditEvent) error
}

type Options struct {
	Approvals            ApprovalProvider
	Downloader           DownloadOpener
	Audit                AuditRepository
	AdministratorUserIDs map[string]struct{}
	DownloadConcurrency  int
	Now                  func() time.Time
}

type Service struct {
	approvals      ApprovalProvider
	downloader     DownloadOpener
	audit          AuditRepository
	administrators map[string]struct{}
	limiter        *downloadLimiter
	now            func() time.Time
}

func NewService(options Options) *Service {
	now := options.Now
	if now == nil {
		now = time.Now
	}
	concurrency := options.DownloadConcurrency
	if concurrency < 1 {
		concurrency = 1
	}
	return &Service{
		approvals:      options.Approvals,
		downloader:     options.Downloader,
		audit:          options.Audit,
		administrators: cloneSet(options.AdministratorUserIDs),
		limiter:        newDownloadLimiter(concurrency),
		now:            now,
	}
}

func (service *Service) List(
	ctx context.Context,
	user domain.User,
	processInstanceID string,
	requestID string,
) ([]domain.Attachment, error) {
	normalizedProcessInstanceID, err := validateRequestIdentity(
		user,
		processInstanceID,
		requestID,
	)
	if err != nil {
		return nil, err
	}
	processInstanceID = normalizedProcessInstanceID
	approval, err := service.approvals.Approval(ctx, processInstanceID)
	if err != nil {
		return nil, service.deny(ctx, user, "attachments.list", processInstanceID, "", requestID, err)
	}
	if !approval.CanAccess(user.UserID, service.administrators) {
		return nil, service.deny(
			ctx,
			user,
			"attachments.list",
			processInstanceID,
			"",
			requestID,
			domain.ErrForbidden,
		)
	}
	if err := service.allow(ctx, user, "attachments.list", processInstanceID, "", requestID); err != nil {
		return nil, err
	}
	return append([]domain.Attachment(nil), approval.Attachments...), nil
}

func (service *Service) Download(
	ctx context.Context,
	user domain.User,
	processInstanceID string,
	fileID string,
	requestID string,
) (*Download, error) {
	normalizedProcessInstanceID, err := validateRequestIdentity(
		user,
		processInstanceID,
		requestID,
	)
	if err != nil {
		return nil, err
	}
	processInstanceID = normalizedProcessInstanceID
	if strings.TrimSpace(fileID) == "" {
		return nil, fmt.Errorf("%w: file ID is required", domain.ErrInvalidInput)
	}
	release, ok := service.limiter.acquire(user.UserID)
	if !ok {
		return nil, service.deny(
			ctx,
			user,
			"attachments.download",
			processInstanceID,
			fileID,
			requestID,
			domain.ErrRateLimited,
		)
	}
	releaseOnReturn := true
	defer func() {
		if releaseOnReturn {
			release()
		}
	}()

	approval, err := service.approvals.Approval(ctx, processInstanceID)
	if err != nil {
		return nil, service.deny(
			ctx,
			user,
			"attachments.download",
			processInstanceID,
			fileID,
			requestID,
			err,
		)
	}
	if !approval.CanAccess(user.UserID, service.administrators) {
		return nil, service.deny(
			ctx,
			user,
			"attachments.download",
			processInstanceID,
			fileID,
			requestID,
			domain.ErrForbidden,
		)
	}
	attachment, found := approval.FindAttachment(fileID)
	if !found {
		return nil, service.deny(
			ctx,
			user,
			"attachments.download",
			processInstanceID,
			fileID,
			requestID,
			domain.ErrNotFound,
		)
	}
	downloadURL, err := service.approvals.DownloadURL(ctx, processInstanceID, fileID)
	if err != nil {
		return nil, service.deny(
			ctx,
			user,
			"attachments.download",
			processInstanceID,
			fileID,
			requestID,
			err,
		)
	}
	download, err := service.downloader.Open(ctx, downloadURL)
	if err != nil {
		return nil, service.deny(
			ctx,
			user,
			"attachments.download",
			processInstanceID,
			fileID,
			requestID,
			err,
		)
	}
	attachment.FileName = SanitizeFilename(attachment.FileName)
	download.Attachment = attachment
	if err := service.allow(
		ctx,
		user,
		"attachments.download",
		processInstanceID,
		fileID,
		requestID,
	); err != nil {
		_ = download.Body.Close()
		return nil, err
	}
	download.Body = &releaseReadCloser{body: download.Body, release: release}
	releaseOnReturn = false
	return download, nil
}

func (service *Service) allow(
	ctx context.Context,
	user domain.User,
	action string,
	processInstanceID string,
	fileID string,
	requestID string,
) error {
	auditContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditWriteTimeout)
	defer cancel()
	if err := service.audit.RecordAudit(auditContext, domain.AuditEvent{
		RequestID:         requestID,
		CorpID:            user.CorpID,
		ActorUserID:       user.UserID,
		Action:            action,
		ProcessInstanceID: processInstanceID,
		FileID:            fileID,
		Decision:          domain.AuditDecisionAllowed,
		CreatedAt:         service.now(),
	}); err != nil {
		return fmt.Errorf("%w: record allowed audit event: %v", domain.ErrUnavailable, err)
	}
	return nil
}

func (service *Service) deny(
	ctx context.Context,
	user domain.User,
	action string,
	processInstanceID string,
	fileID string,
	requestID string,
	cause error,
) error {
	auditContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditWriteTimeout)
	defer cancel()
	auditError := service.audit.RecordAudit(auditContext, domain.AuditEvent{
		RequestID:          requestID,
		CorpID:             user.CorpID,
		ActorUserID:        user.UserID,
		Action:             action,
		ProcessInstanceID:  processInstanceID,
		FileID:             fileID,
		Decision:           domain.AuditDecisionDenied,
		UpstreamErrorClass: errorClass(cause),
		CreatedAt:          service.now(),
	})
	if auditError != nil {
		return fmt.Errorf(
			"%w: original error: %v; record denied audit event: %v",
			domain.ErrUnavailable,
			cause,
			auditError,
		)
	}
	return cause
}

func validateRequestIdentity(
	user domain.User,
	processInstanceID string,
	requestID string,
) (string, error) {
	if strings.TrimSpace(user.CorpID) == "" || strings.TrimSpace(user.UserID) == "" {
		return "", fmt.Errorf("%w: authenticated user is incomplete", domain.ErrUnauthorized)
	}
	normalizedProcessInstanceID, err := domain.NormalizeProcessInstanceID(processInstanceID)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(requestID) == "" {
		return "", fmt.Errorf("%w: request ID is required", domain.ErrInvalidInput)
	}
	return normalizedProcessInstanceID, nil
}

func errorClass(err error) string {
	return domain.ErrorClass(err)
}

func SanitizeFilename(raw string) string {
	normalized := strings.ReplaceAll(raw, "\\", "/")
	normalized = strings.TrimSpace(path.Base(normalized))
	var builder strings.Builder
	for _, character := range normalized {
		switch {
		case unicode.IsControl(character):
			continue
		case character == '"' || character == ';' || character == ':':
			builder.WriteRune('_')
		default:
			builder.WriteRune(character)
		}
	}
	sanitized := strings.TrimSpace(builder.String())
	if sanitized == "" || sanitized == "." || sanitized == ".." {
		return "attachment"
	}
	const maxFilenameBytes = 180
	if len(sanitized) <= maxFilenameBytes {
		return sanitized
	}
	truncated := sanitized[:maxFilenameBytes]
	for !utf8.ValidString(truncated) {
		truncated = truncated[:len(truncated)-1]
	}
	return strings.TrimSpace(truncated)
}

func cloneSet(source map[string]struct{}) map[string]struct{} {
	result := make(map[string]struct{}, len(source))
	for value := range source {
		result[value] = struct{}{}
	}
	return result
}

type downloadLimiter struct {
	mu           sync.Mutex
	limit        int
	activeByUser map[string]int
}

func newDownloadLimiter(limit int) *downloadLimiter {
	return &downloadLimiter{
		limit:        limit,
		activeByUser: make(map[string]int),
	}
}

func (limiter *downloadLimiter) acquire(userID string) (func(), bool) {
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if limiter.activeByUser[userID] >= limiter.limit {
		return nil, false
	}
	limiter.activeByUser[userID]++
	var once sync.Once
	return func() {
		once.Do(func() {
			limiter.mu.Lock()
			defer limiter.mu.Unlock()
			limiter.activeByUser[userID]--
			if limiter.activeByUser[userID] == 0 {
				delete(limiter.activeByUser, userID)
			}
		})
	}, true
}

type releaseReadCloser struct {
	body    io.ReadCloser
	release func()
	once    sync.Once
}

func (reader *releaseReadCloser) Read(buffer []byte) (int, error) {
	count, err := reader.body.Read(buffer)
	if err != nil {
		reader.releaseOnce()
	}
	return count, err
}

func (reader *releaseReadCloser) Close() error {
	err := reader.body.Close()
	reader.releaseOnce()
	return err
}

func (reader *releaseReadCloser) releaseOnce() {
	reader.once.Do(reader.release)
}
