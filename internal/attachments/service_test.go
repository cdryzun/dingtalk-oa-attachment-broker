package attachments

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/domain"
)

type auditContextKey struct{}

func TestListAllowsOnlyApprovalParticipantsAndAdministrators(t *testing.T) {
	approval := testApproval()
	testCases := []struct {
		name    string
		userID  string
		admins  map[string]struct{}
		wantErr error
	}{
		{name: "originator", userID: "originator"},
		{name: "approver", userID: "approver"},
		{name: "task user", userID: "task-user"},
		{name: "cc user", userID: "cc-user"},
		{name: "administrator", userID: "admin", admins: map[string]struct{}{"admin": {}}},
		{name: "unrelated user", userID: "outsider", wantErr: domain.ErrForbidden},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			upstream := &fakeApprovalProvider{approval: approval}
			audit := &recordingAuditRepository{}
			service := NewService(Options{
				Approvals:            upstream,
				Downloader:           &fakeDownloader{},
				Audit:                audit,
				AdministratorUserIDs: testCase.admins,
				DownloadConcurrency:  2,
				Now:                  fixedNow,
			})
			user := domain.User{CorpID: "corp-id", UserID: testCase.userID}

			attachments, err := service.List(
				context.Background(),
				user,
				"instance-id",
				"request-id",
			)
			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("List() error = %v; want %v", err, testCase.wantErr)
			}
			if testCase.wantErr == nil && len(attachments) != 1 {
				t.Errorf("List() attachments = %#v; want one", attachments)
			}
			if len(audit.events) != 1 {
				t.Fatalf("audit events = %d; want 1", len(audit.events))
			}
			wantDecision := domain.AuditDecisionAllowed
			if testCase.wantErr != nil {
				wantDecision = domain.AuditDecisionDenied
			}
			if audit.events[0].Decision != wantDecision ||
				audit.events[0].Action != "attachments.list" {
				t.Errorf("audit event = %#v", audit.events[0])
			}
		})
	}
}

func TestDownloadRevalidatesAttachmentMembershipBeforeGrant(t *testing.T) {
	upstream := &fakeApprovalProvider{approval: testApproval()}
	audit := &recordingAuditRepository{}
	service := NewService(Options{
		Approvals:           upstream,
		Downloader:          &fakeDownloader{},
		Audit:               audit,
		DownloadConcurrency: 2,
		Now:                 fixedNow,
	})

	_, err := service.Download(
		context.Background(),
		domain.User{CorpID: "corp-id", UserID: "approver"},
		"instance-id",
		"other-file",
		"request-id",
	)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Download() error = %v; want not found", err)
	}
	if upstream.downloadURLCalls.Load() != 0 {
		t.Errorf("DownloadURL() calls = %d; want 0", upstream.downloadURLCalls.Load())
	}
	if len(audit.events) != 1 || audit.events[0].Decision != domain.AuditDecisionDenied {
		t.Errorf("audit events = %#v", audit.events)
	}
}

func TestDeniedAuditSurvivesRequestCancellation(t *testing.T) {
	audit := &recordingAuditRepository{}
	service := NewService(Options{
		Approvals:           &fakeApprovalProvider{approvalError: domain.ErrUpstream},
		Downloader:          &fakeDownloader{},
		Audit:               audit,
		DownloadConcurrency: 1,
		Now:                 fixedNow,
	})
	requestContext := context.WithValue(context.Background(), auditContextKey{}, "trace-value")
	requestContext, cancel := context.WithCancel(requestContext)
	cancel()

	_, err := service.List(
		requestContext,
		domain.User{CorpID: "corp-id", UserID: "user-id"},
		"instance-id",
		"request-id",
	)
	if !errors.Is(err, domain.ErrUpstream) {
		t.Fatalf("List() error = %v; want upstream error", err)
	}
	if len(audit.events) != 1 || audit.events[0].Decision != domain.AuditDecisionDenied {
		t.Fatalf("audit events = %#v; want one denied event", audit.events)
	}
	if audit.contextErr != nil {
		t.Errorf("audit context error at write = %v", audit.contextErr)
	}
	if audit.contextValue != "trace-value" {
		t.Errorf("audit context value = %#v", audit.contextValue)
	}
	if remaining := time.Until(audit.deadline); remaining <= 0 || remaining > 5*time.Second {
		t.Errorf("audit deadline remaining = %v; want within 5s", remaining)
	}
}

func TestServiceRejectsProcessCodesBeforeCallingDingTalk(t *testing.T) {
	upstream := &fakeApprovalProvider{approval: testApproval()}
	service := NewService(Options{
		Approvals:           upstream,
		Downloader:          &fakeDownloader{},
		Audit:               &recordingAuditRepository{},
		DownloadConcurrency: 2,
		Now:                 fixedNow,
	})
	user := domain.User{CorpID: "corp-id", UserID: "approver"}

	if _, err := service.List(
		context.Background(),
		user,
		"PROC-TEMPLATE-CODE",
		"request-list",
	); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("List() error = %v; want invalid input", err)
	}
	if _, err := service.Download(
		context.Background(),
		user,
		"proc-template-code",
		"file-id",
		"request-download",
	); !errors.Is(err, domain.ErrInvalidInput) {
		t.Fatalf("Download() error = %v; want invalid input", err)
	}
	if upstream.approvalCalls.Load() != 0 || upstream.downloadURLCalls.Load() != 0 {
		t.Errorf(
			"DingTalk calls = approval %d, download URL %d; want zero",
			upstream.approvalCalls.Load(),
			upstream.downloadURLCalls.Load(),
		)
	}
}

func TestDownloadReturnsStreamWithoutExposingSignedURL(t *testing.T) {
	signedURL, err := url.Parse("https://download.example.test/private-signature")
	if err != nil {
		t.Fatal(err)
	}
	upstream := &fakeApprovalProvider{
		approval:    testApproval(),
		downloadURL: signedURL,
	}
	audit := &recordingAuditRepository{}
	downloader := &fakeDownloader{
		response: &Download{
			Body:          io.NopCloser(strings.NewReader("attachment bytes")),
			ContentType:   "application/octet-stream",
			ContentLength: 16,
		},
	}
	service := NewService(Options{
		Approvals:           upstream,
		Downloader:          downloader,
		Audit:               audit,
		DownloadConcurrency: 2,
		Now:                 fixedNow,
	})

	result, err := service.Download(
		context.Background(),
		domain.User{CorpID: "corp-id", UserID: "approver"},
		"instance-id",
		"file-id",
		"request-id",
	)
	if err != nil {
		t.Fatalf("Download() error = %v", err)
	}
	defer result.Body.Close()
	if result.Attachment.FileName != "report.pdf" {
		t.Errorf("attachment = %#v", result.Attachment)
	}
	if downloader.openedURL != signedURL.String() {
		t.Errorf("opened URL = %q", downloader.openedURL)
	}
	if len(audit.events) != 1 || audit.events[0].Decision != domain.AuditDecisionAllowed {
		t.Errorf("audit events = %#v", audit.events)
	}
}

func TestDownloadEnforcesApprovalAttachmentSize(t *testing.T) {
	testCases := []struct {
		name          string
		body          string
		contentLength int64
		wantReadError error
		wantOpenError error
	}{
		{name: "short unknown-length stream", body: "123", contentLength: -1, wantReadError: io.ErrUnexpectedEOF},
		{name: "long unknown-length stream", body: "123456", contentLength: -1, wantReadError: domain.ErrUpstream},
		{name: "declared length mismatch", body: "123", contentLength: 3, wantOpenError: domain.ErrUpstream},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			approval := testApproval()
			approval.Attachments[0].FileSize = 5
			body := &trackingBody{Reader: strings.NewReader(testCase.body)}
			service := NewService(Options{
				Approvals: &fakeApprovalProvider{
					approval:    approval,
					downloadURL: mustURL(t, "https://download.example.test/signed"),
				},
				Downloader: &fakeDownloader{response: &Download{
					Body:          body,
					ContentLength: testCase.contentLength,
				}},
				Audit:               &recordingAuditRepository{},
				DownloadConcurrency: 1,
				Now:                 fixedNow,
			})

			download, err := service.Download(
				context.Background(),
				domain.User{CorpID: "corp-id", UserID: "approver"},
				"instance-id",
				"file-id",
				"request-id",
			)
			if testCase.wantOpenError != nil {
				if !errors.Is(err, testCase.wantOpenError) || !body.closed {
					t.Fatalf("Download() error = %v, body closed = %v", err, body.closed)
				}
				return
			}
			if err != nil {
				t.Fatalf("Download() error = %v", err)
			}
			defer download.Body.Close()
			if download.ContentLength != 5 {
				t.Errorf("ContentLength = %d; want 5", download.ContentLength)
			}
			_, readErr := io.ReadAll(download.Body)
			if !errors.Is(readErr, testCase.wantReadError) {
				t.Errorf("ReadAll() error = %v; want %v", readErr, testCase.wantReadError)
			}
		})
	}
}

func TestDownloadConcurrencyIsLimitedPerUser(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	downloader := &fakeDownloader{
		open: func(context.Context, *url.URL) (*Download, error) {
			close(started)
			<-release
			return &Download{Body: io.NopCloser(strings.NewReader("ok"))}, nil
		},
	}
	service := NewService(Options{
		Approvals:           &fakeApprovalProvider{approval: testApproval()},
		Downloader:          downloader,
		Audit:               &recordingAuditRepository{},
		DownloadConcurrency: 1,
		Now:                 fixedNow,
	})
	user := domain.User{CorpID: "corp-id", UserID: "approver"}

	var waitGroup sync.WaitGroup
	waitGroup.Add(1)
	go func() {
		defer waitGroup.Done()
		result, err := service.Download(
			context.Background(),
			user,
			"instance-id",
			"file-id",
			"first-request",
		)
		if err == nil {
			_ = result.Body.Close()
		}
	}()
	<-started

	_, err := service.Download(
		context.Background(),
		user,
		"instance-id",
		"file-id",
		"second-request",
	)
	if !errors.Is(err, domain.ErrRateLimited) {
		t.Fatalf("second Download() error = %v; want rate limited", err)
	}
	close(release)
	waitGroup.Wait()
}

func TestSanitizeFilenameRemovesPathAndHeaderControls(t *testing.T) {
	testCases := map[string]string{
		`../../report.pdf`:           "report.pdf",
		"..\\..\\windows.exe":        "windows.exe",
		"line\r\nContent-Length: 1":  "lineContent-Length_ 1",
		`quoted"name.pdf`:            "quoted_name.pdf",
		"":                           "attachment",
		".":                          "attachment",
		"  a valid unicode 文件.pdf  ": "a valid unicode 文件.pdf",
	}
	for input, expected := range testCases {
		if actual := SanitizeFilename(input); actual != expected {
			t.Errorf("SanitizeFilename(%q) = %q; want %q", input, actual, expected)
		}
	}
}

func TestServiceFailsClosedAcrossUpstreamAndAuditErrors(t *testing.T) {
	upstreamFailure := fmt.Errorf("%w: DingTalk failed", domain.ErrUpstream)
	testCases := []struct {
		name           string
		approval       domain.Approval
		approvalError  error
		downloadError  error
		openerError    error
		auditError     error
		want           error
		wantBodyClosed bool
	}{
		{
			name:          "approval lookup",
			approvalError: upstreamFailure,
			want:          domain.ErrUpstream,
		},
		{
			name:     "unrelated user",
			approval: domain.Approval{ProcessInstanceID: "instance-id"},
			want:     domain.ErrForbidden,
		},
		{
			name:          "download grant",
			approval:      testApproval(),
			downloadError: upstreamFailure,
			want:          domain.ErrUpstream,
		},
		{
			name:        "downloader",
			approval:    testApproval(),
			openerError: domain.ErrTooLarge,
			want:        domain.ErrTooLarge,
		},
		{
			name:           "allowed audit",
			approval:       testApproval(),
			auditError:     errors.New("audit failed"),
			want:           domain.ErrUnavailable,
			wantBodyClosed: true,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			body := &trackingBody{Reader: strings.NewReader("data")}
			upstream := &fakeApprovalProvider{
				approval:         testCase.approval,
				approvalError:    testCase.approvalError,
				downloadURLError: testCase.downloadError,
			}
			audit := &recordingAuditRepository{err: testCase.auditError}
			service := NewService(Options{
				Approvals: upstream,
				Downloader: &fakeDownloader{
					response: &Download{Body: body},
					err:      testCase.openerError,
				},
				Audit:               audit,
				DownloadConcurrency: 1,
				Now:                 fixedNow,
			})
			_, err := service.Download(
				context.Background(),
				domain.User{CorpID: "corp-id", UserID: "approver"},
				"instance-id",
				"file-id",
				"request-id",
			)
			if !errors.Is(err, testCase.want) {
				t.Fatalf("Download() error = %v; want %v", err, testCase.want)
			}
			if body.closed != testCase.wantBodyClosed {
				t.Errorf("body closed = %v; want %v", body.closed, testCase.wantBodyClosed)
			}
		})
	}
}

func TestListHandlesUpstreamAndAuditFailures(t *testing.T) {
	service := NewService(Options{
		Approvals: &fakeApprovalProvider{
			approvalError: domain.ErrUnavailable,
		},
		Downloader:          &fakeDownloader{},
		Audit:               &recordingAuditRepository{},
		DownloadConcurrency: 1,
		Now:                 fixedNow,
	})
	_, err := service.List(
		context.Background(),
		domain.User{CorpID: "corp-id", UserID: "approver"},
		"instance-id",
		"request-id",
	)
	if !errors.Is(err, domain.ErrUnavailable) {
		t.Errorf("upstream List() error = %v", err)
	}

	service = NewService(Options{
		Approvals:           &fakeApprovalProvider{approval: testApproval()},
		Downloader:          &fakeDownloader{},
		Audit:               &recordingAuditRepository{err: errors.New("audit failed")},
		DownloadConcurrency: 1,
		Now:                 fixedNow,
	})
	_, err = service.List(
		context.Background(),
		domain.User{CorpID: "corp-id", UserID: "approver"},
		"instance-id",
		"request-id",
	)
	if !errors.Is(err, domain.ErrUnavailable) {
		t.Errorf("audit List() error = %v", err)
	}
}

func TestServiceValidatesRequestIdentityAndDefaults(t *testing.T) {
	service := NewService(Options{})
	if service.now == nil || service.limiter.limit != 1 {
		t.Errorf("default service = %#v", service)
	}
	testCases := []struct {
		name      string
		user      domain.User
		instance  string
		requestID string
		fileID    string
		want      error
	}{
		{
			name:      "missing corporation",
			user:      domain.User{UserID: "user"},
			instance:  "instance",
			requestID: "request",
			fileID:    "file",
			want:      domain.ErrUnauthorized,
		},
		{
			name:      "missing user",
			user:      domain.User{CorpID: "corp"},
			instance:  "instance",
			requestID: "request",
			fileID:    "file",
			want:      domain.ErrUnauthorized,
		},
		{
			name:      "missing instance",
			user:      domain.User{CorpID: "corp", UserID: "user"},
			requestID: "request",
			fileID:    "file",
			want:      domain.ErrInvalidInput,
		},
		{
			name:     "missing request ID",
			user:     domain.User{CorpID: "corp", UserID: "user"},
			instance: "instance",
			fileID:   "file",
			want:     domain.ErrInvalidInput,
		},
		{
			name:      "missing file ID",
			user:      domain.User{CorpID: "corp", UserID: "user"},
			instance:  "instance",
			requestID: "request",
			want:      domain.ErrInvalidInput,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := service.Download(
				context.Background(),
				testCase.user,
				testCase.instance,
				testCase.fileID,
				testCase.requestID,
			)
			if !errors.Is(err, testCase.want) {
				t.Errorf("Download() error = %v; want %v", err, testCase.want)
			}
		})
	}
}

func TestErrorClassCoversStableAuditCategories(t *testing.T) {
	testCases := []struct {
		err  error
		want string
	}{
		{domain.ErrInvalidInput, "invalid_input"},
		{domain.ErrUnauthorized, "unauthorized"},
		{domain.ErrForbidden, "forbidden"},
		{domain.ErrNotFound, "not_found"},
		{domain.ErrConflict, "conflict"},
		{domain.ErrExpired, "expired"},
		{domain.ErrAlreadyUsed, "already_used"},
		{domain.ErrAuthorizationPending, "authorization_pending"},
		{domain.ErrRateLimited, "rate_limited"},
		{domain.ErrTooLarge, "too_large"},
		{domain.ErrUnavailable, "unavailable"},
		{domain.ErrUpstream, "upstream"},
	}
	for _, testCase := range testCases {
		if got := errorClass(testCase.err); got != testCase.want {
			t.Errorf("errorClass(%v) = %q; want %q", testCase.err, got, testCase.want)
		}
	}
}

func TestReleaseReadCloserReleasesOnEOFAndLongNamesAreBounded(t *testing.T) {
	releases := 0
	reader := &releaseReadCloser{
		body:    io.NopCloser(strings.NewReader("x")),
		release: func() { releases++ },
	}
	output, err := io.ReadAll(reader)
	if err != nil || string(output) != "x" {
		t.Fatalf("ReadAll() = %q, %v", output, err)
	}
	if releases != 1 {
		t.Errorf("releases after EOF = %d; want 1", releases)
	}
	if err := reader.Close(); err != nil {
		t.Errorf("Close() error = %v", err)
	}
	if releases != 1 {
		t.Errorf("releases after Close = %d; want 1", releases)
	}

	longName := strings.Repeat("文", 100) + ".pdf"
	sanitized := SanitizeFilename(longName)
	if len(sanitized) > 180 || !utf8.ValidString(sanitized) {
		t.Errorf("long sanitized filename has %d bytes and valid=%v", len(sanitized), utf8.ValidString(sanitized))
	}
}

func testApproval() domain.Approval {
	return domain.Approval{
		ProcessInstanceID: "instance-id",
		OriginatorUserID:  "originator",
		ApproverUserIDs:   []string{"approver"},
		TaskUserIDs:       []string{"task-user"},
		CCUserIDs:         []string{"cc-user"},
		Attachments: []domain.Attachment{
			{FileID: "file-id", FileName: "report.pdf", Source: domain.AttachmentSourceForm},
		},
	}
}

func fixedNow() time.Time {
	return time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
}

type fakeApprovalProvider struct {
	approval         domain.Approval
	approvalError    error
	downloadURL      *url.URL
	downloadURLError error
	approvalCalls    atomic.Int64
	downloadURLCalls atomic.Int64
}

func (fake *fakeApprovalProvider) Approval(
	context.Context,
	string,
) (domain.Approval, error) {
	fake.approvalCalls.Add(1)
	return fake.approval, fake.approvalError
}

func (fake *fakeApprovalProvider) DownloadURL(
	context.Context,
	string,
	string,
) (*url.URL, error) {
	fake.downloadURLCalls.Add(1)
	if fake.downloadURL != nil || fake.downloadURLError != nil {
		return fake.downloadURL, fake.downloadURLError
	}
	return url.Parse("https://download.example.test/signed")
}

type fakeDownloader struct {
	response  *Download
	err       error
	openedURL string
	open      func(context.Context, *url.URL) (*Download, error)
}

func (fake *fakeDownloader) Open(ctx context.Context, downloadURL *url.URL) (*Download, error) {
	fake.openedURL = downloadURL.String()
	if fake.open != nil {
		return fake.open(ctx, downloadURL)
	}
	if fake.response == nil {
		return &Download{Body: io.NopCloser(strings.NewReader("ok"))}, fake.err
	}
	return fake.response, fake.err
}

type recordingAuditRepository struct {
	mu           sync.Mutex
	events       []domain.AuditEvent
	err          error
	contextErr   error
	contextValue any
	deadline     time.Time
}

type trackingBody struct {
	io.Reader
	closed bool
}

func (body *trackingBody) Close() error {
	body.closed = true
	return nil
}

func (repository *recordingAuditRepository) RecordAudit(
	ctx context.Context,
	event domain.AuditEvent,
) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	repository.contextErr = ctx.Err()
	repository.contextValue = ctx.Value(auditContextKey{})
	repository.deadline, _ = ctx.Deadline()
	if repository.contextErr != nil {
		return repository.contextErr
	}
	repository.events = append(repository.events, event)
	return repository.err
}
