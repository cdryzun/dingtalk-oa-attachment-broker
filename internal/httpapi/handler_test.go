package httpapi

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/approvals"
	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/attachments"
	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/auth"
	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/domain"
)

func TestHealthAndReadinessEndpoints(t *testing.T) {
	handler := newTestHandler(t)
	for _, path := range []string{"/healthz", "/readyz"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		if response.Code != http.StatusOK {
			t.Errorf("%s status = %d; want 200", path, response.Code)
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s Cache-Control = %q", path, response.Header().Get("Cache-Control"))
		}
	}
}

func TestAttachmentListSerializesEmptyArray(t *testing.T) {
	handler := newTestHandlerWithServices(
		t,
		&fakeAuthService{user: domain.User{CorpID: "corp-id", UserID: "user-id"}},
		&fakeAttachmentService{},
	)
	request := authenticatedRequest(
		t,
		http.MethodGet,
		"/api/v1/approvals/instance-id/attachments",
		nil,
	)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"attachments":[]`) {
		t.Fatalf("attachment response = %d %s; want empty array", response.Code, response.Body)
	}
}

func TestContentDispositionPreservesPlusAndEncodesSpace(t *testing.T) {
	got := contentDisposition("report+a b.xlsx")
	if !strings.Contains(got, "filename*=UTF-8''report+a%20b.xlsx") {
		t.Errorf("Content-Disposition = %q", got)
	}
}

func TestReadinessIsRateLimitedButLivenessIsExempt(t *testing.T) {
	handler, err := NewHandler(Options{
		Auth:              &fakeAuthService{},
		Attachments:       &fakeAttachmentService{},
		ApprovalSearch:    &fakeApprovalSearchService{},
		Readiness:         fakeReadiness{},
		ReadinessTimeout:  time.Second,
		RequestsPerMinute: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	for index, wantStatus := range []int{http.StatusOK, http.StatusTooManyRequests} {
		request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != wantStatus {
			t.Errorf("readyz request %d status = %d; want %d", index+1, response.Code, wantStatus)
		}
		if wantStatus == http.StatusTooManyRequests && response.Header().Get("Retry-After") != "60" {
			t.Errorf("Retry-After = %q; want 60", response.Header().Get("Retry-After"))
		}
	}
	for range 2 {
		request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Errorf("healthz status = %d; want 200", response.Code)
		}
	}
}

func TestMetricsAreServedOnlyByDedicatedHandler(t *testing.T) {
	handler := newTestHandler(t)
	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("public /metrics status = %d; want 404", response.Code)
	}

	metricsProvider, ok := handler.(interface{ MetricsHandler() http.Handler })
	if !ok {
		t.Fatal("handler does not expose a dedicated metrics handler")
	}
	request = httptest.NewRequest(http.MethodGet, "/metrics", nil)
	response = httptest.NewRecorder()
	metricsProvider.MetricsHandler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("internal /metrics status = %d; want 200", response.Code)
	}
	if !strings.Contains(response.Body.String(), "broker_http_requests_total") {
		t.Errorf("internal /metrics body does not contain broker metrics")
	}

	request = httptest.NewRequest(http.MethodGet, "/missing", nil)
	response = httptest.NewRecorder()
	metricsProvider.MetricsHandler().ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("internal /missing status = %d; want 404", response.Code)
	}
}

func TestMetricsBoundUnrecognizedHTTPMethods(t *testing.T) {
	handler := newTestHandler(t)
	for _, method := range []string{"X-ATTACK-ONE", "X-ATTACK-TWO"} {
		request := httptest.NewRequest(method, "/missing", nil)
		handler.ServeHTTP(httptest.NewRecorder(), request)
	}
	metricsProvider := handler.(interface{ MetricsHandler() http.Handler })
	response := httptest.NewRecorder()
	metricsProvider.MetricsHandler().ServeHTTP(
		response,
		httptest.NewRequest(http.MethodGet, "/metrics", nil),
	)
	body := response.Body.String()
	if strings.Contains(body, "X-ATTACK") || !strings.Contains(body, `method="other"`) {
		t.Fatalf("metrics expose unbounded method labels:\n%s", body)
	}
}

func TestRateLimitUsesForwardedClientOnlyForTrustedProxy(t *testing.T) {
	tests := []struct {
		name           string
		trustedProxies []netip.Prefix
		wantStatuses   []int
	}{
		{
			name:           "trusted proxy",
			trustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			wantStatuses:   []int{http.StatusNotFound, http.StatusNotFound, http.StatusTooManyRequests},
		},
		{
			name:         "untrusted proxy",
			wantStatuses: []int{http.StatusNotFound, http.StatusTooManyRequests, http.StatusTooManyRequests},
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			handler, err := NewHandler(Options{
				Auth:              &fakeAuthService{},
				Attachments:       &fakeAttachmentService{},
				ApprovalSearch:    &fakeApprovalSearchService{},
				Readiness:         fakeReadiness{},
				TrustedProxyCIDRs: testCase.trustedProxies,
				RequestsPerMinute: 1,
				ReadinessTimeout:  time.Second,
			})
			if err != nil {
				t.Fatalf("NewHandler() error = %v", err)
			}

			forwardedClients := []string{"198.51.100.10", "198.51.100.11", "198.51.100.10"}
			for index, forwardedClient := range forwardedClients {
				request := httptest.NewRequest(http.MethodGet, "/missing", nil)
				request.RemoteAddr = "10.0.0.2:12345"
				request.Header.Set("X-Forwarded-For", forwardedClient)
				response := httptest.NewRecorder()

				handler.ServeHTTP(response, request)

				if response.Code != testCase.wantStatuses[index] {
					t.Errorf("request %d status = %d; want %d", index, response.Code, testCase.wantStatuses[index])
				}
			}
		})
	}
}

func TestClientAddressRejectsInvalidForwardedChain(t *testing.T) {
	handler := &Handler{
		trustedProxyCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "10.0.0.2:12345"
	request.Header.Set("X-Forwarded-For", "198.51.100.10, invalid")

	if got := handler.clientAddress(request); got != "10.0.0.2" {
		t.Errorf("clientAddress() = %q; want direct peer", got)
	}
}

func TestClientAddressUsesRightmostUntrustedForwardedHop(t *testing.T) {
	handler := &Handler{
		trustedProxyCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "10.0.0.2:12345"
	request.Header.Set(
		"X-Forwarded-For",
		"203.0.113.7, 198.51.100.10, 10.0.0.3",
	)

	if got := handler.clientAddress(request); got != "198.51.100.10" {
		t.Errorf("clientAddress() = %q; want rightmost untrusted hop", got)
	}
}

func TestReadinessFailsWhenPostgreSQLIsUnavailable(t *testing.T) {
	handler, err := NewHandler(Options{
		Auth:              &fakeAuthService{},
		Attachments:       &fakeAttachmentService{},
		ApprovalSearch:    &fakeApprovalSearchService{},
		Readiness:         fakeReadiness{err: errors.New("database unavailable")},
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		ReadinessTimeout:  time.Second,
		RequestsPerMinute: 120,
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	assertProblem(t, response, http.StatusServiceUnavailable, "service_unavailable")
}

func TestNewHandlerRejectsMissingDependencies(t *testing.T) {
	valid := Options{
		Auth:           &fakeAuthService{},
		Attachments:    &fakeAttachmentService{},
		ApprovalSearch: &fakeApprovalSearchService{},
		Readiness:      fakeReadiness{},
	}
	tests := []struct {
		name   string
		mutate func(*Options)
	}{
		{name: "authentication", mutate: func(options *Options) { options.Auth = nil }},
		{name: "attachments", mutate: func(options *Options) { options.Attachments = nil }},
		{name: "approval search", mutate: func(options *Options) { options.ApprovalSearch = nil }},
		{name: "readiness", mutate: func(options *Options) { options.Readiness = nil }},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			options := valid
			testCase.mutate(&options)
			if _, err := NewHandler(options); err == nil {
				t.Fatal("NewHandler() error = nil; want invalid options")
			}
		})
	}
}

func TestDeviceAuthorizationAndOAuthRoutes(t *testing.T) {
	fakeAuth := &fakeAuthService{
		deviceResponse: auth.DeviceAuthorizationResponse{
			DeviceCode:              "device-code",
			UserCode:                "ABCD-EFGH",
			VerificationURI:         "https://broker.example.test/auth/dingtalk/start",
			VerificationURIComplete: "https://broker.example.test/auth/dingtalk/start?user_code=ABCD-EFGH",
			ExpiresIn:               600,
			Interval:                5,
		},
		startURL: "https://login.dingtalk.com/oauth2/auth?redacted=true",
		sessionResponse: auth.SessionResponse{
			AccessToken:      "access-token",
			TokenType:        "Bearer",
			ExpiresIn:        28800,
			RefreshToken:     "refresh-token",
			RefreshExpiresIn: 2592000,
		},
	}
	handler := newTestHandlerWithAuth(t, fakeAuth)

	createRequest := httptest.NewRequest(http.MethodPost, "/api/v1/device-authorizations", nil)
	createResponse := httptest.NewRecorder()
	handler.ServeHTTP(createResponse, createRequest)
	if createResponse.Code != http.StatusCreated {
		t.Fatalf("create status = %d; body = %s", createResponse.Code, createResponse.Body)
	}
	if !strings.Contains(createResponse.Body.String(), `"deviceCode":"device-code"`) {
		t.Errorf("create body = %s", createResponse.Body)
	}

	startRequest := httptest.NewRequest(
		http.MethodGet,
		"/auth/dingtalk/start?user_code=ABCD-EFGH",
		nil,
	)
	startResponse := httptest.NewRecorder()
	handler.ServeHTTP(startResponse, startRequest)
	if startResponse.Code != http.StatusSeeOther {
		t.Fatalf("start status = %d; want 303", startResponse.Code)
	}
	if startResponse.Header().Get("Location") != fakeAuth.startURL {
		t.Errorf("start Location = %q", startResponse.Header().Get("Location"))
	}

	callbackRequest := httptest.NewRequest(
		http.MethodGet,
		"/auth/dingtalk/callback?state=opaque-state&code=authorization-code",
		nil,
	)
	callbackResponse := httptest.NewRecorder()
	handler.ServeHTTP(callbackResponse, callbackRequest)
	if callbackResponse.Code != http.StatusOK {
		t.Fatalf("callback status = %d; body = %s", callbackResponse.Code, callbackResponse.Body)
	}
	if !strings.Contains(callbackResponse.Header().Get("Content-Type"), "text/html") {
		t.Errorf("callback Content-Type = %q", callbackResponse.Header().Get("Content-Type"))
	}

	tokenRequest := jsonRequest(
		t,
		http.MethodPost,
		"/api/v1/device-authorizations/token",
		`{"deviceCode":"device-code"}`,
	)
	tokenResponse := httptest.NewRecorder()
	handler.ServeHTTP(tokenResponse, tokenRequest)
	if tokenResponse.Code != http.StatusOK ||
		!strings.Contains(tokenResponse.Body.String(), `"accessToken":"access-token"`) {
		t.Errorf("token response = %d %s", tokenResponse.Code, tokenResponse.Body)
	}
}

func TestOAuthCallbackRejectsDeviceAuthorization(t *testing.T) {
	fakeAuth := &fakeAuthService{}
	handler := newTestHandlerWithAuth(t, fakeAuth)
	request := httptest.NewRequest(
		http.MethodGet,
		"/auth/dingtalk/callback?error=access_denied&state=opaque-state",
		nil,
	)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	assertProblem(t, response, http.StatusForbidden, "forbidden")
	if fakeAuth.rejectState != "opaque-state" {
		t.Errorf("rejected state = %q; want opaque-state", fakeAuth.rejectState)
	}
}

func TestAuthenticatedSessionAndAttachmentRoutes(t *testing.T) {
	fakeAuth := &fakeAuthService{
		user: domain.User{
			CorpID:      "corp-id",
			UserID:      "user-id",
			UnionID:     "union-id",
			DisplayName: "Verified User",
		},
		sessionResponse: auth.SessionResponse{
			AccessToken:      "new-access",
			TokenType:        "Bearer",
			ExpiresIn:        28800,
			RefreshToken:     "new-refresh",
			RefreshExpiresIn: 2592000,
		},
	}
	fakeAttachments := &fakeAttachmentService{
		list: []domain.Attachment{
			{FileID: "file-id", FileName: "report.pdf", FileSize: 4},
		},
		download: &attachments.Download{
			Attachment:    domain.Attachment{FileID: "file-id", FileName: "report.pdf"},
			Body:          io.NopCloser(strings.NewReader("data")),
			ContentType:   "application/pdf",
			ContentLength: 4,
		},
	}
	handler := newTestHandlerWithServices(t, fakeAuth, fakeAttachments)

	meRequest := authenticatedRequest(t, http.MethodGet, "/api/v1/me", nil)
	meResponse := httptest.NewRecorder()
	handler.ServeHTTP(meResponse, meRequest)
	if meResponse.Code != http.StatusOK ||
		!strings.Contains(meResponse.Body.String(), `"userId":"user-id"`) {
		t.Errorf("me response = %d %s", meResponse.Code, meResponse.Body)
	}

	listRequest := authenticatedRequest(
		t,
		http.MethodGet,
		"/api/v1/approvals/instance-id/attachments",
		nil,
	)
	listResponse := httptest.NewRecorder()
	handler.ServeHTTP(listResponse, listRequest)
	if listResponse.Code != http.StatusOK ||
		!strings.Contains(listResponse.Body.String(), `"fileId":"file-id"`) {
		t.Errorf("list response = %d %s", listResponse.Code, listResponse.Body)
	}

	downloadRequest := authenticatedRequest(
		t,
		http.MethodGet,
		"/api/v1/approvals/instance-id/attachments/file-id/content",
		nil,
	)
	downloadResponse := httptest.NewRecorder()
	handler.ServeHTTP(downloadResponse, downloadRequest)
	if downloadResponse.Code != http.StatusOK || downloadResponse.Body.String() != "data" {
		t.Errorf("download response = %d %q", downloadResponse.Code, downloadResponse.Body.String())
	}
	if got := downloadResponse.Header().Get("Content-Disposition"); !strings.Contains(got, "report.pdf") {
		t.Errorf("Content-Disposition = %q", got)
	}
	if got := downloadResponse.Header().Get("Content-Type"); got != "application/octet-stream" {
		t.Errorf("Content-Type = %q; want application/octet-stream", got)
	}
	if strings.Contains(downloadResponse.Body.String(), "signed") {
		t.Error("download response exposed signed URL")
	}

	refreshRequest := jsonRequest(
		t,
		http.MethodPost,
		"/api/v1/sessions/refresh",
		`{"refreshToken":"refresh-token"}`,
	)
	refreshResponse := httptest.NewRecorder()
	handler.ServeHTTP(refreshResponse, refreshRequest)
	if refreshResponse.Code != http.StatusOK {
		t.Errorf("refresh response = %d %s", refreshResponse.Code, refreshResponse.Body)
	}

	revokeRequest := authenticatedRequest(t, http.MethodDelete, "/api/v1/sessions/current", nil)
	revokeResponse := httptest.NewRecorder()
	handler.ServeHTTP(revokeResponse, revokeRequest)
	if revokeResponse.Code != http.StatusNoContent {
		t.Errorf("revoke response = %d %s", revokeResponse.Code, revokeResponse.Body)
	}
}

func TestAttachmentRoutesRejectTemplateProcessCodesAfterAuthentication(t *testing.T) {
	fakeAttachments := &fakeAttachmentService{}
	handler := newTestHandlerWithAllServices(
		t,
		&fakeAuthService{user: domain.User{CorpID: "corp-id", UserID: "user-id"}},
		fakeAttachments,
		&fakeApprovalSearchService{},
	)

	for _, path := range []string{
		"/api/v1/approvals/PROC-TEMPLATE/attachments",
		"/api/v1/approvals/proc-template/attachments/file-id/content",
	} {
		request := authenticatedRequest(t, http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		assertProblem(t, response, http.StatusBadRequest, "invalid_request")
	}
	if fakeAttachments.listCalls != 0 || fakeAttachments.downloadCalls != 0 {
		t.Errorf(
			"attachment service calls = list %d, download %d; want zero",
			fakeAttachments.listCalls,
			fakeAttachments.downloadCalls,
		)
	}

	unauthenticated := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/approvals/PROC-TEMPLATE/attachments",
		nil,
	)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, unauthenticated)
	assertProblem(t, response, http.StatusUnauthorized, "unauthorized")
}

func TestAttachmentAPIOperationsEmitStructuredLogsWithoutSecrets(t *testing.T) {
	var logOutput bytes.Buffer
	fakeAuth := &fakeAuthService{
		user: domain.User{
			CorpID:  "corp-id",
			UserID:  "user-id",
			UnionID: "union-id",
		},
	}
	fakeAttachments := &fakeAttachmentService{
		list: []domain.Attachment{
			{FileID: "file-id", FileName: "sensitive-name.xlsx", FileSize: 4},
		},
		download: &attachments.Download{
			Attachment:    domain.Attachment{FileID: "file-id", FileName: "sensitive-name.xlsx"},
			Body:          io.NopCloser(strings.NewReader("data")),
			ContentType:   "application/octet-stream",
			ContentLength: 4,
		},
	}
	handler, err := NewHandler(Options{
		Auth:              fakeAuth,
		Attachments:       fakeAttachments,
		ApprovalSearch:    &fakeApprovalSearchService{},
		Readiness:         fakeReadiness{},
		Logger:            slog.New(slog.NewJSONHandler(&logOutput, nil)),
		ReadinessTimeout:  time.Second,
		RequestsPerMinute: 120,
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	listRequest := authenticatedRequest(
		t,
		http.MethodGet,
		"/api/v1/approvals/instance-id/attachments",
		nil,
	)
	listRequest.Header.Set(requestIDHeader, "list-request")
	listResponse := httptest.NewRecorder()
	handler.ServeHTTP(listResponse, listRequest)
	if listResponse.Code != http.StatusOK {
		t.Fatalf("list status = %d; body = %s", listResponse.Code, listResponse.Body)
	}

	downloadRequest := authenticatedRequest(
		t,
		http.MethodGet,
		"/api/v1/approvals/instance-id/attachments/file-id/content",
		nil,
	)
	downloadRequest.Header.Set(requestIDHeader, "download-request")
	downloadResponse := httptest.NewRecorder()
	handler.ServeHTTP(downloadResponse, downloadRequest)
	if downloadResponse.Code != http.StatusOK {
		t.Fatalf(
			"download status = %d; body = %s",
			downloadResponse.Code,
			downloadResponse.Body,
		)
	}

	records := attachmentLogRecords(t, logOutput.String())
	if len(records) != 2 {
		t.Fatalf("attachment log records = %#v; want 2", records)
	}
	assertLogFields(t, records[0], map[string]any{
		"event":             "attachments.list",
		"outcome":           "success",
		"requestId":         "list-request",
		"corpId":            "corp-id",
		"actorUserId":       "user-id",
		"processInstanceId": "instance-id",
		"attachmentCount":   float64(1),
	})
	assertLogFields(t, records[1], map[string]any{
		"event":             "attachments.download",
		"outcome":           "success",
		"requestId":         "download-request",
		"corpId":            "corp-id",
		"actorUserId":       "user-id",
		"processInstanceId": "instance-id",
		"fileId":            "file-id",
		"bytesWritten":      float64(4),
		"contentLength":     float64(4),
	})
	for _, record := range records {
		if _, ok := record["durationMs"]; !ok {
			t.Errorf("structured log has no durationMs: %#v", record)
		}
	}
	for _, secret := range []string{
		"access-token",
		"sensitive-name.xlsx",
		"Authorization",
		"signedUrl",
	} {
		if strings.Contains(logOutput.String(), secret) {
			t.Errorf("structured logs contain forbidden value %q", secret)
		}
	}
}

func TestAttachmentAPIFailureLogUsesStableErrorClass(t *testing.T) {
	var logOutput bytes.Buffer
	handler, err := NewHandler(Options{
		Auth: &fakeAuthService{
			user: domain.User{CorpID: "corp-id", UserID: "user-id"},
		},
		Attachments: &fakeAttachmentService{
			downloadError: fmt.Errorf(
				"%w: signed URL must remain private",
				domain.ErrUpstream,
			),
		},
		ApprovalSearch:    &fakeApprovalSearchService{},
		Readiness:         fakeReadiness{},
		Logger:            slog.New(slog.NewJSONHandler(&logOutput, nil)),
		ReadinessTimeout:  time.Second,
		RequestsPerMinute: 120,
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	request := authenticatedRequest(
		t,
		http.MethodGet,
		"/api/v1/approvals/instance-id/attachments/file-id/content",
		nil,
	)
	request.Header.Set(requestIDHeader, "failed-request")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	assertProblem(t, response, http.StatusBadGateway, "upstream_error")
	records := attachmentLogRecords(t, logOutput.String())
	if len(records) != 1 {
		t.Fatalf("attachment log records = %#v; want 1", records)
	}
	assertLogFields(t, records[0], map[string]any{
		"event":             "attachments.download",
		"outcome":           "failure",
		"requestId":         "failed-request",
		"corpId":            "corp-id",
		"actorUserId":       "user-id",
		"processInstanceId": "instance-id",
		"fileId":            "file-id",
		"errorClass":        "upstream_error",
	})
	if strings.Contains(logOutput.String(), "signed URL must remain private") {
		t.Error("structured failure log contains the upstream error detail")
	}
}

func TestAttachmentAPIStructuredLogsCoverListAndStreamFailures(t *testing.T) {
	var logOutput bytes.Buffer
	fakeAttachments := &fakeAttachmentService{
		listError: domain.ErrForbidden,
	}
	handler, err := NewHandler(Options{
		Auth: &fakeAuthService{
			user: domain.User{CorpID: "corp-id", UserID: "user-id"},
		},
		Attachments:       fakeAttachments,
		ApprovalSearch:    &fakeApprovalSearchService{},
		Readiness:         fakeReadiness{},
		Logger:            slog.New(slog.NewJSONHandler(&logOutput, nil)),
		ReadinessTimeout:  time.Second,
		RequestsPerMinute: 120,
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}

	listRequest := authenticatedRequest(
		t,
		http.MethodGet,
		"/api/v1/approvals/instance-id/attachments",
		nil,
	)
	listRequest.Header.Set(requestIDHeader, "denied-list")
	listResponse := httptest.NewRecorder()
	handler.ServeHTTP(listResponse, listRequest)
	assertProblem(t, listResponse, http.StatusForbidden, "forbidden")

	fakeAttachments.download = nil
	nilDownloadRequest := authenticatedRequest(
		t,
		http.MethodGet,
		"/api/v1/approvals/instance-id/attachments/file-id/content",
		nil,
	)
	nilDownloadRequest.Header.Set(requestIDHeader, "nil-download")
	nilDownloadResponse := httptest.NewRecorder()
	handler.ServeHTTP(nilDownloadResponse, nilDownloadRequest)
	assertProblem(t, nilDownloadResponse, http.StatusBadGateway, "upstream_error")

	fakeAttachments.download = &attachments.Download{
		Attachment: domain.Attachment{FileID: "file-id", FileName: "private.xlsx"},
		Body: io.NopCloser(&errorAfterReader{
			content: "da",
			err:     errors.New("private transport detail"),
		}),
		ContentType:   "application/octet-stream",
		ContentLength: 4,
	}
	streamRequest := authenticatedRequest(
		t,
		http.MethodGet,
		"/api/v1/approvals/instance-id/attachments/file-id/content",
		nil,
	)
	streamRequest.Header.Set(requestIDHeader, "failed-stream")
	streamResponse := httptest.NewRecorder()
	var recovered any
	func() {
		defer func() { recovered = recover() }()
		handler.ServeHTTP(streamResponse, streamRequest)
	}()
	if recovered != http.ErrAbortHandler {
		t.Fatalf("stream panic = %#v; want http.ErrAbortHandler", recovered)
	}
	if streamResponse.Code != http.StatusOK || streamResponse.Body.String() != "da" {
		t.Errorf(
			"stream response = %d %q; want partial 200 response",
			streamResponse.Code,
			streamResponse.Body.String(),
		)
	}

	records := attachmentLogRecords(t, logOutput.String())
	if len(records) != 3 {
		t.Fatalf("attachment log records = %#v; want 3", records)
	}
	assertLogFields(t, records[0], map[string]any{
		"event":       "attachments.list",
		"outcome":     "failure",
		"requestId":   "denied-list",
		"errorClass":  "forbidden",
		"actorUserId": "user-id",
	})
	if _, ok := records[0]["fileId"]; ok {
		t.Errorf("list log unexpectedly contains fileId: %#v", records[0])
	}
	assertLogFields(t, records[1], map[string]any{
		"event":       "attachments.download",
		"outcome":     "failure",
		"requestId":   "nil-download",
		"errorClass":  "upstream_error",
		"actorUserId": "user-id",
	})
	assertLogFields(t, records[2], map[string]any{
		"event":         "attachments.download",
		"outcome":       "failure",
		"requestId":     "failed-stream",
		"errorClass":    "internal_error",
		"actorUserId":   "user-id",
		"bytesWritten":  float64(2),
		"contentLength": float64(4),
	})
	for _, forbidden := range []string{"private.xlsx", "private transport detail"} {
		if strings.Contains(logOutput.String(), forbidden) {
			t.Errorf("structured logs contain forbidden value %q", forbidden)
		}
	}
}

func TestAttachmentStreamFailureAbortsUnknownLengthResponse(t *testing.T) {
	fakeAttachments := &fakeAttachmentService{
		download: &attachments.Download{
			Attachment: domain.Attachment{FileID: "file-id", FileName: "report.pdf"},
			Body: io.NopCloser(&errorAfterReader{
				content: "partial",
				err:     domain.ErrTooLarge,
			}),
			ContentLength: -1,
		},
	}
	handler := newTestHandlerWithServices(
		t,
		&fakeAuthService{user: domain.User{CorpID: "corp-id", UserID: "user-id"}},
		fakeAttachments,
	)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	request, err := http.NewRequest(
		http.MethodGet,
		server.URL+"/api/v1/approvals/instance-id/attachments/file-id/content",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer access-token")

	response, requestErr := server.Client().Do(request)
	if requestErr == nil {
		defer response.Body.Close()
		body, readErr := io.ReadAll(response.Body)
		if readErr == nil {
			t.Fatalf("read unknown-length stream = %q, nil; want transport failure", body)
		}
	}
}

func TestAuthenticatedApprovalCategoryAndSearchRoutes(t *testing.T) {
	fakeAuth := &fakeAuthService{
		user: domain.User{CorpID: "corp-id", UserID: "user-id"},
	}
	fakeSearch := &fakeApprovalSearchService{
		discoveryResult: approvals.CategoryDiscoveryResult{
			Categories: []approvals.Category{
				{ID: "firmware-flow", DisplayName: "Firmware flow"},
			},
			Complete:        true,
			TotalCategories: 1,
		},
		result: approvals.SearchResult{
			CategoryID: "firmware-flow",
			Items: []approvals.Item{
				{
					ProcessInstanceID: "instance-id",
					Title:             "Firmware release",
					Attachments: []domain.Attachment{
						{FileID: "file-id", FileName: "firmware.zip"},
					},
				},
			},
			NextCursor: "opaque-cursor",
		},
	}
	handler := newTestHandlerWithAllServices(
		t,
		fakeAuth,
		&fakeAttachmentService{},
		fakeSearch,
	)

	categoryRequest := authenticatedRequest(
		t,
		http.MethodGet,
		"/api/v1/approval-categories",
		nil,
	)
	categoryResponse := httptest.NewRecorder()
	handler.ServeHTTP(categoryResponse, categoryRequest)
	if categoryResponse.Code != http.StatusOK ||
		!strings.Contains(categoryResponse.Body.String(), `"id":"firmware-flow"`) {
		t.Errorf("category response = %d %s", categoryResponse.Code, categoryResponse.Body)
	}

	searchRequest := authenticatedRequest(
		t,
		http.MethodGet,
		"/api/v1/approvals?category=firmware-flow&limit=10&createdAfter=2026-06-01T00%3A00%3A00.123456789Z",
		nil,
	)
	searchResponse := httptest.NewRecorder()
	handler.ServeHTTP(searchResponse, searchRequest)
	if searchResponse.Code != http.StatusOK ||
		!strings.Contains(searchResponse.Body.String(), `"nextCursor":"opaque-cursor"`) ||
		!strings.Contains(searchResponse.Body.String(), `"fileId":"file-id"`) {
		t.Errorf("search response = %d %s", searchResponse.Code, searchResponse.Body)
	}
	if fakeSearch.query.CategoryID != "firmware-flow" ||
		fakeSearch.query.Limit != 10 ||
		fakeSearch.query.CreatedAfter == nil ||
		fakeSearch.query.CreatedAfter.Nanosecond() != 123456789 {
		t.Errorf("search query = %#v", fakeSearch.query)
	}
}

func TestAuthenticatedUserVisibleCategoryRoute(t *testing.T) {
	fakeAuth := &fakeAuthService{
		user: domain.User{CorpID: "corp-id", UserID: "user-id"},
	}
	fakeSearch := &fakeApprovalSearchService{
		discoveryResult: approvals.CategoryDiscoveryResult{
			Categories: []approvals.Category{
				{
					ID:            "firmware-flow",
					DisplayName:   "Firmware flow",
					DirectoryName: "Product engineering",
				},
			},
			NextCursor:        "discovery.cursor",
			Complete:          false,
			ScannedPages:      1,
			ScannedCandidates: 42,
			TotalCategories:   101,
		},
	}
	handler := newTestHandlerWithAllServices(
		t,
		fakeAuth,
		&fakeAttachmentService{},
		fakeSearch,
	)

	request := authenticatedRequest(
		t,
		http.MethodGet,
		"/api/v1/me/approval-categories?q=firmware",
		nil,
	)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), `"id":"firmware-flow"`) ||
		!strings.Contains(response.Body.String(), `"directoryName":"Product engineering"`) ||
		!strings.Contains(response.Body.String(), `"nextCursor":"discovery.cursor"`) ||
		!strings.Contains(response.Body.String(), `"complete":false`) ||
		!strings.Contains(response.Body.String(), `"totalCategories":101`) {
		t.Errorf("visible category response = %d %s", response.Code, response.Body)
	}
	if fakeSearch.discoveryUser != fakeAuth.user ||
		fakeSearch.discoveryQuery.Keyword != "firmware" {
		t.Errorf(
			"discovery call user = %#v query = %#v",
			fakeSearch.discoveryUser,
			fakeSearch.discoveryQuery,
		)
	}
}

func TestApprovalSearchRejectsUnknownRepeatedAndInvalidParameters(t *testing.T) {
	handler := newTestHandler(t)
	for _, path := range []string{
		"/api/v1/approvals",
		"/api/v1/approvals?category=firmware-flow&unknown=true",
		"/api/v1/approvals?category=one&category=two",
		"/api/v1/approvals?category=firmware-flow&createdAfter=yesterday",
		"/api/v1/approvals?category=firmware-flow&limit=many",
		"/api/v1/approvals?category=firmware-flow&q=",
		"/api/v1/approvals?category=firmware-flow&cursor=signed.cursor&q=firmware",
		"/api/v1/approval-categories?details=true",
		"/api/v1/me/approval-categories?unknown=true",
		"/api/v1/me/approval-categories?q=",
		"/api/v1/me/approval-categories?q=one&q=two",
		"/api/v1/me/approval-categories?cursor=signed.cursor&q=firmware",
		"/api/v1/me/approval-categories?createdAfter=2026-06-01T00%3A00%3A00Z",
	} {
		request := authenticatedRequest(t, http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		assertProblem(t, response, http.StatusBadRequest, "invalid_request")
	}
}

func TestHandlerUsesProblemJSONAndDoesNotExposeInternalErrors(t *testing.T) {
	fakeAuth := &fakeAuthService{authenticateError: errors.New("database password leaked")}
	handler := newTestHandlerWithAuth(t, fakeAuth)

	request := authenticatedRequest(t, http.MethodGet, "/api/v1/me", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	problem := assertProblem(t, response, http.StatusInternalServerError, "internal_error")
	if strings.Contains(problem.Detail, "password") || strings.Contains(response.Body.String(), "leaked") {
		t.Errorf("problem exposed internal error: %s", response.Body)
	}
	if response.Header().Get("X-Request-ID") == "" ||
		problem.RequestID != response.Header().Get("X-Request-ID") {
		t.Errorf("request ID response = %q problem = %q", response.Header().Get("X-Request-ID"), problem.RequestID)
	}
}

func TestHandlerRejectsUnknownJSONFieldsAndMissingBearer(t *testing.T) {
	handler := newTestHandler(t)
	request := jsonRequest(
		t,
		http.MethodPost,
		"/api/v1/device-authorizations/token",
		`{"deviceCode":"code","unexpected":true}`,
	)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertProblem(t, response, http.StatusBadRequest, "invalid_request")

	request = httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assertProblem(t, response, http.StatusUnauthorized, "unauthorized")
	if response.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Errorf("WWW-Authenticate = %q", response.Header().Get("WWW-Authenticate"))
	}
}

func TestHandlerReturnsMethodAndRouteProblems(t *testing.T) {
	handler := newTestHandler(t)
	for _, testCase := range []struct {
		method string
		path   string
		status int
		code   string
	}{
		{method: http.MethodPut, path: "/healthz", status: 405, code: "method_not_allowed"},
		{method: http.MethodGet, path: "/metrics", status: 404, code: "not_found"},
		{method: http.MethodGet, path: "/missing", status: 404, code: "not_found"},
		{
			method: http.MethodGet,
			path:   "/api/v1/approvals/instance/id/attachments",
			status: 404,
			code:   "not_found",
		},
	} {
		request := httptest.NewRequest(testCase.method, testCase.path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		assertProblem(t, response, testCase.status, testCase.code)
	}
}

func TestDecodeJSONClassifiesOversizedBodies(t *testing.T) {
	body := `{"value":"` + strings.Repeat("x", maxJSONBodyBytes) + `"}`
	request := jsonRequest(t, http.MethodPost, "/", body)
	response := httptest.NewRecorder()
	var destination map[string]string
	if err := decodeJSON(response, request, &destination); !errors.Is(err, domain.ErrTooLarge) {
		t.Errorf("decodeJSON() error = %v; want too large", err)
	}
}

func newTestHandler(t *testing.T) http.Handler {
	t.Helper()
	return newTestHandlerWithServices(t, &fakeAuthService{
		user: domain.User{CorpID: "corp-id", UserID: "user-id"},
	}, &fakeAttachmentService{})
}

func newTestHandlerWithAuth(t *testing.T, authService *fakeAuthService) http.Handler {
	t.Helper()
	return newTestHandlerWithServices(t, authService, &fakeAttachmentService{})
}

func newTestHandlerWithServices(
	t *testing.T,
	authService *fakeAuthService,
	attachmentService *fakeAttachmentService,
) http.Handler {
	return newTestHandlerWithAllServices(
		t,
		authService,
		attachmentService,
		&fakeApprovalSearchService{},
	)
}

func newTestHandlerWithAllServices(
	t *testing.T,
	authService *fakeAuthService,
	attachmentService *fakeAttachmentService,
	approvalSearchService *fakeApprovalSearchService,
) http.Handler {
	t.Helper()
	handler, err := NewHandler(Options{
		Auth:              authService,
		Attachments:       attachmentService,
		ApprovalSearch:    approvalSearchService,
		Readiness:         fakeReadiness{},
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		ReadinessTimeout:  time.Second,
		RequestsPerMinute: 120,
	})
	if err != nil {
		t.Fatalf("NewHandler() error = %v", err)
	}
	return handler
}

func jsonRequest(t *testing.T, method, path, body string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	return request
}

func authenticatedRequest(
	t *testing.T,
	method string,
	path string,
	body io.Reader,
) *http.Request {
	t.Helper()
	request := httptest.NewRequest(method, path, body)
	request.Header.Set("Authorization", "Bearer access-token")
	return request
}

func assertProblem(
	t *testing.T,
	response *httptest.ResponseRecorder,
	status int,
	code string,
) problem {
	t.Helper()
	if response.Code != status {
		t.Fatalf("status = %d; want %d; body = %s", response.Code, status, response.Body)
	}
	if response.Header().Get("Content-Type") != "application/problem+json" {
		t.Errorf("Content-Type = %q; want application/problem+json", response.Header().Get("Content-Type"))
	}
	var body problem
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if body.Code != code || body.Status != status {
		t.Errorf("problem = %#v; want code %q status %d", body, code, status)
	}
	wantType := "/problems/" + code
	if body.Type != wantType {
		t.Errorf("problem type = %q; want %q", body.Type, wantType)
	}
	return body
}

func attachmentLogRecords(t *testing.T, output string) []map[string]any {
	t.Helper()
	var records []map[string]any
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		var record map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			t.Fatalf("decode structured log: %v", err)
		}
		if event, ok := record["event"].(string); ok &&
			strings.HasPrefix(event, "attachments.") {
			records = append(records, record)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan structured logs: %v", err)
	}
	return records
}

func assertLogFields(t *testing.T, record map[string]any, expected map[string]any) {
	t.Helper()
	for field, want := range expected {
		if got := record[field]; got != want {
			t.Errorf("structured log field %q = %#v; want %#v", field, got, want)
		}
	}
}

type fakeAuthService struct {
	deviceResponse    auth.DeviceAuthorizationResponse
	deviceError       error
	startURL          string
	startError        error
	completeError     error
	rejectState       string
	rejectError       error
	sessionResponse   auth.SessionResponse
	exchangeError     error
	user              domain.User
	authenticateError error
	refreshError      error
	revokeError       error
}

func (fake *fakeAuthService) CreateDeviceAuthorization(
	context.Context,
) (auth.DeviceAuthorizationResponse, error) {
	return fake.deviceResponse, fake.deviceError
}

func (fake *fakeAuthService) StartAuthorization(context.Context, string) (string, error) {
	return fake.startURL, fake.startError
}

func (fake *fakeAuthService) CompleteAuthorization(context.Context, string, string) error {
	return fake.completeError
}

func (fake *fakeAuthService) RejectAuthorization(_ context.Context, state string) error {
	fake.rejectState = state
	return fake.rejectError
}

func (fake *fakeAuthService) ExchangeDeviceAuthorization(
	context.Context,
	string,
) (auth.SessionResponse, error) {
	return fake.sessionResponse, fake.exchangeError
}

func (fake *fakeAuthService) Authenticate(context.Context, string) (domain.User, error) {
	return fake.user, fake.authenticateError
}

func (fake *fakeAuthService) Refresh(context.Context, string) (auth.SessionResponse, error) {
	return fake.sessionResponse, fake.refreshError
}

func (fake *fakeAuthService) Revoke(context.Context, string) error {
	return fake.revokeError
}

type fakeAttachmentService struct {
	list          []domain.Attachment
	listError     error
	listCalls     int
	download      *attachments.Download
	downloadError error
	downloadCalls int
}

type fakeApprovalSearchService struct {
	result          approvals.SearchResult
	err             error
	query           approvals.SearchQuery
	discoveryResult approvals.CategoryDiscoveryResult
	discoveryError  error
	discoveryQuery  approvals.CategoryDiscoveryQuery
	discoveryUser   domain.User
}

func (fake *fakeApprovalSearchService) Search(
	_ context.Context,
	_ domain.User,
	query approvals.SearchQuery,
	_ string,
) (approvals.SearchResult, error) {
	fake.query = query
	return fake.result, fake.err
}

func (fake *fakeApprovalSearchService) VisibleCategories(
	_ context.Context,
	user domain.User,
	query approvals.CategoryDiscoveryQuery,
	_ string,
) (approvals.CategoryDiscoveryResult, error) {
	fake.discoveryUser = user
	fake.discoveryQuery = query
	return fake.discoveryResult, fake.discoveryError
}

func (fake *fakeAttachmentService) List(
	context.Context,
	domain.User,
	string,
	string,
) ([]domain.Attachment, error) {
	fake.listCalls++
	return fake.list, fake.listError
}

func (fake *fakeAttachmentService) Download(
	context.Context,
	domain.User,
	string,
	string,
	string,
) (*attachments.Download, error) {
	fake.downloadCalls++
	return fake.download, fake.downloadError
}

type fakeReadiness struct {
	err error
}

func (fake fakeReadiness) Ping(context.Context) error {
	return fake.err
}

type errorAfterReader struct {
	content   string
	err       error
	delivered bool
}

func (reader *errorAfterReader) Read(buffer []byte) (int, error) {
	if reader.delivered {
		return 0, reader.err
	}
	reader.delivered = true
	return copy(buffer, reader.content), nil
}
