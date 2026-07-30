package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/approvals"
	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/attachments"
	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/auth"
	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/domain"
)

const (
	maxJSONBodyBytes                = 16 * 1024
	defaultRequestsPerMinute        = 120
	requestIDHeader                 = "X-Request-ID"
	problemTypeBaseURL              = "/problems/"
	maxForwardedForBytes            = 4096
	maxForwardedForHops             = 32
	authorizationConfirmationCookie = "dingtalk_oa_start_confirmation"
	maxAuthorizationStartBodyBytes  = 1024
	authorizationConfirmationMaxAge = 5 * time.Minute
)

type AuthService interface {
	CreateDeviceAuthorization(context.Context) (auth.DeviceAuthorizationResponse, error)
	StartAuthorization(context.Context, string) (string, error)
	RejectAuthorization(context.Context, string) error
	CompleteAuthorization(context.Context, string, string) error
	ExchangeDeviceAuthorization(context.Context, string) (auth.SessionResponse, error)
	Authenticate(context.Context, string) (domain.User, error)
	Refresh(context.Context, string) (auth.SessionResponse, error)
	Revoke(context.Context, string) error
}

type AttachmentService interface {
	List(context.Context, domain.User, string, string) ([]domain.Attachment, error)
	Download(context.Context, domain.User, string, string, string) (*attachments.Download, error)
}

type ApprovalSearchService interface {
	VisibleCategories(
		context.Context,
		domain.User,
		approvals.CategoryDiscoveryQuery,
		string,
	) (approvals.CategoryDiscoveryResult, error)
	Search(
		context.Context,
		domain.User,
		approvals.SearchQuery,
		string,
	) (approvals.SearchResult, error)
}

type ReadinessChecker interface {
	Ping(context.Context) error
}

type Options struct {
	Auth              AuthService
	Attachments       AttachmentService
	ApprovalSearch    ApprovalSearchService
	Readiness         ReadinessChecker
	Logger            *slog.Logger
	ReadinessTimeout  time.Duration
	RequestsPerMinute int
	TrustedProxyCIDRs []netip.Prefix
}

type Handler struct {
	auth              AuthService
	attachments       AttachmentService
	approvalSearch    ApprovalSearchService
	readiness         ReadinessChecker
	logger            *slog.Logger
	readinessTimeout  time.Duration
	rateLimiter       *rateLimiter
	trustedProxyCIDRs []netip.Prefix
	metrics           *metrics
}

type requestContextKey string

const requestIDContextKey requestContextKey = "request_id"

const rateLimitRetryAfterSeconds = 60

func NewHandler(options Options) (*Handler, error) {
	if options.Auth == nil {
		return nil, fmt.Errorf("authentication service is required")
	}
	if options.Attachments == nil {
		return nil, fmt.Errorf("attachment service is required")
	}
	if options.ApprovalSearch == nil {
		return nil, fmt.Errorf("approval search service is required")
	}
	if options.Readiness == nil {
		return nil, fmt.Errorf("readiness checker is required")
	}
	logger := options.Logger
	if logger == nil {
		logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}
	readinessTimeout := options.ReadinessTimeout
	if readinessTimeout <= 0 {
		readinessTimeout = 2 * time.Second
	}
	requestsPerMinute := options.RequestsPerMinute
	if requestsPerMinute <= 0 {
		requestsPerMinute = defaultRequestsPerMinute
	}
	registry := prometheus.NewRegistry()
	return &Handler{
		auth:              options.Auth,
		attachments:       options.Attachments,
		approvalSearch:    options.ApprovalSearch,
		readiness:         options.Readiness,
		logger:            logger,
		readinessTimeout:  readinessTimeout,
		rateLimiter:       newRateLimiter(requestsPerMinute, time.Now),
		trustedProxyCIDRs: append([]netip.Prefix(nil), options.TrustedProxyCIDRs...),
		metrics:           newMetrics(registry),
	}, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	startedAt := time.Now()
	requestID := requestIDFromHeader(request.Header.Get(requestIDHeader))
	request = request.WithContext(context.WithValue(
		request.Context(),
		requestIDContextKey,
		requestID,
	))
	response.Header().Set(requestIDHeader, requestID)
	response.Header().Set("X-Content-Type-Options", "nosniff")
	response.Header().Set("Referrer-Policy", "no-referrer")
	response.Header().Set("Cache-Control", "no-store")

	statusResponse := &statusResponseWriter{ResponseWriter: response}
	route := routeLabel(request.URL.Path)
	sourceAddress := handler.clientAddress(request)
	defer func() {
		if statusResponse.status == 0 {
			statusResponse.status = http.StatusOK
		}
		duration := time.Since(startedAt)
		handler.metrics.observeRequest(request.Method, route, statusResponse.status, duration)
		handler.logger.InfoContext(
			request.Context(),
			"HTTP request completed",
			"requestId", requestID,
			"method", request.Method,
			"path", request.URL.Path,
			"route", route,
			"status", statusResponse.status,
			"durationMs", duration.Milliseconds(),
			"remoteAddress", sourceAddress,
		)
	}()

	if shouldRateLimit(request.URL.Path) && !handler.rateLimiter.Allow(sourceAddress) {
		writeProblem(statusResponse, request, domain.ErrRateLimited)
	} else {
		handler.route(statusResponse, request)
	}
}

func (handler *Handler) route(response http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/healthz":
		if !allowMethod(response, request, http.MethodGet) {
			return
		}
		writeJSON(response, http.StatusOK, healthResponse{Status: "ok"})
	case "/readyz":
		if !allowMethod(response, request, http.MethodGet) {
			return
		}
		handler.handleReadiness(response, request)
	case "/api/v1/device-authorizations":
		if !allowMethod(response, request, http.MethodPost) {
			return
		}
		handler.handleCreateDeviceAuthorization(response, request)
	case "/auth/dingtalk/start":
		if !allowMethod(response, request, http.MethodGet, http.MethodPost) {
			return
		}
		if request.Method == http.MethodGet {
			handler.handleAuthorizationStartPage(response, request)
			return
		}
		handler.handleAuthorizationStart(response, request)
	case "/auth/dingtalk/callback":
		if !allowMethod(response, request, http.MethodGet) {
			return
		}
		handler.handleAuthorizationCallback(response, request)
	case "/api/v1/device-authorizations/token":
		if !allowMethod(response, request, http.MethodPost) {
			return
		}
		handler.handleDeviceToken(response, request)
	case "/api/v1/sessions/refresh":
		if !allowMethod(response, request, http.MethodPost) {
			return
		}
		handler.handleRefresh(response, request)
	case "/api/v1/sessions/current":
		if !allowMethod(response, request, http.MethodDelete) {
			return
		}
		handler.handleRevoke(response, request)
	case "/api/v1/me":
		if !allowMethod(response, request, http.MethodGet) {
			return
		}
		handler.handleMe(response, request)
	case "/api/v1/me/approval-categories":
		if !allowMethod(response, request, http.MethodGet) {
			return
		}
		handler.handleUserVisibleApprovalCategories(response, request)
	case "/api/v1/approval-categories":
		if !allowMethod(response, request, http.MethodGet) {
			return
		}
		handler.handleApprovalCategories(response, request)
	case "/api/v1/approvals":
		if !allowMethod(response, request, http.MethodGet) {
			return
		}
		handler.handleApprovalSearch(response, request)
	default:
		if strings.HasPrefix(request.URL.Path, "/api/v1/approvals/") {
			handler.handleApprovalRoute(response, request)
			return
		}
		writeProblem(response, request, domain.ErrNotFound)
	}
}

func (handler *Handler) MetricsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/metrics", handler.metrics.handler)
	return mux
}

func (handler *Handler) handleUserVisibleApprovalCategories(
	response http.ResponseWriter,
	request *http.Request,
) {
	user, _, ok := handler.authenticate(response, request)
	if !ok {
		return
	}
	query, err := parseCategoryDiscoveryQuery(request)
	if err != nil {
		writeProblem(response, request, err)
		return
	}
	result, err := handler.approvalSearch.VisibleCategories(
		request.Context(),
		user,
		query,
		requestID(request.Context()),
	)
	if err != nil {
		writeProblem(response, request, err)
		return
	}
	if result.Categories == nil {
		result.Categories = []approvals.Category{}
	}
	writeJSON(response, http.StatusOK, struct {
		Data approvals.CategoryDiscoveryResult `json:"data"`
	}{
		Data: result,
	})
}

func (handler *Handler) handleApprovalCategories(
	response http.ResponseWriter,
	request *http.Request,
) {
	handler.handleUserVisibleApprovalCategories(response, request)
}

func (handler *Handler) handleApprovalSearch(
	response http.ResponseWriter,
	request *http.Request,
) {
	user, _, ok := handler.authenticate(response, request)
	if !ok {
		return
	}
	query, err := parseApprovalSearchQuery(request)
	if err != nil {
		writeProblem(response, request, err)
		return
	}
	result, err := handler.approvalSearch.Search(
		request.Context(),
		user,
		query,
		requestID(request.Context()),
	)
	if err != nil {
		writeProblem(response, request, err)
		return
	}
	if result.Items == nil {
		result.Items = []approvals.Item{}
	}
	writeJSON(response, http.StatusOK, struct {
		Data approvals.SearchResult `json:"data"`
	}{
		Data: result,
	})
}

func parseApprovalSearchQuery(request *http.Request) (approvals.SearchQuery, error) {
	allowed := map[string]struct{}{
		"category":      {},
		"q":             {},
		"createdAfter":  {},
		"createdBefore": {},
		"cursor":        {},
		"limit":         {},
	}
	values := request.URL.Query()
	for key := range values {
		if _, ok := allowed[key]; !ok {
			return approvals.SearchQuery{}, fmt.Errorf(
				"%w: unsupported approval search parameter %q",
				domain.ErrInvalidInput,
				key,
			)
		}
		if len(values[key]) != 1 {
			return approvals.SearchQuery{}, fmt.Errorf(
				"%w: approval search parameter %q must appear once",
				domain.ErrInvalidInput,
				key,
			)
		}
	}
	result := approvals.SearchQuery{
		CategoryID: strings.TrimSpace(values.Get("category")),
		Keyword:    strings.TrimSpace(values.Get("q")),
		Cursor:     strings.TrimSpace(values.Get("cursor")),
	}
	if _, supplied := values["cursor"]; supplied && result.Cursor == "" {
		return approvals.SearchQuery{}, fmt.Errorf(
			"%w: approval search cursor must not be empty",
			domain.ErrInvalidInput,
		)
	}
	if result.CategoryID == "" {
		return approvals.SearchQuery{}, fmt.Errorf(
			"%w: approval category is required",
			domain.ErrInvalidInput,
		)
	}
	for _, parameter := range []string{"createdAfter", "createdBefore", "limit"} {
		if _, supplied := values[parameter]; supplied && strings.TrimSpace(values.Get(parameter)) == "" {
			return approvals.SearchQuery{}, fmt.Errorf(
				"%w: approval search parameter %q must not be empty",
				domain.ErrInvalidInput,
				parameter,
			)
		}
	}
	if _, supplied := values["q"]; supplied && result.Keyword == "" {
		return approvals.SearchQuery{}, fmt.Errorf(
			"%w: approval search keyword must not be empty",
			domain.ErrInvalidInput,
		)
	}
	if result.Cursor != "" &&
		(result.Keyword != "" ||
			strings.TrimSpace(values.Get("createdAfter")) != "" ||
			strings.TrimSpace(values.Get("createdBefore")) != "") {
		return approvals.SearchQuery{}, fmt.Errorf(
			"%w: approval cursor cannot be combined with keyword or time bounds",
			domain.ErrInvalidInput,
		)
	}
	if raw := strings.TrimSpace(values.Get("createdAfter")); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return approvals.SearchQuery{}, fmt.Errorf(
				"%w: createdAfter must use RFC3339",
				domain.ErrInvalidInput,
			)
		}
		result.CreatedAfter = &parsed
	}
	if raw := strings.TrimSpace(values.Get("createdBefore")); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			return approvals.SearchQuery{}, fmt.Errorf(
				"%w: createdBefore must use RFC3339",
				domain.ErrInvalidInput,
			)
		}
		result.CreatedBefore = &parsed
	}
	if raw := strings.TrimSpace(values.Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil {
			return approvals.SearchQuery{}, fmt.Errorf(
				"%w: approval search limit must be an integer",
				domain.ErrInvalidInput,
			)
		}
		result.Limit = parsed
	}
	return result, nil
}

func parseCategoryDiscoveryQuery(
	request *http.Request,
) (approvals.CategoryDiscoveryQuery, error) {
	allowed := map[string]struct{}{
		"q":      {},
		"cursor": {},
	}
	values := request.URL.Query()
	for key := range values {
		if _, ok := allowed[key]; !ok {
			return approvals.CategoryDiscoveryQuery{}, fmt.Errorf(
				"%w: unsupported approval category parameter %q",
				domain.ErrInvalidInput,
				key,
			)
		}
		if len(values[key]) != 1 {
			return approvals.CategoryDiscoveryQuery{}, fmt.Errorf(
				"%w: approval category parameter %q must appear once",
				domain.ErrInvalidInput,
				key,
			)
		}
	}
	result := approvals.CategoryDiscoveryQuery{
		Keyword: strings.TrimSpace(values.Get("q")),
		Cursor:  strings.TrimSpace(values.Get("cursor")),
	}
	if _, supplied := values["q"]; supplied && result.Keyword == "" {
		return approvals.CategoryDiscoveryQuery{}, fmt.Errorf(
			"%w: approval category keyword must not be empty",
			domain.ErrInvalidInput,
		)
	}
	if _, supplied := values["cursor"]; supplied && result.Cursor == "" {
		return approvals.CategoryDiscoveryQuery{}, fmt.Errorf(
			"%w: approval category cursor must not be empty",
			domain.ErrInvalidInput,
		)
	}
	if result.Cursor != "" && result.Keyword != "" {
		return approvals.CategoryDiscoveryQuery{}, fmt.Errorf(
			"%w: category cursor cannot be combined with keyword",
			domain.ErrInvalidInput,
		)
	}
	return result, nil
}

type healthResponse struct {
	Status string `json:"status"`
}

func (handler *Handler) handleReadiness(response http.ResponseWriter, request *http.Request) {
	if handler.readiness == nil {
		writeProblem(response, request, domain.ErrUnavailable)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), handler.readinessTimeout)
	defer cancel()
	if err := handler.readiness.Ping(ctx); err != nil {
		handler.logger.WarnContext(
			request.Context(),
			"readiness check failed",
			"requestId", requestID(request.Context()),
			"error", err,
		)
		writeProblem(response, request, domain.ErrUnavailable)
		return
	}
	writeJSON(response, http.StatusOK, healthResponse{Status: "ok"})
}

func (handler *Handler) handleCreateDeviceAuthorization(
	response http.ResponseWriter,
	request *http.Request,
) {
	result, err := handler.auth.CreateDeviceAuthorization(request.Context())
	if err != nil {
		writeProblem(response, request, err)
		return
	}
	writeJSON(response, http.StatusCreated, result)
}

func (handler *Handler) handleAuthorizationStartPage(
	response http.ResponseWriter,
	request *http.Request,
) {
	userCode := strings.TrimSpace(request.URL.Query().Get("user_code"))
	if userCode == "" || len(userCode) > 64 {
		writeProblem(
			response,
			request,
			fmt.Errorf("%w: user code is required", domain.ErrInvalidInput),
		)
		return
	}
	confirmation, err := newAuthorizationConfirmation()
	if err != nil {
		writeProblem(response, request, domain.ErrUnavailable)
		return
	}
	http.SetCookie(response, &http.Cookie{
		Name:     authorizationConfirmationCookie,
		Value:    confirmation,
		Path:     "/auth/dingtalk/start",
		MaxAge:   int(authorizationConfirmationMaxAge / time.Second),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	action := html.EscapeString(
		"/auth/dingtalk/start?user_code=" + url.QueryEscape(userCode),
	)
	response.Header().Set(
		"Content-Security-Policy",
		"default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
	)
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	response.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(
		response,
		"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"+
			"<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"+
			"<title>DingTalk authorization</title></head><body><main>"+
			"<h1>DingTalk authorization</h1><form method=\"post\" action=\""+action+"\">"+
			"<input type=\"hidden\" name=\"confirmation\" value=\""+confirmation+"\">"+
			"<button type=\"submit\">Continue to DingTalk</button></form></main></body></html>",
	)
}

func newAuthorizationConfirmation() (string, error) {
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", fmt.Errorf("generate authorization confirmation: %w", err)
	}
	return hex.EncodeToString(random[:]), nil
}

func (handler *Handler) handleAuthorizationStart(
	response http.ResponseWriter,
	request *http.Request,
) {
	request.Body = http.MaxBytesReader(response, request.Body, maxAuthorizationStartBodyBytes)
	if err := request.ParseForm(); err != nil {
		writeProblem(
			response,
			request,
			fmt.Errorf("%w: invalid authorization confirmation", domain.ErrInvalidInput),
		)
		return
	}
	cookie, cookieErr := request.Cookie(authorizationConfirmationCookie)
	confirmation := request.PostForm.Get("confirmation")
	if cookieErr != nil || len(confirmation) != 64 || len(cookie.Value) != 64 || subtle.ConstantTimeCompare(
		[]byte(confirmation),
		[]byte(cookie.Value),
	) != 1 {
		writeProblem(response, request, domain.ErrForbidden)
		return
	}
	authorizationURL, err := handler.auth.StartAuthorization(
		request.Context(),
		request.URL.Query().Get("user_code"),
	)
	if err != nil {
		writeProblem(response, request, err)
		return
	}
	parsed, err := url.Parse(authorizationURL)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" {
		writeProblem(response, request, domain.ErrUpstream)
		return
	}
	http.SetCookie(response, &http.Cookie{
		Name:     authorizationConfirmationCookie,
		Path:     "/auth/dingtalk/start",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(response, request, parsed.String(), http.StatusSeeOther)
}

func (handler *Handler) handleAuthorizationCallback(
	response http.ResponseWriter,
	request *http.Request,
) {
	if request.URL.Query().Get("error") != "" {
		if err := handler.auth.RejectAuthorization(
			request.Context(),
			request.URL.Query().Get("state"),
		); err != nil {
			writeProblem(response, request, err)
			return
		}
		writeProblem(response, request, domain.ErrForbidden)
		return
	}
	if err := handler.auth.CompleteAuthorization(
		request.Context(),
		request.URL.Query().Get("state"),
		request.URL.Query().Get("code"),
	); err != nil {
		writeProblem(response, request, err)
		return
	}
	response.Header().Set(
		"Content-Security-Policy",
		"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'",
	)
	response.Header().Set("Content-Type", "text/html; charset=utf-8")
	response.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(
		response,
		"<!doctype html><html><head><meta charset=\"utf-8\"><title>Authorization complete</title></head>"+
			"<body><main><h1>Authorization complete</h1><p>You may return to the requesting client.</p></main></body></html>",
	)
}

func (handler *Handler) handleDeviceToken(response http.ResponseWriter, request *http.Request) {
	var input struct {
		DeviceCode string `json:"deviceCode"`
	}
	if err := decodeJSON(response, request, &input); err != nil {
		writeProblem(response, request, err)
		return
	}
	result, err := handler.auth.ExchangeDeviceAuthorization(request.Context(), input.DeviceCode)
	if err != nil {
		writeProblem(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (handler *Handler) handleRefresh(response http.ResponseWriter, request *http.Request) {
	var input struct {
		RefreshToken string `json:"refreshToken"`
	}
	if err := decodeJSON(response, request, &input); err != nil {
		writeProblem(response, request, err)
		return
	}
	result, err := handler.auth.Refresh(request.Context(), input.RefreshToken)
	if err != nil {
		writeProblem(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, result)
}

func (handler *Handler) handleRevoke(response http.ResponseWriter, request *http.Request) {
	_, accessToken, ok := handler.authenticate(response, request)
	if !ok {
		return
	}
	if err := handler.auth.Revoke(request.Context(), accessToken); err != nil {
		writeProblem(response, request, err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (handler *Handler) handleMe(response http.ResponseWriter, request *http.Request) {
	user, _, ok := handler.authenticate(response, request)
	if !ok {
		return
	}
	writeJSON(response, http.StatusOK, struct {
		Data userResponse `json:"data"`
	}{
		Data: mapUser(user),
	})
}

type userResponse struct {
	CorpID      string `json:"corpId"`
	UserID      string `json:"userId"`
	UnionID     string `json:"unionId"`
	DisplayName string `json:"displayName"`
}

func mapUser(user domain.User) userResponse {
	return userResponse{
		CorpID:      user.CorpID,
		UserID:      user.UserID,
		UnionID:     user.UnionID,
		DisplayName: user.DisplayName,
	}
}

func (handler *Handler) handleApprovalRoute(
	response http.ResponseWriter,
	request *http.Request,
) {
	relative := strings.TrimPrefix(request.URL.Path, "/api/v1/approvals/")
	segments := strings.Split(relative, "/")
	if len(segments) == 2 && segments[1] == "attachments" {
		if !validResourceID(segments[0]) {
			writeProblem(response, request, domain.ErrNotFound)
			return
		}
		if !allowMethod(response, request, http.MethodGet) {
			return
		}
		handler.handleListAttachments(response, request, segments[0])
		return
	}
	if len(segments) == 4 && segments[1] == "attachments" && segments[3] == "content" {
		if !validResourceID(segments[0]) || !validResourceID(segments[2]) {
			writeProblem(response, request, domain.ErrNotFound)
			return
		}
		if !allowMethod(response, request, http.MethodGet) {
			return
		}
		handler.handleDownload(response, request, segments[0], segments[2])
		return
	}
	writeProblem(response, request, domain.ErrNotFound)
}

func (handler *Handler) handleListAttachments(
	response http.ResponseWriter,
	request *http.Request,
	processInstanceID string,
) {
	user, _, ok := handler.authenticate(response, request)
	if !ok {
		return
	}
	normalizedProcessInstanceID, err := domain.NormalizeProcessInstanceID(
		processInstanceID,
	)
	if err != nil {
		writeProblem(response, request, err)
		return
	}
	processInstanceID = normalizedProcessInstanceID
	startedAt := time.Now()
	result, err := handler.attachments.List(
		request.Context(),
		user,
		processInstanceID,
		requestID(request.Context()),
	)
	if err != nil {
		handler.logAttachmentOperation(
			request.Context(),
			slog.LevelWarn,
			user,
			"attachments.list",
			"failure",
			processInstanceID,
			"",
			startedAt,
			slog.String("errorClass", errorCode(err)),
		)
		writeProblem(response, request, err)
		return
	}
	if result == nil {
		result = []domain.Attachment{}
	}
	handler.logAttachmentOperation(
		request.Context(),
		slog.LevelInfo,
		user,
		"attachments.list",
		"success",
		processInstanceID,
		"",
		startedAt,
		slog.Int("attachmentCount", len(result)),
	)
	writeJSON(response, http.StatusOK, struct {
		Data struct {
			ProcessInstanceID string              `json:"processInstanceId"`
			Attachments       []domain.Attachment `json:"attachments"`
		} `json:"data"`
	}{
		Data: struct {
			ProcessInstanceID string              `json:"processInstanceId"`
			Attachments       []domain.Attachment `json:"attachments"`
		}{
			ProcessInstanceID: processInstanceID,
			Attachments:       result,
		},
	})
}

func (handler *Handler) handleDownload(
	response http.ResponseWriter,
	request *http.Request,
	processInstanceID string,
	fileID string,
) {
	user, _, ok := handler.authenticate(response, request)
	if !ok {
		return
	}
	normalizedProcessInstanceID, err := domain.NormalizeProcessInstanceID(
		processInstanceID,
	)
	if err != nil {
		writeProblem(response, request, err)
		return
	}
	processInstanceID = normalizedProcessInstanceID
	startedAt := time.Now()
	download, err := handler.attachments.Download(
		request.Context(),
		user,
		processInstanceID,
		fileID,
		requestID(request.Context()),
	)
	if err != nil {
		handler.logAttachmentOperation(
			request.Context(),
			slog.LevelWarn,
			user,
			"attachments.download",
			"failure",
			processInstanceID,
			fileID,
			startedAt,
			slog.String("errorClass", errorCode(err)),
		)
		writeProblem(response, request, err)
		return
	}
	if download == nil || download.Body == nil {
		handler.logAttachmentOperation(
			request.Context(),
			slog.LevelWarn,
			user,
			"attachments.download",
			"failure",
			processInstanceID,
			fileID,
			startedAt,
			slog.String("errorClass", errorCode(domain.ErrUpstream)),
		)
		writeProblem(response, request, domain.ErrUpstream)
		return
	}
	defer download.Body.Close()

	response.Header().Set("Content-Type", "application/octet-stream")
	response.Header().Set(
		"Content-Disposition",
		contentDisposition(download.Attachment.FileName),
	)
	if download.ContentLength >= 0 {
		response.Header().Set("Content-Length", strconv.FormatInt(download.ContentLength, 10))
	}
	response.WriteHeader(http.StatusOK)
	written, streamError := io.Copy(response, download.Body)
	handler.metrics.downloadBytes.Add(float64(written))
	if streamError != nil {
		handler.metrics.downloadErrors.Inc()
		handler.logAttachmentOperation(
			request.Context(),
			slog.LevelWarn,
			user,
			"attachments.download",
			"failure",
			processInstanceID,
			fileID,
			startedAt,
			slog.Int64("bytesWritten", written),
			slog.Int64("contentLength", download.ContentLength),
			slog.String("errorClass", errorCode(streamError)),
		)
		panic(http.ErrAbortHandler)
	}
	handler.logAttachmentOperation(
		request.Context(),
		slog.LevelInfo,
		user,
		"attachments.download",
		"success",
		processInstanceID,
		fileID,
		startedAt,
		slog.Int64("bytesWritten", written),
		slog.Int64("contentLength", download.ContentLength),
	)
}

func (handler *Handler) logAttachmentOperation(
	ctx context.Context,
	level slog.Level,
	user domain.User,
	event string,
	outcome string,
	processInstanceID string,
	fileID string,
	startedAt time.Time,
	additionalAttributes ...slog.Attr,
) {
	attributes := []slog.Attr{
		slog.String("event", event),
		slog.String("outcome", outcome),
		slog.String("requestId", requestID(ctx)),
		slog.String("corpId", user.CorpID),
		slog.String("actorUserId", user.UserID),
		slog.String("processInstanceId", processInstanceID),
		slog.Int64("durationMs", time.Since(startedAt).Milliseconds()),
	}
	if fileID != "" {
		attributes = append(attributes, slog.String("fileId", fileID))
	}
	attributes = append(attributes, additionalAttributes...)
	handler.logger.LogAttrs(
		ctx,
		level,
		"attachment API operation completed",
		attributes...,
	)
}

func (handler *Handler) authenticate(
	response http.ResponseWriter,
	request *http.Request,
) (domain.User, string, bool) {
	accessToken, ok := bearerToken(request.Header.Get("Authorization"))
	if !ok {
		response.Header().Set("WWW-Authenticate", "Bearer")
		writeProblem(response, request, domain.ErrUnauthorized)
		return domain.User{}, "", false
	}
	user, err := handler.auth.Authenticate(request.Context(), accessToken)
	if err != nil {
		if errors.Is(err, domain.ErrUnauthorized) {
			response.Header().Set("WWW-Authenticate", "Bearer")
		}
		writeProblem(response, request, err)
		return domain.User{}, "", false
	}
	return user, accessToken, true
}

func bearerToken(authorization string) (string, bool) {
	parts := strings.Fields(authorization)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

func decodeJSON(response http.ResponseWriter, request *http.Request, destination any) error {
	contentType := request.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil || mediaType != "application/json" {
		return fmt.Errorf("%w: Content-Type must be application/json", domain.ErrInvalidInput)
	}
	request.Body = http.MaxBytesReader(response, request.Body, maxJSONBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			return fmt.Errorf("%w: decode JSON request", domain.ErrTooLarge)
		}
		return fmt.Errorf("%w: decode JSON request", domain.ErrInvalidInput)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: request must contain one JSON object", domain.ErrInvalidInput)
	}
	return nil
}

func allowMethod(
	response http.ResponseWriter,
	request *http.Request,
	methods ...string,
) bool {
	for _, method := range methods {
		if request.Method == method {
			return true
		}
	}
	response.Header().Set("Allow", strings.Join(methods, ", "))
	writeProblemSpec(response, request, problemSpec{
		Status: http.StatusMethodNotAllowed,
		Code:   "method_not_allowed",
		Title:  "Method Not Allowed",
		Detail: "The requested method is not allowed for this resource.",
	})
	return false
}

type problem struct {
	Type      string `json:"type"`
	Title     string `json:"title"`
	Status    int    `json:"status"`
	Detail    string `json:"detail"`
	Instance  string `json:"instance"`
	Code      string `json:"code"`
	RequestID string `json:"requestId"`
}

type problemSpec struct {
	Status int
	Code   string
	Title  string
	Detail string
}

func writeProblem(response http.ResponseWriter, request *http.Request, err error) {
	if errors.Is(err, domain.ErrRateLimited) {
		response.Header().Set("Retry-After", strconv.Itoa(rateLimitRetryAfterSeconds))
	}
	writeProblemSpec(response, request, problemForError(err))
}

func writeProblemSpec(
	response http.ResponseWriter,
	request *http.Request,
	specification problemSpec,
) {
	response.Header().Set("Content-Type", "application/problem+json")
	response.WriteHeader(specification.Status)
	_ = json.NewEncoder(response).Encode(problem{
		Type:      problemTypeBaseURL + specification.Code,
		Title:     specification.Title,
		Status:    specification.Status,
		Detail:    specification.Detail,
		Instance:  request.URL.Path,
		Code:      specification.Code,
		RequestID: requestID(request.Context()),
	})
}

func problemForError(err error) problemSpec {
	switch {
	case errors.Is(err, domain.ErrInvalidInput):
		return problemSpec{400, "invalid_request", "Invalid Request", "The request is invalid."}
	case errors.Is(err, domain.ErrUnauthorized):
		return problemSpec{401, "unauthorized", "Unauthorized", "A valid bearer token is required."}
	case errors.Is(err, domain.ErrForbidden):
		return problemSpec{403, "forbidden", "Forbidden", "Access to this resource is denied."}
	case errors.Is(err, domain.ErrNotFound):
		return problemSpec{404, "not_found", "Not Found", "The requested resource was not found."}
	case errors.Is(err, domain.ErrConflict), errors.Is(err, domain.ErrAlreadyUsed):
		return problemSpec{409, "conflict", "Conflict", "The request conflicts with current state."}
	case errors.Is(err, domain.ErrExpired):
		return problemSpec{410, "expired", "Expired", "The authorization has expired."}
	case errors.Is(err, domain.ErrAuthorizationPending):
		return problemSpec{428, "authorization_pending", "Authorization Pending", "User authorization is still pending."}
	case errors.Is(err, domain.ErrRateLimited):
		return problemSpec{429, "rate_limited", "Too Many Requests", "The request rate limit was exceeded."}
	case errors.Is(err, domain.ErrTooLarge):
		return problemSpec{413, "payload_too_large", "Payload Too Large", "The attachment exceeds the configured limit."}
	case errors.Is(err, domain.ErrUpstream):
		return problemSpec{502, "upstream_error", "Bad Gateway", "The DingTalk upstream request failed."}
	case errors.Is(err, domain.ErrUnavailable):
		return problemSpec{503, "service_unavailable", "Service Unavailable", "The service is temporarily unavailable."}
	default:
		return problemSpec{500, "internal_error", "Internal Server Error", "An unexpected error occurred."}
	}
}

func writeJSON(response http.ResponseWriter, status int, body any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(body)
}

func requestIDFromHeader(candidate string) string {
	candidate = strings.TrimSpace(candidate)
	if validRequestID(candidate) {
		return candidate
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err == nil {
		return hex.EncodeToString(random[:])
	}
	return strconv.FormatInt(time.Now().UnixNano(), 36)
}

func validRequestID(candidate string) bool {
	if len(candidate) == 0 || len(candidate) > 128 {
		return false
	}
	for _, character := range candidate {
		if !unicode.IsLetter(character) && !unicode.IsDigit(character) &&
			character != '-' && character != '_' && character != '.' {
			return false
		}
	}
	return true
}

func requestID(ctx context.Context) string {
	value, _ := ctx.Value(requestIDContextKey).(string)
	return value
}

func validResourceID(value string) bool {
	if len(value) == 0 || len(value) > 512 {
		return false
	}
	for _, character := range value {
		if unicode.IsSpace(character) || unicode.IsControl(character) ||
			character == '/' || character == '\\' {
			return false
		}
	}
	return true
}

func contentDisposition(filename string) string {
	filename = attachments.SanitizeFilename(filename)
	var fallback strings.Builder
	for _, character := range filename {
		if character >= 0x20 && character <= 0x7e && character != '"' && character != '\\' {
			fallback.WriteRune(character)
		} else {
			fallback.WriteByte('_')
		}
	}
	encoded := url.PathEscape(filename)
	return fmt.Sprintf(
		"attachment; filename=\"%s\"; filename*=UTF-8''%s",
		fallback.String(),
		encoded,
	)
}

func routeLabel(path string) string {
	switch path {
	case "/healthz", "/readyz",
		"/api/v1/device-authorizations",
		"/auth/dingtalk/start",
		"/auth/dingtalk/callback",
		"/api/v1/device-authorizations/token",
		"/api/v1/sessions/refresh",
		"/api/v1/sessions/current",
		"/api/v1/me",
		"/api/v1/me/approval-categories",
		"/api/v1/approval-categories",
		"/api/v1/approvals":
		return path
	}
	if strings.HasPrefix(path, "/api/v1/approvals/") {
		segments := strings.Split(strings.TrimPrefix(path, "/api/v1/approvals/"), "/")
		if len(segments) == 2 && segments[1] == "attachments" {
			return "/api/v1/approvals/{processInstanceId}/attachments"
		}
		if len(segments) == 4 && segments[1] == "attachments" && segments[3] == "content" {
			return "/api/v1/approvals/{processInstanceId}/attachments/{fileId}/content"
		}
	}
	return "unmatched"
}

func shouldRateLimit(path string) bool {
	return path != "/healthz"
}

func (handler *Handler) clientAddress(request *http.Request) string {
	directAddress := directClientAddress(request.RemoteAddr)
	peer, err := netip.ParseAddr(directAddress)
	if err != nil || !containsAddress(handler.trustedProxyCIDRs, peer.Unmap()) {
		return directAddress
	}

	forwarded := strings.Join(request.Header.Values("X-Forwarded-For"), ",")
	if forwarded == "" || len(forwarded) > maxForwardedForBytes {
		return directAddress
	}
	chain := strings.Split(forwarded, ",")
	if len(chain) > maxForwardedForHops {
		return directAddress
	}

	client := peer.Unmap()
	for index := len(chain) - 1; index >= 0; index-- {
		address, parseErr := netip.ParseAddr(strings.TrimSpace(chain[index]))
		if parseErr != nil {
			return directAddress
		}
		client = address.Unmap()
		if !containsAddress(handler.trustedProxyCIDRs, client) {
			return client.String()
		}
	}
	return client.String()
}

func directClientAddress(remoteAddress string) string {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err == nil {
		return host
	}
	return remoteAddress
}

func containsAddress(prefixes []netip.Prefix, address netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func errorCode(err error) string {
	return problemForError(err).Code
}

func metricMethod(method string) string {
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodDelete:
		return method
	default:
		return "other"
	}
}

type statusResponseWriter struct {
	http.ResponseWriter
	status int
}

func (writer *statusResponseWriter) WriteHeader(status int) {
	if writer.status != 0 {
		return
	}
	writer.status = status
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *statusResponseWriter) Write(body []byte) (int, error) {
	if writer.status == 0 {
		writer.WriteHeader(http.StatusOK)
	}
	return writer.ResponseWriter.Write(body)
}

func (writer *statusResponseWriter) Unwrap() http.ResponseWriter {
	return writer.ResponseWriter
}

type metrics struct {
	handler        http.Handler
	requests       *prometheus.CounterVec
	duration       *prometheus.HistogramVec
	downloadBytes  prometheus.Counter
	downloadErrors prometheus.Counter
}

func newMetrics(registry *prometheus.Registry) *metrics {
	result := &metrics{
		requests: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "broker_http_requests_total",
				Help: "Total HTTP requests handled by the broker.",
			},
			[]string{"method", "route", "status"},
		),
		duration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "broker_http_request_duration_seconds",
				Help:    "HTTP request latency in seconds.",
				Buckets: prometheus.DefBuckets,
			},
			[]string{"method", "route"},
		),
		downloadBytes: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "broker_attachment_download_bytes_total",
			Help: "Attachment bytes streamed to authenticated clients.",
		}),
		downloadErrors: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "broker_attachment_stream_errors_total",
			Help: "Attachment streams that failed after response headers were sent.",
		}),
	}
	registry.MustRegister(
		result.requests,
		result.duration,
		result.downloadBytes,
		result.downloadErrors,
	)
	result.handler = promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	return result
}

func (metrics *metrics) observeRequest(
	method string,
	route string,
	status int,
	duration time.Duration,
) {
	method = metricMethod(method)
	metrics.requests.WithLabelValues(method, route, strconv.Itoa(status)).Inc()
	metrics.duration.WithLabelValues(method, route).Observe(duration.Seconds())
}
