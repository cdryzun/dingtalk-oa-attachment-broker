package config

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/domain"
)

const (
	defaultHTTPAddress                     = ":8080"
	defaultMetricsAddress                  = ":9090"
	defaultReadHeaderTimeout               = 5 * time.Second
	defaultReadTimeout                     = 15 * time.Second
	defaultIdleTimeout                     = 60 * time.Second
	defaultShutdownTimeout                 = 15 * time.Second
	defaultDeviceCodeTTL                   = 10 * time.Minute
	defaultAccessTokenTTL                  = 8 * time.Hour
	defaultRefreshTokenTTL                 = 30 * 24 * time.Hour
	defaultAuthPollInterval                = 5 * time.Second
	defaultUpstreamTimeout                 = 30 * time.Second
	defaultDownloadTimeout                 = 10 * time.Minute
	defaultDownloadMaxBytes          int64 = 200 * 1024 * 1024
	defaultDownloadConcurrency             = 5
	defaultReadinessTimeout                = 2 * time.Second
	defaultAuditRetention                  = 180 * 24 * time.Hour
	defaultAuthRecordRetention             = 7 * 24 * time.Hour
	defaultRequestsPerMinute               = 120
	defaultApprovalSearchConcurrency       = 4
	defaultApprovalSearchRate              = 6
	defaultOAuthAuthorizeURL               = "https://login.dingtalk.com/oauth2/auth"
	defaultDingTalkAPIEndpoint             = "api.dingtalk.com"
	defaultDingTalkOAPIBaseURL             = "https://oapi.dingtalk.com"
)

type Config struct {
	HTTPAddress                string
	MetricsAddress             string
	PublicBaseURL              *url.URL
	ReadHeaderTimeout          time.Duration
	ReadTimeout                time.Duration
	IdleTimeout                time.Duration
	ShutdownTimeout            time.Duration
	ReadinessTimeout           time.Duration
	DeviceCodeTTL              time.Duration
	AccessTokenTTL             time.Duration
	RefreshTokenTTL            time.Duration
	AuthPollInterval           time.Duration
	UpstreamTimeout            time.Duration
	DownloadTimeout            time.Duration
	DownloadMaxBytes           int64
	DownloadConcurrencyPerUser int
	AuditRetention             time.Duration
	AuthRecordRetention        time.Duration
	RequestsPerMinute          int
	TrustedProxyCIDRs          []netip.Prefix
	ApprovalSearchConcurrency  int
	ApprovalSearchRate         int
	DingTalkClientID           string
	DingTalkClientSecret       string
	DingTalkCorpID             string
	DingTalkOAuthAuthorizeURL  *url.URL
	DingTalkAPIEndpoint        string
	DingTalkOAPIBaseURL        *url.URL
	DatabaseURL                string
	TokenPepper                string
	AdminUserIDs               map[string]struct{}
}

func Load() (Config, error) {
	httpAddress := valueOrDefault("HTTP_ADDRESS", defaultHTTPAddress)
	if err := validateAddress(httpAddress); err != nil {
		return Config{}, fmt.Errorf("validate HTTP_ADDRESS: %w", err)
	}
	metricsAddress := valueOrDefault("METRICS_ADDRESS", defaultMetricsAddress)
	if err := validateAddress(metricsAddress); err != nil {
		return Config{}, fmt.Errorf("validate METRICS_ADDRESS: %w", err)
	}

	publicBaseURL, err := parsePublicBaseURL(requiredValue("PUBLIC_BASE_URL"))
	if err != nil {
		return Config{}, fmt.Errorf("validate PUBLIC_BASE_URL: %w", err)
	}

	clientID, err := required("DINGTALK_CLIENT_ID")
	if err != nil {
		return Config{}, err
	}
	clientSecret, err := required("DINGTALK_CLIENT_SECRET")
	if err != nil {
		return Config{}, err
	}
	corpID, err := required("DINGTALK_CORP_ID")
	if err != nil {
		return Config{}, err
	}
	databaseURL, err := required("DATABASE_URL")
	if err != nil {
		return Config{}, err
	}
	if err := validateDatabaseURL(databaseURL); err != nil {
		return Config{}, fmt.Errorf("validate DATABASE_URL: %w", err)
	}
	tokenPepper, err := required("TOKEN_PEPPER")
	if err != nil {
		return Config{}, err
	}
	if len(tokenPepper) < 32 {
		return Config{}, fmt.Errorf("validate TOKEN_PEPPER: must contain at least 32 bytes")
	}

	oauthAuthorizeURL, err := parseHTTPSURL(
		"DINGTALK_OAUTH_AUTHORIZE_URL",
		valueOrDefault("DINGTALK_OAUTH_AUTHORIZE_URL", defaultOAuthAuthorizeURL),
	)
	if err != nil {
		return Config{}, err
	}
	oapiBaseURL, err := parseHTTPSURL(
		"DINGTALK_OAPI_BASE_URL",
		valueOrDefault("DINGTALK_OAPI_BASE_URL", defaultDingTalkOAPIBaseURL),
	)
	if err != nil {
		return Config{}, err
	}
	apiEndpoint := valueOrDefault("DINGTALK_API_ENDPOINT", defaultDingTalkAPIEndpoint)
	if err := validateEndpoint(apiEndpoint); err != nil {
		return Config{}, fmt.Errorf("validate DINGTALK_API_ENDPOINT: %w", err)
	}

	readHeaderTimeout, err := positiveDuration(
		"HTTP_READ_HEADER_TIMEOUT",
		defaultReadHeaderTimeout,
	)
	if err != nil {
		return Config{}, err
	}
	readTimeout, err := positiveDuration("HTTP_READ_TIMEOUT", defaultReadTimeout)
	if err != nil {
		return Config{}, err
	}
	idleTimeout, err := positiveDuration("HTTP_IDLE_TIMEOUT", defaultIdleTimeout)
	if err != nil {
		return Config{}, err
	}
	shutdownTimeout, err := positiveDuration("SHUTDOWN_TIMEOUT", defaultShutdownTimeout)
	if err != nil {
		return Config{}, err
	}
	readinessTimeout, err := positiveDuration("READINESS_TIMEOUT", defaultReadinessTimeout)
	if err != nil {
		return Config{}, err
	}
	deviceCodeTTL, err := positiveDuration("DEVICE_CODE_TTL", defaultDeviceCodeTTL)
	if err != nil {
		return Config{}, err
	}
	accessTokenTTL, err := positiveDuration("ACCESS_TOKEN_TTL", defaultAccessTokenTTL)
	if err != nil {
		return Config{}, err
	}
	refreshTokenTTL, err := positiveDuration("REFRESH_TOKEN_TTL", defaultRefreshTokenTTL)
	if err != nil {
		return Config{}, err
	}
	authPollInterval, err := positiveDuration("AUTH_POLL_INTERVAL", defaultAuthPollInterval)
	if err != nil {
		return Config{}, err
	}
	upstreamTimeout, err := positiveDuration("UPSTREAM_TIMEOUT", defaultUpstreamTimeout)
	if err != nil {
		return Config{}, err
	}
	downloadTimeout, err := positiveDuration("DOWNLOAD_TIMEOUT", defaultDownloadTimeout)
	if err != nil {
		return Config{}, err
	}
	auditRetention, err := positiveDuration("AUDIT_RETENTION", defaultAuditRetention)
	if err != nil {
		return Config{}, err
	}
	authRecordRetention, err := positiveDuration(
		"AUTH_RECORD_RETENTION",
		defaultAuthRecordRetention,
	)
	if err != nil {
		return Config{}, err
	}
	downloadMaxBytes, err := positiveInt64("DOWNLOAD_MAX_BYTES", defaultDownloadMaxBytes)
	if err != nil {
		return Config{}, err
	}
	downloadConcurrency, err := positiveInt(
		"DOWNLOAD_CONCURRENCY_PER_USER",
		defaultDownloadConcurrency,
	)
	if err != nil {
		return Config{}, err
	}
	requestsPerMinute, err := positiveInt("REQUESTS_PER_MINUTE", defaultRequestsPerMinute)
	if err != nil {
		return Config{}, err
	}
	trustedProxyCIDRs, err := parseCIDRs("TRUSTED_PROXY_CIDRS", os.Getenv("TRUSTED_PROXY_CIDRS"))
	if err != nil {
		return Config{}, err
	}
	approvalSearchConcurrency, err := positiveInt(
		"APPROVAL_SEARCH_CONCURRENCY",
		defaultApprovalSearchConcurrency,
	)
	if err != nil {
		return Config{}, err
	}
	if approvalSearchConcurrency > domain.MaxApprovalSearchPageSize {
		return Config{}, fmt.Errorf(
			"validate APPROVAL_SEARCH_CONCURRENCY: value must not exceed %d",
			domain.MaxApprovalSearchPageSize,
		)
	}
	approvalSearchRate, err := positiveInt(
		"APPROVAL_SEARCH_REQUESTS_PER_MINUTE",
		defaultApprovalSearchRate,
	)
	if err != nil {
		return Config{}, err
	}
	return Config{
		HTTPAddress:                httpAddress,
		MetricsAddress:             metricsAddress,
		PublicBaseURL:              publicBaseURL,
		ReadHeaderTimeout:          readHeaderTimeout,
		ReadTimeout:                readTimeout,
		IdleTimeout:                idleTimeout,
		ShutdownTimeout:            shutdownTimeout,
		ReadinessTimeout:           readinessTimeout,
		DeviceCodeTTL:              deviceCodeTTL,
		AccessTokenTTL:             accessTokenTTL,
		RefreshTokenTTL:            refreshTokenTTL,
		AuthPollInterval:           authPollInterval,
		UpstreamTimeout:            upstreamTimeout,
		DownloadTimeout:            downloadTimeout,
		DownloadMaxBytes:           downloadMaxBytes,
		DownloadConcurrencyPerUser: downloadConcurrency,
		AuditRetention:             auditRetention,
		AuthRecordRetention:        authRecordRetention,
		RequestsPerMinute:          requestsPerMinute,
		TrustedProxyCIDRs:          trustedProxyCIDRs,
		ApprovalSearchConcurrency:  approvalSearchConcurrency,
		ApprovalSearchRate:         approvalSearchRate,
		DingTalkClientID:           clientID,
		DingTalkClientSecret:       clientSecret,
		DingTalkCorpID:             corpID,
		DingTalkOAuthAuthorizeURL:  oauthAuthorizeURL,
		DingTalkAPIEndpoint:        apiEndpoint,
		DingTalkOAPIBaseURL:        oapiBaseURL,
		DatabaseURL:                databaseURL,
		TokenPepper:                tokenPepper,
		AdminUserIDs:               parseSet(os.Getenv("DINGTALK_ADMIN_USER_IDS")),
	}, nil
}

func LoadDatabaseURL() (string, error) {
	databaseURL, err := required("DATABASE_URL")
	if err != nil {
		return "", err
	}
	if err := validateDatabaseURL(databaseURL); err != nil {
		return "", fmt.Errorf("validate DATABASE_URL: %w", err)
	}
	return databaseURL, nil
}

func valueOrDefault(key, defaultValue string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return defaultValue
}

func requiredValue(key string) string {
	return strings.TrimSpace(os.Getenv(key))
}

func required(key string) (string, error) {
	value := requiredValue(key)
	if value == "" {
		return "", fmt.Errorf("validate %s: value is required", key)
	}
	return value, nil
}

func positiveDuration(key string, defaultValue time.Duration) (time.Duration, error) {
	raw := valueOrDefault(key, defaultValue.String())
	value, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}
	if value <= 0 {
		return 0, fmt.Errorf("validate %s: duration must be positive", key)
	}
	return value, nil
}

func positiveInt64(key string, defaultValue int64) (int64, error) {
	raw := valueOrDefault(key, strconv.FormatInt(defaultValue, 10))
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", key, err)
	}
	if value <= 0 {
		return 0, fmt.Errorf("validate %s: value must be positive", key)
	}
	return value, nil
}

func positiveInt(key string, defaultValue int) (int, error) {
	value, err := positiveInt64(key, int64(defaultValue))
	if err != nil {
		return 0, err
	}
	maxInt := int64(^uint(0) >> 1)
	if value > maxInt {
		return 0, fmt.Errorf("validate %s: value is too large", key)
	}
	return int(value), nil
}

func validateAddress(address string) error {
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("split host and port: %w", err)
	}
	if port == "" {
		return fmt.Errorf("port is required")
	}
	if _, err := net.LookupPort("tcp", port); err != nil {
		return fmt.Errorf("validate port %q: %w", port, err)
	}
	return nil
}

func parsePublicBaseURL(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, fmt.Errorf("value is required")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse URL: %w", err)
	}
	if parsed.Host == "" || parsed.Hostname() == "" {
		return nil, fmt.Errorf("absolute URL is required")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("credentials, query, and fragment are not allowed")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return nil, fmt.Errorf("path must be empty")
	}
	if parsed.Scheme != "https" && !(parsed.Scheme == "http" && isLoopbackHost(parsed.Hostname())) {
		return nil, fmt.Errorf("HTTPS is required except for loopback development")
	}
	parsed.Path = ""
	return parsed, nil
}

func parseHTTPSURL(key, raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", key, err)
	}
	if parsed.Scheme != "https" || parsed.Hostname() == "" {
		return nil, fmt.Errorf("validate %s: absolute HTTPS URL is required", key)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf(
			"validate %s: credentials, query, and fragment are not allowed",
			key,
		)
	}
	return parsed, nil
}

func validateDatabaseURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse URL: %w", err)
	}
	if parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" {
		return fmt.Errorf("PostgreSQL URL is required")
	}
	if parsed.Hostname() == "" || strings.Trim(parsed.Path, "/") == "" {
		return fmt.Errorf("host and database name are required")
	}
	return nil
}

func validateEndpoint(endpoint string) error {
	if strings.ContainsAny(endpoint, "/?#@") {
		return fmt.Errorf("host name without scheme or path is required")
	}
	if endpoint == "" {
		return fmt.Errorf("host name is required")
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func parseCIDRs(key, raw string) ([]netip.Prefix, error) {
	var result []netip.Prefix
	for _, part := range strings.Split(raw, ",") {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("validate %s: invalid CIDR %q", key, value)
		}
		result = append(result, prefix.Masked())
	}
	return result, nil
}

func parseSet(raw string) map[string]struct{} {
	result := make(map[string]struct{})
	for _, part := range strings.Split(raw, ",") {
		value := strings.TrimSpace(part)
		if value != "" {
			result[value] = struct{}{}
		}
	}
	return result
}
