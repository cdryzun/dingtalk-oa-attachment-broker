package config

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestLoadUsesSecureDefaults(t *testing.T) {
	setValidEnvironment(t)
	t.Setenv("HTTP_ADDRESS", "")
	t.Setenv("METRICS_ADDRESS", "")
	t.Setenv("HTTP_READ_HEADER_TIMEOUT", "")
	t.Setenv("HTTP_READ_TIMEOUT", "")
	t.Setenv("HTTP_IDLE_TIMEOUT", "")
	t.Setenv("SHUTDOWN_TIMEOUT", "")
	t.Setenv("DEVICE_CODE_TTL", "")
	t.Setenv("ACCESS_TOKEN_TTL", "")
	t.Setenv("REFRESH_TOKEN_TTL", "")
	t.Setenv("DOWNLOAD_TIMEOUT", "")
	t.Setenv("DOWNLOAD_MAX_BYTES", "")
	t.Setenv("DOWNLOAD_CONCURRENCY_PER_USER", "")
	t.Setenv("AUDIT_RETENTION", "")
	t.Setenv("AUTH_RECORD_RETENTION", "")
	t.Setenv("REQUESTS_PER_MINUTE", "")
	t.Setenv("APPROVAL_SEARCH_CONCURRENCY", "")
	t.Setenv("APPROVAL_SEARCH_REQUESTS_PER_MINUTE", "")
	t.Setenv("DINGTALK_ADMIN_USER_IDS", " admin-1,admin-2,admin-1 ")
	t.Setenv("TRUSTED_PROXY_CIDRS", "")

	got, err := Load()
	if err != nil {
		t.Fatalf("Load() returned an unexpected error: %v", err)
	}

	assertEqual(t, got.HTTPAddress, ":8080")
	assertEqual(t, got.MetricsAddress, ":9090")
	assertEqual(t, got.ReadHeaderTimeout, 5*time.Second)
	assertEqual(t, got.ReadTimeout, 15*time.Second)
	assertEqual(t, got.IdleTimeout, 60*time.Second)
	assertEqual(t, got.ShutdownTimeout, 15*time.Second)
	assertEqual(t, got.DeviceCodeTTL, 10*time.Minute)
	assertEqual(t, got.AccessTokenTTL, 8*time.Hour)
	assertEqual(t, got.RefreshTokenTTL, 30*24*time.Hour)
	assertEqual(t, got.DownloadTimeout, 10*time.Minute)
	assertEqual(t, got.DownloadMaxBytes, int64(200*1024*1024))
	assertEqual(t, got.DownloadConcurrencyPerUser, 5)
	assertEqual(t, got.AuditRetention, 180*24*time.Hour)
	assertEqual(t, got.AuthRecordRetention, 7*24*time.Hour)
	assertEqual(t, got.RequestsPerMinute, 120)
	assertEqual(t, got.ApprovalSearchConcurrency, 4)
	assertEqual(t, got.ApprovalSearchRate, 6)
	if got.PublicBaseURL.String() != "https://broker.example.com" {
		t.Errorf("PublicBaseURL = %q; want %q", got.PublicBaseURL, "https://broker.example.com")
	}
	if len(got.AdminUserIDs) != 2 {
		if len(got.TrustedProxyCIDRs) != 0 {
			t.Errorf("TrustedProxyCIDRs = %v; want empty", got.TrustedProxyCIDRs)
		}
		t.Fatalf("AdminUserIDs length = %d; want 2", len(got.AdminUserIDs))
	}
	if _, ok := got.AdminUserIDs["admin-1"]; !ok {
		t.Error("AdminUserIDs does not contain admin-1")
	}
}

func TestLoadReadsEnvironment(t *testing.T) {
	setValidEnvironment(t)
	t.Setenv("HTTP_ADDRESS", "127.0.0.1:9090")
	t.Setenv("METRICS_ADDRESS", "127.0.0.1:9191")
	t.Setenv("HTTP_READ_HEADER_TIMEOUT", "3s")
	t.Setenv("HTTP_READ_TIMEOUT", "12s")
	t.Setenv("HTTP_IDLE_TIMEOUT", "45s")
	t.Setenv("SHUTDOWN_TIMEOUT", "20s")
	t.Setenv("DEVICE_CODE_TTL", "5m")
	t.Setenv("ACCESS_TOKEN_TTL", "2h")
	t.Setenv("REFRESH_TOKEN_TTL", "168h")
	t.Setenv("DOWNLOAD_TIMEOUT", "30m")
	t.Setenv("DOWNLOAD_MAX_BYTES", "1048576")
	t.Setenv("DOWNLOAD_CONCURRENCY_PER_USER", "2")
	t.Setenv("AUDIT_RETENTION", "720h")
	t.Setenv("AUTH_RECORD_RETENTION", "24h")
	t.Setenv("REQUESTS_PER_MINUTE", "60")
	t.Setenv("APPROVAL_SEARCH_CONCURRENCY", "3")
	t.Setenv("APPROVAL_SEARCH_REQUESTS_PER_MINUTE", "8")
	t.Setenv("TRUSTED_PROXY_CIDRS", "10.0.0.0/8, 2001:db8::/32")

	got, err := Load()
	if err != nil {
		t.Fatalf("Load() returned an unexpected error: %v", err)
	}

	assertEqual(t, got.HTTPAddress, "127.0.0.1:9090")
	assertEqual(t, got.MetricsAddress, "127.0.0.1:9191")
	assertEqual(t, got.ReadHeaderTimeout, 3*time.Second)
	assertEqual(t, got.ReadTimeout, 12*time.Second)
	assertEqual(t, got.IdleTimeout, 45*time.Second)
	assertEqual(t, got.ShutdownTimeout, 20*time.Second)
	assertEqual(t, got.DeviceCodeTTL, 5*time.Minute)
	assertEqual(t, got.AccessTokenTTL, 2*time.Hour)
	assertEqual(t, got.RefreshTokenTTL, 7*24*time.Hour)
	assertEqual(t, got.DownloadTimeout, 30*time.Minute)
	assertEqual(t, got.DownloadMaxBytes, int64(1024*1024))
	assertEqual(t, got.DownloadConcurrencyPerUser, 2)
	assertEqual(t, got.AuditRetention, 30*24*time.Hour)
	assertEqual(t, got.AuthRecordRetention, 24*time.Hour)
	assertEqual(t, got.RequestsPerMinute, 60)
	assertEqual(t, got.ApprovalSearchConcurrency, 3)
	assertEqual(t, got.ApprovalSearchRate, 8)
	wantTrustedProxies := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	if !slices.Equal(got.TrustedProxyCIDRs, wantTrustedProxies) {
		t.Errorf("TrustedProxyCIDRs = %v; want %v", got.TrustedProxyCIDRs, wantTrustedProxies)
	}
}

func TestLoadAllowsLoopbackHTTPForLocalDevelopment(t *testing.T) {
	setValidEnvironment(t)
	t.Setenv("PUBLIC_BASE_URL", "http://127.0.0.1:8080")

	got, err := Load()
	if err != nil {
		t.Fatalf("Load() returned an unexpected error: %v", err)
	}
	if got.PublicBaseURL.Scheme != "http" {
		t.Errorf("PublicBaseURL scheme = %q; want http", got.PublicBaseURL.Scheme)
	}
}

func TestLoadRejectsInvalidConfiguration(t *testing.T) {
	tests := []struct {
		name      string
		key       string
		value     string
		wantError string
	}{
		{name: "invalid address", key: "HTTP_ADDRESS", value: "not-an-address", wantError: "HTTP_ADDRESS"},
		{name: "invalid metrics address", key: "METRICS_ADDRESS", value: "not-an-address", wantError: "METRICS_ADDRESS"},
		{name: "invalid public URL", key: "PUBLIC_BASE_URL", value: "not-a-url", wantError: "PUBLIC_BASE_URL"},
		{name: "insecure public URL", key: "PUBLIC_BASE_URL", value: "http://broker.example.com", wantError: "HTTPS"},
		{name: "zero public URL port", key: "PUBLIC_BASE_URL", value: "https://broker.example.com:0", wantError: "port"},
		{name: "oversized public URL port", key: "PUBLIC_BASE_URL", value: "https://broker.example.com:99999", wantError: "port"},
		{name: "OAuth URL with query", key: "DINGTALK_OAUTH_AUTHORIZE_URL", value: "https://login.example.com/oauth?prompt=consent", wantError: "query"},
		{name: "missing client ID", key: "DINGTALK_CLIENT_ID", value: "", wantError: "DINGTALK_CLIENT_ID"},
		{name: "missing client secret", key: "DINGTALK_CLIENT_SECRET", value: "", wantError: "DINGTALK_CLIENT_SECRET"},
		{name: "missing corporation ID", key: "DINGTALK_CORP_ID", value: "", wantError: "DINGTALK_CORP_ID"},
		{name: "invalid database URL", key: "DATABASE_URL", value: "mysql://localhost/db", wantError: "DATABASE_URL"},
		{name: "short pepper", key: "TOKEN_PEPPER", value: "short", wantError: "TOKEN_PEPPER"},
		{name: "invalid duration", key: "HTTP_READ_HEADER_TIMEOUT", value: "later", wantError: "HTTP_READ_HEADER_TIMEOUT"},
		{name: "invalid read timeout", key: "HTTP_READ_TIMEOUT", value: "later", wantError: "HTTP_READ_TIMEOUT"},
		{name: "non-positive duration", key: "HTTP_IDLE_TIMEOUT", value: "0s", wantError: "HTTP_IDLE_TIMEOUT"},
		{name: "invalid auth retention", key: "AUTH_RECORD_RETENTION", value: "0s", wantError: "AUTH_RECORD_RETENTION"},
		{name: "poll interval reaches device lifetime", key: "AUTH_POLL_INTERVAL", value: "10m", wantError: "AUTH_POLL_INTERVAL"},
		{name: "invalid max bytes", key: "DOWNLOAD_MAX_BYTES", value: "0", wantError: "DOWNLOAD_MAX_BYTES"},
		{name: "invalid concurrency", key: "DOWNLOAD_CONCURRENCY_PER_USER", value: "-1", wantError: "DOWNLOAD_CONCURRENCY_PER_USER"},
		{name: "invalid request rate", key: "REQUESTS_PER_MINUTE", value: "0", wantError: "REQUESTS_PER_MINUTE"},
		{name: "invalid search concurrency", key: "APPROVAL_SEARCH_CONCURRENCY", value: "21", wantError: "APPROVAL_SEARCH_CONCURRENCY"},
		{name: "invalid search rate", key: "APPROVAL_SEARCH_REQUESTS_PER_MINUTE", value: "0", wantError: "APPROVAL_SEARCH_REQUESTS_PER_MINUTE"},
		{name: "invalid trusted proxy CIDR", key: "TRUSTED_PROXY_CIDRS", value: "10.0.0.1", wantError: "TRUSTED_PROXY_CIDRS"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setValidEnvironment(t)
			t.Setenv(tt.key, tt.value)

			_, err := Load()
			if err == nil {
				t.Fatal("Load() returned nil error; want validation error")
			}
			if !strings.Contains(err.Error(), tt.wantError) {
				t.Errorf("Load() error = %q; want it to contain %q", err, tt.wantError)
			}
		})
	}
}

func setValidEnvironment(t *testing.T) {
	t.Helper()
	values := map[string]string{
		"HTTP_ADDRESS":            ":8080",
		"METRICS_ADDRESS":         ":9090",
		"PUBLIC_BASE_URL":         "https://broker.example.com",
		"DINGTALK_CLIENT_ID":      "test-client-id",
		"DINGTALK_CLIENT_SECRET":  "test-client-secret",
		"DINGTALK_CORP_ID":        "test-corp-id",
		"DATABASE_URL":            "postgres://broker:password@localhost:5432/broker?sslmode=disable",
		"TOKEN_PEPPER":            strings.Repeat("p", 32),
		"DINGTALK_ADMIN_USER_IDS": "",
		"TRUSTED_PROXY_CIDRS":     "",
	}
	for key, value := range values {
		t.Setenv(key, value)
	}
}

func assertEqual[T comparable](t *testing.T, got, want T) {
	t.Helper()
	if got != want {
		t.Errorf("got %v; want %v", got, want)
	}
}
