package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/config"
)

func TestRunRejectsInvalidConfiguration(t *testing.T) {
	t.Setenv("HTTP_ADDRESS", "invalid")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	err := run(context.Background(), logger, nil, nil)
	if err == nil {
		t.Fatal("run() returned nil error; want configuration error")
	}
	if !strings.Contains(err.Error(), "load configuration") {
		t.Errorf("run() error = %q; want configuration context", err)
	}
}

func TestRunReturnsListenerFailure(t *testing.T) {
	setValidEnvironment(t)
	t.Setenv("HTTP_ADDRESS", ":8080")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	wantErr := errors.New("listener unavailable")
	listen := func(context.Context, string, string) (net.Listener, error) {
		return nil, wantErr
	}

	err := run(context.Background(), logger, listen, testApplicationBuilder)
	if err == nil {
		t.Fatal("run() returned nil error; want listener error")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("run() error = %v; want it to wrap %v", err, wantErr)
	}
}

func TestRunClosesPublicListenerWhenMetricsListenerFails(t *testing.T) {
	setValidEnvironment(t)
	t.Setenv("HTTP_ADDRESS", "127.0.0.1:0")
	t.Setenv("METRICS_ADDRESS", "127.0.0.1:0")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	publicListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	wantErr := errors.New("metrics listener unavailable")
	listenerCalls := 0
	listen := func(context.Context, string, string) (net.Listener, error) {
		listenerCalls++
		if listenerCalls == 1 {
			return publicListener, nil
		}
		return nil, wantErr
	}

	err = run(context.Background(), logger, listen, testApplicationBuilder)
	if err == nil {
		t.Fatal("run() returned nil error; want metrics listener error")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("run() error = %v; want it to wrap %v", err, wantErr)
	}

	_, acceptErr := publicListener.Accept()
	if !errors.Is(acceptErr, net.ErrClosed) {
		t.Errorf("public listener Accept() error = %v; want net.ErrClosed", acceptErr)
	}
}

func TestRunStopsCleanlyWhenCancelled(t *testing.T) {
	setValidEnvironment(t)
	t.Setenv("HTTP_ADDRESS", "127.0.0.1:0")
	t.Setenv("METRICS_ADDRESS", "127.0.0.1:0")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	addresses := make([]string, 0, 2)
	listen := func(_ context.Context, _, address string) (net.Listener, error) {
		addresses = append(addresses, address)
		return net.Listen("tcp", address)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := run(ctx, logger, listen, testApplicationBuilder); err != nil {
		t.Fatalf("run() returned an unexpected error: %v", err)
	}
	if len(addresses) != 2 {
		t.Fatalf("listener calls = %d; want public and metrics listeners", len(addresses))
	}
	if addresses[0] != "127.0.0.1:0" || addresses[1] != "127.0.0.1:0" {
		t.Errorf("listener addresses = %#v; want both configured addresses", addresses)
	}
}

func TestServeServersKeepsHandlersBoundToTheirListeners(t *testing.T) {
	publicListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for public server: %v", err)
	}
	metricsListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = publicListener.Close()
		t.Fatalf("listen for metrics server: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	newHandler := func(body string) http.Handler {
		return http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			_, _ = response.Write([]byte(body))
		})
	}
	servers := []serverRuntime{
		{
			name:     "public",
			server:   newTestHTTPServer(newHandler("public"), logger),
			listener: publicListener,
		},
		{
			name:     "metrics",
			server:   newTestHTTPServer(newHandler("metrics"), logger),
			listener: metricsListener,
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = publicListener.Close()
		_ = metricsListener.Close()
	})
	result := make(chan error, 1)
	go func() {
		result <- serveServers(ctx, servers, time.Second)
	}()

	client := &http.Client{Timeout: 2 * time.Second}
	assertHTTPBody(t, client, publicListener.Addr().String(), "public")
	assertHTTPBody(t, client, metricsListener.Addr().String(), "metrics")

	cancel()
	select {
	case serveErr := <-result:
		if serveErr != nil {
			t.Fatalf("serveServers() error = %v", serveErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("serveServers() did not stop after cancellation")
	}
}

func newTestHTTPServer(handler http.Handler, logger *slog.Logger) *http.Server {
	return &http.Server{
		Handler:  handler,
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}
}

func assertHTTPBody(
	t *testing.T,
	client *http.Client,
	address string,
	want string,
) {
	t.Helper()
	response, err := client.Get("http://" + address)
	if err != nil {
		t.Fatalf("GET %s: %v", address, err)
	}
	defer func() {
		if closeErr := response.Body.Close(); closeErr != nil {
			t.Errorf("close response body: %v", closeErr)
		}
	}()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if string(body) != want {
		t.Errorf("response body = %q; want %q", body, want)
	}
}

func testApplicationBuilder(
	context.Context,
	config.Config,
	*slog.Logger,
) (*application, error) {
	return &application{
		handler:        http.NewServeMux(),
		metricsHandler: http.NewServeMux(),
		close:          func() {},
	}, nil
}

func setValidEnvironment(t *testing.T) {
	t.Helper()
	values := map[string]string{
		"PUBLIC_BASE_URL":        "https://broker.example.test",
		"METRICS_ADDRESS":        "127.0.0.1:9090",
		"DINGTALK_CLIENT_ID":     "client-id",
		"DINGTALK_CLIENT_SECRET": "client-secret",
		"DINGTALK_CORP_ID":       "corp-id",
		"DATABASE_URL":           "postgres://broker:password@database.example.test/broker",
		"TOKEN_PEPPER":           strings.Repeat("p", 32),
	}
	for key, value := range values {
		t.Setenv(key, value)
	}
}
