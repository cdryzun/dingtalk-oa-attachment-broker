package server

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/config"
)

func TestNewAppliesConfiguration(t *testing.T) {
	cfg := config.Config{
		HTTPAddress:       "127.0.0.1:9090",
		ReadHeaderTimeout: 4 * time.Second,
		ReadTimeout:       12 * time.Second,
		IdleTimeout:       30 * time.Second,
		ShutdownTimeout:   8 * time.Second,
	}
	handler := http.NewServeMux()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	got := New(cfg, handler, logger)

	if got.Addr != cfg.HTTPAddress {
		t.Errorf("Addr = %q; want %q", got.Addr, cfg.HTTPAddress)
	}
	if got.Handler != handler {
		t.Error("Handler does not match the supplied handler")
	}
	if got.ReadHeaderTimeout != cfg.ReadHeaderTimeout {
		t.Errorf("ReadHeaderTimeout = %s; want %s", got.ReadHeaderTimeout, cfg.ReadHeaderTimeout)
	}
	if got.ReadTimeout != cfg.ReadTimeout {
		t.Errorf("ReadTimeout = %s; want %s", got.ReadTimeout, cfg.ReadTimeout)
	}
	if got.IdleTimeout != cfg.IdleTimeout {
		t.Errorf("IdleTimeout = %s; want %s", got.IdleTimeout, cfg.IdleTimeout)
	}
}

func TestNewAtAddressOverridesPublicAddress(t *testing.T) {
	cfg := config.Config{
		HTTPAddress:       "127.0.0.1:8080",
		ReadHeaderTimeout: 4 * time.Second,
		ReadTimeout:       12 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	handler := http.NewServeMux()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	got := NewAtAddress("127.0.0.1:9090", cfg, handler, logger)

	if got.Addr != "127.0.0.1:9090" {
		t.Errorf("Addr = %q; want metrics address", got.Addr)
	}
	if got.Handler != handler {
		t.Error("Handler does not match the supplied metrics handler")
	}
}

func TestServeDoesNotStartWithCancelledContext(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := listener.Close(); closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			t.Errorf("close listener: %v", closeErr)
		}
	})

	cfg := config.Config{
		HTTPAddress:       listener.Addr().String(),
		ReadHeaderTimeout: time.Second,
		IdleTimeout:       time.Second,
		ShutdownTimeout:   time.Second,
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	httpServer := New(cfg, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), logger)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := Serve(ctx, httpServer, listener, cfg.ShutdownTimeout); err != nil {
		t.Fatalf("Serve() returned an unexpected error: %v", err)
	}
}

func TestServeGracefullyStopsRunningServer(t *testing.T) {
	baseListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	listener := &acceptNotifyingListener{
		Listener:  baseListener,
		accepting: make(chan struct{}),
	}

	cfg := config.Config{
		HTTPAddress:       listener.Addr().String(),
		ReadHeaderTimeout: time.Second,
		IdleTimeout:       time.Second,
		ShutdownTimeout:   time.Second,
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	httpServer := New(cfg, http.NewServeMux(), logger)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)

	go func() {
		result <- Serve(ctx, httpServer, listener, cfg.ShutdownTimeout)
	}()

	select {
	case <-listener.accepting:
	case <-time.After(time.Second):
		t.Fatal("HTTP server did not start accepting connections")
	}
	cancel()

	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("Serve() returned an unexpected error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve() did not stop after context cancellation")
	}
}

func TestServeReturnsListenerFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if err := listener.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	httpServer := &http.Server{
		Handler:  http.NewServeMux(),
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}

	err = Serve(context.Background(), httpServer, listener, time.Second)
	if err == nil {
		t.Fatal("Serve() returned nil error; want listener failure")
	}
	if !errors.Is(err, net.ErrClosed) {
		t.Errorf("Serve() error = %v; want it to wrap net.ErrClosed", err)
	}
}

func TestServeForcesCloseWhenGracefulShutdownTimesOut(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	handlerStarted := make(chan struct{})
	releaseHandler := make(chan struct{})
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() {
			close(releaseHandler)
		})
	}
	t.Cleanup(release)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
			close(handlerStarted)
			<-releaseHandler
			response.WriteHeader(http.StatusNoContent)
		}),
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}
	ctx, cancel := context.WithCancel(context.Background())
	serveResult := make(chan error, 1)
	go func() {
		serveResult <- Serve(ctx, httpServer, listener, time.Millisecond)
	}()

	clientResult := make(chan error, 1)
	go func() {
		response, requestErr := http.Get("http://" + listener.Addr().String())
		if response != nil {
			if closeErr := response.Body.Close(); requestErr == nil {
				requestErr = closeErr
			}
		}
		clientResult <- requestErr
	}()

	select {
	case <-handlerStarted:
	case <-time.After(time.Second):
		t.Fatal("request handler did not start")
	}
	cancel()

	select {
	case serveErr := <-serveResult:
		if serveErr == nil {
			t.Fatal("Serve() returned nil error; want shutdown timeout")
		}
		if !errors.Is(serveErr, context.DeadlineExceeded) {
			t.Errorf("Serve() error = %v; want it to wrap context deadline", serveErr)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve() did not return after shutdown timeout")
	}

	select {
	case requestErr := <-clientResult:
		if requestErr == nil {
			t.Fatal("client request completed successfully; want forced connection closure")
		}
	case <-time.After(time.Second):
		t.Fatal("active connection was not closed after shutdown timeout")
	}

	release()
}

type acceptNotifyingListener struct {
	net.Listener
	accepting chan struct{}
	once      sync.Once
}

func (l *acceptNotifyingListener) Accept() (net.Conn, error) {
	l.once.Do(func() {
		close(l.accepting)
	})
	return l.Listener.Accept()
}
