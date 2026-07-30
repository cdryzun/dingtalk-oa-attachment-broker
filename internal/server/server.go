package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/config"
)

func New(cfg config.Config, handler http.Handler, logger *slog.Logger) *http.Server {
	return NewAtAddress(cfg.HTTPAddress, cfg, handler, logger)
}

func NewAtAddress(
	address string,
	cfg config.Config,
	handler http.Handler,
	logger *slog.Logger,
) *http.Server {
	return &http.Server{
		Addr:              address,
		Handler:           handler,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.DownloadTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelError),
	}
}

func Serve(
	ctx context.Context,
	httpServer *http.Server,
	listener net.Listener,
	shutdownTimeout time.Duration,
) error {
	if ctx.Err() != nil {
		if err := listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			return fmt.Errorf("close listener after cancellation: %w", err)
		}
		return nil
	}

	serveResult := make(chan error, 1)
	go func() {
		serveResult <- httpServer.Serve(listener)
	}()

	select {
	case err := <-serveResult:
		if err == nil || errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve HTTP: %w", err)
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		if shutdownErr := httpServer.Shutdown(shutdownContext); shutdownErr != nil {
			closeErr := httpServer.Close()
			serveErr := <-serveResult

			var wrappedCloseErr error
			if closeErr != nil {
				wrappedCloseErr = fmt.Errorf("force close HTTP server: %w", closeErr)
			}

			var wrappedServeErr error
			if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				wrappedServeErr = fmt.Errorf("serve HTTP during forced shutdown: %w", serveErr)
			}

			return errors.Join(
				fmt.Errorf("shut down HTTP server: %w", shutdownErr),
				wrappedCloseErr,
				wrappedServeErr,
			)
		}

		err := <-serveResult
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve HTTP during shutdown: %w", err)
		}
		return nil
	}
}
