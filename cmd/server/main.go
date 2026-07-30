package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/config"
	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/server"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	if err := run(
		ctx,
		logger,
		new(net.ListenConfig).Listen,
		productionApplication,
	); err != nil {
		logger.Error("server stopped with an error", "error", err)
		os.Exit(1)
	}
}

func run(
	ctx context.Context,
	logger *slog.Logger,
	listen func(context.Context, string, string) (net.Listener, error),
	build applicationBuilder,
) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load configuration: %w", err)
	}

	runtime, err := build(ctx, cfg, logger)
	if err != nil {
		return fmt.Errorf("build application: %w", err)
	}
	defer runtime.close()

	listener, err := listen(ctx, "tcp", cfg.HTTPAddress)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", cfg.HTTPAddress, err)
	}
	metricsListener, err := listen(ctx, "tcp", cfg.MetricsAddress)
	if err != nil {
		closeErr := listener.Close()
		var wrappedCloseErr error
		if closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			wrappedCloseErr = fmt.Errorf("close HTTP listener: %w", closeErr)
		}
		return errors.Join(
			fmt.Errorf("listen on %s: %w", cfg.MetricsAddress, err),
			wrappedCloseErr,
		)
	}

	maintenanceContext, stopMaintenance := context.WithCancel(ctx)
	maintenanceDone := make(chan struct{})
	if runtime.maintenance != nil {
		go func() {
			defer close(maintenanceDone)
			runtime.maintenance(maintenanceContext)
		}()
	} else {
		close(maintenanceDone)
	}
	defer func() {
		stopMaintenance()
		<-maintenanceDone
	}()

	httpServer := server.New(cfg, runtime.handler, logger)
	metricsServer := server.NewAtAddress(
		cfg.MetricsAddress,
		cfg,
		runtime.metricsHandler,
		logger,
	)
	servers := []serverRuntime{
		{name: "public", server: httpServer, listener: listener},
		{name: "metrics", server: metricsServer, listener: metricsListener},
	}
	logger.Info(
		"servers started",
		"httpAddress",
		listener.Addr().String(),
		"metricsAddress",
		metricsListener.Addr().String(),
	)

	if err := serveServers(ctx, servers, cfg.ShutdownTimeout); err != nil {
		return err
	}

	logger.Info("servers stopped")
	return nil
}

type serverRuntime struct {
	name     string
	server   *http.Server
	listener net.Listener
}

type serverResult struct {
	name string
	err  error
}

func serveServers(
	ctx context.Context,
	servers []serverRuntime,
	shutdownTimeout time.Duration,
) error {
	serveContext, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan serverResult, len(servers))
	for _, runtime := range servers {
		go func(current serverRuntime) {
			results <- serverResult{
				name: current.name,
				err: server.Serve(
					serveContext,
					current.server,
					current.listener,
					shutdownTimeout,
				),
			}
		}(runtime)
	}

	var serveErrors []error
	for index := 0; index < len(servers); index++ {
		result := <-results
		if index == 0 {
			cancel()
		}
		if result.err != nil {
			serveErrors = append(
				serveErrors,
				fmt.Errorf("%s server: %w", result.name, result.err),
			)
		}
	}
	return errors.Join(serveErrors...)
}
