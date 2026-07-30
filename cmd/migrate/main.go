package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/config"
	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/postgres"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	if err := run(ctx); err != nil {
		logger.Error("database migration failed", "error", err)
		os.Exit(1)
	}
	logger.Info("database migration completed")
}

func run(ctx context.Context) error {
	databaseURL, err := config.LoadDatabaseURL()
	if err != nil {
		return fmt.Errorf("load database configuration: %w", err)
	}
	store, err := postgres.Open(ctx, databaseURL)
	if err != nil {
		return fmt.Errorf("open PostgreSQL store: %w", err)
	}
	defer store.Close()
	if err := store.Migrate(ctx); err != nil {
		return fmt.Errorf("apply database migrations: %w", err)
	}
	return nil
}
