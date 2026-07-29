package main

import (
	"context"
	"strings"
	"testing"
)

func TestRunRejectsInvalidDatabaseConfiguration(t *testing.T) {
	t.Setenv("DATABASE_URL", "mysql://localhost/database")

	err := run(context.Background())
	if err == nil {
		t.Fatal("run() error = nil; want configuration failure")
	}
	if !strings.Contains(err.Error(), "database configuration") {
		t.Errorf("run() error = %q; want database configuration context", err)
	}
}
