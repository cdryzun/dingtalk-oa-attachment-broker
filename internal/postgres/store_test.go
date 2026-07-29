package postgres

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	embeddedpostgres "github.com/fergusstrange/embedded-postgres"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/auth"
	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/domain"
)

var integrationDatabaseURL string

func TestMain(testingMain *testing.M) {
	if configuredURL := os.Getenv("TEST_DATABASE_URL"); configuredURL != "" {
		integrationDatabaseURL = configuredURL
		os.Exit(testingMain.Run())
	}

	tempDirectory, err := os.MkdirTemp("", "dingtalk-broker-postgres-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create embedded PostgreSQL directory: %v\n", err)
		os.Exit(1)
	}
	port, err := freePort()
	if err != nil {
		fmt.Fprintf(os.Stderr, "allocate embedded PostgreSQL port: %v\n", err)
		_ = os.RemoveAll(tempDirectory)
		os.Exit(1)
	}
	database := embeddedpostgres.NewDatabase(
		embeddedpostgres.DefaultConfig().
			Version(embeddedpostgres.V17).
			Port(port).
			Username("postgres").
			Password("postgres").
			Database("broker_test").
			RuntimePath(filepath.Join(tempDirectory, "runtime")).
			DataPath(filepath.Join(tempDirectory, "data")).
			BinariesPath(filepath.Join(tempDirectory, "bin")).
			CachePath(filepath.Join(tempDirectory, "cache")).
			StartTimeout(90 * time.Second),
	)
	if err := database.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "start embedded PostgreSQL: %v\n", err)
		_ = os.RemoveAll(tempDirectory)
		os.Exit(1)
	}
	integrationDatabaseURL = fmt.Sprintf(
		"postgres://postgres:postgres@127.0.0.1:%d/broker_test?sslmode=disable",
		port,
	)

	exitCode := testingMain.Run()
	if err := database.Stop(); err != nil {
		fmt.Fprintf(os.Stderr, "stop embedded PostgreSQL: %v\n", err)
		exitCode = 1
	}
	if err := os.RemoveAll(tempDirectory); err != nil {
		fmt.Fprintf(os.Stderr, "remove embedded PostgreSQL directory: %v\n", err)
		exitCode = 1
	}
	os.Exit(exitCode)
}

func TestMigrateIsIdempotentAndCreatesRequiredSchema(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()

	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("Migrate() second call error = %v", err)
	}

	tableNames := []string{"users", "device_authorizations", "sessions", "audit_events", "schema_migrations"}
	for _, tableName := range tableNames {
		var exists bool
		err := store.pool.QueryRow(
			ctx,
			`SELECT to_regclass('public.' || $1) IS NOT NULL`,
			tableName,
		).Scan(&exists)
		if err != nil {
			t.Fatalf("query table %s: %v", tableName, err)
		}
		if !exists {
			t.Errorf("table %s does not exist", tableName)
		}
	}

	indexNames := []string{"sessions_refresh_expires_at_idx", "sessions_revoked_at_idx"}
	for _, indexName := range indexNames {
		var exists bool
		err := store.pool.QueryRow(
			ctx,
			`SELECT to_regclass('public.' || $1) IS NOT NULL`,
			indexName,
		).Scan(&exists)
		if err != nil {
			t.Fatalf("query index %s: %v", indexName, err)
		}
		if !exists {
			t.Errorf("index %s does not exist", indexName)
		}
	}
}

func TestStorePersistsDeviceAuthorizationAndRotatingSessions(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	deviceHash := []byte("device-hash")
	stateHash := []byte("state-hash")
	user := domain.User{
		CorpID:      "corp-id",
		UserID:      "user-id",
		UnionID:     "union-id",
		DisplayName: "Verified User",
	}

	err := store.CreateDeviceAuthorization(ctx, auth.DeviceAuthorization{
		DeviceCodeHash: deviceHash,
		UserCode:       "ABCD-EFGH",
		CreatedAt:      now,
		ExpiresAt:      now.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("CreateDeviceAuthorization() error = %v", err)
	}
	if err := store.BindOAuthState(ctx, "ABCD-EFGH", stateHash, now); err != nil {
		t.Fatalf("BindOAuthState() error = %v", err)
	}

	_, err = store.ExchangeDeviceAuthorization(ctx, deviceHash, testSessionSeed(now, "first"), now)
	if !errors.Is(err, domain.ErrAuthorizationPending) {
		t.Fatalf("ExchangeDeviceAuthorization() before approval error = %v; want pending", err)
	}

	claimedDeviceHash, err := store.ClaimOAuthState(ctx, stateHash, now)
	if err != nil {
		t.Fatalf("ClaimOAuthState() error = %v", err)
	}
	if string(claimedDeviceHash) != string(deviceHash) {
		t.Errorf("claimed device hash = %q; want %q", claimedDeviceHash, deviceHash)
	}
	if _, err := store.ClaimOAuthState(ctx, stateHash, now); !errors.Is(err, domain.ErrUnauthorized) {
		t.Errorf("replayed ClaimOAuthState() error = %v; want unauthorized", err)
	}
	_, err = store.ExchangeDeviceAuthorization(ctx, deviceHash, testSessionSeed(now, "authorizing"), now)
	if !errors.Is(err, domain.ErrAuthorizationPending) {
		t.Fatalf("ExchangeDeviceAuthorization() while authorizing error = %v; want pending", err)
	}

	if err := store.CompleteDeviceAuthorization(ctx, claimedDeviceHash, user, now); err != nil {
		t.Fatalf("CompleteDeviceAuthorization() error = %v", err)
	}
	sessionUser, err := store.ExchangeDeviceAuthorization(
		ctx,
		deviceHash,
		testSessionSeed(now, "first"),
		now,
	)
	if err != nil {
		t.Fatalf("ExchangeDeviceAuthorization() error = %v", err)
	}
	if sessionUser != user {
		t.Errorf("exchanged user = %#v; want %#v", sessionUser, user)
	}

	_, err = store.ExchangeDeviceAuthorization(ctx, deviceHash, testSessionSeed(now, "duplicate"), now)
	if !errors.Is(err, domain.ErrAlreadyUsed) {
		t.Fatalf("second ExchangeDeviceAuthorization() error = %v; want already used", err)
	}

	authenticatedUser, err := store.GetSessionByAccessToken(ctx, []byte("first-access"), now)
	if err != nil {
		t.Fatalf("GetSessionByAccessToken() error = %v", err)
	}
	if authenticatedUser != user {
		t.Errorf("authenticated user = %#v; want %#v", authenticatedUser, user)
	}

	rotatedUser, err := store.RotateSession(
		ctx,
		[]byte("first-refresh"),
		testSessionSeed(now, "second"),
		now,
	)
	if err != nil {
		t.Fatalf("RotateSession() error = %v", err)
	}
	if rotatedUser != user {
		t.Errorf("rotated user = %#v; want %#v", rotatedUser, user)
	}
	if _, err := store.GetSessionByAccessToken(ctx, []byte("first-access"), now); !errors.Is(err, domain.ErrUnauthorized) {
		t.Errorf("old access token error = %v; want unauthorized", err)
	}
	if _, err := store.GetSessionByAccessToken(ctx, []byte("second-access"), now); err != nil {
		t.Fatalf("new access token error = %v", err)
	}

	if err := store.RevokeSession(ctx, []byte("second-access"), now); err != nil {
		t.Fatalf("RevokeSession() error = %v", err)
	}
	if _, err := store.GetSessionByAccessToken(ctx, []byte("second-access"), now); !errors.Is(err, domain.ErrUnauthorized) {
		t.Errorf("revoked access token error = %v; want unauthorized", err)
	}
}

func TestStoreReturnsDeniedDeviceAuthorizationImmediately(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	deviceHash := []byte("denied-device")
	stateHash := []byte("denied-state")
	if err := store.CreateDeviceAuthorization(ctx, auth.DeviceAuthorization{
		DeviceCodeHash: deviceHash,
		UserCode:       "DENY-CODE",
		CreatedAt:      now,
		ExpiresAt:      now.Add(10 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.BindOAuthState(ctx, "DENY-CODE", stateHash, now); err != nil {
		t.Fatal(err)
	}
	claimedHash, err := store.ClaimOAuthState(ctx, stateHash, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RejectDeviceAuthorization(ctx, claimedHash, now); err != nil {
		t.Fatal(err)
	}
	if err := store.RejectDeviceAuthorization(ctx, claimedHash, now); err != nil {
		t.Fatalf("idempotent RejectDeviceAuthorization() error = %v", err)
	}
	_, err = store.ExchangeDeviceAuthorization(ctx, deviceHash, testSessionSeed(now, "denied"), now)
	if !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("ExchangeDeviceAuthorization() error = %v; want forbidden", err)
	}
}

func TestStoreFailsClosedForExpiredAndUnknownCredentials(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)

	err := store.CreateDeviceAuthorization(ctx, auth.DeviceAuthorization{
		DeviceCodeHash: []byte("expired-device"),
		UserCode:       "EXPR-CODE",
		CreatedAt:      now.Add(-20 * time.Minute),
		ExpiresAt:      now.Add(-10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("CreateDeviceAuthorization() error = %v", err)
	}
	if err := store.BindOAuthState(ctx, "EXPR-CODE", []byte("state"), now); !errors.Is(err, domain.ErrExpired) {
		t.Errorf("BindOAuthState() error = %v; want expired", err)
	}
	if _, err := store.GetSessionByAccessToken(ctx, []byte("unknown"), now); !errors.Is(err, domain.ErrUnauthorized) {
		t.Errorf("unknown access token error = %v; want unauthorized", err)
	}
	if _, err := store.RotateSession(
		ctx,
		[]byte("unknown"),
		testSessionSeed(now, "unused"),
		now,
	); !errors.Is(err, domain.ErrUnauthorized) {
		t.Errorf("unknown refresh token error = %v; want unauthorized", err)
	}
	if err := store.RevokeSession(ctx, []byte("unknown"), now); !errors.Is(err, domain.ErrUnauthorized) {
		t.Errorf("unknown revoke error = %v; want unauthorized", err)
	}
}

func TestStoreRecordsAndPrunesAuditEvents(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 17, 10, 0, 0, 0, time.UTC)
	events := []domain.AuditEvent{
		{
			RequestID:         "old-request",
			CorpID:            "corp-id",
			ActorUserID:       "user-id",
			Action:            "attachments.list",
			ProcessInstanceID: "instance-id",
			Decision:          domain.AuditDecisionAllowed,
			CreatedAt:         now.Add(-181 * 24 * time.Hour),
		},
		{
			RequestID:          "current-request",
			CorpID:             "corp-id",
			ActorUserID:        "user-id",
			Action:             "attachments.download",
			ProcessInstanceID:  "instance-id",
			FileID:             "file-id",
			Decision:           domain.AuditDecisionDenied,
			UpstreamErrorClass: "forbidden",
			CreatedAt:          now,
		},
	}
	for _, event := range events {
		if err := store.RecordAudit(ctx, event); err != nil {
			t.Fatalf("RecordAudit() error = %v", err)
		}
	}

	deleted, err := store.PruneAudit(ctx, now.Add(-180*24*time.Hour))
	if err != nil {
		t.Fatalf("PruneAudit() error = %v", err)
	}
	if deleted != 1 {
		t.Errorf("PruneAudit() deleted = %d; want 1", deleted)
	}

	var remaining int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM audit_events`).Scan(&remaining); err != nil {
		t.Fatalf("count audit events: %v", err)
	}
	if remaining != 1 {
		t.Errorf("remaining audit events = %d; want 1", remaining)
	}
}

func TestStorePrunesOnlyExpiredAuthenticationStateOutsideRetention(t *testing.T) {
	store := openTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)
	before := now.Add(-7 * 24 * time.Hour)

	if _, err := store.pool.Exec(
		ctx,
		`INSERT INTO users (
			corp_id, user_id, union_id, display_name, created_at, updated_at
		) VALUES ('corp-id', 'user-id', 'union-id', 'Verified User', $1, $1)`,
		now.Add(-30*24*time.Hour),
	); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := store.pool.Exec(
		ctx,
		`INSERT INTO device_authorizations (
			device_code_hash, user_code, status, created_at, expires_at
		) VALUES
			($1, 'OLD1-CODE', 'pending', $4, $4),
			($2, 'NEW1-CODE', 'pending', $4, $5),
			($3, 'LIVE-CODE', 'pending', $5, $6)`,
		[]byte("old-device"),
		[]byte("recent-device"),
		[]byte("live-device"),
		now.Add(-8*24*time.Hour),
		now.Add(-24*time.Hour),
		now.Add(time.Hour),
	); err != nil {
		t.Fatalf("insert device authorizations: %v", err)
	}
	if _, err := store.pool.Exec(
		ctx,
		`INSERT INTO sessions (
			corp_id, user_id, access_token_hash, refresh_token_hash,
			access_expires_at, refresh_expires_at, revoked_at, created_at
		) VALUES
			('corp-id', 'user-id', $1, $2, $9, $5, NULL, $8),
			('corp-id', 'user-id', $3, $4, $9, $10, $5, $8),
			('corp-id', 'user-id', $6, $7, $9, $10, $9, $8),
			('corp-id', 'user-id', $11, $12, $10, $10, NULL, $9)`,
		[]byte("expired-access"),
		[]byte("expired-refresh"),
		[]byte("revoked-access"),
		[]byte("revoked-refresh"),
		now.Add(-8*24*time.Hour),
		[]byte("recent-revoked-access"),
		[]byte("recent-revoked-refresh"),
		now.Add(-30*24*time.Hour),
		now.Add(-24*time.Hour),
		now.Add(24*time.Hour),
		[]byte("active-access"),
		[]byte("active-refresh"),
	); err != nil {
		t.Fatalf("insert sessions: %v", err)
	}

	deleted, err := store.PruneAuthenticationState(ctx, before)
	if err != nil {
		t.Fatalf("PruneAuthenticationState() error = %v", err)
	}
	if deleted.DeviceAuthorizations != 1 {
		t.Errorf("deleted device authorizations = %d; want 1", deleted.DeviceAuthorizations)
	}
	if deleted.Sessions != 2 {
		t.Errorf("deleted sessions = %d; want 2", deleted.Sessions)
	}

	var remainingAuthorizations int
	if err := store.pool.QueryRow(
		ctx,
		`SELECT count(*) FROM device_authorizations`,
	).Scan(&remainingAuthorizations); err != nil {
		t.Fatalf("count device authorizations: %v", err)
	}
	if remainingAuthorizations != 2 {
		t.Errorf("remaining device authorizations = %d; want 2", remainingAuthorizations)
	}
	var remainingSessions int
	if err := store.pool.QueryRow(ctx, `SELECT count(*) FROM sessions`).Scan(&remainingSessions); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if remainingSessions != 2 {
		t.Errorf("remaining sessions = %d; want 2", remainingSessions)
	}
}

func TestRollbackUsesBoundedContext(t *testing.T) {
	transaction := &rollbackRecorder{}
	rollback(transaction)
	if !transaction.called {
		t.Fatal("rollback() did not call transaction")
	}
	if transaction.deadline.IsZero() {
		t.Fatal("rollback() context did not have a deadline")
	}
	remaining := time.Until(transaction.deadline)
	if remaining <= 0 || remaining > rollbackTimeout {
		t.Errorf("rollback() deadline remaining = %v; want within %v", remaining, rollbackTimeout)
	}
	rollback(nil)
}

func TestUnlockMigrationUsesBoundedContext(t *testing.T) {
	recorder := &migrationUnlockRecorder{}
	unlockMigration(recorder)
	if !recorder.called {
		t.Fatal("unlockMigration() did not execute the unlock query")
	}
	if recorder.deadline.IsZero() {
		t.Fatal("unlockMigration() context did not have a deadline")
	}
	remaining := time.Until(recorder.deadline)
	if remaining <= 0 || remaining > rollbackTimeout {
		t.Errorf("unlock deadline remaining = %v; want within %v", remaining, rollbackTimeout)
	}
	if len(recorder.arguments) != 1 || recorder.arguments[0] != migrationAdvisoryLockID {
		t.Errorf("unlock arguments = %#v", recorder.arguments)
	}
}

type rollbackRecorder struct {
	called   bool
	deadline time.Time
}

func (recorder *rollbackRecorder) Rollback(ctx context.Context) error {
	recorder.called = true
	recorder.deadline, _ = ctx.Deadline()
	return errors.New("rollback test error")
}

type migrationUnlockRecorder struct {
	called    bool
	deadline  time.Time
	arguments []any
}

func (recorder *migrationUnlockRecorder) Exec(
	ctx context.Context,
	_ string,
	arguments ...any,
) (pgconn.CommandTag, error) {
	recorder.called = true
	recorder.deadline, _ = ctx.Deadline()
	recorder.arguments = arguments
	return pgconn.CommandTag{}, errors.New("unlock test error")
}

func openTestStore(t *testing.T) *Store {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	store, err := Open(ctx, integrationDatabaseURL)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	t.Cleanup(store.Close)
	if err := store.Migrate(ctx); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	if _, err := store.pool.Exec(
		ctx,
		`TRUNCATE TABLE audit_events, sessions, device_authorizations, users RESTART IDENTITY CASCADE`,
	); err != nil {
		t.Fatalf("truncate test tables: %v", err)
	}
	if err := store.Ping(ctx); err != nil {
		t.Fatalf("Ping() error = %v", err)
	}
	return store
}

func testSessionSeed(now time.Time, prefix string) auth.SessionSeed {
	return auth.SessionSeed{
		AccessTokenHash:  []byte(prefix + "-access"),
		RefreshTokenHash: []byte(prefix + "-refresh"),
		AccessExpiresAt:  now.Add(8 * time.Hour),
		RefreshExpiresAt: now.Add(30 * 24 * time.Hour),
	}
}

func freePort() (uint32, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	_, rawPort, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		return 0, err
	}
	port, err := strconv.ParseUint(rawPort, 10, 32)
	if err != nil {
		return 0, err
	}
	return uint32(port), nil
}
