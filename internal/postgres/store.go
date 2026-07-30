package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/auth"
	"github.com/cdryzun/dingtalk-oa-attachment-broker/internal/domain"
)

type Store struct {
	pool *pgxpool.Pool
}

type AuthenticationPruneResult struct {
	DeviceAuthorizations int64
	Sessions             int64
}

const rollbackTimeout = 5 * time.Second

func Open(ctx context.Context, databaseURL string) (*Store, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		return nil, fmt.Errorf("create PostgreSQL pool: %w", err)
	}
	store := &Store{pool: pool}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping PostgreSQL: %w", err)
	}
	return store, nil
}

func (store *Store) Close() {
	store.pool.Close()
}

func (store *Store) Ping(ctx context.Context) error {
	if err := store.pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping PostgreSQL: %w", err)
	}
	var ready bool
	if err := store.pool.QueryRow(
		ctx,
		`SELECT
			to_regclass('public.schema_migrations') IS NOT NULL
			AND to_regclass('public.users') IS NOT NULL
			AND to_regclass('public.device_authorizations') IS NOT NULL
			AND to_regclass('public.sessions') IS NOT NULL
			AND to_regclass('public.audit_events') IS NOT NULL`,
	).Scan(&ready); err != nil {
		return fmt.Errorf("check PostgreSQL schema readiness: %w", err)
	}
	if !ready {
		return fmt.Errorf("%w: PostgreSQL schema is not migrated", domain.ErrUnavailable)
	}
	versions, err := migrationVersions()
	if err != nil {
		return fmt.Errorf("%w: inspect embedded migrations: %v", domain.ErrUnavailable, err)
	}
	var applied int
	if err := store.pool.QueryRow(
		ctx,
		`SELECT count(*) FROM schema_migrations WHERE version = ANY($1::text[])`,
		versions,
	).Scan(&applied); err != nil {
		return fmt.Errorf("check PostgreSQL migration ledger: %w", err)
	}
	if applied != len(versions) {
		return fmt.Errorf("%w: PostgreSQL schema migrations are incomplete", domain.ErrUnavailable)
	}
	return nil
}

func (store *Store) CreateDeviceAuthorization(
	ctx context.Context,
	authorization auth.DeviceAuthorization,
) error {
	_, err := store.pool.Exec(
		ctx,
		`INSERT INTO device_authorizations (
			device_code_hash, user_code, created_at, expires_at
		) VALUES ($1, $2, $3, $4)`,
		authorization.DeviceCodeHash,
		authorization.UserCode,
		authorization.CreatedAt,
		authorization.ExpiresAt,
	)
	if err != nil {
		return classifyWriteError("create device authorization", err)
	}
	return nil
}

func (store *Store) BindOAuthState(
	ctx context.Context,
	userCode string,
	stateHash []byte,
	now time.Time,
) error {
	transaction, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("%w: begin OAuth state transaction: %w", domain.ErrUnavailable, err)
	}
	defer rollback(transaction)

	var status string
	var expiresAt time.Time
	var existingStateHash []byte
	err = transaction.QueryRow(
		ctx,
		`SELECT status, expires_at, oauth_state_hash
		 FROM device_authorizations
		 WHERE user_code = $1
		 FOR UPDATE`,
		userCode,
	).Scan(&status, &expiresAt, &existingStateHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("%w: load device authorization by user code: %w", domain.ErrUnavailable, err)
	}
	if !expiresAt.After(now) {
		return domain.ErrExpired
	}
	if status != "pending" || len(existingStateHash) != 0 {
		return domain.ErrAlreadyUsed
	}
	if _, err := transaction.Exec(
		ctx,
		`UPDATE device_authorizations SET oauth_state_hash = $1 WHERE user_code = $2`,
		stateHash,
		userCode,
	); err != nil {
		return classifyWriteError("bind OAuth state", err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return fmt.Errorf("%w: commit OAuth state transaction: %w", domain.ErrUnavailable, err)
	}
	return nil
}

func (store *Store) RejectOAuthState(
	ctx context.Context,
	stateHash []byte,
	now time.Time,
) error {
	tag, err := store.pool.Exec(
		ctx,
		`UPDATE device_authorizations
		 SET status = 'denied', oauth_state_hash = NULL
		 WHERE oauth_state_hash = $1
		   AND status = 'pending'
		   AND expires_at > $2`,
		stateHash,
		now,
	)
	if err != nil {
		return classifyWriteError("reject OAuth state", err)
	}
	if tag.RowsAffected() != 1 {
		return domain.ErrUnauthorized
	}
	return nil
}

func (store *Store) ClaimOAuthState(
	ctx context.Context,
	stateHash []byte,
	now time.Time,
) ([]byte, error) {
	transaction, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, fmt.Errorf("%w: begin OAuth state claim transaction: %w", domain.ErrUnavailable, err)
	}
	defer rollback(transaction)

	var deviceCodeHash []byte
	var status string
	var expiresAt time.Time
	err = transaction.QueryRow(
		ctx,
		`SELECT device_code_hash, status, expires_at
		 FROM device_authorizations
		 WHERE oauth_state_hash = $1
		 FOR UPDATE`,
		stateHash,
	).Scan(&deviceCodeHash, &status, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrUnauthorized
	}
	if err != nil {
		return nil, fmt.Errorf("%w: load device authorization by OAuth state: %w", domain.ErrUnavailable, err)
	}
	if !expiresAt.After(now) {
		return nil, domain.ErrExpired
	}
	if status != "pending" {
		return nil, domain.ErrAlreadyUsed
	}

	if _, err := transaction.Exec(
		ctx,
		`UPDATE device_authorizations
		 SET status = 'authorizing', oauth_state_hash = NULL
		 WHERE device_code_hash = $1`,
		deviceCodeHash,
	); err != nil {
		return nil, fmt.Errorf("%w: claim OAuth state: %w", domain.ErrUnavailable, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return nil, fmt.Errorf("%w: commit OAuth state claim transaction: %w", domain.ErrUnavailable, err)
	}
	return append([]byte(nil), deviceCodeHash...), nil
}

func (store *Store) RejectDeviceAuthorization(
	ctx context.Context,
	deviceCodeHash []byte,
	now time.Time,
) error {
	transaction, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("%w: begin authorization rejection transaction: %w", domain.ErrUnavailable, err)
	}
	defer rollback(transaction)

	var status string
	var expiresAt time.Time
	err = transaction.QueryRow(
		ctx,
		`SELECT status, expires_at
		 FROM device_authorizations
		 WHERE device_code_hash = $1
		 FOR UPDATE`,
		deviceCodeHash,
	).Scan(&status, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrUnauthorized
	}
	if err != nil {
		return fmt.Errorf("%w: load claimed device authorization for rejection: %w", domain.ErrUnavailable, err)
	}
	if !expiresAt.After(now) {
		return domain.ErrExpired
	}
	switch status {
	case "authorizing":
	case "denied":
		return nil
	case "approved", "consumed":
		return domain.ErrAlreadyUsed
	default:
		return fmt.Errorf("%w: device authorization was not claimed", domain.ErrConflict)
	}

	if _, err := transaction.Exec(
		ctx,
		`UPDATE device_authorizations
		 SET status = 'denied'
		 WHERE device_code_hash = $1`,
		deviceCodeHash,
	); err != nil {
		return fmt.Errorf("%w: reject device authorization: %w", domain.ErrUnavailable, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return fmt.Errorf("%w: commit authorization rejection transaction: %w", domain.ErrUnavailable, err)
	}
	return nil
}

func (store *Store) CompleteDeviceAuthorization(
	ctx context.Context,
	deviceCodeHash []byte,
	user domain.User,
	now time.Time,
) error {
	transaction, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("%w: begin authorization completion transaction: %w", domain.ErrUnavailable, err)
	}
	defer rollback(transaction)

	var status string
	var expiresAt time.Time
	err = transaction.QueryRow(
		ctx,
		`SELECT status, expires_at
		 FROM device_authorizations
		 WHERE device_code_hash = $1
		 FOR UPDATE`,
		deviceCodeHash,
	).Scan(&status, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrUnauthorized
	}
	if err != nil {
		return fmt.Errorf("%w: load claimed device authorization: %w", domain.ErrUnavailable, err)
	}
	if !expiresAt.After(now) {
		return domain.ErrExpired
	}
	switch status {
	case "authorizing":
	case "approved", "consumed":
		return domain.ErrAlreadyUsed
	default:
		return fmt.Errorf("%w: device authorization was not claimed", domain.ErrConflict)
	}

	_, err = transaction.Exec(
		ctx,
		`INSERT INTO users (
			corp_id, user_id, union_id, display_name, created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $5)
		ON CONFLICT (corp_id, user_id) DO UPDATE SET
			union_id = EXCLUDED.union_id,
			display_name = EXCLUDED.display_name,
			updated_at = EXCLUDED.updated_at`,
		user.CorpID,
		user.UserID,
		user.UnionID,
		user.DisplayName,
		now,
	)
	if err != nil {
		return classifyWriteError("upsert authenticated user", err)
	}
	if _, err := transaction.Exec(
		ctx,
		`UPDATE device_authorizations
		 SET status = 'approved',
		     corp_id = $1,
		     user_id = $2,
		     authorized_at = $3
		 WHERE device_code_hash = $4`,
		user.CorpID,
		user.UserID,
		now,
		deviceCodeHash,
	); err != nil {
		return fmt.Errorf("%w: approve device authorization: %w", domain.ErrUnavailable, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return fmt.Errorf("%w: commit authorization completion transaction: %w", domain.ErrUnavailable, err)
	}
	return nil
}

func (store *Store) ExchangeDeviceAuthorization(
	ctx context.Context,
	deviceCodeHash []byte,
	session auth.SessionSeed,
	now time.Time,
) (domain.User, error) {
	transaction, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return domain.User{}, fmt.Errorf("%w: begin device exchange transaction: %w", domain.ErrUnavailable, err)
	}
	defer rollback(transaction)

	var status string
	var expiresAt time.Time
	var corpID *string
	var userID *string
	err = transaction.QueryRow(
		ctx,
		`SELECT status, expires_at, corp_id, user_id
		 FROM device_authorizations
		 WHERE device_code_hash = $1
		 FOR UPDATE`,
		deviceCodeHash,
	).Scan(&status, &expiresAt, &corpID, &userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.User{}, domain.ErrUnauthorized
	}
	if err != nil {
		return domain.User{}, fmt.Errorf("%w: load device authorization by device code: %w", domain.ErrUnavailable, err)
	}
	if !expiresAt.After(now) {
		return domain.User{}, domain.ErrExpired
	}
	switch status {
	case "pending", "authorizing":
		return domain.User{}, domain.ErrAuthorizationPending
	case "denied":
		return domain.User{}, domain.ErrForbidden
	case "consumed":
		return domain.User{}, domain.ErrAlreadyUsed
	case "approved":
	default:
		return domain.User{}, fmt.Errorf("%w: invalid device authorization status", domain.ErrConflict)
	}
	if corpID == nil || userID == nil {
		return domain.User{}, fmt.Errorf("%w: approved authorization has no user", domain.ErrConflict)
	}

	user, err := loadUser(ctx, transaction, *corpID, *userID)
	if err != nil {
		return domain.User{}, err
	}
	if err := insertSession(ctx, transaction, user, session, now); err != nil {
		return domain.User{}, err
	}
	if _, err := transaction.Exec(
		ctx,
		`UPDATE device_authorizations
		 SET status = 'consumed', consumed_at = $1
		 WHERE device_code_hash = $2`,
		now,
		deviceCodeHash,
	); err != nil {
		return domain.User{}, fmt.Errorf("%w: consume device authorization: %w", domain.ErrUnavailable, err)
	}
	if err := transaction.Commit(ctx); err != nil {
		return confirmDeviceExchangeCommit(
			ctx,
			session.AccessTokenHash,
			now,
			err,
			store.GetSessionByAccessToken,
		)
	}
	return user, nil
}

func confirmDeviceExchangeCommit(
	ctx context.Context,
	accessTokenHash []byte,
	now time.Time,
	commitErr error,
	lookup func(context.Context, []byte, time.Time) (domain.User, error),
) (domain.User, error) {
	confirmationContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	defer cancel()
	user, err := lookup(confirmationContext, accessTokenHash, now)
	if err == nil {
		return user, nil
	}
	return domain.User{}, fmt.Errorf(
		"%w: commit device exchange transaction: %v; confirmation failed: %v",
		domain.ErrUnavailable,
		commitErr,
		err,
	)
}

func (store *Store) GetSessionByAccessToken(
	ctx context.Context,
	accessTokenHash []byte,
	now time.Time,
) (domain.User, error) {
	var user domain.User
	err := store.pool.QueryRow(
		ctx,
		`SELECT u.corp_id, u.user_id, u.union_id, u.display_name
		 FROM sessions AS s
		 JOIN users AS u
		   ON u.corp_id = s.corp_id AND u.user_id = s.user_id
		 WHERE s.access_token_hash = $1
		   AND s.revoked_at IS NULL
		   AND s.access_expires_at > $2`,
		accessTokenHash,
		now,
	).Scan(&user.CorpID, &user.UserID, &user.UnionID, &user.DisplayName)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.User{}, domain.ErrUnauthorized
	}
	if err != nil {
		return domain.User{}, fmt.Errorf("%w: load session by access token: %w", domain.ErrUnavailable, err)
	}
	return user, nil
}

func (store *Store) RotateSession(
	ctx context.Context,
	refreshTokenHash []byte,
	replacement auth.SessionSeed,
	now time.Time,
) (domain.User, error) {
	transaction, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return domain.User{}, fmt.Errorf("%w: begin session rotation transaction: %w", domain.ErrUnavailable, err)
	}
	defer rollback(transaction)

	var sessionID int64
	var refreshExpiresAt time.Time
	var revokedAt *time.Time
	var user domain.User
	err = transaction.QueryRow(
		ctx,
		`SELECT s.id, s.refresh_expires_at, s.revoked_at,
		        u.corp_id, u.user_id, u.union_id, u.display_name
		 FROM sessions AS s
		 JOIN users AS u
		   ON u.corp_id = s.corp_id AND u.user_id = s.user_id
		 WHERE s.refresh_token_hash = $1
		 FOR UPDATE OF s`,
		refreshTokenHash,
	).Scan(
		&sessionID,
		&refreshExpiresAt,
		&revokedAt,
		&user.CorpID,
		&user.UserID,
		&user.UnionID,
		&user.DisplayName,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.User{}, domain.ErrUnauthorized
	}
	if err != nil {
		return domain.User{}, fmt.Errorf("%w: load session by refresh token: %w", domain.ErrUnavailable, err)
	}
	if revokedAt != nil || !refreshExpiresAt.After(now) {
		return domain.User{}, domain.ErrUnauthorized
	}
	if _, err := transaction.Exec(
		ctx,
		`UPDATE sessions SET revoked_at = $1 WHERE id = $2`,
		now,
		sessionID,
	); err != nil {
		return domain.User{}, fmt.Errorf("%w: revoke rotated session: %w", domain.ErrUnavailable, err)
	}
	if err := insertSession(ctx, transaction, user, replacement, now); err != nil {
		return domain.User{}, err
	}
	if err := transaction.Commit(ctx); err != nil {
		return domain.User{}, fmt.Errorf("%w: commit session rotation transaction: %w", domain.ErrUnavailable, err)
	}
	return user, nil
}

func (store *Store) RevokeSession(
	ctx context.Context,
	accessTokenHash []byte,
	now time.Time,
) error {
	tag, err := store.pool.Exec(
		ctx,
		`UPDATE sessions
		 SET revoked_at = $1
		 WHERE access_token_hash = $2 AND revoked_at IS NULL`,
		now,
		accessTokenHash,
	)
	if err != nil {
		return fmt.Errorf("%w: revoke session: %w", domain.ErrUnavailable, err)
	}
	if tag.RowsAffected() != 1 {
		return domain.ErrUnauthorized
	}
	return nil
}

func (store *Store) RecordAudit(ctx context.Context, event domain.AuditEvent) error {
	if err := event.Validate(); err != nil {
		return err
	}
	_, err := store.pool.Exec(
		ctx,
		`INSERT INTO audit_events (
			request_id, corp_id, actor_user_id, action, process_instance_id,
			file_id, decision, upstream_error_class, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		event.RequestID,
		event.CorpID,
		event.ActorUserID,
		event.Action,
		event.ProcessInstanceID,
		event.FileID,
		event.Decision,
		event.UpstreamErrorClass,
		event.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("%w: record audit event: %w", domain.ErrUnavailable, err)
	}
	return nil
}

func (store *Store) PruneAudit(ctx context.Context, before time.Time) (int64, error) {
	tag, err := store.pool.Exec(
		ctx,
		`DELETE FROM audit_events WHERE created_at < $1`,
		before,
	)
	if err != nil {
		return 0, fmt.Errorf("prune audit events: %w", err)
	}
	return tag.RowsAffected(), nil
}

func (store *Store) PruneAuthenticationState(
	ctx context.Context,
	before time.Time,
) (AuthenticationPruneResult, error) {
	transaction, err := store.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return AuthenticationPruneResult{}, fmt.Errorf(
			"begin authentication state prune transaction: %w",
			err,
		)
	}
	defer rollback(transaction)

	sessionTag, err := transaction.Exec(
		ctx,
		`DELETE FROM sessions
		 WHERE (refresh_expires_at < $1 AND access_expires_at < $1)
		    OR (revoked_at IS NOT NULL AND revoked_at < $1)`,
		before,
	)
	if err != nil {
		return AuthenticationPruneResult{}, fmt.Errorf("prune sessions: %w", err)
	}
	authorizationTag, err := transaction.Exec(
		ctx,
		`DELETE FROM device_authorizations WHERE expires_at < $1`,
		before,
	)
	if err != nil {
		return AuthenticationPruneResult{}, fmt.Errorf(
			"prune device authorizations: %w",
			err,
		)
	}
	if err := transaction.Commit(ctx); err != nil {
		return AuthenticationPruneResult{}, fmt.Errorf(
			"commit authentication state prune transaction: %w",
			err,
		)
	}
	return AuthenticationPruneResult{
		DeviceAuthorizations: authorizationTag.RowsAffected(),
		Sessions:             sessionTag.RowsAffected(),
	}, nil
}

type queryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

type executor interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

func loadUser(
	ctx context.Context,
	query queryer,
	corpID string,
	userID string,
) (domain.User, error) {
	var user domain.User
	err := query.QueryRow(
		ctx,
		`SELECT corp_id, user_id, union_id, display_name
		 FROM users
		 WHERE corp_id = $1 AND user_id = $2`,
		corpID,
		userID,
	).Scan(&user.CorpID, &user.UserID, &user.UnionID, &user.DisplayName)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.User{}, fmt.Errorf("%w: session user does not exist", domain.ErrConflict)
	}
	if err != nil {
		return domain.User{}, fmt.Errorf("%w: load user: %w", domain.ErrUnavailable, err)
	}
	return user, nil
}

func insertSession(
	ctx context.Context,
	exec executor,
	user domain.User,
	session auth.SessionSeed,
	now time.Time,
) error {
	_, err := exec.Exec(
		ctx,
		`INSERT INTO sessions (
			corp_id, user_id, access_token_hash, refresh_token_hash,
			access_expires_at, refresh_expires_at, created_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		user.CorpID,
		user.UserID,
		session.AccessTokenHash,
		session.RefreshTokenHash,
		session.AccessExpiresAt,
		session.RefreshExpiresAt,
		now,
	)
	if err != nil {
		return classifyWriteError("create session", err)
	}
	return nil
}

type transactionRollbacker interface {
	Rollback(context.Context) error
}

func rollback(transaction transactionRollbacker) {
	if transaction == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), rollbackTimeout)
	defer cancel()
	_ = transaction.Rollback(ctx)
}

func classifyWriteError(operation string, err error) error {
	var postgresError *pgconn.PgError
	if errors.As(err, &postgresError) && postgresError.Code == "23505" {
		return fmt.Errorf("%w: %s", domain.ErrConflict, operation)
	}
	return fmt.Errorf("%w: %s: %v", domain.ErrUnavailable, operation, err)
}
