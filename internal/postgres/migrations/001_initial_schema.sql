CREATE TABLE users (
    corp_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    union_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (corp_id, user_id),
    UNIQUE (corp_id, union_id)
);

CREATE TABLE device_authorizations (
    device_code_hash BYTEA PRIMARY KEY,
    user_code TEXT NOT NULL UNIQUE,
    oauth_state_hash BYTEA UNIQUE,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'authorizing', 'approved', 'denied', 'consumed')),
    corp_id TEXT,
    user_id TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    authorized_at TIMESTAMPTZ,
    consumed_at TIMESTAMPTZ,
    FOREIGN KEY (corp_id, user_id) REFERENCES users (corp_id, user_id),
    CHECK (
        (corp_id IS NULL AND user_id IS NULL)
        OR (corp_id IS NOT NULL AND user_id IS NOT NULL)
    )
);

CREATE INDEX device_authorizations_expires_at_idx
    ON device_authorizations (expires_at);

CREATE TABLE sessions (
    id BIGSERIAL PRIMARY KEY,
    corp_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    access_token_hash BYTEA NOT NULL UNIQUE,
    refresh_token_hash BYTEA NOT NULL UNIQUE,
    access_expires_at TIMESTAMPTZ NOT NULL,
    refresh_expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    FOREIGN KEY (corp_id, user_id) REFERENCES users (corp_id, user_id)
);

CREATE INDEX sessions_access_lookup_idx
    ON sessions (access_token_hash, access_expires_at)
    WHERE revoked_at IS NULL;

CREATE INDEX sessions_refresh_lookup_idx
    ON sessions (refresh_token_hash, refresh_expires_at)
    WHERE revoked_at IS NULL;

CREATE TABLE audit_events (
    id BIGSERIAL PRIMARY KEY,
    request_id TEXT NOT NULL,
    corp_id TEXT NOT NULL,
    actor_user_id TEXT NOT NULL,
    action TEXT NOT NULL,
    process_instance_id TEXT NOT NULL,
    file_id TEXT NOT NULL DEFAULT '',
    decision TEXT NOT NULL CHECK (decision IN ('allowed', 'denied')),
    upstream_error_class TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX audit_events_created_at_idx ON audit_events (created_at);
CREATE INDEX audit_events_actor_idx
    ON audit_events (corp_id, actor_user_id, created_at DESC);
