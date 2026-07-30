CREATE INDEX sessions_refresh_expires_at_idx
    ON sessions (refresh_expires_at);

CREATE INDEX sessions_revoked_at_idx
    ON sessions (revoked_at)
    WHERE revoked_at IS NOT NULL;
