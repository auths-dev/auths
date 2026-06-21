-- Auth sessions table for the Auths auth server.
--
-- Uses native PostgreSQL types:
--   UUID       → sqlx maps uuid::Uuid directly (no TEXT round-trip)
--   TIMESTAMPTZ → sqlx maps chrono::DateTime<Utc> directly (no RFC3339 parsing)
--   status TEXT CHECK(...) preferred over CREATE TYPE ENUM for easier evolution

CREATE TABLE IF NOT EXISTS auth_sessions (
    id           UUID        PRIMARY KEY,
    nonce        TEXT        NOT NULL,
    domain       TEXT        NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ NOT NULL,
    status       TEXT        NOT NULL
        CHECK (status IN ('pending', 'verified', 'expired')),
    verified_did TEXT,
    verified_at  TIMESTAMPTZ
);

-- Used by the cleanup loop to find expired sessions efficiently.
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at
    ON auth_sessions (expires_at);

-- Used for nonce lookup and potential uniqueness checks.
CREATE INDEX IF NOT EXISTS idx_sessions_nonce
    ON auth_sessions (nonce);

-- Partial index: list_active() only reads pending sessions.
CREATE INDEX IF NOT EXISTS idx_sessions_status_pending
    ON auth_sessions (status) WHERE status = 'pending';
