-- Dynamically registered OIDC clients (RFC 7591).
--
-- client_secret_hash and registration_access_token_hash store Argon2 hashes.
-- JSONB columns store arrays for redirect_uris, grant_types, response_types.

CREATE TABLE IF NOT EXISTS registered_clients (
    client_id                      TEXT PRIMARY KEY,
    client_name                    TEXT,
    keri_aid                       TEXT NOT NULL,
    client_secret_hash             TEXT,
    redirect_uris                  JSONB NOT NULL DEFAULT '[]',
    grant_types                    JSONB NOT NULL DEFAULT '["authorization_code"]',
    response_types                 JSONB NOT NULL DEFAULT '["code"]',
    token_endpoint_auth_method     TEXT NOT NULL DEFAULT 'client_secret_basic',
    registration_access_token_hash TEXT NOT NULL UNIQUE,
    jwks                           JSONB,
    created_at                     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at                     TIMESTAMPTZ,
    revoked_at                     TIMESTAMPTZ
);

-- Fast lookup by KERI AID (list all clients for a given identity).
CREATE INDEX IF NOT EXISTS idx_registered_clients_keri_aid
    ON registered_clients (keri_aid);

-- Partial index for cleanup of expired clients.
CREATE INDEX IF NOT EXISTS idx_registered_clients_expires_at
    ON registered_clients (expires_at) WHERE expires_at IS NOT NULL;
