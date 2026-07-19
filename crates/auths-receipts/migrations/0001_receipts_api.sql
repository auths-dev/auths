-- receipts-api data model (plan RC-E3.3.1).
-- Every table is tenant-scoped by account_id; every query filters on it.
-- A row from another account is a 404, never a 403 — no enumeration oracle.
--
-- Timestamps are timestamptz; the application binds RFC-3339 text and casts.
-- JSON payloads are jsonb; the application binds text and casts ($n::jsonb) —
-- the sqlx json/chrono features are deliberately off (see the crate manifest).

CREATE TABLE IF NOT EXISTS api_accounts (
    id            text PRIMARY KEY,
    name          text NOT NULL,
    auths_root    text,
    billing_mode  text NOT NULL DEFAULT 'metered'
                  CHECK (billing_mode IN ('retainer', 'metered', 'contract')),
    retainer_included_bundles integer NOT NULL DEFAULT 0,
    overage_cents integer NOT NULL DEFAULT 0,
    price_book    jsonb NOT NULL DEFAULT '{}'::jsonb,
    status        text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    created_at    timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
    id           text PRIMARY KEY,
    account_id   text NOT NULL REFERENCES api_accounts(id),
    key_prefix   text NOT NULL UNIQUE,
    key_hash     text NOT NULL,
    name         text NOT NULL DEFAULT '',
    scopes       text[] NOT NULL DEFAULT '{}',
    created_at   timestamptz NOT NULL,
    last_used_at timestamptz,
    revoked_at   timestamptz
);

CREATE TABLE IF NOT EXISTS bundles (
    id             text PRIMARY KEY,
    account_id     text NOT NULL REFERENCES api_accounts(id),
    dispute_ref    text,
    subject_root   text NOT NULL,
    subject_agent  text NOT NULL,
    settlement_tx  text NOT NULL,
    call_index     integer NOT NULL,
    log_hash       text NOT NULL,
    call_verdict   text NOT NULL,
    log_verdict    text NOT NULL,
    anchor_tier    text NOT NULL,
    -- S3: bundle_json already carries only args_hash — no column may re-expand
    -- hashed fields.
    bundle_json    jsonb NOT NULL,
    size_bytes     integer NOT NULL,
    created_at     timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS bundles_dispute_ref ON bundles (account_id, dispute_ref);
CREATE INDEX IF NOT EXISTS bundles_created ON bundles (account_id, created_at DESC);

CREATE TABLE IF NOT EXISTS usage_events (
    id              text PRIMARY KEY,
    account_id      text NOT NULL REFERENCES api_accounts(id),
    api_key_id      text NOT NULL REFERENCES api_keys(id),
    kind            text NOT NULL
                    CHECK (kind IN ('bundle_build', 'dispute_evidence', 'verify', 'export', 'reversal')),
    unit_cost_cents integer NOT NULL DEFAULT 0,
    bundle_id       text REFERENCES bundles(id),
    idempotency_key text,
    metadata        jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at      timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS usage_events_account ON usage_events (account_id, created_at);

CREATE TABLE IF NOT EXISTS idempotency_keys (
    account_id    text NOT NULL REFERENCES api_accounts(id),
    key           text NOT NULL,
    request_hash  text NOT NULL,
    response_json jsonb NOT NULL,
    status_code   integer NOT NULL,
    created_at    timestamptz NOT NULL,
    PRIMARY KEY (account_id, key)
);

CREATE TABLE IF NOT EXISTS usage_rollups (
    account_id    text NOT NULL REFERENCES api_accounts(id),
    period        text NOT NULL,
    by_kind       jsonb NOT NULL,
    total_cents   bigint NOT NULL,
    rolled_up_at  timestamptz NOT NULL,
    PRIMARY KEY (account_id, period)
);
