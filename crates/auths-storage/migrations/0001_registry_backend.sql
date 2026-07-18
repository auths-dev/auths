-- Postgres registry backend schema (task #6, performance initiative).
--
-- Design intent (see docs/plans/storage/registry-backend-decision.md, Option B):
-- reproduce the observable semantics of the single-writer GitRegistryBackend —
-- append-only per-prefix event logs, monotonic key-state, attestation history,
-- org members, tenant metadata — but WITHOUT a global lock. Concurrency safety
-- lives in the constraints below, not in an exclusive file lock:
--
--   * registry_events PRIMARY KEY (tenant, prefix, seq) is the CAS-equivalent:
--     two writers racing the same sequence number -> exactly one INSERT wins,
--     the other hits a unique violation (mapped to RegistryError::EventExists),
--     mirroring the git backend's CAS abort. Writers to DIFFERENT identities
--     touch DIFFERENT rows and never serialize.
--   * registry_key_state advances only forward; the append path and
--     write_key_state both guard the UPDATE so a stored key-state never rolls
--     back to a lower sequence.
--
-- Sequence numbers are the domain u128; NUMERIC(40,0) holds the full range
-- (u128::MAX has 39 digits). Bound and read as text so no decimal crate is
-- needed; ORDER BY / comparisons stay numeric.
--
-- Timestamps are stored as BIGINT epoch-milliseconds so the backend needs no
-- extra sqlx type feature (the `chrono` feature transitively pulls sqlx-sqlite,
-- which collides on the `sqlite3` native `links` with auths-index). Millisecond
-- precision is ample for metadata and attestation staleness ordering.

-- Tenant metadata backing init_if_needed() and metadata().
CREATE TABLE IF NOT EXISTS registry_tenants (
    tenant     TEXT   NOT NULL PRIMARY KEY,
    status     TEXT   NOT NULL DEFAULT 'active',
    created_at BIGINT NOT NULL
);

-- Append-only KEL events. The composite primary key is the concurrency-safety
-- mechanism; event_bytes/attachment are stored verbatim (BYTEA) so a KEL can be
-- re-derived and authenticated offline.
CREATE TABLE IF NOT EXISTS registry_events (
    tenant      TEXT          NOT NULL,
    prefix      TEXT          NOT NULL,
    seq         NUMERIC(40,0) NOT NULL CHECK (seq >= 0),
    said        TEXT          NOT NULL,
    event_bytes BYTEA         NOT NULL,
    attachment  BYTEA,
    created_at  BIGINT        NOT NULL,
    PRIMARY KEY (tenant, prefix, seq)
);

-- One monotonic key-state row per identity. Doubles as the tip (sequence, said)
-- and the cached KeyState (state_bytes). Never decreases in sequence.
CREATE TABLE IF NOT EXISTS registry_key_state (
    tenant      TEXT          NOT NULL,
    prefix      TEXT          NOT NULL,
    sequence    NUMERIC(40,0) NOT NULL CHECK (sequence >= 0),
    said        TEXT          NOT NULL,
    state_bytes BYTEA         NOT NULL,
    updated_at  BIGINT        NOT NULL,
    PRIMARY KEY (tenant, prefix)
);

-- Append-only device-attestation history. The "current" attestation for a
-- device is the row with the greatest id for (tenant, subject_did).
CREATE TABLE IF NOT EXISTS registry_attestations (
    id          BIGSERIAL PRIMARY KEY,
    tenant      TEXT      NOT NULL,
    subject_did TEXT      NOT NULL,
    rid         TEXT      NOT NULL,
    att_bytes   BYTEA     NOT NULL,
    att_ts      BIGINT,
    revoked_at  BIGINT,
    expires_at  BIGINT,
    created_at  BIGINT    NOT NULL
);
CREATE INDEX IF NOT EXISTS registry_attestations_subject_idx
    ON registry_attestations (tenant, subject_did, id);

-- Latest-view org -> member attestation (overwrites on re-store).
CREATE TABLE IF NOT EXISTS registry_org_members (
    tenant       TEXT   NOT NULL,
    org          TEXT   NOT NULL,
    member_did   TEXT   NOT NULL,
    member_bytes BYTEA  NOT NULL,
    updated_at   BIGINT NOT NULL,
    PRIMARY KEY (tenant, org, member_did)
);
