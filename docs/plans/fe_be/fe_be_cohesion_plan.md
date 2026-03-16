# Frontend-Backend Integration Audit

**Date:** 2026-03-16
**Repos audited:**
- `auths-site` — Next.js 16 frontend (`apps/web/src/`)
- `auths-cloud/crates/auths-registry-server` — Axum registry API
- `auths-cloud/crates/auths-auth-server` — Axum auth API
- `auths-cloud/crates/auths-cache` — Redis/Git tiered cache
- `auths` — CLI and core Rust crates

**Scope:** Full-stack trace of all API endpoints the frontend calls, covering contract alignment, auth piping, SQL schema, error contracts, fixture drift, and naming consistency.

---

## Epic 1: Backend Identity Response Shape Does Not Match Frontend Contract

Summary: The backend `IdentityResponse::Active` nests key data under `key_state.current_keys` (array of KERI strings), but the frontend expects top-level `public_keys` (array of `{ key_id, algorithm, public_key_hex, created_at }` objects). The frontend's `fetchIdentity()` papers over this with a transformation that fabricates `key_id`, hardcodes `algorithm`, and fabricates `created_at`. Meanwhile `fetchBatchIdentities()` skips the transformation entirely, so `public_keys` is `undefined` on batch-fetched identities. Since there's no backwards compatibility concern, fix the backend to return the shape the frontend needs.

### Task 1: Flatten `public_keys` into `IdentityResponse::Active` on the backend

**Repo:** `auths-cloud`
**File:** `crates/auths-registry-server/src/routes/identity.rs`
**Lines:** ~39–91

**Problem:**
Backend returns `key_state: { current_keys: ["Dbase64url..."], next_commitment, last_event_said, is_abandoned }`. Frontend wants `public_keys: [{ key_id, algorithm, public_key_hex, created_at }]` and `is_abandoned` at the top level. The frontend fabricates `key_id` as `"key-{index}"`, hardcodes `algorithm` as `"Ed25519"`, and sets `created_at` to `new Date().toISOString()` (a lie). The `fetchBatchIdentities()` path doesn't do this transformation at all, so batch-fetched identities have no `public_keys`.

**Current code:**
```rust
#[serde(tag = "status")]
pub enum IdentityResponse {
    #[serde(rename = "active")]
    Active {
        did: String,
        sequence: u64,
        key_state: KeyStateResponse,
        platform_claims: Vec<PlatformClaimResponse>,
        artifacts: Vec<ArtifactEntryResponse>,
        trust_tier: Option<String>,
        trust_score: Option<u32>,
    },
    #[serde(rename = "unclaimed")]
    Unclaimed { did: String },
}
```

**Fixed code:**
```rust
#[derive(Debug, Serialize, JsonSchema)]
pub struct PublicKeyResponse {
    pub key_id: String,
    pub algorithm: String,
    pub public_key_hex: String,
    pub created_at: String,
}

#[serde(tag = "status")]
pub enum IdentityResponse {
    #[serde(rename = "active")]
    Active {
        did: String,
        sequence: u64,
        public_keys: Vec<PublicKeyResponse>,
        is_abandoned: bool,
        platform_claims: Vec<PlatformClaimResponse>,
        artifacts: Vec<ArtifactEntryResponse>,
        trust_tier: Option<String>,
        trust_score: Option<u32>,
    },
    #[serde(rename = "unclaimed")]
    Unclaimed { did: String },
}
```

Construct `public_keys` in the handler by mapping `key_state.current_keys` with their index as `key_id`, the algorithm from KERI key prefix (`"D"` → Ed25519), and `created_at` from `identity_state.updated_at`. Keep `KeyStateResponse` as an internal type if needed for KEL operations, but don't expose it in the identity response.

**Why:** Eliminates the entire frontend transformation layer. Both `fetchIdentity()` and `fetchBatchIdentities()` become simple pass-throughs. Fixes the batch identity bug and removes fabricated data.

---

### Task 2: Remove frontend `key_state → public_keys` transformation

**Repo:** `auths-site`
**File:** `apps/web/src/lib/api/registry.ts`
**Lines:** ~350–411

**Problem:**
After Task 1, the backend returns `public_keys` directly. The manual transformation in `fetchIdentity()` (lines 370–411) is now dead code that would double-wrap the data.

**Current code:**
```typescript
const keyState = (data.key_state ?? {}) as Record<string, unknown>;
const currentKeys = Array.isArray(keyState.current_keys)
  ? (keyState.current_keys as string[])
  : [];
const public_keys = currentKeys.map((key, i) => ({
  key_id: `key-${i}`,
  algorithm: 'Ed25519',
  public_key_hex: key,
  created_at: new Date().toISOString(),
}));
// ... 40 lines of manual reshaping
```

**Fixed code:**
```typescript
export async function fetchIdentity(
  did: string,
  signal?: AbortSignal,
): Promise<IdentityResponse> {
  if (USE_FIXTURES) {
    const fixture = await resolveIdentityFixture(did);
    if (fixture) return fixture;
  }
  return registryFetch<IdentityResponse>(
    `/v1/identities/${encodeURIComponent(did)}`,
    undefined,
    signal,
  );
}
```

Simple pass-through — the backend now returns the exact shape the frontend needs.

**Why:** ~40 lines of fragile transformation code replaced by a direct cast. No more fabricated fields.

---

## Epic 2: Invite-Accepted Members Get Zero Capabilities

Summary: When a user accepts an org invite, the `accept_invite` handler inserts an `org_members` row with `capabilities = '[]'` (empty JSON array), regardless of role. This means invite-accepted members — even admins — cannot perform any operations until an admin manually updates their capabilities.

### Task 1: Assign default capabilities based on role on invite acceptance

**Repo:** `auths-cloud`
**File:** `crates/auths-registry-server/src/routes/invite.rs`
**Lines:** ~222–232

**Problem:**
`accept_invite` sets `capabilities` to `'[]'` for all members. Compare with `create_org` which gives the founder `["sign_commit", "sign_release", "manage_members", "rotate_keys"]`. An admin who joins via invite gets zero capabilities.

**Current code:**
```rust
sqlx::query(
    "INSERT INTO org_members (org_did, member_did, role, capabilities, log_sequence, granted_at) \
     VALUES ($1, $2, $3, '[]', 0, NOW()) \
     ON CONFLICT (org_did, member_did) DO NOTHING",
)
.bind(&org_did)
.bind(&identity.did)
.bind(&role)
.execute(pool)
.await
```

**Fixed code:**
```rust
let capabilities = match role.as_str() {
    "admin" => serde_json::json!(["sign_commit", "sign_release", "manage_members", "rotate_keys"]),
    "member" => serde_json::json!(["sign_commit", "sign_release"]),
    _ => serde_json::json!([]),
};

sqlx::query(
    "INSERT INTO org_members (org_did, member_did, role, capabilities, log_sequence, granted_at) \
     VALUES ($1, $2, $3, $4, 0, NOW()) \
     ON CONFLICT (org_did, member_did) DO UPDATE SET role = $3, capabilities = $4, revoked_at = NULL",
)
.bind(&org_did)
.bind(&identity.did)
.bind(&role)
.bind(&capabilities)
.execute(pool)
.await
```

**Why:** Without this, every member who joins via invite link has no signing or management capabilities. The `ON CONFLICT DO UPDATE` also fixes the silent-drop issue (see Epic 4).

---

## Epic 3: Log Sequence Race Condition in Org Creation

Summary: `create_org` calculates the next `log_sequence` via `SELECT COALESCE(MAX(log_sequence), -1) + 1` without any locking. Concurrent org creations get duplicate sequences. The `ON CONFLICT (log_sequence) DO NOTHING` silently drops the second org's activity log entry.

### Task 1: Use a sequence or advisory lock for log_sequence generation in create_org

**Repo:** `auths-cloud`
**File:** `crates/auths-registry-server/src/routes/org.rs`
**Lines:** ~390–410

**Problem:**
Two concurrent `POST /v1/orgs` requests both read `MAX(log_sequence)` as N, both try to insert N+1, one succeeds and the other's `ON CONFLICT DO NOTHING` silently drops the log entry. The second org's creation and member addition are never recorded in the activity feed.

**Current code:**
```rust
let create_seq: i64 = sqlx::query_scalar::<_, i64>(
    "SELECT COALESCE(MAX(log_sequence), -1) + 1 FROM log_entries",
)
.fetch_one(pool)
.await
.map_err(|e| ApiError::StorageError(format!("log sequence query failed: {e}")))?;

sqlx::query(
    "INSERT INTO log_entries \
     (log_sequence, entry_type, actor_did, summary, metadata, \
      merkle_included, is_genesis_phase, occurred_at) \
     VALUES ($1, 'org_create', $2, $3, $4, TRUE, FALSE, NOW()) \
     ON CONFLICT (log_sequence) DO NOTHING",
)
```

**Fixed code:**
```rust
let create_seq: i64 = sqlx::query_scalar::<_, i64>(
    "INSERT INTO log_entries \
     (log_sequence, entry_type, actor_did, summary, metadata, \
      merkle_included, is_genesis_phase, occurred_at) \
     VALUES (\
       (SELECT COALESCE(MAX(log_sequence), -1) + 1 FROM log_entries), \
       'org_create', $1, $2, $3, TRUE, FALSE, NOW()\
     ) \
     RETURNING log_sequence",
)
.bind(&org_did)
.bind(format!("Organization created: {}", &body.display_name))
.bind(serde_json::json!({"display_name": &body.display_name}))
.fetch_one(pool)
.await
.map_err(|e| ApiError::StorageError(format!("org create log entry failed: {e}")))?;
```

Alternatively, use a Postgres `SEQUENCE` (like the fallback path in `register_identity` already uses `genesis_log_seq`).

**Why:** Without this fix, concurrent org creations silently lose activity log entries — the transparency feed is incomplete.

---

### Task 2: Same race in member_seq calculation

**Repo:** `auths-cloud`
**File:** `crates/auths-registry-server/src/routes/org.rs`
**Lines:** ~413, ~429–442

**Problem:**
`member_seq = create_seq + 1` assumes no other entry was inserted between the two writes. If the first entry was dropped due to conflict (pre-fix) or another concurrent writer grabbed `create_seq + 1`, the member addition log entry is also lost.

**Current code:**
```rust
let member_seq = create_seq + 1;

sqlx::query(
    "INSERT INTO log_entries \
     (log_sequence, entry_type, ...) \
     VALUES ($1, 'org_add_member', ...) \
     ON CONFLICT (log_sequence) DO NOTHING",
)
.bind(member_seq)
```

**Fixed code:**
Use the same atomic INSERT...RETURNING pattern as Task 1, or wrap both inserts in a transaction.

**Why:** Same race condition as Task 1, affecting the member addition log entry.

---

## Epic 4: org_members ON CONFLICT DO NOTHING Silently Drops Updates

Summary: Both `create_org` and `accept_invite` use `ON CONFLICT (org_did, member_did) DO NOTHING` when inserting members. If the member row already exists (e.g., re-invited after revocation, or partial retry), the update is silently lost.

### Task 1: Change ON CONFLICT to DO UPDATE in create_org admin insert

**Repo:** `auths-cloud`
**File:** `crates/auths-registry-server/src/routes/org.rs`
**Lines:** ~416–426

**Problem:**
If an org is partially created (identity_state row exists from a previous attempt), the admin member insert silently does nothing on retry. The admin has no capabilities.

**Current code:**
```rust
sqlx::query(
    "INSERT INTO org_members (org_did, member_did, role, capabilities, log_sequence, granted_at) \
     VALUES ($1, $2, 'admin', $3, $4, NOW()) \
     ON CONFLICT (org_did, member_did) DO NOTHING",
)
```

**Fixed code:**
```rust
sqlx::query(
    "INSERT INTO org_members (org_did, member_did, role, capabilities, log_sequence, granted_at) \
     VALUES ($1, $2, 'admin', $3, $4, NOW()) \
     ON CONFLICT (org_did, member_did) DO UPDATE SET \
       role = EXCLUDED.role, \
       capabilities = EXCLUDED.capabilities, \
       revoked_at = NULL",
)
```

**Why:** Without `DO UPDATE`, a partially-failed org creation followed by a retry leaves the admin with stale or missing capabilities.

---

### Task 2: Change ON CONFLICT to DO UPDATE in accept_invite

**Repo:** `auths-cloud`
**File:** `crates/auths-registry-server/src/routes/invite.rs`
**Lines:** ~222–232

**Problem:**
If an admin revokes a member and then re-invites them, the `accept_invite` handler's `DO NOTHING` means the member row still has `revoked_at` set — they appear revoked despite accepting a new invite.

**Current code:**
```rust
sqlx::query(
    "INSERT INTO org_members (org_did, member_did, role, capabilities, log_sequence, granted_at) \
     VALUES ($1, $2, $3, '[]', 0, NOW()) \
     ON CONFLICT (org_did, member_did) DO NOTHING",
)
```

**Fixed code:**
```rust
sqlx::query(
    "INSERT INTO org_members (org_did, member_did, role, capabilities, log_sequence, granted_at) \
     VALUES ($1, $2, $3, $4, 0, NOW()) \
     ON CONFLICT (org_did, member_did) DO UPDATE SET \
       role = EXCLUDED.role, \
       capabilities = EXCLUDED.capabilities, \
       revoked_at = NULL, \
       granted_at = EXCLUDED.granted_at",
)
```

**Why:** Without `DO UPDATE`, re-invited members stay revoked and new invite data is silently dropped.

---

## Epic 5: Invite Not Found Returns IDENTITY_NOT_FOUND Error Code

Summary: The `get_invite` and `accept_invite` handlers return `ApiError::IdentityNotFound("invite not found")` when an invite code is invalid, producing HTTP 404 with error code `IDENTITY_NOT_FOUND`. The error code is semantically wrong.

### Task 1: Add InviteNotFound error variant or use generic NotFound

**Repo:** `auths-cloud`
**File:** `crates/auths-registry-server/src/routes/invite.rs`
**Lines:** 127, 204

**Problem:**
Frontend checks `error.status === 404` (correct), but the error code `IDENTITY_NOT_FOUND` is confusing for invite endpoints — it suggests an identity issue, not an invalid invite code.

**Current code:**
```rust
return Err(ApiError::IdentityNotFound("invite not found".into()));
```

**Fixed code:**
```rust
// In error.rs, add:
#[error("invite not found: {0}")]
InviteNotFound(String),
// Map to: status 404, code "INVITE_NOT_FOUND", title "Invite Not Found"

// In invite.rs:
return Err(ApiError::InviteNotFound(code));
```

**Why:** Error code `IDENTITY_NOT_FOUND` on an invite endpoint is misleading in logs and for API consumers who switch on `code`. No backwards compat concern — just add the correct variant.

---

## Epic 6: Fixture Drift — Identity Shape Does Not Match Real API

Summary: Fixtures return `ActiveIdentity` with `key_id: "key-laptop-001"` and `created_at: "2024-12-01T..."`, but the real backend (after Epic 1 fix) will return `key_id: "key-0"` and `created_at` from `identity_state.updated_at`. Fixtures should match the real API shape exactly so dev-mode and production behave identically.

### Task 1: Align fixture identity shapes to match the real backend response

**Repo:** `auths-site`
**File:** `apps/web/src/lib/api/fixtures.ts`
**Lines:** ~35–80 (SOVEREIGN_IDENTITY and other persona definitions)

**Problem:**
Fixture `key_id` values like `"key-laptop-001"` don't match the backend's `"key-0"` format. Any component that renders or keys on `key_id` behaves differently in dev vs prod.

**Current code (fixture):**
```typescript
const SOVEREIGN_IDENTITY: ActiveIdentity = {
  status: 'active',
  did: SOVEREIGN_DID,
  public_keys: [
    {
      key_id: 'key-laptop-001',
      algorithm: 'Ed25519',
      public_key_hex: 'aB3d...',
      created_at: '2024-12-01T10:00:00Z',
    },
    // ...
  ],
  // ...
};
```

**Fixed code:**
```typescript
const SOVEREIGN_IDENTITY: ActiveIdentity = {
  status: 'active',
  did: SOVEREIGN_DID,
  public_keys: [
    {
      key_id: 'key-0',
      algorithm: 'Ed25519',
      public_key_hex: 'DaB3d...',  // KERI-encoded key as backend returns
      created_at: '2025-01-15T10:00:00Z',
    },
    // ...
  ],
  // ...
};
```

Apply the same `key_id` format (`"key-0"`, `"key-1"`, `"key-2"`) and KERI-encoded `public_key_hex` values across all 6 persona fixtures.

**Why:** Fixtures and real API should return identical shapes. No backwards compat concern — just make fixtures match reality.

---

## Epic 7: Naming Inconsistency — display_name vs name

Summary: The org name field is called `display_name` in most endpoints but `name` in `GET /v1/orgs/{did}/status`. Frontend types mirror this split. While not a runtime bug, this makes the API confusing and error-prone for consumers.

### Task 1: Rename OrgStatusResponse.name to display_name (backend)

**Repo:** `auths-cloud`
**File:** `crates/auths-registry-server/src/routes/org.rs`
**Lines:** ~454–460

**Problem:**
`OrgStatusResponse` uses `name` while `create_org` response, `get_invite` response, and the DB column all use `display_name`.

**Current code:**
```rust
pub struct OrgStatusResponse {
    pub org_did: String,
    pub name: String,
    pub member_count: i64,
    pub pending_invites: i64,
    pub signing_policy_enabled: bool,
}
```

**Fixed code:**
```rust
pub struct OrgStatusResponse {
    pub org_did: String,
    pub display_name: String,
    pub member_count: i64,
    pub pending_invites: i64,
    pub signing_policy_enabled: bool,
}
```

Also update the handler (line 519) to set `display_name: name` instead of `name`.

**Why:** Inconsistent field naming across related endpoints. API consumers must remember that `POST /v1/orgs` returns `display_name` but `GET /v1/orgs/{did}/status` returns `name` for the same concept.

---

### Task 2: Rename OrgStatusResponse.name to display_name (frontend)

**Repo:** `auths-site`
**File:** `apps/web/src/lib/api/registry.ts`
**Lines:** ~901–907

**Problem:**
Frontend type mirrors the backend's inconsistency.

**Current code:**
```typescript
export interface OrgStatusResponse {
  org_did: string;
  name: string;
  member_count: number;
  pending_invites: number;
  signing_policy_enabled: boolean;
}
```

**Fixed code:**
```typescript
export interface OrgStatusResponse {
  org_did: string;
  display_name: string;
  member_count: number;
  pending_invites: number;
  signing_policy_enabled: boolean;
}
```

**Why:** Must stay in sync with the backend rename from Task 1.

---

---

## Epic 8: Auth Server vs Registry Server Error Response Shape Divergence

Summary: The auth server (`auths-auth-server`) returns errors as `{ error: string, code: string }`, while the registry server (`auths-registry-server`) returns RFC 9457 Problem Details with `{ type: string, title: string, status: number, detail: string, code: string }`. The frontend error parser handles both via a fallback chain, but two different error contracts across the same product's APIs is a maintenance risk.

### Task 1: Align auth server error response to RFC 9457

**Repo:** `auths-cloud`
**File:** `crates/auths-auth-server/src/error.rs`
**Lines:** entire file

**Problem:**
Auth server's `ErrorResponse` has `{ error, code }` while registry server's has `{ type, title, status, detail, code }`. The frontend must handle both shapes in its error parsing logic (lines 237–252 of `registry.ts`). The fallback chain works today but is fragile — any change to field order or naming could break one path.

**Current code:**
```rust
pub struct ErrorResponse {
    pub error: String,
    pub code: String,
}
```

**Fixed code:**
```rust
pub struct ErrorResponse {
    #[serde(rename = "type")]
    pub error_type: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
    pub code: String,
}
```

And update `IntoResponse` to construct the full RFC 9457 body:

```rust
let error_type = format!("urn:auths:error:{}", code.to_lowercase().replace('_', "-"));
let body = ErrorResponse {
    error_type,
    title: title.to_string(),
    status: status.as_u16(),
    detail: error_message,
    code: code.to_string(),
};
```

**Why:** One error contract across both APIs means the frontend can rely on a single parsing path.

---

### Task 2: Simplify frontend error parser to use only RFC 9457 fields

**Repo:** `auths-site`
**File:** `apps/web/src/lib/api/registry.ts`
**Lines:** ~237–252 (in `registryFetch`), ~958–965 (in `registryFetchAuth`), ~1006–1013 (in `authFetch`)

**Problem:**
After Task 1, both servers return RFC 9457 `{ type, title, status, detail, code }`. The frontend's fallback chain (`body.detail` → `body.error` → `body.message`) is now unnecessary — `body.detail` is always present. The `body.error` and `body.message` fallbacks are dead code.

**Current code:**
```typescript
if (typeof body.detail === 'string') {
  message = body.detail;
  detail = body.detail;
} else if (typeof body.error === 'string') {
  message = body.error;
} else if (typeof body.message === 'string') {
  message = body.message;
}
if (typeof body.code === 'string') code = body.code;
if (typeof body.type === 'string') errorType = body.type;
```

**Fixed code:**
```typescript
message = body.detail ?? res.statusText;
detail = body.detail;
code = body.code;
errorType = body.type;
```

**Why:** No backwards compat concern — both servers now return the same shape. Dead fallback paths are confusion risk.

---

## Epic 9: Signing Policy Check Only Tests Row Existence

Summary: `get_org_status` determines `signing_policy_enabled` via `SELECT EXISTS(SELECT 1 FROM org_policies WHERE org_did = $1)`. If a policy row exists but its `policy_expr` has `require_signing: false`, the status endpoint still reports `signing_policy_enabled: true`.

### Task 1: Check policy_expr content, not just row existence

**Repo:** `auths-cloud`
**File:** `crates/auths-registry-server/src/routes/org.rs`
**Lines:** ~509–515

**Problem:**
An org that created a policy then set `require_signing: false` still has a row in `org_policies`. The `EXISTS` check reports signing as enabled when it's actually disabled.

**Current code:**
```rust
let signing_policy_enabled: bool = sqlx::query_scalar::<_, bool>(
    "SELECT EXISTS(SELECT 1 FROM org_policies WHERE org_did = $1)",
)
.bind(&org_did)
.fetch_one(pool)
.await
.map_err(|e| ApiError::StorageError(format!("policy check failed: {e}")))?;
```

**Fixed code:**
```rust
let signing_policy_enabled: bool = sqlx::query_scalar::<_, bool>(
    "SELECT COALESCE(\
       (SELECT (policy_expr->>'require_signing')::boolean \
        FROM org_policies WHERE org_did = $1), \
       false\
     )",
)
.bind(&org_did)
.fetch_one(pool)
.await
.map_err(|e| ApiError::StorageError(format!("policy check failed: {e}")))?;
```

**Why:** Without this, the dashboard shows "Signing policy: On" even when the org explicitly disabled signing. Misleading for org admins.

---

## Epic 10: Rename `did_prefix` Column to `did` Across All Tables

Summary: The column `did_prefix` stores the complete DID string (`did:keri:E...`), not just the KERI prefix (`E...`). The name is misleading and invites bugs where developers strip the `did:keri:` scheme before querying, getting zero rows. Since there are zero users, rename the column outright instead of documenting the mismatch.

### Task 1: Rename `did_prefix` → `did` in existing CREATE TABLE migrations

**Repo:** `auths-cloud`
**Files:**
- `crates/auths-registry-server/migrations/004_public_registry.sql`
- `crates/auths-registry-server/migrations/005_platform_claims_unique.sql`
- `crates/auths-registry-server/migrations/006_identity_state.sql`
- `crates/auths-registry-server/migrations/007_kel_events.sql`
- `crates/auths-registry-server/migrations/014_backfill_log_entries.sql`
- `crates/auths-registry-server/migrations/018_genesis_log_fallback.sql`

**Problem:**
`did_prefix` is used as a column name in 4 tables: `identity_state` (PK), `public_registrations`, `platform_claims`, `kel_events`, plus referenced in indexes and backfill migrations. The name implies it stores just the prefix portion, but it stores the full DID. Database will be rebuilt from scratch so just fix the DDL directly.

**Current code (004_public_registry.sql):**
```sql
CREATE TABLE public_registrations (
    ...
    did_prefix           TEXT NOT NULL,
    ...
);
CREATE TABLE platform_claims (
    ...
    did_prefix      TEXT NOT NULL,
    ...
);
CREATE INDEX idx_platform_claims_did ON platform_claims (did_prefix);
```

**Fixed code:**
```sql
CREATE TABLE public_registrations (
    ...
    did              TEXT NOT NULL,
    ...
);
CREATE TABLE platform_claims (
    ...
    did             TEXT NOT NULL,
    ...
);
CREATE INDEX idx_platform_claims_did ON platform_claims (did);
```

Apply the same `did_prefix` → `did` rename in `005_platform_claims_unique.sql` (unique index), `006_identity_state.sql` (PK column), `007_kel_events.sql` (column + composite PK), `014_backfill_log_entries.sql` (SELECT/INSERT references), and `018_genesis_log_fallback.sql` (SELECT/INSERT references).

**Why:** Clean column name from day one. No migration needed since the DB is rebuilt from scratch.

---

### Task 2: Update all Rust SQL queries referencing `did_prefix`

**Repo:** `auths-cloud`
**File:** Multiple files in `crates/auths-registry-server/src/` (~40 references)

**Problem:**
Every SQL string literal that references `did_prefix` must be updated to `did`. Affected files:

| File | Approx references |
|------|-------------------|
| `routes/identity.rs` | 3 |
| `routes/org.rs` | 5 |
| `routes/invite.rs` | 1 |
| `routes/pubkeys.rs` | 2 |
| `middleware/identity_auth.rs` | 2 |
| `services/registration.rs` | 4 |
| `services/proof_verification.rs` | 2 |
| `sequencer/mod.rs` | 6 |
| `sequencer/validation.rs` | 4 |
| `sequencer/auto_provision.rs` | 2 |

**Current code (example from identity_auth.rs):**
```rust
"SELECT current_keys FROM identity_state WHERE did_prefix = $1 AND is_abandoned = FALSE"
```

**Fixed code:**
```rust
"SELECT current_keys FROM identity_state WHERE did = $1 AND is_abandoned = FALSE"
```

Apply the same `did_prefix` → `did` rename in every SQL string literal and Rust variable name across all listed files.

**Why:** SQL queries must match the renamed column or they will fail at runtime.

---

### Task 3: Rename `did_prefix` Rust variables to `did` where they hold full DIDs

**Repo:** `auths-cloud`
**File:** `crates/auths-registry-server/src/services/registration.rs` and others

**Problem:**
Rust code uses `did_prefix` as a variable name for the full DID string (e.g., `let did_prefix = format!("did:keri:{}", prefix);`). After the column rename, keeping the variable name `did_prefix` re-introduces the same confusion at the code level.

**Current code:**
```rust
let did_prefix = format!("did:keri:{}", prefix);
sqlx::query("INSERT INTO public_registrations (did_prefix) VALUES ($1)")
    .bind(&did_prefix)
```

**Fixed code:**
```rust
let did = format!("did:keri:{}", prefix);
sqlx::query("INSERT INTO public_registrations (did) VALUES ($1)")
    .bind(&did)
```

**Why:** Variable names should match column names to avoid the same semantic confusion the column rename is fixing.

---

## Appendix: Items Verified as Correct

These integration points were audited and found to be working correctly:

1. **Error parsing fallback chain**: The frontend reads `body.detail` → `body.error` → `body.message` in that order. This covers both registry (`detail`) and auth (`error`) server error shapes.

2. **Error type field**: Registry server uses `#[serde(rename = "type")]` on `error_type`, so it serializes as `"type"` in JSON. Frontend reads `body.type`. Match confirmed.

3. **Auth challenge → verify flow**: Frontend maps `raw.challenge` → `nonce`, constructs CLI command with `--nonce`, auth server verifies against stored nonce. Signature payload reconstruction uses the same canonical JSON. Flow is correct.

4. **Session token → registry middleware**: Frontend stores UUID token from verify response, sends as `Bearer {uuid}`, registry middleware parses as UUID, validates against auth server's `/auth/status/{uuid}`. Works correctly.

5. **Anonymous tier promotion**: Middleware promotes DB tier `"anonymous"` to `"individual"` for signed requests (line 242 of identity_auth.rs), preventing the "same string, different semantics" collision between "unauthenticated" and "unpaid" anonymous.

6. **OrgPolicyResponse for public org page**: `fetchOrgPolicy` uses unauthenticated `registryFetch` and the backend's `get_policy` is indeed a public endpoint (no auth check). No bug.

7. **Activity feed types**: Frontend `FeedEntry` fields (`log_sequence`, `entry_type`, `actor_did`, `summary`, `metadata`, `occurred_at`, `merkle_included`, `is_genesis_phase`) match backend `log_entries` columns exactly.

8. **Artifact query/response**: Frontend `ArtifactEntry` fields match backend `ArtifactEntryResponse` fields.

9. **Namespace types**: Frontend `NamespaceInfo` and `NamespaceBrowseResponse` match backend response shapes.

10. **Network stats**: Frontend `NetworkStats` fields match backend stats endpoint.
