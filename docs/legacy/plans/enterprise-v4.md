# Enterprise Hexagonal Refactoring Plan v4

> M&A Readiness: Registry Server Clock Injection, Verifier Determinism, and Adapter Port Completeness
> Date: 2026-02-28

## Executive Summary

This plan addresses the findings from a fourth technical due diligence cycle against the auths workspace. The previous cycles (v1–v3) resolved: git2 coupling in `auths-id`, CLI fat handlers, telemetry sink hardcoding (v1/v2), `Utc::now()` eradication from `auths-core` and `auths-id` production paths, `UuidProvider` port creation, SDK org workflow extraction, and in-memory recovery tests (v3).

This cycle audits the resulting state and finds three residual risk categories:

1. **Registry server is a clock-injection dead zone** — `auths-registry-server` contains 15+ production `Utc::now()` calls across routes (`verify.rs`, `device.rs`, `pairing.rs`, `verify_commit.rs`, `pubkeys.rs`, `tenant.rs`, `billing.rs`, `identity.rs`), extractors (`signature.rs`), and adapters (`memory_pairing_store.rs`, `postgres_pairing_store.rs`, `postgres_tenant_metadata_store.rs`). `ServerState` has no `ClockProvider` field. Org routes use `SystemClock` directly (hardcoded import) rather than injecting through state. Every other route calls `Utc::now()` without mediation.

2. **`auths-verifier` production clock leak** — `IdentityBundle::check_freshness()` at `core.rs:311` calls `Utc::now()` directly. This is a public method on a core verification type in a crate designed for WASM/FFI embedding. An acquirer embedding `auths-verifier` in a non-standard runtime (WASM, deterministic replay, time-travel debugging) cannot control freshness checks. The `ClockProvider` trait exists in `auths-verifier/src/clock.rs` but is not threaded to this call site.

3. **Index fallback timestamps** — `auths-index/src/index.rs` uses `Utc::now()` as a fallback in 3 SQLite deserialization paths (lines 258, 324, 405) and `auths-id/src/storage/indexed.rs:88` uses `Utc::now()` as a fallback when attestation timestamp is `None`. These are low-severity but represent data integrity risks: a corrupted or missing timestamp silently becomes "right now" rather than surfacing an error.

The good news: the architectural foundation is solid. `auths-core` and `auths-id` production code are clean. The SDK properly injects `ClockProvider` and `UuidProvider`. Org routes correctly delegate to SDK workflows. Recovery tests use `FakeRegistryBackend`. The `clippy.toml` disallowed-methods configuration and `check-arch.sh` boundary guard are enforced in CI. This plan threads the remaining clock injection to the server layer and closes the last verifier gap.

---

## Current Architecture (What's Good)

**Resolved since v3 — no longer findings:**
- `parse_keri_did` replaced with `CanonicalDid::parse` in `org.rs` (Story 3.1 complete)
- `add_organization_member`, `revoke_organization_member`, `update_member_capabilities` live in `auths-sdk/src/workflows/org.rs` (Story 3.2 complete)
- `find_admin_by_pubkey` and `find_member_attestation` migrated to SDK (Story 3.3 complete)
- No `Attestation` construction with empty signatures in `org.rs` (Story 3.2 complete)
- Recovery tests use `FakeRegistryBackend` with no `init_test_repo()` (Story 4.1 complete)
- `UuidProvider` trait + `SystemUuidProvider` + `DeterministicUuidProvider` all exist (Epic 1 complete)
- `.clippy.toml` disallows `Uuid::new_v4()` workspace-wide (Epic 1 complete)
- `clippy.toml` disallows `Utc::now()`, `SystemTime::now()`, `std::env::var` (Epic 2 complete)
- `auths-core/src/` production paths: zero `Utc::now()` violations
- `auths-id/src/` production paths: zero `Utc::now()` violations (all in `#[cfg(test)]`)
- `auths-sdk/src/` production paths: zero `Utc::now()` or `Uuid::new_v4()` violations
- `auths-verifier/tests/cases/revocation_adversarial.rs` uses `FIXED_TS` constant, not `Utc::now()`
- `check-arch.sh` enforces SDK boundaries in CI (no `Utc::now()`, `std::fs::`, `git2::`, concrete storage types)
- `deny.toml` confines `reqwest`, `git2`, `sqlx`, `axum`, `dialoguer` to allowed crate scopes

**Ports and fakes fully operational:**
- `ClockProvider` — `auths-verifier/src/clock.rs` (trait), `SystemClock` (adapter), `MockClock` in `auths-test-utils/src/fakes/clock.rs`
- `UuidProvider` — `auths-core/src/ports/id.rs` (trait), `SystemUuidProvider` (adapter), `DeterministicUuidProvider` in `auths-test-utils/src/fakes/id.rs`
- `FakeRegistryBackend` — `auths-test-utils/src/fakes/registry.rs`, passes 18+ contract tests
- `InMemoryStorage` — `auths-test-utils/src/storage_fakes.rs`, implements all 6 storage port traits
- `MemoryEventSink` — `auths-test-utils/src/fakes/telemetry.rs`
- `FakeGitLogProvider`, `FakeGitDiagnosticProvider`, `FakeCryptoDiagnosticProvider` — test doubles for audit and diagnostics

---

## Audit Findings Summary

| # | Finding | Location | Severity | Impact |
|---|---------|----------|----------|--------|
| F1 | `Utc::now()` in registry route handlers | `routes/verify.rs:77,145` `routes/device.rs:63,120` `routes/pubkeys.rs:123` `routes/pairing.rs:145,188,229,264` `routes/verify_commit.rs:136` `routes/identity.rs:158` `routes/tenant.rs:198` `routes/billing.rs:357,395,571` | HIGH | Expiration checks, session timestamps, and event emission are non-deterministic; impossible to test time-boundary edge cases |
| F2 | `Utc::now()` in registry signature extractor | `extractors/signature.rs:121` | HIGH | Timestamp skew validation is non-deterministic; clock skew edge cases untestable |
| F3 | `Utc::now()` in registry adapters | `adapters/memory_pairing_store.rs:154` `adapters/postgres_pairing_store.rs:317,334` `adapters/postgres_tenant_metadata_store.rs:41,198` | MEDIUM | Adapter cleanup and rate-limiting tied to OS clock; acceptable for operational code but blocks deterministic integration tests |
| F4 | `SystemClock` hardcoded in org routes | `routes/org.rs:22,254,287,320,401,490,523,556,634` | MEDIUM | SDK workflows receive `&SystemClock` directly instead of injected clock from `ServerState`; org routes are correct in delegating to SDK but wrong in where the clock comes from |
| F5 | `IdentityBundle::check_freshness()` calls `Utc::now()` | `auths-verifier/src/core.rs:311` | HIGH | Public method on embeddable verification crate; WASM/FFI consumers cannot control freshness; violates the `ClockProvider` pattern defined in the same crate |
| F6 | `Utc::now()` fallback in index deserialization | `auths-index/src/index.rs:258,324,405` | LOW | Corrupted timestamps silently become current time instead of surfacing errors |
| F7 | `Utc::now()` fallback in indexed storage | `auths-id/src/storage/indexed.rs:88` | LOW | Missing attestation timestamp defaults to current time rather than propagating `None` |
| F8 | No `ClockProvider` in `ServerState` | `auths-registry-server/src/lib.rs:92–123` | HIGH | No mechanism to inject test clocks into the server; every route must independently import `SystemClock` or call `Utc::now()` |
| F9 | `Uuid::new_v4()` in registry adapters | `middleware/trace.rs:22` `adapters/postgres_tenant_metadata_store.rs:193,194` | LOW | Both have `#[allow(clippy::disallowed_methods)]`; trace IDs and API key generation are adapter-boundary concerns |

> **Not a finding**: `Utc::now()` in `auths-cli/src/` — CLI is the presentation boundary where OS clock access is correct per CLAUDE.md. `Utc::now()` in `auths-core/src/witness/server.rs:481` — witness HTTP handler boundary, acceptable. `Utc::now()` in `auths-registry-server/src/routes/pairing.rs:448–531` and `routes/analytics.rs:429–430` and `adapters/postgres_pairing_store.rs:364–469` — all within `#[cfg(test)]` blocks.

---

## Mandatory Structural Principles

These inherit from v3 and add two new constraints discovered in this cycle.

### 1. `ServerState` Must Own All Injectable Ports

Every non-deterministic dependency used by route handlers must be available on `ServerState` (or extractable from it via Axum extensions). Route handlers must not import concrete port implementations (`SystemClock`, `SystemUuidProvider`) directly. Instead, `ServerState` provides them through accessor methods, enabling test harnesses to substitute fakes.

### 2. Embeddable Crates Must Accept Injected Time on All Public Methods

`auths-verifier` is designed for WASM and FFI embedding. Any public method that uses the current time must accept it as a parameter (`now: DateTime<Utc>`) or via a `&dyn ClockProvider`. Internal convenience methods that call `Utc::now()` are prohibited on public types — they must live on wrapper types in the CLI or server layer.

### 3. Deserialization Must Not Fabricate Timestamps

When deserializing stored data, a missing or unparseable timestamp should either propagate `None` or return an error. Using `Utc::now()` as a fallback silently fabricates data, which undermines audit trails and deterministic replay.

### 4. (Inherited) Route Handlers Are Anemic Mappers

HTTP handlers contain: JSON deserialization → boundary type parsing → one SDK/service call → HTTP response mapping. Domain logic (expiration checks, timestamp generation, UUID creation) is prohibited in route files.

### 5. (Inherited) All Ports Must Have Fakes

Every port trait must have a corresponding deterministic fake in `auths-test-utils`.

---

## Epic 5: Registry Server Clock Injection

**Objective**: Inject `ClockProvider` into `ServerState` and thread it to every production `Utc::now()` call site in `auths-registry-server`. Route handlers, extractors, and adapters must use the injected clock.

**Success Metrics:**
- `ServerState` has a `clock: Arc<dyn ClockProvider>` field with a `.clock()` accessor
- Zero `Utc::now()` calls in `routes/*.rs` production paths (excluding `#[cfg(test)]`)
- Zero `Utc::now()` calls in `extractors/signature.rs` production path
- Org routes use `state.clock()` instead of `&SystemClock` import
- All adapters with `Utc::now()` accept injected time or use the clock from state
- Registry server integration tests can inject `MockClock`

**Exit Criteria:**
- `grep -rn 'Utc::now()' crates/auths-registry-server/src/ | grep -v '#\[cfg(test)\]' | grep -v '// ' | grep -v '/// '` returns zero matches (excluding test blocks and comments)
- All existing tests pass with `MockClock` or `SystemClock` interchangeably

### Story 5.1: Add `ClockProvider` to `ServerState` [S]

**Why**: `ServerState` (defined at `lib.rs:92`) currently has no clock field. Every route independently imports `SystemClock` or calls `Utc::now()` because there is no central injection point. Adding a single `Arc<dyn ClockProvider>` field enables the entire server to be driven by a test clock.

**Acceptance Criteria:**
- `ServerStateInner` gains a `clock: Arc<dyn ClockProvider>` field
- `ServerStateBuilder` gains a `.clock(impl ClockProvider)` builder method (defaults to `SystemClock`)
- `ServerState` gains a `.clock() -> &dyn ClockProvider` accessor
- `main.rs` / server bootstrap uses `.clock(SystemClock)` explicitly (or relies on default)

**Task Breakdown:**

| Role | Description | Files | DoD |
|------|-------------|-------|-----|
| Backend | Add `clock` field to `ServerStateInner` | `crates/auths-registry-server/src/lib.rs` | Field present, builder method works, accessor compiles |
| Backend | Update `ServerStateBuilder` with `.clock()` and default | `crates/auths-registry-server/src/lib.rs` | Default is `SystemClock`; override accepted |
| Backend | Verify `main.rs` bootstrap compiles | `crates/auths-registry-server/src/main.rs` | Server starts with SystemClock |

### Story 5.2: Inject Clock into Route Handlers [M]

**Why**: 10 route handler functions across 7 files call `Utc::now()` in production paths for expiration checks, session timestamps, event emission, and response fields. Each must be refactored to use `state.clock().now()`.

**Acceptance Criteria:**
- `routes/verify.rs`: expiration checks at lines 77, 145 use injected clock
- `routes/device.rs`: expiration checks at lines 63, 120 use injected clock
- `routes/pubkeys.rs`: expiration filter at line 123 uses injected clock
- `routes/pairing.rs`: session creation at line 145, TTL checks at lines 188, 229, 264 use injected clock
- `routes/verify_commit.rs`: event timestamp at line 136 uses injected clock
- `routes/identity.rs`: anonymized client ID at line 158 uses injected clock
- `routes/tenant.rs`: response timestamp at line 198 uses injected clock
- `routes/billing.rs`: subscription record timestamps at lines 357, 395, 571 use injected clock
- No `Utc::now()` remains in any route handler production path

**Task Breakdown:**

| Role | Description | Files | DoD |
|------|-------------|-------|-----|
| Backend | Refactor verify routes to accept clock from state | `crates/auths-registry-server/src/routes/verify.rs` | `is_expired` check uses `state.clock().now()` |
| Backend | Refactor device routes to accept clock from state | `crates/auths-registry-server/src/routes/device.rs` | Expiration checks use `state.clock().now()` |
| Backend | Refactor pubkeys route to accept clock from state | `crates/auths-registry-server/src/routes/pubkeys.rs` | Expiration filter uses `state.clock().now()` |
| Backend | Refactor pairing routes to accept clock from state | `crates/auths-registry-server/src/routes/pairing.rs` | Session creation and TTL checks use `state.clock().now()` |
| Backend | Refactor verify_commit route to accept clock from state | `crates/auths-registry-server/src/routes/verify_commit.rs` | Event timestamp uses `state.clock().now()` |
| Backend | Refactor identity route to accept clock from state | `crates/auths-registry-server/src/routes/identity.rs` | Anonymized client ID uses `state.clock().now()` |
| Backend | Refactor tenant route to accept clock from state | `crates/auths-registry-server/src/routes/tenant.rs` | Response timestamp uses `state.clock().now()` |
| Backend | Refactor billing routes to accept clock from state | `crates/auths-registry-server/src/routes/billing.rs` | Subscription record timestamps use `state.clock().now()` |

### Story 5.3: Inject Clock into Org Routes via `ServerState` [S]

**Why**: `routes/org.rs` correctly delegates to SDK workflows but hardcodes `&SystemClock` (imported at line 22, used at lines 254, 287, 320, 401, 490, 523, 556, 634). This bypasses the injection point, meaning org route tests cannot use `MockClock`.

**Acceptance Criteria:**
- `use auths_core::ports::clock::SystemClock;` import removed from `org.rs`
- All SDK workflow calls pass `state.clock()` instead of `&SystemClock`
- `SystemClock.now()` calls for expiration checks (lines 401, 634) replaced with `state.clock().now()`

**Task Breakdown:**

| Role | Description | Files | DoD |
|------|-------------|-------|-----|
| Backend | Replace `SystemClock` with `state.clock()` in org handlers | `crates/auths-registry-server/src/routes/org.rs` | No `SystemClock` import; all clock access via state |

### Story 5.4: Inject Clock into Signature Extractor [M]

**Why**: `extractors/signature.rs:121` calls `Utc::now()` for timestamp skew validation. This is a security-critical path — if the clock skew check uses an uncontrolled clock, edge cases around the 5-minute skew window cannot be tested deterministically. The extractor must receive the clock from `ServerState` (available as an Axum extension).

**Acceptance Criteria:**
- `verify_signed_request()` accepts a clock parameter or extracts it from state
- Skew calculation at line 122 uses injected time
- Existing tests updated to use `MockClock` for deterministic skew checks

**Task Breakdown:**

| Role | Description | Files | DoD |
|------|-------------|-------|-----|
| Backend | Thread clock through signature verification | `crates/auths-registry-server/src/extractors/signature.rs` | `Utc::now()` removed from production path; tests pass with MockClock |

### Story 5.5: Inject Clock into Adapters [M]

**Why**: Three adapter modules call `Utc::now()` in production paths: `memory_pairing_store.rs:154` (TTL cleanup), `postgres_pairing_store.rs:317,334` (cleanup/rate-limit cutoffs), and `postgres_tenant_metadata_store.rs:41,198` (record timestamps). While adapters are outer-layer code, injecting a clock enables deterministic integration tests that verify TTL logic without sleep/wait.

**Acceptance Criteria:**
- `PairingStore` trait methods that need current time accept `now: DateTime<Utc>` or the store holds a `ClockProvider`
- `TenantMetadataStore` trait methods accept `now: DateTime<Utc>` where timestamps are generated
- `MemoryPairingStore` and `PostgresPairingStore` implementations use injected time
- Adapter tests use `MockClock`

**Task Breakdown:**

| Role | Description | Files | DoD |
|------|-------------|-------|-----|
| Backend | Add clock to pairing store trait/impls | `crates/auths-registry-server/src/ports.rs`, `crates/auths-registry-server/src/adapters/memory_pairing_store.rs`, `crates/auths-registry-server/src/adapters/postgres_pairing_store.rs` | Cleanup and rate-limit use injected time |
| Backend | Add clock to tenant metadata store | `crates/auths-registry-server/src/adapters/postgres_tenant_metadata_store.rs` | Record timestamps use injected time |

--- DONE DONE DONE DONE

## Epic 6: Verifier Determinism — `check_freshness()` Clock Injection

**Objective**: Remove the last `Utc::now()` from `auths-verifier` production code. `IdentityBundle::check_freshness()` must accept injected time so that WASM/FFI consumers and fuzz targets can control freshness evaluation.

**Success Metrics:**
- `check_freshness()` accepts `now: DateTime<Utc>` parameter
- Zero `Utc::now()` calls in `auths-verifier/src/` production code
- All callers updated (CLI, servers, tests)
- WASM compilation still passes (`cargo check --target wasm32-unknown-unknown --no-default-features --features wasm`)

**Exit Criteria:**
- `grep -rn 'Utc::now()' crates/auths-verifier/src/ | grep -v '#\[cfg(test)\]' | grep -v '// '` returns only the `SystemClock::now()` implementation in `clock.rs:38`

### Story 6.1: Parameterise `check_freshness()` [S]

**Why**: `IdentityBundle::check_freshness()` at `core.rs:311` is a public method on a type designed for embedding. The method calculates `(Utc::now() - self.bundle_timestamp).num_seconds()` — a single-line change to accept `now: DateTime<Utc>` makes the entire verification pipeline deterministic. The `ClockProvider` trait already exists in `auths-verifier/src/clock.rs` but is not used here.

**Acceptance Criteria:**
- `check_freshness(&self, now: DateTime<Utc>)` — signature change
- All callers in `auths-cli` and `auths-registry-server` pass `Utc::now()` or `clock.now()` at call sites
- Test helpers in `auths-verifier/src/core.rs` updated

**Task Breakdown:**

| Role | Description | Files | DoD |
|------|-------------|-------|-----|
| Backend | Change `check_freshness` signature | `crates/auths-verifier/src/core.rs` | Method accepts `now` parameter |
| Backend | Update CLI callers | `crates/auths-cli/src/commands/verify_commit.rs`, `crates/auths-cli/src/commands/id/identity.rs` | Pass `Utc::now()` at presentation boundary |
| Backend | Update server callers (if any) | `crates/auths-registry-server/src/routes/` | Pass `state.clock().now()` |
| Backend | Update test callers | `crates/auths-verifier/src/core.rs` test module | Tests pass fixed timestamps |

--- DONE DONE DONE DONE

## Epic 7: Index Timestamp Integrity

**Objective**: Replace `Utc::now()` fallbacks in `auths-index` deserialization and `auths-id` indexed storage with explicit error handling. Corrupted or missing timestamps must surface as errors, not silently become the current time.

**Success Metrics:**
- Zero `Utc::now()` in `auths-index/src/index.rs` deserialization paths
- `auths-id/src/storage/indexed.rs:88` no longer uses `Utc::now()` as fallback
- Missing timestamps produce `Option<DateTime<Utc>>` or explicit errors

**Exit Criteria:**
- `grep -rn 'Utc::now()' crates/auths-index/src/ | grep -v '#\[cfg(test)\]' | grep -v '// '` returns zero matches
- `grep -rn 'Utc::now()' crates/auths-id/src/storage/indexed.rs` returns zero matches

### Story 7.1: Fix `auths-index` Deserialization Fallbacks [S]

**Why**: `index.rs` lines 258, 324, 405 use `.unwrap_or_else(|_| Utc::now())` when parsing stored RFC 3339 timestamps from SQLite. If a database row contains a malformed timestamp, the code silently replaces it with the current time. This makes the index non-deterministic and masks data corruption. The `updated_at` field on `IndexedAttestation` and `IndexedIdentity` should use `DateTime::UNIX_EPOCH` as the fallback (indicating "unknown" rather than "right now") or propagate the parse error.

**Acceptance Criteria:**
- Lines 258, 324, 405 use `DateTime::UNIX_EPOCH` (or a sentinel constant) instead of `Utc::now()` as the parse-failure fallback
- A `tracing::warn!` emitted when the fallback is used (aids operational debugging)
- No behavior change for well-formed data

**Task Breakdown:**

| Role | Description | Files | DoD |
|------|-------------|-------|-----|
| Backend | Replace `Utc::now()` fallbacks with `UNIX_EPOCH` + warning | `crates/auths-index/src/index.rs` | Three call sites updated; `tracing::warn!` on fallback |

### Story 7.2: Fix `auths-id` Indexed Storage Fallback [S]

**Why**: `storage/indexed.rs:88` calls `att.timestamp.unwrap_or_else(Utc::now)`. When an attestation has no `timestamp` field, the index record gets the current wall-clock time as `updated_at`. This is a data integrity issue — the index should reflect the attestation's actual state, not fabricate a timestamp.

**Acceptance Criteria:**
- `updated_at` uses `att.timestamp.unwrap_or(DateTime::UNIX_EPOCH)` (or the attestation's `created_at` if available)
- A `tracing::debug!` emitted when fallback is used

**Task Breakdown:**

| Role | Description | Files | DoD |
|------|-------------|-------|-----|
| Backend | Replace `Utc::now()` fallback | `crates/auths-id/src/storage/indexed.rs` | Line 88 uses epoch sentinel instead of wall clock |

---

## PR Sequencing Plan

Ordered to minimise merge conflicts and ensure each PR is independently mergeable.

| PR | Scope | Risk | Depends On | Epic |
|----|-------|------|------------|------|
| **PR-1** | Add `ClockProvider` to `ServerState` + builder + accessor | Low | — | 5 |
| **PR-2** | Parameterise `IdentityBundle::check_freshness()` to accept `now` | Low | — | 6 |
| **PR-3** | Fix `auths-index` deserialization fallbacks (3 call sites) | Low | — | 7 |
| **PR-4** | Fix `auths-id/src/storage/indexed.rs:88` fallback | Low | — | 7 |
| **PR-5** | Inject clock into verify + device + pubkeys routes | Medium | PR-1 | 5 |
| **PR-6** | Inject clock into pairing routes (session creation + TTL checks) | Medium | PR-1 | 5 |
| **PR-7** | Inject clock into verify_commit + identity + tenant + billing routes | Medium | PR-1 | 5 |
| **PR-8** | Replace `SystemClock` hardcoding in org routes with `state.clock()` | Low | PR-1 | 5 |
| **PR-9** | Inject clock into signature extractor | Medium | PR-1 | 5 |
| **PR-10** | Inject clock into pairing store adapters (memory + postgres) | Medium | PR-1 | 5 |
| **PR-11** | Inject clock into tenant metadata store adapter | Low | PR-1 | 5 |
| **PR-12** | Update `check_freshness()` callers in CLI and servers | Low | PR-2 | 6 |

---

## File Inventory

### Files to Modify (22)

| File | Epic | Change |
|------|------|--------|
| `crates/auths-registry-server/src/lib.rs` | 5 | Add `clock: Arc<dyn ClockProvider>` to `ServerStateInner`, builder method, accessor |
| `crates/auths-registry-server/src/routes/verify.rs` | 5 | Replace `Utc::now()` with `state.clock().now()` at lines 77, 145 |
| `crates/auths-registry-server/src/routes/device.rs` | 5 | Replace `Utc::now()` with `state.clock().now()` at lines 63, 120 |
| `crates/auths-registry-server/src/routes/pubkeys.rs` | 5 | Replace `Utc::now()` with `state.clock().now()` at line 123 |
| `crates/auths-registry-server/src/routes/pairing.rs` | 5 | Replace `Utc::now()` with `state.clock().now()` at lines 145, 188, 229, 264 |
| `crates/auths-registry-server/src/routes/verify_commit.rs` | 5 | Replace `Utc::now()` with `state.clock().now()` at line 136 |
| `crates/auths-registry-server/src/routes/identity.rs` | 5 | Replace `Utc::now()` with `state.clock().now()` at line 158 |
| `crates/auths-registry-server/src/routes/tenant.rs` | 5 | Replace `Utc::now()` with `state.clock().now()` at line 198 |
| `crates/auths-registry-server/src/routes/billing.rs` | 5 | Replace `Utc::now()` with `state.clock().now()` at lines 357, 395, 571 |
| `crates/auths-registry-server/src/routes/org.rs` | 5 | Remove `SystemClock` import; use `state.clock()` at lines 254, 287, 320, 401, 490, 523, 556, 634 |
| `crates/auths-registry-server/src/extractors/signature.rs` | 5 | Accept clock parameter; replace `Utc::now()` at line 121 |
| `crates/auths-registry-server/src/adapters/memory_pairing_store.rs` | 5 | Inject clock for TTL cleanup at line 154 |
| `crates/auths-registry-server/src/adapters/postgres_pairing_store.rs` | 5 | Inject clock for cleanup/rate-limit at lines 317, 334 |
| `crates/auths-registry-server/src/adapters/postgres_tenant_metadata_store.rs` | 5 | Inject clock for record timestamps at lines 41, 198 |
| `crates/auths-verifier/src/core.rs` | 6 | `check_freshness(&self, now: DateTime<Utc>)` signature change at line 310 |
| `crates/auths-cli/src/commands/verify_commit.rs` | 6 | Pass `Utc::now()` to `check_freshness()` |
| `crates/auths-cli/src/commands/id/identity.rs` | 6 | Pass `Utc::now()` to `check_freshness()` |
| `crates/auths-index/src/index.rs` | 7 | Replace `Utc::now()` fallbacks at lines 258, 324, 405 with `UNIX_EPOCH` + warning |
| `crates/auths-id/src/storage/indexed.rs` | 7 | Replace `Utc::now()` fallback at line 88 with `UNIX_EPOCH` |

### New Files (0)

No new files required. All infrastructure (`ClockProvider`, `MockClock`, `ServerState`) already exists.

---

## Guardrails & Test Strategy

### CI Checks

The following checks are already in place and will catch regressions:

```bash
# Existing: clippy disallowed methods (catches Utc::now() in all crates)
cargo clippy --all-targets --all-features -- -D warnings -D clippy::disallowed_methods

# Existing: architecture boundary check (SDK layer)
./scripts/check-arch.sh

# Existing: cargo-deny (confines dependencies to allowed scopes)
cargo deny check

# Existing: network-isolated unit tests
# CI drops outbound network via iptables, runs tests in isolation

# Existing: WASM compilation check
cd crates/auths-verifier && cargo check --target wasm32-unknown-unknown --no-default-features --features wasm
```

**New CI check to add (recommended):**

```bash
# Registry server clock audit: zero Utc::now() outside test blocks
./scripts/check-server-clock.sh
```

```bash
#!/usr/bin/env bash
# scripts/check-server-clock.sh
set -e
VIOLATIONS=$(grep -rn 'Utc::now()' crates/auths-registry-server/src/ \
    --include="*.rs" \
    | grep -v '#\[cfg(test)\]' \
    | grep -v '#\[allow(clippy::disallowed_methods)\]' \
    | grep -Ev '^\s*//' \
    | grep -Ev '^\s*///' \
    || true)
if [ -n "$VIOLATIONS" ]; then
    echo "SERVER CLOCK VIOLATION: Utc::now() found outside test blocks"
    echo "$VIOLATIONS"
    exit 1
fi
echo "Server clock injection check passed."
```

### Mocking Strategy

| Port | Fake | Location | Used By |
|------|------|----------|---------|
| `ClockProvider` | `MockClock` | `auths-test-utils/src/fakes/clock.rs` | All epics |
| `UuidProvider` | `DeterministicUuidProvider` | `auths-test-utils/src/fakes/id.rs` | Epic 5 (org routes) |
| `RegistryBackend` | `FakeRegistryBackend` | `auths-test-utils/src/fakes/registry.rs` | Epic 5 (integration tests) |
| `PairingStore` | `MemoryPairingStore` (already exists) | `auths-registry-server/src/adapters/memory_pairing_store.rs` | Epic 5 (pairing tests) |

### Test Pyramid

| Level | Scope | Deterministic? | Clock Source |
|-------|-------|----------------|--------------|
| **Unit** | SDK workflows, policy eval, verification | Yes | `MockClock` / fixed `DateTime` |
| **Integration** | Registry server routes with in-memory backends | Yes (after Epic 5) | `MockClock` via `ServerState` |
| **End-to-end** | CLI → server → storage round-trips | No (OS clock OK) | `SystemClock` |
| **Fuzz** | Verification chains, concurrent sessions | Yes | `ArbitraryClock` (already exists) |
| **Contract** | `RegistryBackend`, `GitLogProvider`, `EventSink` | Yes | `MockClock` |

---

## Code Standards (Enforced)

Inherited from v3. No additions required — the existing standards cover all v4 work:

1. **DRY & Separated**: Business workflows entirely separated from I/O. No monolithic functions.
2. **Documentation**: Rustdoc mandatory for all exported SDK/Core items. `/// Description`, `/// Args:`, `/// Usage:` blocks per CLAUDE.md conventions.
3. **Minimalism**: No inline comments explaining process. Use structural decomposition. Per CLAUDE.md: only comment opinionated decisions.
4. **Domain-Specific Errors**: `thiserror` enums only. No `anyhow::Error` or `Box<dyn Error>` in Core/SDK. Example: `DomainError::InvalidSignature`, `StorageError::ConcurrentModification`.
5. **`thiserror`/`anyhow` Translation Boundary**: The ban on `anyhow` in Core/SDK is strict, but the CLI and API servers (`auths-auth-server`, `auths-registry-server`) **must** define a clear translation boundary where domain errors are wrapped with operational context. The CLI and server crates continue using `anyhow::Context` to collect system-level information (paths, environment, subprocess output), but always wrap the domain `thiserror` errors cleanly — never discard the typed error.
6. **No reverse dependencies**: Core and SDK must never reference presentation layer crates.
7. **All Ports Must Have Fakes**: Every port trait (`ClockProvider`, `UuidProvider`, `RegistryBackend`, etc.) must have a corresponding fake in `auths-test-utils`. No port is added without an accompanying deterministic test double.
8. **Fuzz Targets Use Injected Ports Exclusively**: Any field in a fuzz target scenario that is time- or identity-dependent must be derived from the injected clock or ID provider. Direct OS system calls (`Utc::now()`, `Uuid::new_v4()`) are prohibited even in fuzz targets that already have a controlled provider.
