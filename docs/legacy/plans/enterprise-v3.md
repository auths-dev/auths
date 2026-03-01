# Enterprise Hexagonal Refactoring Plan v3

> M&A Readiness: Side-Effect Eradication, SDK Boundary Enforcement, and Test Determinism
> Date: 2026-02-28

## Executive Summary

This plan addresses the findings from a second technical due diligence cycle against the auths workspace. The previous plan (v2) resolved git2 coupling in `auths-id`, CLI fat handlers, and telemetry sink hardcoding. This cycle audits the resulting state and finds three residual risk categories that block acquirer integrations:

1. **Non-deterministic side effects in production domain code** — `Utc::now()` appears 13 times across `auths-core` and `auths-id` production paths (not test blocks), hardwiring the domain to OS-level clock entropy. The `ClockProvider` trait already exists in `auths-core::ports::clock` and `auths-verifier::clock`, but it has not been threaded into the call sites that need it. No `UuidProvider` port exists for UUID generation.

2. **SDK boundary violations in the registry server** — `auths-registry-server/src/routes/org.rs` contains a custom `parse_keri_did` function (duplicating `CanonicalDid::parse` from `auths-policy::types`), two free-standing helper functions (`find_admin_by_pubkey`, `find_member_attestation`) that are domain-level lookups living in an HTTP module, direct `Attestation` struct construction with empty signatures (lines 309–326, 583–600), and 8 direct calls to `chrono::Utc::now()` and 2 to `uuid::Uuid::new_v4()`. `auths-sdk/src/workflows/org.rs` exists but contains only `Role` enum and `member_role_order` — the `add_organization_member` business transaction does not exist in the SDK at all.

3. **Non-deterministic test suites** — `auths-id/tests/cases/recovery.rs` uses `auths_test_utils::git::init_test_repo()` (physical git2 repositories) for all three recovery tests, despite `FakeRegistryBackend` being fully implemented in `auths-test-utils/src/fakes/registry.rs`. `auths-verifier/tests/cases/revocation_adversarial.rs` embeds `Utc::now()` in the shared `create_signed_attestation` helper (lines 26–27) and in every test call site. The fuzz target `concurrent_verify.rs` initialises an `ArbitraryClock` correctly for TTL tests but ignores it on line 67 — `verified_at: Utc::now()` — defeating the fuzzer's temporal control.

The good news: the infrastructure for fixing all three is already in place. `ClockProvider`, `FakeRegistryBackend`, `MockClock`, `InMemoryStorage`, and `CanonicalDid` all exist. This plan threads them to the right call sites and fills the gaps (`UuidProvider`, `add_organization_member` SDK workflow, in-memory KEL tests).

---

## Current Architecture (What's Good)

**Ports already defined and implemented:**
- `ClockProvider` — `auths-core/src/ports/clock.rs` and `auths-verifier/src/clock.rs`. Fully injectable. Used correctly in `auths-sdk` (device.rs, pairing.rs, context.rs, rotation.rs).
- `FakeRegistryBackend` — `auths-test-utils/src/fakes/registry.rs`. Implements the full `RegistryBackend` trait (events, key states, attestations, org members) in `Mutex<HashMap>`. Already passes `registry_backend_contract_tests!` in `auths-id/tests/cases/registry_contract.rs`.
- `MockClock` — `auths-test-utils/src/fakes/clock.rs`. Returns a fixed timestamp.
- `CanonicalDid` — `auths-policy/src/types.rs`. Full validation (control chars, method/id segments, lowercase method). Ready for use at HTTP boundaries.
- Contract test macro — `registry_backend_contract_tests!` already exercises both `FakeRegistryBackend` and `GitRegistryBackend` via the same suite.

**What is already clean:**
- `auths-policy/src/eval.rs` — zero side effects; time is injected via `EvalContext`
- `auths-sdk/src/workflows/` — all existing workflows (`artifact`, `audit`, `diagnostics`, `provision`, `policy_diff`, `rotation`) use injected `ClockProvider`, no direct `Utc::now()` in `src/` paths
- `auths-auth-server` — `InMemorySessionStore::with_clock()` correctly injects the clock; `app_service.rs` routes all time through `Arc<dyn ClockProvider>`
- `auths-verifier/src/verify.rs` — accepts explicit time via `verify_at_time()` signature; `ClockProvider` is the entry point

---

## Audit Findings Summary

| Finding | Location | Severity | Evidence |
|---------|----------|----------|----------|
| `Utc::now()` in production core | `auths-core/src/trust/resolve.rs:146,217` `auths-core/src/trust/pinned.rs:276` `auths-core/src/pairing/token.rs:81,93` `auths-core/src/witness/storage.rs:97,157` | HIGH | Production paths bypass `ClockProvider` |
| `Utc::now()` in production domain | `auths-id/src/attestation/verify.rs:25,35` `auths-id/src/attestation/core.rs:35` `auths-id/src/keri/kel.rs:323,750,813` `auths-id/src/keri/incremental.rs:233` `auths-id/src/storage/keri.rs:592,621,638,666,677` `auths-id/src/agent_identity.rs:240,332,336` `auths-id/src/freeze.rs:200,201` | HIGH | Domain logic couples to OS clock |
| `Utc::now()` in fuzz target | `auths-auth-server/fuzz/fuzz_targets/concurrent_verify.rs:67` | MEDIUM | `ArbitraryClock` exists on line 34 but `verified_at` still calls `Utc::now()` |
| `Utc::now()` in domain tests | `auths-verifier/tests/cases/revocation_adversarial.rs:26,27,71,95,104,122` | MEDIUM | Non-deterministic test construction, flaky on clock boundaries |
| `Uuid::new_v4()` with no port | `auths-registry-server/src/routes/org.rs:311,585` | HIGH | `UuidProvider` trait does not exist; no adapter hook for acquirers |
| Custom DID parsing in route | `auths-registry-server/src/routes/org.rs:31–47` | HIGH | `CanonicalDid::parse` exists in `auths-policy` but is ignored; duplicate validation logic diverges from the policy engine |
| Domain helpers in HTTP module | `auths-registry-server/src/routes/org.rs:222–270` | HIGH | `find_admin_by_pubkey` and `find_member_attestation` are domain lookups living in an Axum handler file |
| `Attestation` construction with empty sigs | `auths-registry-server/src/routes/org.rs:309–326,583–600` | CRITICAL | Attestations stored with empty `identity_signature` and `device_signature`; no SDK signing step invoked |
| `add_organization_member` SDK gap | `auths-sdk/src/workflows/org.rs` | HIGH | File only contains `Role` enum; full member-add transaction lives nowhere in the SDK |
| Physical git repos in domain tests | `auths-id/tests/cases/recovery.rs:12,47,82` | MEDIUM | All three tests call `init_test_repo()` (physical disk I/O) despite `FakeRegistryBackend` being available |

> **Not a finding**: `Utc::now()` in `auths-core/src/policy/org.rs`, `device.rs`, and `auths-id/src/policy/mod.rs` — these are all in `#[cfg(test)]` blocks. The policy module itself is free of production clock reads.

---

## Mandatory Structural Principles

These inherit from v2 and add two new constraints discovered in this cycle.

### 1. `UuidProvider` Parity with `ClockProvider`

Every non-deterministic system call requires a port. Time has `ClockProvider`. UUID generation currently has no equivalent. An `UuidProvider` trait must be defined in `auths-core::ports`, with:
- `SystemUuidProvider` (wraps `Uuid::new_v4()`) as the production adapter
- `DeterministicUuidProvider` (counter-based) in `auths-test-utils::fakes`

### 2. Fuzz Targets Must Use Injected Ports for All Fields

When a fuzz target controls a clock or ID provider, every timestamp or identifier in the test scenario must be sourced from that provider. Mixing an injected provider with direct `Utc::now()` or `Uuid::new_v4()` within the same target defeats the fuzzer's state control.

### 3. Route Handlers Are Anemic Mappers, Not Domain Orchestrators

HTTP handlers must contain: JSON deserialization → boundary type parsing (e.g., `CanonicalDid::parse`) → one SDK call → HTTP response mapping. Domain lookups (`find_admin_by_pubkey`), struct construction (`Attestation { ... }`), and time/ID generation (`Utc::now()`, `Uuid::new_v4()`) are prohibited in route files.

### 4. Stored Attestations Must Bear Cryptographic Signatures

Any code path that constructs an `Attestation` and calls `store_org_member` must produce attestations with non-empty `identity_signature` and `device_signature`. Creating structurally valid but cryptographically unsigned attestations undermines the trust model this system is built on.

---

## Epic 3: SDK Boundary Enforcement — Registry Server Org Routes

**Objective**: Remove all domain logic from `auths-registry-server/src/routes/org.rs` and consolidate it into `auths-sdk/src/workflows/org.rs`. HTTP handlers become anemic mappers.

**Success Metrics:**
- `parse_keri_did` deleted from `org.rs`; replaced with `CanonicalDid::parse` at the HTTP boundary
- `find_admin_by_pubkey` and `find_member_attestation` moved to `auths-sdk`
- `Attestation` construction (with actual signing) moved to `auths-sdk`
- All `Utc::now()` and `Uuid::new_v4()` removed from `org.rs`; replaced with injected ports
- HTTP handlers are ≤ 30 lines each (excluding request/response type definitions)

### Story 3.1: Replace `parse_keri_did` with `CanonicalDid::parse` [S]

**Why**: `auths-registry-server/src/routes/org.rs:31–47` manually validates the `did:keri:` prefix and applies KERI-specific derivation-code checks that differ from `CanonicalDid::parse` in `auths-policy/src/types.rs`. The two implementations will drift over time. If `CanonicalDid` is ever extended (e.g., to handle multi-base encoding variants), the HTTP layer will silently remain on the old rules.

**Acceptance Criteria:**
- `parse_keri_did` function deleted
- All call sites use `CanonicalDid::parse(&org_did).map_err(|e| ApiError::InvalidRequest(...))`
- `auths-registry-server/Cargo.toml` adds `auths-policy` as a dependency (if not already present)

**Files:**
- `crates/auths-registry-server/src/routes/org.rs` — remove `parse_keri_did`, replace 8 call sites
- `crates/auths-registry-server/Cargo.toml` — add `auths-policy` dependency

```rust
// Before:
let prefix = parse_keri_did(&org_did)?;

// After:
use auths_policy::types::CanonicalDid;
let canonical = CanonicalDid::parse(&org_did)
    .map_err(|e| ApiError::InvalidRequest(format!("invalid organization DID: {}", e)))?;
let prefix = canonical.as_str();
```

### Story 3.2: Implement `add_organization_member` SDK Workflow [L]

**Why**: The `add_member` handler in `org.rs:287–338` and its multi-tenant variant (`org.rs:561–612`) construct `Attestation` structs with **empty `identity_signature` and `device_signature` fields** (lines 314–315, 588–589). This means the stored attestation is structurally valid but cryptographically unsigned — a critical integrity gap. The business transaction (admin lookup → capability validation → attestation construction → signing → storage) must live in the SDK, where it can be tested without HTTP and where signing can be properly enforced.

**Acceptance Criteria:**
- `auths-sdk/src/workflows/org.rs` implements `add_organization_member(backend, clock, id_provider, cmd) -> Result<Attestation, OrgError>`
- The workflow performs: signature verification → admin lookup → capability parsing → attestation construction with actual signing → storage
- The HTTP handlers for `add_member` and `add_member_for_tenant` delegate to this function
- No `Attestation { ... }` construction with empty signatures remains in `org.rs`
- `OrgError` is a `thiserror` enum covering: `AdminNotFound`, `InvalidCapability`, `StorageError`, `SignatureError`, `InvalidDid`

**Files:**
- `crates/auths-sdk/src/workflows/org.rs` — implement `add_organization_member`, `revoke_organization_member`, `update_member_capabilities`
- `crates/auths-sdk/src/error.rs` — add `OrgError` thiserror enum
- `crates/auths-registry-server/src/routes/org.rs` — handlers become thin delegates

```rust
// crates/auths-sdk/src/workflows/org.rs

pub struct AddMemberCommand {
    pub org_did: CanonicalDid,
    pub member_did: String,
    pub role: String,
    pub capabilities: Vec<String>,
    pub signature_hex: String,
    pub public_key_hex: String,
    pub raw_payload: Vec<u8>,
}

pub async fn add_organization_member(
    backend: &dyn RegistryBackend,
    clock: &dyn ClockProvider,
    id_provider: &dyn UuidProvider,
    cmd: AddMemberCommand,
) -> Result<Attestation, OrgError> {
    let parsed_capabilities = parse_capabilities(&cmd.capabilities)?;
    let admin = find_admin(backend, cmd.org_did.as_str(), &cmd.public_key_hex)?;
    let member = build_signed_member_attestation(&admin, &cmd, parsed_capabilities, clock, id_provider)?;
    backend.store_org_member(cmd.org_did.as_str(), &member)
        .map_err(OrgError::StorageError)?;
    Ok(member)
}
```

### Story 3.3: Migrate `find_admin_by_pubkey` and `find_member_attestation` to SDK [M]

**Why**: These two functions are domain-level registry queries. Their presence in `org.rs` means any interface other than HTTP (gRPC, CLI, test harness) that needs to validate admin privileges or look up a member must either call through the HTTP server or duplicate the logic.

**Acceptance Criteria:**
- `find_admin_by_pubkey` migrated to `auths-sdk/src/workflows/org.rs` as `find_admin`
- `find_member_attestation` migrated as `find_member`
- Both functions are `pub(crate)` within `auths-sdk` (not part of the public API surface, only used by other SDK workflows)
- `org.rs` no longer defines these functions

**Files:**
- `crates/auths-sdk/src/workflows/org.rs` — add `find_admin`, `find_member`
- `crates/auths-registry-server/src/routes/org.rs` — remove the two helper functions

---

## Epic 4: In-Memory Domain Test Harness for KERI Recovery

**Objective**: Replace physical git repository I/O in `auths-id/tests/cases/recovery.rs` with the existing `FakeRegistryBackend`. Domain-level KERI tests must run in memory.

**Success Metrics:**
- Zero `init_test_repo()` calls in `auths-id/tests/cases/recovery.rs`
- All three recovery tests (`attacker_cannot_rotate_without_precommitted_key`, `full_recovery_flow_end_to_end`, `compromised_key_cannot_rotate_after_recovery`) pass using only `FakeRegistryBackend` and injected keys
- Test suite execution time for the recovery module drops from I/O-bound to milliseconds

### Story 4.1: Refactor Recovery Tests to Use `FakeRegistryBackend` [M]

**Why**: `auths-id/tests/cases/recovery.rs` calls `init_test_repo()` on lines 12, 47, and 82. Each call initialises a physical git2 repository in a `tempfile::TempDir`. The three tests are domain logic tests: they verify that a compromised key cannot rotate without the pre-committed next key. This is a cryptographic invariant that has no dependency on git2 — the KEL append-only enforcement is what matters, and `FakeRegistryBackend` already enforces sequence gaps (`RegistryError::SequenceGap`) and prevents overwrites (`RegistryError::EventExists`).

**Acceptance Criteria:**
- `auths-id/tests/cases/recovery.rs` imports `auths_test_utils::fakes::registry::FakeRegistryBackend`
- All three test functions use `FakeRegistryBackend::new()` as the KEL backend
- `create_keri_identity`, `rotate_keys`, `validate_kel`, and `get_key_state` are called with the fake backend
- No `tempfile` or `git2` imports remain in `recovery.rs`

**Note on prerequisite**: This story depends on Epic 2 (Story 2.2) because `create_keri_identity` and `rotate_keys` currently call `Utc::now()` internally. Once those accept an injected `now: DateTime<Utc>`, the tests can pass a fixed timestamp.

**Files:**
- `crates/auths-id/tests/cases/recovery.rs` — replace all `init_test_repo()` with `FakeRegistryBackend::new()`

```rust
// Before:
let (_dir, repo) = auths_test_utils::git::init_test_repo();
let init: InceptionResult = create_keri_identity(&repo, None).unwrap();

// After:
let backend = FakeRegistryBackend::new();
let fixed_ts = DateTime::UNIX_EPOCH + Duration::days(1000);
let init: InceptionResult = create_keri_identity(&backend, fixed_ts, None).unwrap();
```

---

## PR Sequencing Plan

Ordered to minimise merge conflicts and ensure each PR is independently mergeable.

| PR | Scope | Risk | Depends On | Epic |
|----|-------|------|------------|------|
| **PR-1** | Add `UuidProvider` trait + `SystemUuidProvider` in `auths-core`; add `DeterministicUuidProvider` in `auths-test-utils` | Low | — | 1 |
| **PR-2** | Fix `concurrent_verify.rs` fuzzer: `verified_at: now` instead of `Utc::now()` | Low | — | 1 |
| **PR-3** | Parameterise `create_signed_attestation` in `revocation_adversarial.rs` to accept fixed timestamps | Low | — | 1 |
| **PR-4** | Add `.clippy.toml` disallowing `Uuid::new_v4`; annotate existing adapter call sites temporarily | Low | PR-1 | 1 |
| **PR-5** | Inject clock into `auths-core` trust and pairing functions | Medium | — | 2 |
| **PR-6** | Inject clock into `auths-id` attestation verify/core paths | Medium | PR-5 | 2 |
| **PR-7** | Inject clock into `auths-id` KEL and storage paths | **High** | PR-6 | 2 |
| **PR-8** | Inject clock into `auths-id` agent identity, freeze, and domain message paths | Medium | PR-7 | 2 |
| **PR-9** | Replace `parse_keri_did` in `org.rs` with `CanonicalDid::parse` | Low | — | 3 |
| **PR-10** | Define `OrgError` thiserror enum in `auths-sdk`; add `auths-policy` dep to registry server | Low | — | 3 |
| **PR-11** | Implement `add_organization_member` SDK workflow with proper signing; migrate `find_admin` and `find_member` | **High** | PR-1, PR-10 | 3 |
| **PR-12** | Refactor HTTP handlers in `org.rs` to delegate to SDK workflow | Medium | PR-11 | 3 |
| **PR-13** | Refactor `recovery.rs` to use `FakeRegistryBackend` | Medium | PR-7 | 4 |
| **PR-14** | Remove temporary `#[allow(clippy::disallowed_methods)]` from PR-4; all call sites now use `UuidProvider` | Low | PR-12 | 1 |

---

## File Inventory

### New Files (5)

| File | Epic | Purpose |
|------|------|---------|
| `crates/auths-core/src/ports/id.rs` | 1 | `UuidProvider` trait + `SystemUuidProvider` adapter |
| `crates/auths-test-utils/src/fakes/id.rs` | 1 | `DeterministicUuidProvider` for tests and fuzzers |
| `crates/auths-sdk/src/error/org.rs` | 3 | `OrgError` thiserror enum |
| `.clippy.toml` | 1 | Workspace-level disallowed methods |

### Files to Modify (27)

| File | Epic | Change |
|------|------|--------|
| `crates/auths-core/src/ports/mod.rs` | 1 | Add `pub mod id;` |
| `crates/auths-core/src/trust/resolve.rs` | 2 | Accept `now: DateTime<Utc>` in trust resolution |
| `crates/auths-core/src/trust/pinned.rs` | 2 | Accept `now: DateTime<Utc>` |
| `crates/auths-core/src/pairing/token.rs` | 2 | Accept `now: DateTime<Utc>` in `new()` and `is_valid()` |
| `crates/auths-core/src/witness/storage.rs` | 2 | Accept `now: DateTime<Utc>` |
| `crates/auths-id/src/attestation/verify.rs` | 2 | Accept `now: DateTime<Utc>` for expiry/skew checks |
| `crates/auths-id/src/attestation/core.rs` | 2 | Accept `now: DateTime<Utc>` for timestamp updates |
| `crates/auths-id/src/attestation/create.rs` | 2 | Accept `now: DateTime<Utc>` for skew validation |
| `crates/auths-id/src/keri/kel.rs` | 2 | Accept `now: DateTime<Utc>` in event creation functions |
| `crates/auths-id/src/keri/incremental.rs` | 2 | Accept `now: DateTime<Utc>` |
| `crates/auths-id/src/storage/keri.rs` | 2 | Accept `now: DateTime<Utc>` in storage writes |
| `crates/auths-id/src/agent_identity.rs` | 2 | Accept `now: DateTime<Utc>` |
| `crates/auths-id/src/freeze.rs` | 2 | Accept `now: DateTime<Utc>` in `freeze()` |
| `crates/auths-id/src/domain/attestation_message.rs` | 2 | Accept `now: DateTime<Utc>` |
| `crates/auths-sdk/src/` (all callers) | 2 | Pass `clock.now()` to above functions |
| `crates/auths-auth-server/fuzz/fuzz_targets/concurrent_verify.rs` | 1 | Use `now` from `clock.now()` for `verified_at` |
| `crates/auths-verifier/tests/cases/revocation_adversarial.rs` | 1 | Parameterise helper; use fixed timestamps |
| `crates/auths-registry-server/src/routes/org.rs` | 3 | Remove `parse_keri_did`, domain helpers, `Attestation` construction; delegate to SDK |
| `crates/auths-registry-server/Cargo.toml` | 3 | Add `auths-policy` dependency |
| `crates/auths-sdk/src/workflows/org.rs` | 3 | Add full member management workflows |
| `crates/auths-sdk/src/error.rs` | 3 | Add `OrgError` |
| `crates/auths-test-utils/src/fakes/mod.rs` | 1 | Add `pub mod id;` |
| `crates/auths-id/tests/cases/recovery.rs` | 4 | Replace `init_test_repo()` with `FakeRegistryBackend` |
| `.github/workflows/ci.yml` | 1 | Add `clippy::disallowed_methods` flag to CI clippy step |

---

## Code Standards (Enforced)

Inherited from v2 with two additions:

1. **DRY & Separated**: Business workflows entirely separated from I/O. No monolithic functions.
2. **Documentation**: Rustdoc mandatory for all exported SDK/Core items. `/// Description`, `/// Args:`, `/// Usage:` blocks per CLAUDE.md conventions.
3. **Minimalism**: No inline comments explaining process. Use structural decomposition. Per CLAUDE.md: only comment opinionated decisions.
4. **Domain-Specific Errors**: `thiserror` enums only. No `anyhow::Error` or `Box<dyn Error>` in Core/SDK.
5. **`thiserror`/`anyhow` Translation Boundary**: `anyhow::Context` permitted at CLI/server boundaries only. SDK error types use typed `thiserror` variants.
6. **No reverse dependencies**: Core and SDK must never reference presentation layer crates.
7. **All Ports Must Have Fakes**: Every port trait (`ClockProvider`, `UuidProvider`, `RegistryBackend`, etc.) must have a corresponding fake in `auths-test-utils`. No port is added without an accompanying deterministic test double.
8. **Fuzz Targets Use Injected Ports Exclusively**: Any field in a fuzz target scenario that is time- or identity-dependent must be derived from the injected clock or ID provider. Direct OS system calls (`Utc::now()`, `Uuid::new_v4()`) are prohibited even in fuzz targets that already have a controlled provider.
