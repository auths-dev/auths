# KERI Identity Unification across Radicle Stack

## Overview

Unify Radicle device identities (`did:key`) with KERI person identities (`did:keri`) across four repositories:
- `auths-radicle` (Rust identity/bridge logic)
- `radicle-httpd` (Rust HTTP API)
- `radicle-explorer` (Svelte frontend)
- `auths-verifier` / `auths-verifier-ts` (WASM verification)

The goal is for `auths-radicle` to be **the single interface** that Radicle consumers (heartwood, radicle-explorer, radicle.xyz) use for identity resolution, KERI state, and device verification.

## Architectural Principles

- **Type Safety**: Move away from "string-ly typed" DIDs to structured objects. Enforce the Rust-to-Svelte contract at the boundary via Zod schemas.
- **DRY**: Centralize all KERI resolution logic in `auths-radicle`. Consumers (radicle-httpd, frontend) must never re-implement Git commit-walking or KEL replay.
- **Ports & Adapters**: Use the `AuthsStorage` trait to decouple bridge logic from Git implementations, enabling testing and future optimization (e.g., SQLite cache layer).
- **Error Fidelity**: Never swallow resolution errors. Introduce typed `IdentityError` variants at the HTTP boundary for production debugging.
- **Complexity Hiding**: The 2-blob attestation storage format (Git refs) is a Radicle implementation detail. The API layer must serialize it into clean JSON so the frontend never touches raw Git data.

## Scope

### In Scope
- Fix compile blockers in `delegates.rs`, `identity.rs`, `v1.rs` (Axum syntax, module registration, impl blocks)
- Refactor `RadicleIdentity` and expose `resolve_keri` publicly
- WASM binding audit for `verifyDeviceLink`
- Complete radicle-httpd endpoints: user/delegate with devices, KEL, attestations
- `did:keri` -> repos resolution in delegates_repos_handler
- Frontend: WASM integration, DID parsing for `did:keri`, HTTP client methods, Profile Unification UI, auths.ts helper
- E2E: API assertions in radicle-e2e.sh, optional Playwright test

### Out of Scope
- Mobile layout optimization for KERI profiles
- Verification result caching strategy
- Delegation support (`dip`/`drt` events)
- KERI witness quorum enforcement

## Approach

### Phase 1: Infrastructure Cleanup (4 tasks)
Prerequisite fixes in `identity.rs` (stray `}`), `delegates.rs` (duplicate derive, extra `}`), Axum route syntax (`:did` -> `{did}`), and `v1.rs` identity module registration. These are silent killers of IDE intelligence and route matching.

### Phase 2: Core Logic Refactoring (3 tasks)
Refactor `RadicleIdentity` struct (structured DIDs, not strings), expose `resolve_keri` as the "rich" public API (separate from the `DidResolver` trait for internal vs external consumption), audit WASM bindings for JSON field name mismatches.

### Phase 3: API Implementation (4 tasks)
Extend user endpoint with real device list and proper error propagation, implement KEL endpoint with correct RIP-X namespace ref discovery, implement attestation endpoint that hides 2-blob storage complexity, add `did:keri` -> repos "UX glue" lookup.

### Phase 4: Frontend Implementation (5 tasks)
WASM integration + Vite config (lazy init, no top-level-await), DID parsing/formatting for `did:keri` (including blockies avatar seeding), Zod-validated HTTP client methods, Profile Unification UI with Svelte 5 runes, auths.ts verification helper.

### Phase 5: Verification (2 tasks)
E2E API assertions to guard the bridge contract, optional Playwright coverage for the "Verified" badge in-browser.

## Required Repositories
1. `/Users/bordumb/workspace/repositories/auths-base/auths/crates` - identity and bridge logic
2. `/Users/bordumb/workspace/repositories/heartwood/crates` - Radicle node, storage, API
3. `/Users/bordumb/workspace/repositories/radicle-base/radicle-explorer` - Svelte frontend + radicle-httpd
4. `/Users/bordumb/workspace/repositories/radicle-base/radicle-explorer/radicle-httpd` - HTTP API crate

## Work Conventions
- Do NOT run workspace clippy, tests, or full builds
- If running checks: `cargo build -p auths-{crate_name} --all-features 2>&1 | grep "^error\[E" -A 10`
- Commits use `--no-verify`, do NOT add Claude as co-author
- auths-* crates are pre-launch: backwards compatibility not important
- Code straight through, think deeply about downstream issues

## Quick Commands
```bash
# Smoke test: check auths-radicle compiles
cargo build -p auths-radicle --all-features 2>&1 | grep "^error\[E" -A 10

# Smoke test: check auths-verifier WASM target
cargo check -p auths-verifier --target wasm32-unknown-unknown --no-default-features --features wasm

# Smoke test: check radicle-httpd compiles
cd /Users/bordumb/workspace/repositories/radicle-base/radicle-explorer/radicle-httpd && cargo build 2>&1 | grep "^error\[E" -A 10
```

## Acceptance
- [ ] `RadicleIdentity` has structured KERI fields (not string-typed) and `resolve_keri` is public
- [ ] WASM `verifyDeviceLink` returns JSON matching `DeviceLinkResult` TypeScript type (no field mismatches)
- [ ] `GET /v1/users/:did` returns `controller_did`, `is_keri`, populated `devices` with proper error variants
- [ ] `GET /v1/identity/:did/kel` returns full KEL JSON via RIP-X namespace refs
- [ ] `GET /v1/identity/:did/attestations` returns clean attestation JSON (2-blob complexity hidden)
- [ ] Frontend parses and displays both `did:key` and `did:keri` identities with consistent avatars
- [ ] Profile Unification toggles between Device View and Person View using Svelte 5 runes
- [ ] WASM verification runs lazily on page load via `auths.ts` helper (no blocking of initial paint)
- [ ] E2E script asserts `controller_did` after `pair` operation (bridge contract guard)
- [ ] All files compile (no `error[E` output from targeted builds)

## Key References
- `RadicleIdentity`: `auths-radicle/src/identity.rs:69-80`
- `resolve_keri`: `auths-radicle/src/identity.rs:117-136`
- `wasm_verify_device_link`: `auths-verifier/src/wasm.rs:369-411`
- `DeviceLinkVerification`: `auths-verifier/src/verify.rs:205-240`
- `@auths/verifier` TS package: `packages/auths-verifier-ts/src/index.ts`
- radicle-httpd v1 router: `radicle-httpd/src/api/v1.rs:14-27`
- delegates handler: `radicle-httpd/src/api/v1/delegates.rs:35-57`
- identity endpoints: `radicle-httpd/src/api/v1/identity.rs:1-39`
- parseNodeId: `radicle-explorer/src/lib/utils.ts:16-37`
- User View: `radicle-explorer/src/views/users/View.svelte:1-425`
- HttpdClient: `radicle-explorer/http-client/index.ts:157-270`
- E2E script: `auths/scripts/radicle-e2e.sh`
- Review: `auths/docs/plans/radicle_cleanup.md`

## Risks
- `radicle 0.21.0` may not have `Did::Keri` variant — delegates.rs pattern matching requires it
- Cross-repo relative paths (`../../../auths-base/...`) may break in CI
- Heartwood uses Rust edition 2021 vs auths edition 2024 — syntax differences possible
- WASM `Event` serialization format may not match what frontend `verifyDeviceLink()` expects
- `kel_handler` repo discovery path is likely wrong (uses `storage_path/did` not identity namespace refs)
