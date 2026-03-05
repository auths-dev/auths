# Code Safety: Eradicate unwrap/expect and Remove anyhow from Library Crates

## Overview

Mobile apps and external FFI/WASM consumers cannot tolerate panics. This epic eliminates all `unwrap()` and `expect()` calls from library crate production code, removes `anyhow` from `auths-core`'s runtime dependencies, and enforces these constraints via clippy lints.

## Scope

**In scope (lint enforcement):** `auths-core`, `auths-verifier`, `auths-sdk`, `auths-id`
**In scope (anyhow removal):** `auths-core` (only library crate still using anyhow in production code)
**Out of scope:** `auths-cli` (presentation layer — anyhow is appropriate per CLAUDE.md), `auths-storage` (deferred), `auths-policy` (deferred)

**Key finding:** `auths-sdk` is already clean — 0 non-test unwraps, no anyhow dependency. Only lint configuration needed.

## Current State

| Crate | Non-test unwrap/expect | anyhow in deps |
|-------|----------------------|----------------|
| auths-core | ~40+ (mutex ~18, crypto ~5, witness ~7, config ~2, FFI ~3) | Yes (api/runtime.rs) |
| auths-id | ~7 (structurally guaranteed, guarded) | No |
| auths-verifier | ~1 genuine (FFI tokio runtime); rest are safe catch_unwind | No |
| auths-sdk | 0 | No |

## Approach

### `#[allow]` Policy

Three categories of unwrap/expect, each with a defined handling:

1. **Structurally guaranteed** (e.g., `git2::Oid` always 20 bytes, `strip_prefix` after `starts_with`): Use `#[allow(clippy::expect_used)]` with `// SAFETY:` comment explaining the invariant.

2. **Mutex locks**: Convert to `Result` propagation using `.lock().map_err(|_| DomainError::MutexPoisoned)?`. The `AgentError::MutexError` variant already exists. For methods that currently return `()`, either change signature to `Result<()>` or use `.lock().unwrap_or_else(|e| e.into_inner())` to silently recover from poisoning (appropriate for cache-clear operations).

3. **Static/global initialization** (tokio runtime in `Lazy`/`with_runtime`): Use `#[allow(clippy::expect_used)]` with `// SAFETY:` comment — these are unrecoverable and should crash the process.

### anyhow Removal Strategy

The only production `anyhow` usage in library crates is in `auths-core/src/api/runtime.rs` (ssh-add interaction, macOS-only). Replace with new `AgentError` variants or a focused `SshAgentError` enum. Move `anyhow` to `[dev-dependencies]` only.

### Lint Enforcement

Add to `clippy.toml`:
```toml
allow-unwrap-in-tests = true
allow-expect-in-tests = true
```

Add `#![deny(clippy::unwrap_used, clippy::expect_used)]` to each target crate's `lib.rs`. Add `#![allow(clippy::unwrap_used, clippy::expect_used)]` to integration test entry points (`tests/integration.rs`) due to clippy issue #13981.

## Quick Commands

```bash
# Smoke test — verify all crates compile and pass after changes
cargo clippy --all-targets --all-features -- -D warnings
cargo nextest run --workspace
cargo test --all --doc

# WASM check (auths-verifier)
cd crates/auths-verifier && cargo check --target wasm32-unknown-unknown --no-default-features --features wasm
```

## Acceptance Criteria

- [ ] Zero `unwrap()`/`expect()` in non-test code of auths-core, auths-id, auths-verifier, auths-sdk — except where explicitly `#[allow]`-ed with SAFETY comment
- [ ] `#![deny(clippy::unwrap_used, clippy::expect_used)]` present in all 4 crate lib.rs files
- [ ] `clippy.toml` has `allow-unwrap-in-tests = true` and `allow-expect-in-tests = true`
- [ ] `anyhow` removed from `auths-core` `[dependencies]` (kept only in `[dev-dependencies]`)
- [ ] All existing tests pass (`cargo nextest run --workspace && cargo test --all --doc`)
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes
- [ ] WASM target check passes for auths-verifier
- [ ] No new `#[allow]` annotations without a `// SAFETY:` comment

## References

- clippy.toml: `/Users/bordumb/workspace/repositories/auths-base/auths/clippy.toml`
- auths-core error types: `crates/auths-core/src/error.rs` (AgentError, TrustError)
- auths-core mutex unwraps: `crates/auths-core/src/storage/memory.rs`, `crates/auths-core/src/signing.rs`
- auths-core anyhow usage: `crates/auths-core/src/api/runtime.rs:46,52,585`
- auths-verifier FFI: `crates/auths-verifier/src/ffi.rs`
- auths-id unwraps: `crates/auths-id/src/witness.rs`, `crates/auths-id/src/identity/resolve.rs`
- Clippy issue #13981: allow-unwrap-in-tests doesn't cover integration tests
- Existing `AgentError::MutexError` variant for mutex poisoning
