# fn-2.1 Extract MockStorage to shared test helper

## Description
Extract the duplicated `MockStorage` struct and its `AuthsStorage` trait implementation from 6 test files into a single shared location.

## Current state

`MockStorage` (with `HashMap` fields for `key_states`, `attestations`, `device_to_identity`, `identity_tips`) is copy-pasted in:
1. `crates/auths-radicle/src/verify.rs` (unit tests)
2. `crates/auths-radicle/tests/cases/authorization.rs`
3. `crates/auths-radicle/tests/cases/revocation.rs`
4. `crates/auths-radicle/tests/cases/multi_device_e2e.rs`
5. `crates/auths-radicle/tests/cases/stale_state.rs`
6. `crates/auths-radicle/tests/cases/stale_node.rs`

Also duplicated: helper functions like `make_key_state()`, `make_attestation()`, `register_device()`, `make_enforce_request()`.

## Target

Create `crates/auths-radicle/tests/cases/helpers.rs` (or add to `crates/auths-test-utils`) with:
- `MockStorage` struct + `AuthsStorage` impl
- Shared helper functions used across multiple test files

Update all 6 files to import from the shared module. Per CLAUDE.md test conventions, test helpers belong in `tests/cases/` submodules or `auths-test-utils`.

## Key files

- `crates/auths-radicle/src/verify.rs` — unit test `MockStorage` (in `#[cfg(test)]` module)
- `crates/auths-radicle/tests/cases/mod.rs` — test module registry
- All 6 files listed above

## Code Quality
- **DRY**: Do not repeat logic; extract shared patterns into helper functions or traits.
- **Modular Design**: Avoid monolithic functions. Decompose complex logic into small, focused, and testable units.
- **Strictness**: Adhere to the "Zero-Debt" mandate—if old code is redundant, delete it; do not leave "TODO" or "Legacy" stubs.

## Acceptance
- [ ] `MockStorage` defined in exactly one place for integration tests
- [ ] All integration test files (`authorization.rs`, `revocation.rs`, `multi_device_e2e.rs`, `stale_state.rs`, `stale_node.rs`) import `MockStorage` from the shared module
- [ ] Unit tests in `verify.rs` either import from shared or keep a minimal local copy (acceptable since unit tests are in `src/`)
- [ ] Common helper functions extracted alongside `MockStorage`
- [ ] `cargo nextest run -p auths_radicle` passes — all existing tests still work
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` clean
## Done summary
Extracted MockStorage, make_key_state, make_test_attestation, DeviceFixture, and register_device into shared helpers.rs. Rewrote all 5 integration test files (authorization, revocation, stale_state, stale_node, multi_device_e2e) to use shared helpers. Removed all duplicate code.
## Evidence
- Commits:
- Tests: deferred to fn-2.4
- PRs:
