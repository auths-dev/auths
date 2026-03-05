# fn-2.4 Add Rust integration test for two-device controller resolution

## Description
Add a Rust integration test that explicitly verifies two devices linked to the same identity resolve to the same controller DID via the bridge's `find_identity_for_device`.

## What to add

In `crates/auths-radicle/tests/cases/multi_device_e2e.rs` (or a new test function within it), add a test that:

1. Creates two device keypairs with distinct DIDs
2. Registers both under the same controller identity DID in MockStorage
3. Calls `find_identity_for_device(device1_did, repo_id)` → gets controller DID
4. Calls `find_identity_for_device(device2_did, repo_id)` → gets controller DID
5. Asserts both return `Some(same_controller_did)`
6. Also tests the negative case: an unregistered device DID returns `None`

This test uses the shared MockStorage from fn-2.1. The test should be named something like `two_devices_resolve_to_same_controller`.

## Key files

- `crates/auths-radicle/tests/cases/multi_device_e2e.rs` — add new test function
- Shared MockStorage from fn-2.1

## Note

This tests the trait-level resolution contract. The real Git-backed `AuthsStorage` implementation is out of scope for Iteration 1 but this test establishes the behavioral contract that any implementation must satisfy.

## Code Quality
- **DRY**: Do not repeat logic; extract shared patterns into helper functions or traits.
- **Modular Design**: Avoid monolithic functions. Decompose complex logic into small, focused, and testable units.
- **Strictness**: Adhere to the "Zero-Debt" mandate—if old code is redundant, delete it; do not leave "TODO" or "Legacy" stubs.

## Acceptance
- [ ] Test `two_devices_resolve_to_same_controller` exists in `multi_device_e2e.rs`
- [ ] Two device DIDs resolve to the same controller DID via `find_identity_for_device`
- [ ] Unregistered device DID returns `None`
- [ ] Uses shared MockStorage (from fn-2.1), not a local copy
- [ ] `cargo nextest run -p auths_radicle -E 'test(two_devices_resolve)'` passes
## Done summary
Added two_devices_resolve_to_same_controller test that verifies both devices resolve to same controller DID and unregistered device returns None. All 66 auths-radicle tests pass. Clippy and full build clean.
## Evidence
- Commits:
- Tests: 66 passed, 0 skipped
- PRs:
