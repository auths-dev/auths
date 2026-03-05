# fn-3.7 Add did:keri resolution to RadicleIdentityResolver

## Description
REPLACE the `UnsupportedMethod` error arm in `RadicleIdentityResolver::resolve()` with full KEL replay logic for `did:keri` identifiers. No static DID mapping. No shortcuts.

## Strict Requirements

1. **REPLACE**: The `did:keri:` match arm at `crates/auths-radicle/src/identity.rs:180-191` must perform full KEL replay to verify the current key. No caching a result from a previous call. No trusting a pre-resolved mapping.
2. **KEL replay mandatory**: If a DID is `did:keri:`, the resolver MUST NOT return a result unless it has replayed the KEL from inception to current tip and verified every event's signature chain.
3. **DELETE** any "static" DID mapping from earlier prototypes if present
4. **Reuse** `ed25519_to_did_key()` from `auths-id/src/identity/resolve.rs:157` for key-to-DID conversion
5. **Reuse** KEL validation from `auths-id/src/keri/validate.rs` -- this is pure, stateless validation (no I/O side effects)

## Implementation

In `crates/auths-radicle/src/identity.rs`:

1. Extract KERI prefix from `did:keri:<prefix>`
2. Load KEL from identity repo at `refs/keri/kel` via `GitRadicleStorage` (fn-3.6)
3. Replay full event chain using `validate_kel()` from `auths-id/src/keri/validate.rs`
4. Extract current signing key(s) from derived `KeyState`
5. Convert to `did:key:` identifiers via `ed25519_to_did_key()`
6. Return resolved keys

## Dependencies
- fn-3.6 (real `AuthsStorage` / `GitRadicleStorage`) -- needed to load KEL from Git

## Key Files
- `crates/auths-radicle/src/identity.rs:180-191` -- REPLACE `UnsupportedMethod` arm
- `crates/auths-id/src/identity/resolve.rs:157` -- `ed25519_to_did_key()` (reuse)
- `crates/auths-id/src/keri/validate.rs` -- `validate_kel()` (reuse -- pure function)
- `crates/auths-id/src/keri/state.rs` -- `KeyState` (derive current keys from)

## Test Plan
- Test: valid `did:keri:` resolves to correct `did:key:` after full KEL replay
- Test: post-rotation `did:keri:` resolves to NEW key (not old)
- Test: nonexistent `did:keri:` returns typed error
- Test: corrupt KEL returns error (not partial result)
- Test: `did:key:` resolution unchanged (regression)
## Problem

`RadicleIdentityResolver::resolve()` at `crates/auths-radicle/src/identity.rs:180-191` returns `UnsupportedMethod` for `did:keri:` DIDs. Phase 4 requires resolving `did:keri` identifiers to discover which `did:key` is currently authorized.

## Implementation

In `crates/auths-radicle/src/identity.rs`:

1. Add a `did:keri:` match arm in `resolve()` that:
   - Extracts the KERI prefix from `did:keri:<prefix>`
   - Loads the KEL from the identity repo at `refs/keri/kel`
   - Processes the event chain to derive current key state
   - Returns the current signing key(s) as `did:key:` identifiers

2. The resolver needs access to a Git repository (it already has `git2::Repository`). For `did:keri` resolution, it may need to access a different repo (the identity repo vs the project repo). Consider:
   - Adding a method `resolve_keri(&self, prefix: &str, identity_repo: &Repository) -> Result<Vec<String>>`
   - Or accepting the identity repo path as part of the resolver config

3. Reuse `ed25519_to_did_key()` from `auths-id/src/identity/resolve.rs:157` for key-to-DID conversion

## Key Files
- `crates/auths-radicle/src/identity.rs:59-192` -- `RadicleIdentityResolver`
- `crates/auths-id/src/identity/resolve.rs:157` -- `ed25519_to_did_key()` (reuse)
- `crates/auths-radicle/src/refs.rs` -- `KERI_KEL_REF` constant

## Test Plan
- Unit test: resolve valid `did:keri:` returns correct `did:key:` for current signing key
- Unit test: resolve `did:keri:` after rotation returns new key, not old key
- Unit test: resolve nonexistent `did:keri:` returns appropriate error
- Unit test: `did:key:` resolution still works unchanged

## Code Quality
- **DRY**: Do not repeat logic; extract shared patterns into helper functions or traits.
- **Modular Design**: Avoid monolithic functions. Decompose complex logic into small, focused, and testable units.
- **Strictness**: Adhere to the "Zero-Debt" mandate—if old code is redundant, delete it; do not leave "TODO" or "Legacy" stubs.

## Acceptance
- [ ] `UnsupportedMethod` arm for `did:keri:` REPLACED with KEL replay
- [ ] Full KEL replay mandatory -- no shortcuts, no cached results
- [ ] Reuses `validate_kel()` from `auths-id` (pure function)
- [ ] Reuses `ed25519_to_did_key()` for key conversion
- [ ] Test: valid `did:keri:` resolves to correct `did:key:`
- [ ] Test: post-rotation resolves to new key
- [ ] Test: nonexistent `did:keri:` returns typed error
- [ ] Test: corrupt KEL returns error
- [ ] Test: `did:key:` regression passes
- [ ] `cargo nextest run -p auths-radicle` passes
## Done summary
Replaced UnsupportedMethod arm for did:keri: with full KEL replay via replay_kel(). Added resolve_keri method, read_kel_events helper, 3 new error variants, identity_repo_path support. 10 tests including rotation and separate identity repo.
## Evidence
- Commits: 7b8cac1
- Tests: resolve_did_keri_returns_correct_key, resolve_did_keri_after_rotation_returns_new_key, resolve_did_keri_no_kel_returns_error, resolve_did_keri_corrupt_kel_returns_error, resolve_did_keri_with_separate_identity_repo
- PRs:
