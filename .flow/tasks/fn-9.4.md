# fn-9.4 Fix unwraps in auths-id

## Description
## Fix unwraps in auths-id

7 occurrences in non-test code, most are structurally guaranteed.

### Changes

1. **`src/witness.rs:44`** — `.expect("git2::Oid is always 20 bytes")`: Add `#[allow(clippy::expect_used)]` with `// SAFETY: git2::Oid is always exactly 20 bytes`.

2. **`src/witness.rs:61`** — `.expect("EventHash is always 20 bytes")`: Same — `#[allow]` with SAFETY comment.

3. **`src/identity/resolve.rs:111`** — `did.strip_prefix("did:keri:").unwrap()` guarded by `starts_with` check on line 110. Refactor to `if let Some(suffix) = did.strip_prefix("did:keri:")` to eliminate the unwrap entirely.

4. **`src/identity/resolve.rs:162`** — `.expect("ed25519_to_did_key requires exactly 32 bytes")`: This is a documented precondition. Convert to proper error return if the function signature allows it, or `#[allow]` with SAFETY comment.

5. **`src/attestation/export.rs:154`** — `previous_attestation.as_ref().unwrap()` guarded by `is_none()` check on line 152. Refactor to `if let Some(prev) = previous_attestation.as_ref()`.

6. **`src/domain/attestation_message.rs:27`** — `previous.unwrap()` guarded by `is_none()` check on line 25. Refactor to `if let Some(prev) = previous`.

7. **`src/keri/incremental.rs:283`** — `.expect("parent_count was 1")` after count check. Add `#[allow]` with SAFETY comment, or refactor to use `.ok_or_else()`.

### Files to modify
- `crates/auths-id/src/witness.rs`
- `crates/auths-id/src/identity/resolve.rs`
- `crates/auths-id/src/attestation/export.rs`
- `crates/auths-id/src/domain/attestation_message.rs`
- `crates/auths-id/src/keri/incremental.rs`

### Smoke test
```bash
cargo nextest run -p auths_id
```
## Acceptance
- [ ] All `unwrap()`/`expect()` in `crates/auths-id/src/` have either been replaced or annotated with `#[allow]` + SAFETY comment
- [ ] Guarded unwraps (strip_prefix, is_none checks) refactored to `if let` / `match` patterns
- [ ] `cargo nextest run -p auths_id` passes
- [ ] No functional behavior changes
## Done summary
TBD

## Evidence
- Commits:
- Tests:
- PRs:
