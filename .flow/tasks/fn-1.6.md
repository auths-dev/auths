# fn-1.6 Full verification pipeline wired to Radicle storage

## Description
Wire `DefaultBridge::verify_signer()` to use the `RadicleAuthsStorage` impl from fn-1.4/1.5, creating the full authorization pipeline: DID translation -> identity lookup -> KEL validation -> attestation verification -> policy evaluation -> result.

### What to implement

1. Update `DefaultBridge::verify_signer()` at `crates/auths-radicle/src/verify.rs:100-127` to:
   - Use `repo_id` (currently unused) for identity lookup scope
   - Call `find_identity_for_device()` with the device's `did:key` and `repo_id`
   - Load `KeyState` via `load_key_state()`
   - Load attestation via `load_attestation()`
   - Verify both RIP-X signatures
   - Evaluate policy (revocation, expiry) via `evaluate_compiled()` at `crates/auths-id/src/policy/mod.rs:153`
   - Return `VerifyResult::Verified`, `Rejected`, or `Warn`
2. **Fail-closed design**: The pipeline must be fail-closed — any error defaults to `Rejected` unless specifically handled by Observe mode (fn-1.9). An unhandled error path should never produce `Verified`.
3. **anyhow migration**: Migrate `identity.rs` from `anyhow` to `thiserror`. Currently `identity.rs:6` imports `anyhow::{Context, Error, Result, anyhow}` — this violates the project's thiserror-only rule for library crates. Create domain-specific error variants in `BridgeError` or a new `IdentityError` enum.
4. Remove `anyhow` from `Cargo.toml` if no longer needed after migration.

### Key context

- The existing `DefaultBridge` at `verify.rs:55-80` is generic over `AuthsStorage`. Wire it to `RadicleAuthsStorage`.
- `CompiledPolicy` at `verify.rs:60` is configured at construction time — default policy checks `not_revoked()` and `not_expired()`.
- The policy does NOT currently check capabilities — that's fn-1.7.
- Clock injection: `now: DateTime<Utc>` is already a parameter of `verify_signer()`.

### Affected files
- Modified: `crates/auths-radicle/src/verify.rs`
- Modified: `crates/auths-radicle/src/identity.rs` (anyhow -> thiserror migration)
- Modified: `crates/auths-radicle/src/bridge.rs` (if BridgeError needs new variants)
- Modified: `crates/auths-radicle/Cargo.toml` (remove anyhow dep if possible)

## Code Quality
- **DRY**: Do not repeat logic; extract shared patterns into helper functions or traits.
- **Modular Design**: Avoid monolithic functions. Decompose complex logic into small, focused, and testable units.
- **Strictness**: Adhere to the "Zero-Debt" mandate—if old code is redundant, delete it; do not leave "TODO" or "Legacy" stubs.

## Acceptance
- [ ] Valid device with valid attestation -> `VerifyResult::Verified`
- [ ] Revoked device -> `VerifyResult::Rejected`
- [ ] Expired attestation -> `VerifyResult::Rejected`
- [ ] Unknown device (no attestation) -> `VerifyResult::Rejected`
- [ ] Valid device after key rotation (KEL sequence > 0) -> `VerifyResult::Verified`
- [ ] Tamper: modified attestation blob (signature mismatch) -> `VerifyResult::Rejected`
- [ ] Tamper: swapped did-key and did-keri blobs -> `VerifyResult::Rejected`
- [ ] **Fail-closed**: Any unhandled error in the pipeline produces `Rejected`, never `Verified`
- [ ] `identity.rs` uses `thiserror` errors only (no `anyhow` imports)
- [ ] `anyhow` removed from `Cargo.toml` (or justified if still needed)
- [ ] `cargo nextest run -p auths-radicle` passes
- [ ] `cargo clippy -p auths-radicle -- -D warnings` passes
## Done summary
- Full fail-closed verification pipeline in DefaultBridge::verify_signer
- Migrated identity.rs from anyhow to thiserror (IdentityError enum)
- Removed anyhow dependency from Cargo.toml
- Any unhandled error produces Rejected, never Verified
## Evidence
- Commits: e7d038d
- Tests: cargo nextest run -p auths-radicle
- PRs:
