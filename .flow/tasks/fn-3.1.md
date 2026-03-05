# fn-3.1 Add #[non_exhaustive] to bridge public types

## Description
ENFORCE `#[non_exhaustive]` on ALL public enums in `auths-radicle` that cross the crate boundary. Even pre-launch, this prevents the bridge API from being brittle when consumed by Heartwood.

## Strict Requirements

1. **ENFORCE** on all four public enums:
   - `BridgeError` at `crates/auths-radicle/src/bridge.rs`
   - `VerifyResult` at `crates/auths-radicle/src/bridge.rs`
   - `EnforcementMode` at `crates/auths-radicle/src/bridge.rs`
   - `SignerInput` at `crates/auths-radicle/src/bridge.rs`
2. **UPDATE** any internal exhaustive matches to include wildcard arms
3. **AUDIT**: Check for any other public enums in `auths-radicle/src/` that should also get `#[non_exhaustive]` (e.g., `AttestationConversionError` if added by fn-3.3)

## Key Files
- `crates/auths-radicle/src/bridge.rs` -- all four enums
- `crates/auths-radicle/src/` -- audit for additional public enums

## Verification
- `cargo nextest run -p auths-radicle` passes
- `cargo clippy --all-targets --all-features -- -D warnings` clean
## Target Types

1. `BridgeError` at `crates/auths-radicle/src/bridge.rs` -- error type returned by `RadicleAuthsBridge` methods
2. `VerifyResult` at `crates/auths-radicle/src/bridge.rs` -- verification outcome enum
3. `EnforcementMode` at `crates/auths-radicle/src/bridge.rs` -- observe vs enforce enum
4. `SignerInput` at `crates/auths-radicle/src/bridge.rs` -- pre-verified vs needs-bridge enum

## Implementation

Add `#[non_exhaustive]` above each enum definition. Update any internal exhaustive matches to include wildcard arms if needed. Run `cargo nextest run -p auths-radicle` to verify nothing breaks.

## Conventions
- No process comments (CLAUDE.md rule)
- Run `cargo clippy --all-targets --all-features -- -D warnings` after changes

## Code Quality
- **DRY**: Do not repeat logic; extract shared patterns into helper functions or traits.
- **Modular Design**: Avoid monolithic functions. Decompose complex logic into small, focused, and testable units.
- **Strictness**: Adhere to the "Zero-Debt" mandate—if old code is redundant, delete it; do not leave "TODO" or "Legacy" stubs.

## Acceptance
- [ ] `BridgeError` has `#[non_exhaustive]`
- [ ] `VerifyResult` has `#[non_exhaustive]`
- [ ] `EnforcementMode` has `#[non_exhaustive]`
- [ ] `SignerInput` has `#[non_exhaustive]`
- [ ] All other public enums in `auths-radicle` audited and annotated
- [ ] Internal matches updated with wildcard arms
- [ ] `cargo nextest run -p auths-radicle` passes
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` clean
## Done summary
Added #[non_exhaustive] to all 6 public enums in auths-radicle: VerifyResult, EnforcementMode, BridgeError, SignerInput (bridge.rs), RadAttestationError (attestation.rs), IdentityError (identity.rs). No wildcard arms needed since #[non_exhaustive] only affects external consumers.
## Evidence
- Commits:
- Tests:
- PRs:
