# fn-1.8 Threshold verification for mixed delegate types

## Description
Ensure `verify_multiple_signers()` and `meets_threshold()` work correctly with mixed `Did::Key` + `Did::Keri` delegate types in M-of-N threshold verification.

Radicle will almost always be a hybrid of `Did::Key` (for legacy nodes) and `Did::Keri` (for teams). This is the "real world" scenario.

### Terminology note

- **`Did::Key` / `Did::Keri`** — Rust enum variants in Heartwood's type system, used for code-level dispatch (match arms, type checks).
- **`did:key:z6Mk...` / `did:keri:EXq5...`** — DID method strings per the W3C spec, used at the wire/serialization layer.

They refer to the same identities. This task operates at the Rust type level (`Did::Key` vs `Did::Keri`) to determine which signers go through the bridge.

### What to implement

1. Update `verify_multiple_signers()` at `crates/auths-radicle/src/verify.rs:160` to handle the case where some signers are `Did::Key` delegates (not going through the bridge) and some are `Did::Keri` attested devices (going through the bridge).
2. Accept a `delegate_type` indicator per signer so the function knows which signers should be verified via the bridge and which are pre-verified `Did::Key` delegates.
3. `meets_threshold()` at `verify.rs:188` should count both types of verified signers toward the threshold.

### Architecture principle

The bridge must remain **agnostic of how `did:key` is verified**. It only provides the "KERI-side" of the threshold answer. `Did::Key` verification results are pre-computed by Heartwood and passed in. The bridge does not duplicate Heartwood's existing Ed25519 delegate verification.

Consider accepting `Vec<VerifyResult>` for pre-verified `Did::Key` signers alongside `Vec<&[u8; 32]>` for signers needing bridge verification.

### Key context

- Currently `verify_multiple_signers()` calls `bridge.verify_signer()` for ALL signers — this fails for `Did::Key` signers who don't have `AuthsStorage` entries.
- The Heartwood side (fn-3.2's `CompositeAuthorityChecker`) will handle `Did::Key` delegates directly.

### Affected files
- Modified: `crates/auths-radicle/src/verify.rs`

## Code Quality
- **DRY**: Do not repeat logic; extract shared patterns into helper functions or traits.
- **Modular Design**: Avoid monolithic functions. Decompose complex logic into small, focused, and testable units.
- **Strictness**: Adhere to the "Zero-Debt" mandate—if old code is redundant, delete it; do not leave "TODO" or "Legacy" stubs.

## Acceptance
- [ ] 3 signers (2 Did::Key + 1 Did::Keri), threshold 2, all valid -> passes
- [ ] 3 signers, threshold 2, one Did::Keri revoked -> passes (2 Did::Key remain)
- [ ] 3 signers, threshold 2, two revoked -> fails
- [ ] Mixed Did::Key + Did::Keri delegates in threshold -> both types counted correctly
- [ ] Bridge does NOT re-verify Did::Key signers (accepts pre-verified results)
- [ ] Empty signer list with threshold 0 -> passes (edge case)
- [ ] `cargo nextest run -p auths-radicle` passes
## Done summary
- SignerInput enum: PreVerified (Did::Key) and NeedsBridgeVerification (Did::Keri)
- verify_multiple_signers accepts mixed signer inputs
- meets_threshold counts both types of verified signers
- Bridge does NOT re-verify Did::Key signers
## Evidence
- Commits: e7d038d
- Tests: cargo nextest run -p auths-radicle
- PRs:
