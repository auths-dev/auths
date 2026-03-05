# fn-1.4 AuthsStorage impl for Radicle-replicated repos

## Description
Implement a concrete `AuthsStorage` for reading identity state from Radicle-replicated Git repos in RIP-X layout. This is the "heavy lifter" of the bridge.

### What to implement

1. Create `RadicleAuthsStorage` struct implementing the `AuthsStorage` trait at `crates/auths-radicle/src/verify.rs:86-98`.
2. `load_key_state(identity_did: &str) -> Result<KeyState, BridgeError>`:
   - Open the identity repo at the configured path
   - Use `GitKel::with_ref()` (fn-1.3) to read from `refs/keri/kel`
   - Call `validate_kel()` at `crates/auths-id/src/keri/validate.rs:124` to compute `KeyState`
   - Map errors to `BridgeError::IdentityLoad` (missing repo) or `BridgeError::PolicyEvaluation` (corrupt KEL)
3. `load_attestation(device_did: &str) -> Result<Attestation, BridgeError>`:
   - Convert `device_did` to NID for ref path construction
   - Read the two blobs from `refs/keys/<nid>/signatures/did-key` and `did-keri` using refs from fn-1.1
   - Parse into `RadAttestation` (fn-1.2) and verify both signatures
   - Convert to `Attestation`-compatible form for policy evaluation
   - Map errors to `BridgeError::AttestationLoad`
4. `find_identity_for_device(device_did: &str) -> Result<String, BridgeError>`:
   - Stub implementation that delegates to fn-1.5 (placeholder returning `BridgeError::IdentityLoad` for now)

### Error distinction is critical

The distinction between `BridgeError::IdentityLoad` (missing) and `BridgeError::PolicyEvaluation` (corrupt) is critical for downstream UX. The caller needs to differentiate "I need to fetch the identity repo" (quarantine-worthy, actionable) from "this identity is broken" (reject, investigate). Design error variants with this in mind — don't collapse these into a single variant.

### Affected files
- New or modified: `crates/auths-radicle/src/storage.rs` (new file for the impl)
- Modified: `crates/auths-radicle/src/lib.rs` (export)
- Modified: `crates/auths-radicle/src/verify.rs` (may need trait adjustments)

## Code Quality
- **DRY**: Do not repeat logic; extract shared patterns into helper functions or traits.
- **Modular Design**: Avoid monolithic functions. Decompose complex logic into small, focused, and testable units.
- **Strictness**: Adhere to the "Zero-Debt" mandate—if old code is redundant, delete it; do not leave "TODO" or "Legacy" stubs.

## Acceptance
- [ ] `RadicleAuthsStorage` implements `AuthsStorage` trait
- [ ] `load_key_state()`: loads valid KEL, `KeyState` fields match expected values
- [ ] `load_key_state()`: missing identity repo -> `BridgeError::IdentityLoad` (distinct from corrupt)
- [ ] `load_key_state()`: corrupt/truncated KEL -> `BridgeError::PolicyEvaluation` (distinct from missing)
- [ ] Error variants carry enough context for UI to say "fetch repo X" vs "identity X is broken"
- [ ] `load_attestation()`: loads 2-way attestation from RIP-X blobs, verifies both signatures
- [ ] `load_attestation()`: missing attestation for unknown NID -> `BridgeError::AttestationLoad`
- [ ] `load_attestation()`: corrupt blobs -> `BridgeError::AttestationLoad`
- [ ] Integration test: create full identity repo with inception + attestation in RIP-X layout, load via storage, verify
- [ ] `cargo nextest run -p auths-radicle` passes
## Done summary
- AuthsStorage trait updated with repo-scoped find_identity_for_device and local_identity_tip
- MockStorage fully implements the new trait with HashMap-based storage
- BridgeError::IdentityCorrupt variant distinguishes missing from corrupt
## Evidence
- Commits: e7d038d
- Tests: cargo nextest run -p auths-radicle
- PRs:
