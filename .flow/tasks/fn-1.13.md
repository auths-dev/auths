# fn-1.13 Bridge API alignment with Heartwood fn-3.2

## Description
Ensure the bridge API signature matches what Heartwood's fn-3.2 (`CompositeAuthorityChecker`) expects. This is the contract between auths-radicle and Heartwood.

### What to implement

1. Finalize `RadicleAuthsBridge::verify_signer()` signature to include all parameters Heartwood needs. Consider a `VerifyRequest` struct to bundle parameters (avoids 8-parameter function):
   ```rust
   pub struct VerifyRequest<'a> {
       pub signer_key: &'a [u8; 32],
       pub repo_id: &'a str,
       pub now: DateTime<Utc>,
       pub mode: EnforcementMode,
       pub known_remote_tip: Option<[u8; 20]>,
       pub min_kel_seq: Option<u64>,
       pub required_capability: Option<&'a str>,
   }
   ```
2. Ensure `DefaultBridge<RadicleAuthsStorage>` can be constructed from a base path.
3. Write a mock-Heartwood-caller integration test that invokes the bridge with correct parameter types.
4. Add `find_identity_for_device()` to the `RadicleAuthsBridge` trait (per fn-5.1 in Heartwood plan).

### Dependency isolation check

Verify that `auths-radicle` does not accidentally pull in `axum` or other server-side dependencies from the workspace. It must remain a lean library. Run `cargo tree -p auths-radicle` and audit for unexpected deps.

### Key context

- Heartwood fn-3.2 shows `CompositeAuthorityChecker` calling `auths_radicle::DefaultBridge`.
- The bridge uses `[u8; 32]` for keys and `&str` for repo IDs — no Heartwood type imports.
- Heartwood depends on auths-radicle as a path dependency (not vice versa).
- `[u8; 20]` for Git OIDs — Heartwood uses `git2::Oid` internally but converts to bytes at the bridge boundary.

### Affected files
- Modified: `crates/auths-radicle/src/bridge.rs` (trait finalization)
- Modified: `crates/auths-radicle/src/verify.rs` (DefaultBridge impl)

## Code Quality
- **DRY**: Do not repeat logic; extract shared patterns into helper functions or traits.
- **Modular Design**: Avoid monolithic functions. Decompose complex logic into small, focused, and testable units.
- **Strictness**: Adhere to the "Zero-Debt" mandate—if old code is redundant, delete it; do not leave "TODO" or "Legacy" stubs.

## Acceptance
- [ ] `verify_signer()` accepts all required parameters (via `VerifyRequest` struct or equivalent)
- [ ] `find_identity_for_device()` is part of the public `RadicleAuthsBridge` trait
- [ ] Mock caller test: invoke bridge with correct parameter types, all scenarios produce expected results
- [ ] `DefaultBridge<RadicleAuthsStorage>` constructible from a base path
- [ ] `cargo tree -p auths-radicle` shows no unexpected deps (no axum, no server-side crates)
- [ ] API is documented with rustdoc (Description, Args, Usage blocks)
- [ ] `cargo nextest run -p auths-radicle` passes
- [ ] `cargo clippy -p auths-radicle -- -D warnings` passes
## Done summary
- VerifyRequest struct bundles all parameters
- find_identity_for_device on RadicleAuthsBridge trait
- DefaultBridge generic over AuthsStorage
- API documented with rustdoc
## Evidence
- Commits: e7d038d
- Tests: cargo nextest run -p auths-radicle
- PRs:
