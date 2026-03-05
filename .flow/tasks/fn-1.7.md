# fn-1.7 Capability-scoped authorization

## Description
Add capability-scoped authorization to the verification pipeline. Different operations require different capabilities (e.g., `sign_commit` for ref updates, `sign_release` for release tags).

This moves the project from "Identification" to "Authorization" — a requirement for enterprise-grade Git workflows where CI/CD bots have different rights than lead engineers.

### What to implement

1. Extend `verify_signer()` to accept a `required_capability: Option<&str>` parameter.
2. When a capability is required, check it against the attestation's `capabilities` field.
3. Update `DefaultBridge::with_storage()` or `PolicyBuilder` to support capability requirements.
4. Handle edge cases:
   - Attestation with empty capabilities and no required capability -> `Verified`
   - Attestation with empty capabilities but required `sign_commit` -> `Rejected`
   - Attestation with `[sign_commit, sign_release]` and required `sign_commit` -> `Verified`

### Key context

- Current test helper `make_attestation()` at `verify.rs:285` creates attestations with `capabilities: vec![]`. Update test helpers.
- `CompiledPolicy` at `verify.rs:60` builds via `PolicyBuilder::new().not_revoked().not_expired()` — may need `.requires_capability()` method.
- Heartwood fn-3.2 will pass `"sign_commit"` for ref updates. The bridge must accept this as the `required_capability`.

### Affected files
- Modified: `crates/auths-radicle/src/verify.rs`
- Modified: `crates/auths-radicle/src/bridge.rs` (trait signature if capability param added)

## Code Quality
- **DRY**: Do not repeat logic; extract shared patterns into helper functions or traits.
- **Modular Design**: Avoid monolithic functions. Decompose complex logic into small, focused, and testable units.
- **Strictness**: Adhere to the "Zero-Debt" mandate—if old code is redundant, delete it; do not leave "TODO" or "Legacy" stubs.

## Acceptance
- [ ] Device with `sign_commit` capability pushing refs -> `Verified`
- [ ] Device with only `sign_release` capability pushing refs (requires `sign_commit`) -> `Rejected`
- [ ] Device with `[sign_commit, sign_release]` and required `sign_release` -> `Verified`
- [ ] No capability required (None) -> capability check skipped
- [ ] Test helpers updated to create attestations with non-empty capabilities
- [ ] `cargo nextest run -p auths-radicle` passes
## Done summary
- Capability-scoped authorization via required_capability in VerifyRequest
- Empty capabilities on attestation = legacy device, check skipped
- Non-empty capabilities must include required cap or be rejected
## Evidence
- Commits: e7d038d
- Tests: cargo nextest run -p auths-radicle
- PRs:
