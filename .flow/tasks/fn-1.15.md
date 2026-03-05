# fn-1.15 Revocation E2E test

## Description
End-to-end test proving revocation stops a device from being authorized, under both observe and enforce modes.

### What to implement

1. E2E test (enforce mode):
   - Create identity, authorize device, verify acceptance
   - Revoke device (set `revoked_at`, anchor in KEL via IXN event)
   - Verify rejection
2. E2E test (observe mode):
   - Same flow but verify `Warn` instead of `Rejected`
3. E2E test: revocation of one device does not affect other authorized devices
4. E2E test: re-authorization after revocation (new attestation for same NID) works

### Key context

- Revocation involves: setting `revoked_at` on attestation, re-signing with KERI key, anchoring IXN in KEL.
- After revocation, `KeyState.sequence` increments.
- Re-authorization: new attestation blobs overwrite old ones at `refs/keys/<nid>/signatures/`.
- Use `auths_test_utils::crypto::create_test_keypair()` for unique keys per device.
- Tests use actual Git-backed storage in RIP-X layout.

### Affected files
- New: `crates/auths-radicle/tests/cases/revocation.rs`
- Modified: `crates/auths-radicle/tests/cases/mod.rs`

## Code Quality
- **DRY**: Do not repeat logic; extract shared patterns into helper functions or traits.
- **Modular Design**: Avoid monolithic functions. Decompose complex logic into small, focused, and testable units.
- **Strictness**: Adhere to the "Zero-Debt" mandate—if old code is redundant, delete it; do not leave "TODO" or "Legacy" stubs.

## Acceptance
- [ ] E2E: device accepted before revocation, rejected after (enforce mode)
- [ ] E2E: device accepted before revocation, warned after (observe mode)
- [ ] E2E: revocation of one device does not affect other authorized devices
- [ ] E2E: re-authorization after revocation (new attestation) -> `Verified`
- [ ] Tests use actual Git-backed storage in RIP-X layout
- [ ] `cargo nextest run -p auths-radicle` passes
## Done summary
Implemented revocation integration tests in tests/cases/revocation.rs. 4 tests: enforce revocation rejects, observe revocation warns, revocation does not affect other devices, reauthorization after revocation.
## Evidence
- Commits: ec503fa
- Tests: cargo build -p auths-radicle --all-features --tests
- PRs:
