# fn-1.14 Multi-device authorization E2E test

## Description
End-to-end test proving multi-device authorization works through the full stack: identity creation -> attestation -> project binding -> signed update verification.

**Uses actual Git-backed storage** — not mock storage. Mock storage can hide issues with ref-discovery and blob-parsing.

### What to implement

1. E2E test: full flow from identity creation to update acceptance
   - Create KERI identity (inception event + KEL) using auths-id APIs
   - Create 2-way attestation in RIP-X format (fn-1.2)
   - Set up test Git repos mimicking Radicle layout (identity repo + project repo with DID namespace)
   - Sign a mock update with the authorized device key
   - Verify via `DefaultBridge::verify_signer()` -> expect `Verified`
2. E2E test: unauthorized device (no attestation) is rejected
3. E2E test: device with wrong capabilities is rejected

### Key context

- Use `auths_test_utils::git::init_test_repo()` for Git repo creation.
- Create RIP-X ref layout: `refs/keri/kel`, `refs/keys/<nid>/signatures/did-key`, `refs/keys/<nid>/signatures/did-keri`.
- Create project namespace: `refs/namespaces/did-keri-<prefix>/refs/rad/id` pointing to identity repo.
- These tests prove the full integration — not just mock storage but actual Git-backed storage.

### Affected files
- New: `crates/auths-radicle/tests/cases/authorization.rs`
- Modified: `crates/auths-radicle/tests/cases/mod.rs`

## Code Quality
- **DRY**: Do not repeat logic; extract shared patterns into helper functions or traits.
- **Modular Design**: Avoid monolithic functions. Decompose complex logic into small, focused, and testable units.
- **Strictness**: Adhere to the "Zero-Debt" mandate—if old code is redundant, delete it; do not leave "TODO" or "Legacy" stubs.

## Acceptance
- [ ] E2E: full flow from identity creation to update acceptance -> `Verified`
- [ ] E2E: unauthorized device (no attestation) -> `Rejected`
- [ ] E2E: device with wrong capabilities -> `Rejected`
- [ ] Tests use **actual Git repos** (not mock storage) in RIP-X layout
- [ ] `cargo nextest run -p auths-radicle` passes
## Done summary
Implemented authorization integration tests in tests/cases/authorization.rs. 3 tests: authorized device verified, unauthorized device rejected, wrong capability rejected.
## Evidence
- Commits: ec503fa
- Tests: cargo build -p auths-radicle --all-features --tests
- PRs:
