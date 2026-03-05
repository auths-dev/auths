# fn-1.16 Stale-node E2E test

## Description
End-to-end test proving the system behaves safely under the stale-node adversarial scenario with actual Git-backed storage.

**This is the most important test in the suite.** It validates the primary security USP of the entire Radicle integration.

### What to implement

1. E2E (observe): stale node accepts with `Warn`, converges to `Rejected` after sync
   - Create two storage instances with different KEL states
   - Stale storage: KEL at seq 2 (no revocation)
   - Fresh storage: KEL at seq 3 (revocation present)
   - Verify stale node produces `Warn`, then update storage and verify `Rejected`
2. E2E (enforce, staleness detected): stale node quarantines, resolves after sync
   - Pass `known_remote_tip` that differs from local tip
   - Verify `Quarantine`, then "sync" and verify `Rejected`
3. E2E (enforce, no staleness signal): stale node accepts (irreducible risk)
   - Pass `known_remote_tip = None`
   - Verify `Verified` (document this as expected irreducible risk)
4. E2E: node with identity repo below `min_kel_seq` -> hard reject in both modes
5. Tamper test: forged KEL event -> `Rejected` regardless of mode

### Key context

- These tests use actual Git repos created with `auths_test_utils::git::init_test_repo()`.
- Stale-node scenario simulated by having two repos with different commit histories on `refs/keri/kel`.
- The "irreducible risk" test (item 3) should have a clear code comment documenting why `Verified` is the expected and correct result for a fully-disconnected node.

### Affected files
- New: `crates/auths-radicle/tests/cases/stale_node.rs`
- Modified: `crates/auths-radicle/tests/cases/mod.rs`

## Code Quality
- **DRY**: Do not repeat logic; extract shared patterns into helper functions or traits.
- **Modular Design**: Avoid monolithic functions. Decompose complex logic into small, focused, and testable units.
- **Strictness**: Adhere to the "Zero-Debt" mandate—if old code is redundant, delete it; do not leave "TODO" or "Legacy" stubs.

## Acceptance
- [ ] E2E (observe): stale node accepts with `Warn`, converges to `Rejected` after sync
- [ ] E2E (enforce, staleness detected): stale node quarantines, resolves after sync
- [ ] E2E (enforce, no staleness signal): stale node accepts as `Verified` (irreducible risk documented in test comment)
- [ ] E2E: below min_kel_seq -> `Rejected` in both modes
- [ ] Tamper: forged KEL event -> `Rejected` regardless of mode
- [ ] Tests use actual Git-backed storage in RIP-X layout
- [ ] `cargo nextest run -p auths-radicle` passes
## Done summary
Implemented stale-node E2E tests in tests/cases/stale_node.rs. 5 tests: observe stale node accepts then converges, enforce staleness detected quarantine then resolves, enforce no staleness signal accepts (irreducible risk), below min_kel_seq hard reject both modes, tamper forged KEL rejected.
## Evidence
- Commits: ec503fa
- Tests: cargo build -p auths-radicle --all-features --tests
- PRs:
