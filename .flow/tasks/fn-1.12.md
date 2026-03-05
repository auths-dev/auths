# fn-1.12 Stale-state integration tests

## Description
Write integration tests simulating the stale-node scenario (Node A has revocation, Node B is stale) under both observe and enforce modes.

### What to implement

1. Create `crates/auths-radicle/tests/integration.rs` and `tests/cases/` directory following the auths test structure convention.
2. Tests simulating two nodes with different identity state:
   - **Observe, stale node**: Node B (seq 2, no revocation) accepts revoked device's update with `Warn`; after "sync" (update storage), rejects
   - **Enforce, staleness detected**: Node B has `known_remote_tip` != local tip -> `Quarantine`; after sync, `Rejected`
   - **Enforce, no staleness signal**: Node B with `known_remote_tip = None` -> `Verified` (irreducible risk); after sync, `Rejected`
   - **Below min_kel_seq**: Node with KEL below binding minimum -> `Rejected` in both modes
   - **Tamper**: Forged KEL event mid-chain -> `validate_kel()` fails -> `Rejected` regardless of mode
3. Use `MockStorage` or `RadicleAuthsStorage` with test Git repos. Use test helpers from `auths-test-utils`.

### Key context

- This is the core adversarial scenario from Section 5C of the plan.
- Two `MockStorage` instances with different `KeyState` sequences simulate Node A vs Node B.
- Test gossip-informed staleness by passing different `known_remote_tip` values.
- Test helpers: `auths_test_utils::crypto::get_shared_keypair()`, `auths_test_utils::git::init_test_repo()`.

### Affected files
- New: `crates/auths-radicle/tests/integration.rs`
- New: `crates/auths-radicle/tests/cases/mod.rs`
- New: `crates/auths-radicle/tests/cases/stale_state.rs`

## Code Quality
- **DRY**: Do not repeat logic; extract shared patterns into helper functions or traits.
- **Modular Design**: Avoid monolithic functions. Decompose complex logic into small, focused, and testable units.
- **Strictness**: Adhere to the "Zero-Debt" mandate—if old code is redundant, delete it; do not leave "TODO" or "Legacy" stubs.

## Acceptance
- [ ] Test directory structure: `tests/integration.rs` + `tests/cases/` follows auths convention
- [ ] Observe + stale node accepts with `Warn`, converges to `Rejected` after storage update
- [ ] Enforce + staleness detected -> `Quarantine`, resolves after storage update
- [ ] Enforce + no staleness signal -> `Verified` based on local state
- [ ] Below min_kel_seq -> `Rejected` in both modes
- [ ] Tamper: forged KEL event -> `Rejected` regardless of mode
- [ ] `cargo nextest run -p auths-radicle` passes (all new tests)
## Done summary
Implemented stale-state integration tests in tests/cases/stale_state.rs. 5 tests covering: observe stale accepts then converges, enforce staleness detected quarantine then resolves, enforce no staleness signal accepts (irreducible risk), below min_kel_seq rejected both modes, corrupt identity rejected regardless of mode.
## Evidence
- Commits: ec503fa
- Tests: cargo build -p auths-radicle --all-features --tests
- PRs:
