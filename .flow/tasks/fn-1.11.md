# fn-1.11 Binding integrity via min_kel_seq

## Description
Implement `min_kel_seq` binding integrity check. This prevents accepting identity state that predates the project binding (e.g., an attacker feeding a truncated KEL).

This is a critical security invariant — not a freshness heuristic.

### What to implement

1. Add `min_kel_seq: Option<u64>` parameter to `verify_signer()`.
2. **Check ordering**: `min_kel_seq` must be checked BEFORE policy evaluation. If the KEL is below the binding minimum, the identity state is untrusted — we should not even look at rotation/revocation state from an untrusted KEL.
3. After loading `KeyState` but before policy evaluation, compare `key_state.sequence` against `min_kel_seq`:
   - If `min_kel_seq` is `None` -> no binding check
   - If local seq >= min_kel_seq -> passes, proceed to policy evaluation
   - If local seq < min_kel_seq -> `Rejected` (not `Warn`, not `Quarantine` — this is a tamper indicator)
4. This check applies in BOTH observe and enforce modes. Unlike staleness (which is a freshness concern), a KEL below the binding minimum is a hard integrity violation that is never downgraded.

### Key context

- `min_kel_seq` is NOT a freshness tool. It's a binding integrity tool. A node at seq 3 above minimum 2 could still be stale (revocation at seq 4). Staleness is handled by fn-1.10.
- `KeyState.sequence` at `crates/auths-id/src/keri/state.rs:17-37` gives the current KEL sequence.
- The `min_kel_seq` value comes from the project binding (stored in the `did-keri-` namespace blob on Heartwood side). Passed as a parameter.

### Affected files
- Modified: `crates/auths-radicle/src/verify.rs`
- Modified: `crates/auths-radicle/src/bridge.rs` (trait signature update)

## Code Quality
- **DRY**: Do not repeat logic; extract shared patterns into helper functions or traits.
- **Modular Design**: Avoid monolithic functions. Decompose complex logic into small, focused, and testable units.
- **Strictness**: Adhere to the "Zero-Debt" mandate—if old code is redundant, delete it; do not leave "TODO" or "Legacy" stubs.

## Acceptance
- [ ] Local seq 5, min seq 2 -> passes (above minimum)
- [ ] Local seq 2, min seq 2 -> passes (at minimum)
- [ ] Local seq 1, min seq 2 -> `Rejected` (binding integrity violation)
- [ ] Local seq 0 (only inception), min seq 3 -> `Rejected`
- [ ] No min_kel_seq (None) -> check skipped
- [ ] **min_kel_seq check runs BEFORE policy evaluation** (untrusted KEL state is never evaluated)
- [ ] Observe mode + below min -> `Rejected` (NOT downgraded to Warn — this is tamper, not staleness)
- [ ] `cargo nextest run -p auths-radicle` passes
## Done summary
- min_kel_seq binding integrity check BEFORE policy evaluation
- Hard reject in ALL modes (never downgraded to Warn in Observe)
- None = no binding check
## Evidence
- Commits: e7d038d
- Tests: cargo nextest run -p auths-radicle
- PRs:
