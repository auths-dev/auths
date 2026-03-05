# fn-1.9 Enforcement mode configuration (observe/enforce)

## Description
Implement observe/enforce enforcement modes and add the `Quarantine` variant to `VerifyResult`.

`Quarantine` is a first-class citizen in decentralized systems — it handles the "I'm behind on gossip" state gracefully.

### What to implement

1. Add `Quarantine { reason: String, identity_repo_rid: Option<String> }` variant to `VerifyResult` at `crates/auths-radicle/src/bridge.rs:26-43`.
2. Define `EnforcementMode` enum: `Observe` | `Enforce`.
3. Update `verify_signer()` to accept `mode: EnforcementMode`.
4. Mode-dependent behavior:
   - **Observe**: `Rejected` results are downgraded to `Warn`. Bridge is informational only, never blocks.
   - **Enforce**: `Rejected` results stay `Rejected`. Missing identity state produces `Quarantine`.
5. Update `is_allowed()` at `bridge.rs:47` — `Quarantine` is NOT allowed (treated like `Rejected` for the caller).
6. **UX requirement**: `Quarantine` results must include the specific identity repo RID that needs fetching, so the CLI can report actionable information (e.g., "fetch identity repo rad:z3gq... to resolve").

### Key context

- Observe mode = detection-and-flagging. Enforce mode = hard authorization boundary.
- The `VerifyResult` currently has `Verified`, `Rejected`, `Warn`. `Quarantine` is new.
- In enforce mode, "identity repo not found" -> `Quarantine` (not `Rejected`). The distinction: `Quarantine` means "I can't decide, fetch more data"; `Rejected` means "I can decide, and the answer is no."
- In observe mode, both `Rejected` and `Quarantine` scenarios downgrade to `Warn`.

### Affected files
- Modified: `crates/auths-radicle/src/bridge.rs` (VerifyResult, new types)
- Modified: `crates/auths-radicle/src/verify.rs` (mode parameter, conditional logic)

## Code Quality
- **DRY**: Do not repeat logic; extract shared patterns into helper functions or traits.
- **Modular Design**: Avoid monolithic functions. Decompose complex logic into small, focused, and testable units.
- **Strictness**: Adhere to the "Zero-Debt" mandate—if old code is redundant, delete it; do not leave "TODO" or "Legacy" stubs.

## Acceptance
- [ ] `VerifyResult::Quarantine` variant exists with `reason` and `identity_repo_rid` fields
- [ ] `EnforcementMode` enum with `Observe` and `Enforce` variants
- [ ] Observe mode + revoked device -> `Warn` (not `Rejected`)
- [ ] Enforce mode + revoked device -> `Rejected`
- [ ] Observe mode + missing identity repo -> `Warn`
- [ ] Enforce mode + missing identity repo -> `Quarantine` with the specific RID to fetch
- [ ] `Quarantine.is_allowed()` returns `false`
- [ ] Quarantine results carry enough context for CLI to display actionable fetch instructions
- [ ] `cargo nextest run -p auths-radicle` passes
## Done summary
- VerifyResult::Quarantine with reason and identity_repo_rid
- EnforcementMode enum (Observe/Enforce)
- Observe mode downgrades Rejected to Warn
- Quarantine includes specific RID for CLI
## Evidence
- Commits: e7d038d
- Tests: cargo nextest run -p auths-radicle
- PRs:
