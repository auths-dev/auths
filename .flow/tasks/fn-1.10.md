# fn-1.10 Gossip-informed staleness detection

## Description
Implement gossip-informed staleness detection. When the bridge knows (via a gossip-announced tip OID) that a newer identity repo version exists but hasn't been fetched locally, it should signal staleness.

This is the core solution to the "Revocation Race" — the mechanism that narrows the vulnerability window for connected nodes.

### What to implement

1. Add `known_remote_tip: Option<[u8; 20]>` parameter to `verify_signer()` (Git OIDs are 20 bytes / SHA-1).
2. After loading identity state, compare the local identity repo's tip OID against `known_remote_tip`:
   - If `known_remote_tip` is `None` (disconnected) -> no staleness signal
   - If local tip == remote tip -> no staleness signal
   - If local tip != remote tip -> staleness detected
3. Staleness behavior by mode:
   - Observe: add `Warn` with message "identity repo has newer tip available"
   - Enforce: return `Quarantine` with message including the identity repo RID and newer tip
4. The staleness check supplements (does not replace) the authorization check. If the device is revoked AND stale, the `Rejected` result takes priority.

### Design note

Passing `Option<[u8; 20]>` keeps the bridge purely cryptographic/logical and leaves gossip/network concerns to Heartwood. The bridge doesn't need to know about gossip protocol details.

### Key context

- The `known_remote_tip` comes from Heartwood's `RefsAnnouncement` data. Only announcements from identity repo delegates are credible (Heartwood filters this).
- Git OID comparison is a simple byte comparison.

### Affected files
- Modified: `crates/auths-radicle/src/verify.rs`
- Modified: `crates/auths-radicle/src/bridge.rs` (trait signature update)

## Code Quality
- **DRY**: Do not repeat logic; extract shared patterns into helper functions or traits.
- **Modular Design**: Avoid monolithic functions. Decompose complex logic into small, focused, and testable units.
- **Strictness**: Adhere to the "Zero-Debt" mandate—if old code is redundant, delete it; do not leave "TODO" or "Legacy" stubs.

## Acceptance
- [ ] Local tip == remote tip -> no staleness warning
- [ ] Local tip != remote tip -> staleness detected
- [ ] No remote tip known (None) -> no staleness warning
- [ ] Remote tip provided, identity repo missing locally -> staleness + missing state combined
- [ ] Observe + stale -> `Warn` with descriptive message
- [ ] Enforce + stale -> `Quarantine` with identity repo RID and tip info
- [ ] Stale + revoked device -> `Rejected` (revocation takes priority over staleness)
- [ ] `cargo nextest run -p auths-radicle` passes
## Done summary
- known_remote_tip parameter in VerifyRequest (Option<[u8; 20]>)
- Staleness detected when local tip != remote tip
- No staleness signal when disconnected (None)
- Observe: Warn, Enforce: Quarantine for stale state
## Evidence
- Commits: e7d038d
- Tests: cargo nextest run -p auths-radicle
- PRs:
