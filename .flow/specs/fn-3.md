# Full Radicle + Auths Integration (Phases 2-5)

## Overview

Provide invisible multi-device identity for Radicle users. A user should manage identity across multiple machines using standard `rad` commands without understanding KERI, attestations, or the auths infrastructure.

Phase 1 (Bridge Finalization) is complete (fn-1.x). This epic covers the remaining auths-side work for Phases 2-5: SDK embedding, storage unification, identity document evolution, and gossip preparation.

**Philosophy: Clean Sweep.** We are pre-launch. Backwards compatibility is NOT a requirement. Every task labeled DELETE or REPLACE results in a smaller, more specific codebase. We are removing the "maybe it's a Radicle project, maybe it's not" ambiguity. If it uses the Radicle bridge, it follows Radicle rules, 100%. Zero legacy paths. Zero fallback logic. Zero dual-format support.

## Scope

### In Scope (auths repo)
- API hardening: `#[non_exhaustive]` on public bridge types
- Ref path reconciliation between `auths-id` and `auths-radicle`
- Attestation format conversion (`RadAttestation` <-> `Attestation`) -- critical "glue" task
- Real `AuthsStorage` implementation for Git-backed repos -- critical "glue" task
- SDK-level seed import (extract from CLI)
- SDK error type migration (`anyhow` -> `thiserror`)
- `did:keri` resolution in `RadicleIdentityResolver`
- Identity deduplication in `meets_threshold` (Radicle "Person Rule" compliance)
- RIP-X specification document
- E2E script modernization
- WASM validation for `auths-radicle` types (future-proofing for web verification)

### Out of Scope (Heartwood repo, tracked separately)
- Modifying `Doc.delegates` to support `did:keri`
- `CompositeAuthorityChecker` integration in fetch pipeline
- Gossip protocol changes for KEL event propagation
- `rad sync` identity-first fetch ordering
- mDNS/LAN device pairing (deferred; registry-based pairing ships first)
- Organization accounts / threshold signatures (future epic)

## Approach

### Phase 1: Storage & Path Cleanup (DELETE legacy)
1. **ENFORCE** `#[non_exhaustive]` on all public bridge enums. Safety mandate even pre-launch.
2. **DELETE** `refs/rad/multidevice/nodes` from `auths-id`. REPLACE with `KEYS_PREFIX` from `refs.rs`. Zero fallback logic. Old paths are garbage.
3. **REPLACE** single-JSON attestation logic with 2-blob-only format. If `load_attestation` finds old JSON, it errors -- no fix-up.

### Phase 2: Translation & Implementation (SWAP stubs for real code)
4. **DELETE** `import_from_file` logic from CLI. SDK's `import_seed()` is the single source of truth. CLI becomes 3-line wrapper.
5. **PURGE** `anyhow` from `auths-sdk` dependencies entirely. DELETE `map_storage_err` helpers. Use `From` impls.
6. **SWAP** the empty `storage.rs` stub for `GitRadicleStorage`. Bare-repo only. Add `is_stale` as first-class trait method. REPLACE ad-hoc staleness logic.

### Phase 3: Identity & Consensus Rules (REWRITE broken logic)
7. **REPLACE** `UnsupportedMethod` error for `did:keri` with full KEL replay. No result without full chain verification.
8. **REWRITE** `verify_multiple_signers` from scratch. Returns `BTreeMap<IdentityDid, Vec<VerifyResult>>`. DELETE old "count every signature" logic.
9. Write formal RIP-X specification document while implementation is fresh.

### Phase 4: Portability & E2E (STRIP legacy, ISOLATE for WASM)
10. **STRIP** all `LAYOUT_ARGS` from e2e script. If flags are needed, fn-3.2 failed.
11. **ISOLATE** bridge types into `no_std` core. MOVE `chrono`/`git2` to `std` feature. Raw `i64` timestamps for WASM.

## Key Research Findings

### Reusable Code (DO NOT DUPLICATE)
- `auths_id::identity::ed25519_to_did_key()` at `crates/auths-id/src/identity/resolve.rs:157`
- `auths_id::storage::layout::StorageLayoutConfig::radicle()` at `crates/auths-id/src/storage/layout.rs:158`
- `auths_radicle::refs::*` at `crates/auths-radicle/src/refs.rs` -- RIP-X ref path constants
- `auths_radicle::verify::AuthsStorage` trait at `crates/auths-radicle/src/verify.rs:67`
- `auths_sdk::device::link_device()` at `crates/auths-sdk/src/device.rs:74`
- `auths_core::storage::keychain::KeyStorage` trait at `crates/auths-core/src/storage/keychain.rs:141`

### Resolved Decisions (Clean Sweep)
1. **Canonical ref layout**: RIP-X layout (`refs/keys/<nid>/signatures/{did-key,did-keri}`) is canonical. Old `refs/rad/multidevice/nodes` is DELETED.
2. **Attestation format**: 2-blob only. Single JSON = error. `TryFrom` conversion is the mandatory gateway.
3. **Storage**: Bare-repo only. `is_stale` as first-class trait method.
4. **SDK errors**: `anyhow` PURGED from `auths-sdk`. Domain `thiserror` variants only.
5. **CLI key import**: CLI is thin wrapper. SDK function is single source of truth.
6. **E2E layout**: No `LAYOUT_ARGS` overrides. Default layout = RIP-X layout.

### Remaining Gotchas
1. **JCS canonical ordering**: `RadCanonicalPayload` must use `json-canon`. Non-canonical JSON = rejection.
2. **KEL linear history**: `GitRadicleStorage` must reject merge commits (same as `kel.rs`).
3. **Quorum counting**: `meets_threshold` must REWRITE to use `BTreeMap<IdentityDid, Vec<VerifyResult>>`. "Person Rule" compliance.
4. **WASM isolation**: `chrono::DateTime<Utc>` in bridge types must become cfg-conditional `i64` for WASM.

## Open Questions (deferred, not blocking)

1. **mDNS/LAN pairing**: Deferred to future epic. Registry-based pairing ships first.
2. **Migration path**: How do existing `did:key`-only Radicle users upgrade to `did:keri`? (Address in RIP-X spec, fn-3.9)
3. **`rad auth` opt-in vs automatic**: Product decision, out of scope for this epic.
4. **Post-rotation attestation validity**: Address in RIP-X spec (fn-3.9).

## Risks & Mitigations

| Risk | Mitigation |
|------|------------|
| Heartwood RIP process blocks Phase 4 | Complete all auths-side prep (tasks 1-8) independently. RIP can proceed in parallel. |
| Ref path divergence causes silent failures | Task 2 (reconciliation) is high priority, blocks task 6 (storage impl) |
| SDK error migration breaks consumers | Run full workspace test suite after migration. Feature-flag if needed. |
| Binary size bloat when Heartwood depends on auths-sdk | Profile with `cargo bloat`. Gate heavy deps behind features. |
| gitoxide migration in Heartwood breaks `RadicleIdentityResolver` | `StorageLayoutConfig::gitoxide()` preset already exists. Monitor Heartwood roadmap. |
| WASM compatibility breaks as features are added | fn-3.11 adds WASM CI check. Catch `std` bloat early before it's hard to untangle. |

## Quick Commands (Smoke Tests)

```bash
# Run all auths-radicle tests
cargo nextest run -p auths-radicle

# Run workspace tests
cargo nextest run --workspace

# Clippy + format check
cargo clippy --all-targets --all-features -- -D warnings && cargo fmt --check --all

# WASM check (auths-verifier)
cd crates/auths-verifier && cargo check --target wasm32-unknown-unknown --no-default-features --features wasm

# WASM check (auths-radicle, after fn-3.11)
cd crates/auths-radicle && cargo check --target wasm32-unknown-unknown --no-default-features --features wasm

# E2E test (requires rad CLI)
just e2e-radicle
```

## Acceptance Criteria

### Deletions (codebase SMALLER after this epic)
- [ ] `refs/rad/multidevice/nodes` DELETED from entire codebase
- [ ] `grep -r "multidevice" crates/` returns zero results
- [ ] Single-JSON attestation code paths DELETED from `auths-radicle`
- [ ] `anyhow` REMOVED from `auths-sdk/Cargo.toml` dependencies
- [ ] `map_storage_err` / `map_device_storage_err` helpers DELETED
- [ ] CLI `key_import` crypto logic DELETED (wrapper only)
- [ ] `LAYOUT_ARGS` DELETED from e2e script
- [ ] Old "count every signature" `meets_threshold` logic DELETED

### Additions
- [ ] All bridge public types have `#[non_exhaustive]`
- [ ] `RadAttestation` <-> `Attestation` 2-blob conversion (mandatory gateway)
- [ ] `GitRadicleStorage` replaces empty stub (bare-repo only)
- [ ] `is_stale` as first-class `AuthsStorage` trait method
- [ ] `auths_sdk::keys::import_seed()` (no file I/O)
- [ ] SDK error types: domain `thiserror` variants only
- [ ] `RadicleIdentityResolver` resolves `did:keri:` via full KEL replay
- [ ] `verify_multiple_signers` returns `BTreeMap<IdentityDid, Vec<VerifyResult>>`
- [ ] RIP-X spec document drafted
- [ ] `auths-radicle` bridge types compile to WASM (`no_std` + `alloc`)
- [ ] `cargo nextest run --workspace` passes
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` clean

## References

- fn-1.x (Bridge Finalization) -- DONE
- fn-2.x (Bridge Polish) -- in progress
- `crates/auths-radicle/src/bridge.rs` -- `RadicleAuthsBridge` trait, `VerifyRequest`
- `crates/auths-radicle/src/verify.rs` -- `AuthsStorage` trait, `DefaultBridge`
- `crates/auths-radicle/src/refs.rs` -- RIP-X ref path constants
- `crates/auths-radicle/src/attestation.rs` -- `RadAttestation` 2-blob format
- `crates/auths-radicle/src/identity.rs` -- `RadicleIdentityResolver`
- `crates/auths-radicle/src/storage.rs` -- EMPTY STUB (target for task 6)
- `crates/auths-id/src/storage/layout.rs` -- `StorageLayoutConfig::radicle()`
- `crates/auths-sdk/src/device.rs` -- `link_device()`
- `crates/auths-cli/src/commands/key.rs` -- `key_import()` (extract target)
- [KERI IETF Draft](https://weboftrust.github.io/ietf-keri/draft-ssmith-keri.html)
- [did:keri Method v0.1](https://identity.foundation/keri/did_methods/)
- [Radicle Protocol Guide](https://radicle.xyz/guides/protocol)
