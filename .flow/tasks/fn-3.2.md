# fn-3.2 Reconcile ref path constants between auths-id and auths-radicle

## Description
DELETE the legacy `refs/rad/multidevice/nodes` constant from `auths-id` entirely. Replace with `KEYS_PREFIX` (`refs/keys`) from `auths-radicle`. No fallback logic. No dual-path support.

## Strict Requirements

1. **DELETE** `refs/rad/multidevice/nodes` from `StorageLayoutConfig::radicle()` at `crates/auths-id/src/storage/layout.rs:158-165`
2. **REPLACE** the attestation prefix with `refs/keys` (matching `KEYS_PREFIX` in `crates/auths-radicle/src/refs.rs`)
3. **ALIGN** the KEL prefix: `StorageLayoutConfig::radicle()` must use `refs/keri/kel` (matching `KERI_KEL_REF` in `refs.rs`), not `refs/did/keri`
4. **DEFAULT**: If no layout is provided, the system MUST default to the RIP-X layout. Zero "fallback" logic to check old paths. If old-format data exists at old paths, it is garbage and ignored.
5. **DELETE** any code that constructs or reads `refs/rad/multidevice/nodes` paths -- grep the entire workspace and remove all references

## Key Files
- `crates/auths-id/src/storage/layout.rs` -- DELETE old constants, update `radicle()` preset
- `crates/auths-radicle/src/refs.rs` -- source of truth (DO NOT MODIFY)
- `crates/auths-id/src/storage/attestation.rs` -- update any path construction using old prefix
- Any other files referencing `refs/rad/multidevice` -- DELETE those references

## Verification
- `grep -r "multidevice" crates/` returns zero results
- `grep -r "refs/rad/multidevice" .` returns zero results
- `StorageLayoutConfig::radicle()` attestation prefix matches `refs.rs` `KEYS_PREFIX`
- `cargo nextest run --workspace` passes
## Current State

Two divergent layouts:
- `auths-id/src/storage/layout.rs:158-165` -- `StorageLayoutConfig::radicle()` uses:
  - `identity_ref: "refs/rad/id"`
  - `attestation_prefix: "refs/rad/multidevice/nodes"` (OLD)
  - `kel_prefix: "refs/did/keri"` (per-identity namespaced)

- `auths-radicle/src/refs.rs` -- RIP-X layout uses:
  - `RAD_ID_REF: "refs/rad/id"` (matches)
  - `KEYS_PREFIX: "refs/keys"` with `refs/keys/<nid>/signatures/{did-key,did-keri}` (NEW 2-blob format)
  - `KERI_KEL_REF: "refs/keri/kel"` (single identity per repo)

## Action

1. Update `StorageLayoutConfig::radicle()` to match the RIP-X constants in `refs.rs`:
   - Change `attestation_prefix` from `"refs/rad/multidevice/nodes"` to `"refs/keys"` (or the appropriate prefix that aligns with `KEYS_PREFIX`)
   - Change `kel_prefix` to align with `KERI_KEL_REF = "refs/keri/kel"` for the Radicle context (single-identity repo)
2. Document the two contexts: auths-id layout (multi-identity, `~/.auths` repo) vs Radicle layout (single-identity, per-user identity repo)
3. Ensure `refs.rs` remains the source of truth for Radicle ref paths
4. Update any code that constructs paths using the old layout constants

## Key Files
- `crates/auths-id/src/storage/layout.rs` -- `StorageLayoutConfig::radicle()`
- `crates/auths-radicle/src/refs.rs` -- RIP-X constants
- `crates/auths-id/src/storage/attestation.rs` -- uses layout config for ref construction

## Code Quality
- **DRY**: Do not repeat logic; extract shared patterns into helper functions or traits.
- **Modular Design**: Avoid monolithic functions. Decompose complex logic into small, focused, and testable units.
- **Strictness**: Adhere to the "Zero-Debt" mandate—if old code is redundant, delete it; do not leave "TODO" or "Legacy" stubs.

## Acceptance
- [ ] `refs/rad/multidevice/nodes` constant DELETED from `auths-id`
- [ ] `StorageLayoutConfig::radicle()` attestation prefix is `refs/keys` (matches `KEYS_PREFIX`)
- [ ] `StorageLayoutConfig::radicle()` KEL prefix is `refs/keri/kel` (matches `KERI_KEL_REF`)
- [ ] `grep -r "multidevice" crates/` returns zero results
- [ ] Zero fallback logic -- no code checks old paths
- [ ] `cargo nextest run --workspace` passes
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` clean
## Done summary
Replaced all refs/rad/multidevice/nodes with refs/keys across layout.rs, tests, scripts, and 5 doc files. grep verification: zero results.
## Evidence
- Commits:
- Tests:
- PRs:
