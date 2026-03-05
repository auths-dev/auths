# fn-1.1 Define RIP-X ref path constants in auths-radicle

## Description
Create `crates/auths-radicle/src/refs.rs` with constants for all RIP-X Git ref paths. These constants are the source of truth for ref paths used by both auths-radicle and Heartwood.

### What to implement

1. Add `refs.rs` module to `crates/auths-radicle/src/`
2. Export it from `lib.rs`
3. Define `pub const` constants:
   - `KERI_KEL_REF = "refs/keri/kel"` — KEL commit chain
   - `KEYS_PREFIX = "refs/keys"` — device attestation root
   - `SIGNATURES_DIR = "signatures"` — signatures subdirectory
   - `DID_KEY_BLOB = "did-key"` — device signature blob name
   - `DID_KERI_BLOB = "did-keri"` — identity signature blob name
   - `RAD_ID_REF = "refs/rad/id"` — identity pointer in DID namespace
4. Add path construction helpers:
   - `device_signatures_ref(nid: &str) -> String` — `refs/keys/<nid>/signatures`
   - `device_did_key_ref(nid: &str) -> String` — `refs/keys/<nid>/signatures/did-key`
   - `device_did_keri_ref(nid: &str) -> String` — `refs/keys/<nid>/signatures/did-keri`
   - `identity_namespace_prefix(keri_prefix: &str) -> String` — `refs/namespaces/did-keri-<prefix>` (must handle `:` to `-` character replacement per RIP-X to ensure Heartwood compatibility)
   - `identity_rad_id_ref(keri_prefix: &str) -> String` — `refs/namespaces/did-keri-<prefix>/refs/rad/id`

### Key context

- Current auths paths (`refs/did/keri/<prefix>/kel`) differ from RIP-X paths (`refs/keri/kel`). These constants define the RIP-X layout specifically.
- Heartwood's `IdentityNamespace` at `heartwood/crates/radicle/src/identity/namespace.rs:46-62` already parses `did-keri-<prefix>` patterns — our helpers must produce compatible strings.
- **Character replacement**: `identity_namespace_prefix()` must replace `:` with `-` in the KERI prefix (e.g., `did:keri:EXq5...` becomes `did-keri-EXq5...`) per RIP-X spec.
- **RIP-X citations**: Each constant's rustdoc must cite its RIP-X section reference (e.g., `/// RIP-X Section 2.1: KEL storage`).

### Affected files
- New: `crates/auths-radicle/src/refs.rs`
- Modified: `crates/auths-radicle/src/lib.rs` (add `pub mod refs;`)

## Code Quality
- **DRY**: Do not repeat logic; extract shared patterns into helper functions or traits.
- **Modular Design**: Avoid monolithic functions. Decompose complex logic into small, focused, and testable units.
- **Strictness**: Adhere to the "Zero-Debt" mandate—if old code is redundant, delete it; do not leave "TODO" or "Legacy" stubs.

## Acceptance
- [ ] `refs.rs` exists with all 6 `pub const` constants matching RIP-X spec strings exactly
- [ ] Path construction helpers produce valid Git refnames
- [ ] `identity_namespace_prefix("EXq5...")` produces `refs/namespaces/did-keri-EXq5...` (compatible with Heartwood's `IdentityNamespace::from_ref_component()`)
- [ ] `identity_namespace_prefix()` handles `:` to `-` character replacement per RIP-X spec
- [ ] Each constant/helper has rustdoc citing the specific RIP-X section it implements
- [ ] All public items have rustdoc with `/// Description`, `/// Args:`, `/// Usage:` blocks
- [ ] Module exported from `lib.rs`
- [ ] `cargo build -p auths-radicle` passes
- [ ] `cargo clippy -p auths-radicle -- -D warnings` passes
- [ ] Unit tests: constants match expected strings, helpers produce valid refnames, character replacement works
## Done summary
- Added `crates/auths-radicle/src/refs.rs` with 6 pub const RIP-X ref path constants
- Added 5 path construction helpers with colon-to-dash character replacement
- Each constant has rustdoc citing RIP-X section reference
- 8 unit tests covering constants, helpers, character replacement, Heartwood compatibility
## Evidence
- Commits: 821698a0035cd6499b5fa5a2310699d74cc7e492
- Tests: cargo nextest run -p auths-radicle -E test(refs)
- PRs:
