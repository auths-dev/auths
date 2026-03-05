# fn-5.5 Refactor RadicleIdentity struct for KERI-specific fields

## Description
## Refactor RadicleIdentity struct for KERI-specific fields

**Repo**: `/Users/bordumb/workspace/repositories/auths-base/auths/crates/auths-radicle/src/identity.rs`

### Design Principle
Move away from "string-ly typed" DIDs to structured objects. `RadicleIdentity` should be the single type-safe representation that downstream consumers (radicle-httpd, frontend) depend on — never raw DID strings.

### Context
`RadicleIdentity` at line 69-80 already has `keri_state: Option<KeyState>`, `keys: Vec<Did>`, `sequence: u64`, and `document: Option<RadicleIdentityDocument>`. The struct needs review and potential additions to fully support the unified profile view.

### What to do
1. Read the current `RadicleIdentity` struct and `KeyState` (from `auths-id/src/keri/state.rs`)
2. Ensure `RadicleIdentity` includes:
   - `did: Did` — the identity DID (did:key or did:keri) as a structured type, not a string
   - `keys: Vec<Did>` — current signing key DIDs
   - `sequence: u64` — KERI sequence number (0 for did:key)
   - `keri_state: Option<KeyState>` — full KERI key state when resolved
   - `document: Option<RadicleIdentityDocument>` — Radicle identity document
   - `is_abandoned: bool` — whether the KERI identity has been abandoned (no next-key commitment). Required for "Person View" to show warning state.
   - `devices: Vec<Did>` — list of attested device DIDs (for the unified profile). Required for "Person View" device list.
3. Ensure `RadicleIdentity` derives `Serialize` for API consumption
4. If `KeyState` needs additional fields (witness list, configuration traits), update it in `auths-id`
5. Add builder or constructor methods as needed per CLAUDE.md conventions (docstrings with Description, Args, Usage)
6. Use the `AuthsStorage` trait for any device resolution — this Ports & Adapters pattern decouples from Git specifics

### Key files
- `auths-radicle/src/identity.rs:69-80` — `RadicleIdentity` struct
- `auths-id/src/keri/state.rs:17+` — `KeyState` struct
- `auths-radicle/src/bridge.rs:193-232` — `RadicleAuthsBridge` trait (uses `list_devices()`)
- CLAUDE.md conventions: Rust edition 2024, docstrings required
## Refactor RadicleIdentity struct for KERI-specific fields

**Repo**: `/Users/bordumb/workspace/repositories/auths-base/auths/crates/auths-radicle/src/identity.rs`

### Context
`RadicleIdentity` at line 69-80 already has `keri_state: Option<KeyState>`, `keys: Vec<Did>`, `sequence: u64`, and `document: Option<RadicleIdentityDocument>`. The struct needs review and potential additions to fully support the unified profile view.

### What to do
1. Read the current `RadicleIdentity` struct and `KeyState` (from `auths-id/src/keri/state.rs`)
2. Ensure `RadicleIdentity` includes:
   - `did: Did` — the identity DID (did:key or did:keri)
   - `keys: Vec<Did>` — current signing key DIDs
   - `sequence: u64` — KERI sequence number (0 for did:key)
   - `keri_state: Option<KeyState>` — full KERI key state when resolved
   - `document: Option<RadicleIdentityDocument>` — Radicle identity document
   - `is_abandoned: bool` — whether the KERI identity has been abandoned (no next-key commitment)
   - `devices: Vec<Did>` — list of attested device DIDs (for the unified profile)
3. Ensure `RadicleIdentity` derives `Serialize` for API consumption
4. If `KeyState` needs additional fields (witness list, configuration traits), update it in `auths-id`
5. Add builder or constructor methods as needed per CLAUDE.md conventions (docstrings with Description, Args, Usage)

### Key files
- `auths-radicle/src/identity.rs:69-80` — `RadicleIdentity` struct
- `auths-id/src/keri/state.rs:17+` — `KeyState` struct
- `auths-radicle/src/bridge.rs:193-232` — `RadicleAuthsBridge` trait (uses `list_devices()`)
- CLAUDE.md conventions: Rust edition 2024, docstrings required
## Acceptance
- [ ] `RadicleIdentity` has all fields needed for unified profile view
- [ ] `RadicleIdentity` derives `Serialize` (at minimum)
- [ ] `is_abandoned` flag exposed
- [ ] `devices` field populated from bridge resolution
- [ ] `cargo build -p auths-radicle --all-features` shows no `error[E` output
## Done summary
- Added `is_abandoned: bool` field derived from `KeyState.is_abandoned`
- Added `devices: Vec<Did>` field (defaults empty, populated by caller/bridge)
- Added `is_keri()` helper method
- Added docstring with usage example

Why:
- Profile Unification UI needs `is_abandoned` for warning state and `devices` for Person View device list
- Struct is now the single type-safe representation for downstream consumers

Verification:
- `cargo build -p auths-radicle --all-features` compiles cleanly
## Evidence
- Commits: adef1d321fa5f396dbd225a1cf27525a38d3f9b3
- Tests: cargo build -p auths-radicle --all-features
- PRs:
