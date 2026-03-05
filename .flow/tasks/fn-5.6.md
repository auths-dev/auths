# fn-5.6 Expose resolve_keri publicly and return enriched RadicleIdentity

## Description
## Expose resolve_keri publicly

**Repo**: `/Users/bordumb/workspace/repositories/auths-base/auths/crates/auths-radicle/src/identity.rs`

### Design Principle
`resolve_keri` is the **"rich" public API** for external consumers (radicle-httpd, CLI). It returns the full `RadicleIdentity` with all fields needed for UI rendering. The `DidResolver` trait implementation remains separate — it's the **internal/generic** interface returning `ResolvedDid` for DID resolution pipelines. This separation serves internal vs. external consumption patterns.

### Context
`resolve_keri` at line 117-136 already exists as a method on `RadicleIdentityResolver`. It replays KEL via `resolve_keri_state()`, converts CESR keys to `PublicKey`, and returns `RadicleIdentity` with `keri_state: Some(...)`. Currently it may not be `pub` or the method signature may not return the enriched struct.

### What to do
1. Make `resolve_keri` a `pub` method on `RadicleIdentityResolver`
2. Ensure it returns `Result<RadicleIdentity, IdentityError>` (not `ResolvedDid`)
3. Populate all new fields from fn-5.5 (including `devices` via bridge, `is_abandoned`)
4. Make `resolve_kel_events` also `pub` — needed by radicle-httpd's `kel_handler`. This centralizes the Git commit-walking logic so radicle-httpd never re-implements it (DRY principle).
5. Re-export from `lib.rs` if not already: `pub use identity::{RadicleIdentity, RadicleIdentityResolver};`
6. Check `lib.rs:15-19` boundary constraint: auths-radicle imports heartwood types, not the other way around

### Key files
- `auths-radicle/src/identity.rs:117-136` — `resolve_keri` method
- `auths-radicle/src/identity.rs:274-302` — `resolve_keri_state` helper
- `auths-radicle/src/lib.rs:15-19` — module re-exports
- `radicle-httpd/src/api/v1/identity.rs:26` — consumer of `resolve_kel_events`
- `radicle-httpd/src/api/v1/delegates.rs:40` — consumer of `resolver.resolve()`
## Expose resolve_keri publicly

**Repo**: `/Users/bordumb/workspace/repositories/auths-base/auths/crates/auths-radicle/src/identity.rs`

### Context
`resolve_keri` at line 117-136 already exists as a method on `RadicleIdentityResolver`. It replays KEL via `resolve_keri_state()`, converts CESR keys to `PublicKey`, and returns `RadicleIdentity` with `keri_state: Some(...)`. Currently it may not be `pub` or the method signature may not return the enriched struct.

The `DidResolver` trait impl at line 378-416 returns a generic `ResolvedDid` — we want `resolve_keri` to be the **richer** public API that returns full `RadicleIdentity` instead.

### What to do
1. Make `resolve_keri` a `pub` method on `RadicleIdentityResolver`
2. Ensure it returns `Result<RadicleIdentity, IdentityError>` (not `ResolvedDid`)
3. Populate all new fields from fn-5.5 (including `devices` via bridge, `is_abandoned`)
4. Make `resolve_kel_events` also `pub` — needed by radicle-httpd's `kel_handler`
5. Re-export from `lib.rs` if not already: `pub use identity::{RadicleIdentity, RadicleIdentityResolver};`
6. Check `lib.rs:15-19` boundary constraint: auths-radicle imports heartwood types, not the other way around

### Key files
- `auths-radicle/src/identity.rs:117-136` — `resolve_keri` method
- `auths-radicle/src/identity.rs:274-302` — `resolve_keri_state` helper
- `auths-radicle/src/lib.rs:15-19` — module re-exports
- `radicle-httpd/src/api/v1/identity.rs:26` — consumer of `resolve_kel_events`
- `radicle-httpd/src/api/v1/delegates.rs:40` — consumer of `resolver.resolve()`
## Acceptance
- [ ] `resolve_keri` is `pub` and returns `Result<RadicleIdentity, IdentityError>`
- [ ] `resolve_kel_events` is `pub`
- [ ] Both are methods on `RadicleIdentityResolver` (not free functions)
- [ ] `RadicleIdentity` and `RadicleIdentityResolver` re-exported from `lib.rs`
- [ ] `cargo build -p auths-radicle --all-features` shows no `error[E` output
## Done summary
- Verified `resolve_keri`, `resolve_kel_events`, `resolve_keri_state` are all `pub` methods on `RadicleIdentityResolver`
- Verified `RadicleIdentity`, `RadicleIdentityResolver`, `IdentityError` are re-exported from `lib.rs`
- `resolve_keri` already returns enriched `RadicleIdentity` with all fn-5.5 fields

Why:
- All criteria were already satisfied from prior work and fn-5.5 refactor
- No code changes needed — this was a verification-only pass

Verification:
- `cargo build -p auths-radicle --all-features` compiles cleanly
- Grep confirms all methods are `pub`
## Evidence
- Commits:
- Tests: cargo build -p auths-radicle --all-features
- PRs:
