# fn-5.1 Fix identity.rs impl block structure (stray closing brace)

## Description
## Fix identity.rs impl block structure

**Repo**: `/Users/bordumb/workspace/repositories/auths-base/auths/crates/auths-radicle/src/identity.rs`

### Problem
Line 272 has a stray closing brace `}` that prematurely closes the `impl RadicleIdentityResolver` block. This causes `resolve_keri_state` (line 274-302) and `resolve_kel_events` to become free functions instead of methods, which means `resolver.resolve_kel_events(&repo)` calls from radicle-httpd will not compile.

### What to do
1. Read `identity.rs` and map the full `impl RadicleIdentityResolver` block boundaries
2. Remove or relocate the stray `}` at line 272
3. Ensure `resolve_keri_state` and `resolve_kel_events` are properly inside the `impl` block
4. Verify: `cargo build -p auths-radicle --all-features 2>&1 | grep "^error\[E" -A 10`

### Key files
- `auths-radicle/src/identity.rs:272` — stray brace
- `auths-radicle/src/identity.rs:274-302` — `resolve_keri_state`
- `auths-radicle/src/identity.rs:378-416` — `DidResolver` trait impl (should remain separate)
## Acceptance
- [ ] No stray closing brace breaking the `impl RadicleIdentityResolver` block
- [ ] `resolve_keri_state` is a method on `RadicleIdentityResolver`
- [ ] `resolve_kel_events` is a method on `RadicleIdentityResolver`
- [ ] `cargo build -p auths-radicle --all-features` shows no `error[E` output
## Done summary
- Removed stray closing brace at line 272 that prematurely closed `impl RadicleIdentityResolver`
- Added missing `RepoId` import and fixed `RepoIdError` -> `repo::IdError` type reference
- Removed unused `self` import from `crate::refs`

Why:
- `resolve_keri_state` and `resolve_kel_events` were orphaned as free functions instead of methods
- Code now compiles cleanly with `cargo build -p auths-radicle --all-features`

Verification:
- `cargo build -p auths-radicle --all-features` produces no `error[E` output
## Evidence
- Commits: f8f90b7beaabf1e9d180516a1e1a020c451ad247
- Tests: cargo build -p auths-radicle --all-features
- PRs:
