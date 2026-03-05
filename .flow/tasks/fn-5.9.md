# fn-5.9 Implement GET /v1/identity/:did/kel with correct repo discovery

## Description
## Implement GET /v1/identity/:did/kel with correct repo discovery

**Repo**: `/Users/bordumb/workspace/repositories/radicle-base/radicle-explorer/radicle-httpd/src/api/v1/identity.rs`

### Context
`kel_handler` exists but has two critical issues:
1. Uses `git2::Repository` directly (line 5) — but `git2` is not a direct dependency of radicle-httpd
2. Repo discovery at line 26-28 uses `storage_path.join(did.to_string())` which is wrong — KERI data lives in identity repos found via RIP-X namespace refs (`refs/namespaces/did-keri-<prefix>/refs/rad/id`), not at `{storage}/{did}`

### What to do
1. Replace `git2::Repository` usage with `RadicleIdentityResolver::resolve_kel_events()` (made public in fn-5.6)
2. Construct a `RadicleIdentityResolver` from the httpd `Context` (which has `profile: Arc<Profile>`)
3. Use the resolver's internal repo discovery (which uses the `Layout` struct from refs.rs)
4. Return the KEL events as JSON array, serialized in the format that `verifyDeviceLink()` WASM expects
5. Add proper error handling using the `IdentityError` variant from fn-5.8
6. Remove the `git2` import

### Key files
- `radicle-httpd/src/api/v1/identity.rs:1-39` — current kel_handler
- `auths-radicle/src/identity.rs` — `resolve_kel_events` (public after fn-5.6)
- `auths-radicle/src/refs.rs:1-216` — Layout struct with namespace ref paths
- `auths-verifier/src/keri.rs` — Event types for serialization reference
## Acceptance
- [ ] Uses `RadicleIdentityResolver::resolve_kel_events()` instead of raw git2
- [ ] Correct repo discovery via RIP-X namespace refs
- [ ] Returns JSON array of KEL events matching WASM `verifyDeviceLink` input format
- [ ] Proper error handling (404 for unknown DID, 502 for corrupt KEL)
- [ ] No direct `git2` import in identity.rs
## Done summary
- Added `resolve_kel(&self, did: &Did)` public method to RadicleIdentityResolver for repo-discovery + KEL retrieval
- Rewrote `kel_handler` to use `resolver.resolve_kel(&did)` instead of raw git2
- Removed `git2::Repository` import from identity.rs
- Errors propagated via `IdentityError` variant (from fn-5.8)

Why:
- Old handler used incorrect repo discovery (`storage_path/did` instead of namespace refs)
- Handler now delegates all Git logic to the resolver (DRY principle)

Verification:
- `cargo build -p auths-radicle --all-features` compiles cleanly
## Evidence
- Commits: 88adc1f7630e908064792696c03dc9ff3b637de9, 58de0aecb81b6770fcc9e91fe149d22275992a9a
- Tests: cargo build -p auths-radicle --all-features
- PRs:
