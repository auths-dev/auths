# fn-5.11 Implement did:keri -> repos lookup in delegates_repos_handler

## Description
## Implement did:keri -> repos lookup in delegates_repos_handler

**Repo**: `/Users/bordumb/workspace/repositories/radicle-base/radicle-explorer/radicle-httpd/src/api/v1/delegates.rs`

### Design Principle
This task is the **"UX glue"** for identity unification. Without this lookup, searching for repos by a KERI DID returns nothing — completely breaking the mental model that a person's identity encompasses all their device-linked repos. If this fails, the entire Person View is hollow.

### Context
`delegates_repos_handler` at line 61+ filters repos where `repo.doc.delegates().iter().any(|d| *d == did)`. Radicle projects have `did:key` delegates. When a user queries by `did:keri`, no repos match because projects don't directly list `did:keri` as delegates.

### What to do
1. When the input DID is `did:keri`, first resolve it to its linked device `did:key`s via `RadicleIdentityResolver`
2. Filter repos where any delegate matches **any** of the resolved device DIDs
3. Merge results and deduplicate
4. Maintain backwards compatibility: `did:key` queries still work as before
5. Consider caching the resolution result within the handler (same request may resolve multiple repos)

### Key files
- `radicle-httpd/src/api/v1/delegates.rs:61+` — delegates_repos_handler
- `auths-radicle/src/identity.rs` — resolve to get device list
- `auths-radicle/src/bridge.rs:193-232` — `find_identity_for_device()`
## Implement did:keri -> repos lookup in delegates_repos_handler

**Repo**: `/Users/bordumb/workspace/repositories/radicle-base/radicle-explorer/radicle-httpd/src/api/v1/delegates.rs`

### Context
`delegates_repos_handler` at line 61+ filters repos where `repo.doc.delegates().iter().any(|d| *d == did)`. Radicle projects have `did:key` delegates. When a user queries by `did:keri`, no repos match because projects don't directly list `did:keri` as delegates.

### What to do
1. When the input DID is `did:keri`, first resolve it to its linked device `did:key`s via `RadicleIdentityResolver`
2. Filter repos where any delegate matches **any** of the resolved device DIDs
3. Merge results and deduplicate
4. Maintain backwards compatibility: `did:key` queries still work as before
5. Consider caching the resolution result within the handler (same request may resolve multiple repos)

### Key files
- `radicle-httpd/src/api/v1/delegates.rs:61+` — delegates_repos_handler
- `auths-radicle/src/identity.rs` — resolve to get device list
- `auths-radicle/src/bridge.rs:193-232` — `find_identity_for_device()`
## Acceptance
- [ ] `did:keri` queries resolve to device DIDs and return their repos
- [ ] `did:key` queries still work as before (no regression)
- [ ] Results are deduplicated when multiple devices share a repo
- [ ] Returns empty array (not error) when KERI identity has no linked devices
## Done summary
- Added did:keri -> did:key resolution in delegates_repos_handler using RadicleIdentityResolver
- Built HashSet of match DIDs: for did:key, just the DID itself; for did:keri, all resolved device keys
- Replaced direct `*d == did` comparison with `match_dids.contains(d)` in both All and Pinned branches
- Empty HashSet (resolution failure) returns empty array gracefully

Why:
- Radicle projects list did:key delegates, not did:keri — without this, Person View shows no repos

Verification:
- Compiles cleanly (only pre-existing auths-verifier edition errors)
## Evidence
- Commits: c1fec6d0bcd3810a44ff2a056bad356f64c6b84c
- Tests: cargo build (radicle-httpd)
- PRs:
