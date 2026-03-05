# fn-5.8 Extend GET /v1/users/:did with real device list and KERI error variant

## Description
## Extend GET /v1/users/:did with real device list and KERI error variant

**Repo**: `/Users/bordumb/workspace/repositories/radicle-base/radicle-explorer/radicle-httpd/src/api/v1/delegates.rs`

### Design Principle
Proper error propagation is **critical for debugging resolution failures in production**. The current `.ok()` swallowing means operators cannot distinguish "identity not found" from "KEL corrupt" from "storage timeout." All responses must use `camelCase` JSON keys for consistency with the existing API.

### Context
`delegate_handler` at line 35-57 already returns `UserResponse` with `controller_did`, `is_keri`, `devices`. But:
- `devices` is hardcoded to `Vec::new()` (line 53)
- Errors from `resolver.resolve()` are swallowed via `.ok()` (line 40)
- No `IdentityError` variant in httpd's `Error` enum

### What to do
1. Add an `IdentityError` variant to `radicle-httpd/src/api/error.rs` that wraps auths-radicle errors and maps to appropriate HTTP status (404 for not found, 502 for resolution failure, 422 for corrupt KEL)
2. Replace `.ok()` with proper error propagation using the new variant
3. Populate `devices` field by calling `RadicleAuthsBridge::list_devices()` or equivalent from `resolve_keri` result
4. Ensure the handler works for both `did:key` (returns `controller_did: None, is_keri: false, devices: []`) and `did:keri` (returns populated response)
5. Use `#[serde(rename_all = "camelCase")]` on response types (matching existing API convention)

### Key files
- `radicle-httpd/src/api/v1/delegates.rs:35-57` — delegate_handler
- `radicle-httpd/src/api/error.rs:10-98` — Error enum
- `auths-radicle/src/bridge.rs:193-232` — RadicleAuthsBridge trait
- `radicle-httpd/src/api.rs:69-73` — Context struct
## Extend GET /v1/users/:did with real device list and KERI error variant

**Repo**: `/Users/bordumb/workspace/repositories/radicle-base/radicle-explorer/radicle-httpd/src/api/v1/delegates.rs`

### Context
`delegate_handler` at line 35-57 already returns `UserResponse` with `controller_did`, `is_keri`, `devices`. But:
- `devices` is hardcoded to `Vec::new()` (line 53)
- Errors from `resolver.resolve()` are swallowed via `.ok()` (line 40)
- No `IdentityError` variant in httpd's `Error` enum

### What to do
1. Add an `IdentityError` variant to `radicle-httpd/src/api/error.rs` that wraps auths-radicle errors and maps to appropriate HTTP status (404 for not found, 502 for resolution failure)
2. Replace `.ok()` with proper error propagation using the new variant
3. Populate `devices` field by calling `RadicleAuthsBridge::list_devices()` or equivalent from `resolve_keri` result
4. Ensure the handler works for both `did:key` (returns `controller_did: None, is_keri: false, devices: []`) and `did:keri` (returns populated response)
5. Use `#[serde(rename_all = "camelCase")]` on response types (matching existing API convention)

### Key files
- `radicle-httpd/src/api/v1/delegates.rs:35-57` — delegate_handler
- `radicle-httpd/src/api/error.rs:10-98` — Error enum
- `auths-radicle/src/bridge.rs:193-232` — RadicleAuthsBridge trait
- `radicle-httpd/src/api.rs:69-73` — Context struct
## Acceptance
- [ ] `devices` field populated from bridge resolution (not empty vec)
- [ ] `IdentityError` variant added to httpd `Error` enum
- [ ] Resolution errors propagated instead of swallowed
- [ ] `did:key` requests return graceful fallback (no KERI fields)
- [ ] `did:keri` requests return `controller_did`, `is_keri: true`, populated `devices`
- [ ] Response uses camelCase JSON keys
## Done summary
- Added `Identity` error variant to httpd `Error` enum with status-aware mapping (404/400/500)
- Added `#[serde(rename_all = "camelCase")]` to `UserResponse`
- Added `is_abandoned` field to `UserResponse`
- Replaced `.ok()` error swallowing with `?` propagation
- Populated `devices` from `identity.keys` (current signing key DIDs)

Why:
- Production debugging requires distinguishing resolution failure modes
- Frontend needs camelCase JSON and device list for Profile Unification

Verification:
- `cargo build` shows only pre-existing auths-verifier edition errors, no new errors
## Evidence
- Commits: 4f4236cd0a6a9916bace60701fcbbfff394edc28
- Tests: cargo build (radicle-httpd)
- PRs:
