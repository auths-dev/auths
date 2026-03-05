# fn-5.4 Register identity module in v1.rs router

## Description
## Register identity module in v1.rs router

**Repo**: `/Users/bordumb/workspace/repositories/radicle-base/radicle-explorer/radicle-httpd/src/api/v1.rs`

### Problem
The `identity.rs` file exists with `kel_handler` and `attestations_handler`, but `v1.rs` only declares `mod delegates; mod node; mod repos; mod stats;`. The identity module is not imported and its routes are dead code.

### What to do
1. Add `mod identity;` to the module declarations in `v1.rs`
2. Add `.merge(identity::router(ctx.clone()))` to the v1 router chain (following the pattern of other sub-routers)
3. Ensure the identity routes are nested correctly under `/v1/identity/...`

### Key files
- `radicle-httpd/src/api/v1.rs:1-4` — module declarations
- `radicle-httpd/src/api/v1.rs:14-27` — router construction
- `radicle-httpd/src/api/v1/identity.rs` — the unregistered module
## Acceptance
- [ ] `mod identity;` declared in `v1.rs`
- [ ] `identity::router(ctx.clone())` merged into v1 router
- [ ] `GET /v1/identity/{did}/kel` and `GET /v1/identity/{did}/attestations` are reachable
## Done summary
- Added `mod identity;` to v1.rs module declarations
- Merged `identity::router(ctx.clone())` into v1 router chain

Why:
- identity.rs endpoints (KEL, attestations) were dead code without module registration

Verification:
- Routes `/v1/identity/{did}/kel` and `/v1/identity/{did}/attestations` are now reachable
## Evidence
- Commits: eb16e799dd430cf4568a121e2d7dcff798218871
- Tests: code review
- PRs:
