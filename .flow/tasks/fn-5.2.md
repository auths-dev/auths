# fn-5.2 Fix delegates.rs syntax errors (duplicate derive, extra brace)

## Description
## Fix delegates.rs syntax errors

**Repo**: `/Users/bordumb/workspace/repositories/radicle-base/radicle-explorer/radicle-httpd/src/api/v1/delegates.rs`

### Problem
1. Duplicate `#[derive(Serialize)]` at lines 17-18
2. Extra closing brace `}}` at line 57 — causes `delegates_repos_handler` (line 61) to be defined outside the module scope
3. These errors prevent the radicle-httpd crate from compiling

### What to do
1. Remove the duplicate `#[derive(Serialize)]`
2. Fix the extra closing brace at line 57
3. Verify `delegates_repos_handler` is correctly scoped
4. Verify: `cd /Users/bordumb/workspace/repositories/radicle-base/radicle-explorer/radicle-httpd && cargo build 2>&1 | grep "^error\[E" -A 10`

### Key files
- `radicle-httpd/src/api/v1/delegates.rs:17-18` — duplicate derive
- `radicle-httpd/src/api/v1/delegates.rs:57` — extra closing brace
- `radicle-httpd/src/api/v1/delegates.rs:61+` — delegates_repos_handler displaced
## Acceptance
- [ ] No duplicate `#[derive(Serialize)]` on `UserResponse`
- [ ] `delegate_handler` and `delegates_repos_handler` are both properly scoped
- [ ] No extra closing braces
- [ ] radicle-httpd compiles without `error[E` output
## Done summary
- Removed duplicate `#[derive(Serialize)]` on `UserResponse` (lines 17-18)
- Removed extra closing brace `}}` at line 57 that displaced `delegates_repos_handler`

Why:
- Both handlers are now properly scoped within the module
- Note: radicle-httpd still has pre-existing build errors from auths-verifier let-chain syntax (edition 2024 vs 2021 mismatch) — unrelated to this fix

Verification:
- delegates.rs compiles cleanly; remaining errors are in auths-verifier dependency
## Evidence
- Commits: 45f774512175b525101f1c97529c63eb8396458e
- Tests: cargo build (radicle-httpd)
- PRs:
