# fn-1.17 CI integration

## Description
Ensure the auths-radicle test suite runs in CI on all three platforms and integrate with the existing CI workflow.

### What to implement

1. Update `.github/workflows/` to include auths-radicle tests.
2. Ensure tests work on Ubuntu (x86_64), macOS (aarch64), and Windows (x86_64).
3. Verify WASM check for auths-verifier still passes (regression check).
4. Ensure test completion within reasonable time (< 5 minutes).
5. Handle any platform-specific issues:
   - Git config requirements (`user.name`, `user.email`)
   - Temp directory paths (Windows vs Unix)
   - File permissions for Git repos

### Key context

- CI already runs on all three platforms per CLAUDE.md.
- Git config is required per CLAUDE.md CI Requirements section.
- **`vendored-libgit2` feature**: `auths-radicle` depends on `git2`. Ensure the `vendored-libgit2` feature is used to avoid "missing libgit2" errors on Windows/macOS runners that may not have system libgit2 installed.
- The WASM check must still pass: `cd crates/auths-verifier && cargo check --target wasm32-unknown-unknown --no-default-features --features wasm`.

### Affected files
- Modified: `.github/workflows/` (CI configuration)
- Possibly modified: `crates/auths-radicle/Cargo.toml` (ensure `vendored-libgit2` feature)
- Possibly modified: `crates/auths-radicle/tests/` (platform-specific test guards if needed)

## Code Quality
- **DRY**: Do not repeat logic; extract shared patterns into helper functions or traits.
- **Modular Design**: Avoid monolithic functions. Decompose complex logic into small, focused, and testable units.
- **Strictness**: Adhere to the "Zero-Debt" mandate—if old code is redundant, delete it; do not leave "TODO" or "Legacy" stubs.

## Acceptance
- [ ] CI runs auths-radicle test suite
- [ ] All tests pass on Ubuntu, macOS, and Windows
- [ ] `vendored-libgit2` feature used (no system libgit2 dependency on CI runners)
- [ ] WASM check for auths-verifier passes (no regression)
- [ ] Test suite completes within 5 minutes
- [ ] `cargo nextest run --workspace` passes in CI
## Done summary
Created .github/workflows/ci.yml with cross-platform CI: fmt check, clippy, nextest on ubuntu/macos/windows, doc tests, and WASM verification for auths-verifier.
## Evidence
- Commits: 515ac84
- Tests: cargo build -p auths-radicle --all-features --tests
- PRs:
