# fn-9.1 Configure clippy.toml and integration test lint allowances

## Description
## Configure clippy.toml and integration test lint allowances

Set up the clippy configuration that will be enforced in the final task (fn-9.7). This task does NOT enable the deny lints yet — it only prepares the infrastructure so that when lints are enabled, tests still pass.

### Changes

1. **`clippy.toml`** — Add two lines:
   ```toml
   allow-unwrap-in-tests = true
   allow-expect-in-tests = true
   ```

2. **Integration test entry points** — Add `#![allow(clippy::unwrap_used, clippy::expect_used)]` to the top of each integration test file. Due to clippy issue #13981, `allow-unwrap-in-tests` does NOT cover `tests/` directories. Files to update:
   - `crates/auths-core/tests/integration.rs`
   - `crates/auths-id/tests/integration.rs`
   - `crates/auths-verifier/tests/integration.rs`
   - `crates/auths-sdk/tests/integration.rs`
   - Any other `tests/integration.rs` or `tests/*.rs` files in target crates

### Files to modify
- `/Users/bordumb/workspace/repositories/auths-base/auths/clippy.toml`
- All `tests/integration.rs` files in target crates

### Smoke test
```bash
cargo clippy --all-targets --all-features -- -D warnings
```
## Acceptance
- [ ] `clippy.toml` contains `allow-unwrap-in-tests = true` and `allow-expect-in-tests = true`
- [ ] All integration test entry points in target crates have `#![allow(clippy::unwrap_used, clippy::expect_used)]`
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes
- [ ] `cargo nextest run --workspace` passes
## Done summary
TBD

## Evidence
- Commits:
- Tests:
- PRs:
