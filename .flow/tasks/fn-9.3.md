# fn-9.3 Fix unwraps in auths-verifier (FFI/WASM boundaries)

## Description
## Fix unwraps in auths-verifier (FFI/WASM boundaries)

The auths-verifier has very few issues — WASM is already clean, and FFI uses `catch_unwind` correctly.

### Changes

1. **`src/ffi.rs:16`** — `tokio::runtime::Builder...build().expect("FFI: failed to create tokio runtime")` in `with_runtime()`. This is unrecoverable (no runtime = no function). Add `#[allow(clippy::expect_used)]` with `// SAFETY: Tokio runtime creation is unrecoverable — process cannot function without it`.

2. **`src/ffi.rs:225,336,411,540`** — `result.unwrap_or_else(|_| ERR_VERIFY_PANIC)` on `catch_unwind` results. These are NOT panicking — they handle panics. Add `#[allow(clippy::unwrap_used)]` with `// SAFETY: unwrap_or_else on catch_unwind result — handles panic with error code`.

3. **`src/wasm.rs:93,160,219`** — `unwrap_or_else` producing fallback JSON strings. Same treatment — `#[allow]` with safety comment.

4. **Add `#![deny(clippy::unwrap_used, clippy::expect_used)]` is NOT done in this task** — that's fn-9.7. This task only fixes/annotates the code so it will be ready.

### Files to modify
- `crates/auths-verifier/src/ffi.rs`
- `crates/auths-verifier/src/wasm.rs`

### Smoke test
```bash
cargo nextest run -p auths_verifier
cd crates/auths-verifier && cargo check --target wasm32-unknown-unknown --no-default-features --features wasm
```
## Acceptance
- [ ] All `unwrap()`/`expect()` in `crates/auths-verifier/src/` have either been replaced or annotated with `#[allow]` + SAFETY comment
- [ ] `cargo nextest run -p auths_verifier` passes
- [ ] WASM check passes: `cd crates/auths-verifier && cargo check --target wasm32-unknown-unknown --no-default-features --features wasm`
- [ ] No functional behavior changes
## Done summary
TBD

## Evidence
- Commits:
- Tests:
- PRs:
