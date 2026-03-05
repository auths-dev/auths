# fn-9.7 Enable deny lints in all target crate lib.rs files

## Description
## Enable deny lints in all target crate lib.rs files

Final enforcement task. All unwraps/expects must already be fixed or annotated by prior tasks.

### Changes

Add to each target crate's `lib.rs`:
```rust
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
```

Target crates:
- `crates/auths-core/src/lib.rs`
- `crates/auths-verifier/src/lib.rs`
- `crates/auths-sdk/src/lib.rs`
- `crates/auths-id/src/lib.rs`

### Verification

Run the full CI suite to confirm everything passes:
```bash
cargo fmt --check --all
cargo clippy --all-targets --all-features -- -D warnings
cargo nextest run --workspace
cargo test --all --doc
cd crates/auths-verifier && cargo check --target wasm32-unknown-unknown --no-default-features --features wasm
```

If any violations remain, fix them before merging. Do NOT weaken the lint to `warn`.

### Smoke test
```bash
cargo clippy --all-targets --all-features -- -D warnings
```
## Acceptance
- [ ] `#![deny(clippy::unwrap_used)]` and `#![deny(clippy::expect_used)]` present in all 4 target crate lib.rs files
- [ ] `cargo fmt --check --all` passes
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes with zero unwrap/expect violations
- [ ] `cargo nextest run --workspace` passes
- [ ] `cargo test --all --doc` passes
- [ ] WASM check passes: `cd crates/auths-verifier && cargo check --target wasm32-unknown-unknown --no-default-features --features wasm`
## Done summary
TBD

## Evidence
- Commits:
- Tests:
- PRs:
