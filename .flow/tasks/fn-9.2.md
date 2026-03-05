# fn-9.2 Remove anyhow from auths-core runtime dependencies

## Description
## Remove anyhow from auths-core runtime dependencies

The only production `anyhow` usage in library crates is in `crates/auths-core/src/api/runtime.rs` (macOS ssh-add interaction, lines 46, 52, 577-630). Replace with `thiserror` domain errors.

### Changes

1. **Identify replacement error types**: The `register_keys_with_macos_agent_internal` function uses `anyhow::Context`, `anyhow::Result`, and `anyhow::bail!` for 8 fallible operations (DER parsing, key conversion, temp file I/O, ssh-add execution). Options:
   - Extend existing `AgentError` with new variants for ssh-agent operations
   - Create a focused `SshAgentError` enum in `crates/auths-core/src/api/` and add `#[from]` variant to `AgentError`

2. **Migrate call sites**: Replace `anyhow::Context` with `.map_err(|e| NewError::Variant { ... })`, replace `anyhow::bail!` with `return Err(NewError::Variant { ... })`.

3. **Update `Cargo.toml`**: Move `anyhow` from `[dependencies]` to `[dev-dependencies]` only (it's already in `[dev-dependencies]` at line 80).

4. **Update match arms**: Lines 684-693 currently downcast `anyhow::Error` to concrete types. With `thiserror`, these become direct pattern matches.

### Files to modify
- `crates/auths-core/src/api/runtime.rs` — Replace anyhow usage
- `crates/auths-core/src/error.rs` — Add new error variants (or new error enum)
- `crates/auths-core/Cargo.toml` — Remove anyhow from `[dependencies]`

### Smoke test
```bash
cargo build --package auths_core
cargo nextest run -p auths_core
```
## Acceptance
- [ ] No `anyhow` imports in `crates/auths-core/src/` (grep confirms zero matches)
- [ ] `anyhow` removed from `[dependencies]` in `crates/auths-core/Cargo.toml` (kept in `[dev-dependencies]`)
- [ ] All ssh-add error paths use typed `thiserror` variants
- [ ] `cargo build --package auths_core` succeeds
- [ ] `cargo nextest run -p auths_core` passes
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes
## Done summary
TBD

## Evidence
- Commits:
- Tests:
- PRs:
