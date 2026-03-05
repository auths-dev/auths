# WASM Verification & API Surface Hardening

## Overview

Three tasks that improve the auths ecosystem's production-readiness:

1. **Implement `WebCryptoProvider::verify_ed25519()`** — unblocks the entire WASM story (browser SDKs, mobile WebView, npm package) by replacing the TODO stub with a real SubtleCrypto-backed implementation.
2. **Seal the public API surface of `auths-core`** — replace wildcard `pub use` re-exports with explicit exports, preventing accidental exposure of internal types (platform keychains, FFI functions) and protecting semver stability.
3. **Add WASM binding tests and WebCryptoProvider tests** — set up `wasm-pack test` infrastructure and add test coverage for the 7 `#[wasm_bindgen]` functions and the WebCryptoProvider implementation.

## Scope

### In scope
- WebCrypto Ed25519 verify implementation using `web-sys` SubtleCrypto
- Adding `web-sys`, `js-sys`, `wasm-bindgen`, `wasm-bindgen-futures` deps to `auths-crypto`
- Conditional `#[async_trait(?Send)]` on wasm32 for `CryptoProvider` trait
- Removing `pub use api::*`, `pub use config::*`, `pub use storage::*` from `auths-core/src/lib.rs`
- Making platform keychain structs `pub(crate)` in `storage/mod.rs`
- Setting up `wasm_bindgen_test` infrastructure in `auths-crypto` and `auths-verifier`
- WebCryptoProvider test cases mirroring Ring provider tests
- WASM binding integration tests (attestation verify, artifact signature)
- WASM compilation checks

### Out of scope
- Browser compatibility fallback for Ed25519 (tracked separately)
- `KeriSequence` visibility changes (analysis shows it is a legitimate public type)
- `IdentityDID` double-path cleanup (tracked as v1_launch Task 0.3)
- Gating `memory` storage module behind test feature
- Sealing sub-wildcards inside `api/mod.rs`

## Approach

### Task 0.1: WebCrypto verify (fn-8.1)
1. Add wasm-gated deps to `auths-crypto/Cargo.toml`
2. Update `CryptoProvider` trait with conditional `async_trait(?Send)` on wasm32
3. Implement `verify_ed25519()` using SubtleCrypto importKey + verify
4. Get SubtleCrypto via `js_sys::global()` for Window + Worker compatibility
5. Verify WASM compilation

### Task 0.2: Seal API surface (fn-8.2)
1. Remove three wildcard re-exports from `auths-core/src/lib.rs`
2. Make platform keychain structs `pub(crate)` in `storage/mod.rs`
3. Keep public module + explicit exports of consumer-facing types
4. Validate with `cargo check --workspace`

### Task 0.3: WASM tests (fn-8.3, depends on fn-8.1)
1. Add `wasm-bindgen-test` to dev-dependencies
2. Create WebCryptoProvider tests using RFC 8032 test vectors
3. Create WASM binding integration tests for public `#[wasm_bindgen]` functions
4. Add `wasm-pack test` to CI/justfile

## Quick commands

```bash
# Smoke test — WASM compilation
cd crates/auths-crypto && cargo check --target wasm32-unknown-unknown --no-default-features --features wasm

# Smoke test — workspace builds
cargo check --workspace
cargo nextest run --workspace

# Smoke test — existing verifier WASM check
cd crates/auths-verifier && cargo check --target wasm32-unknown-unknown --no-default-features --features wasm

# WASM tests (after fn-8.3)
cd crates/auths-crypto && wasm-pack test --headless --chrome --no-default-features --features wasm
cd crates/auths-verifier && wasm-pack test --headless --chrome --no-default-features --features wasm
```

## Acceptance

- [ ] `WebCryptoProvider::verify_ed25519()` compiles for wasm32
- [ ] `RingCryptoProvider` still compiles and passes all tests on native targets
- [ ] `cargo check --workspace` passes (no downstream breakage from API sealing)
- [ ] `cargo nextest run --workspace` passes
- [ ] No platform keychain structs are importable from `auths_core::` root
- [ ] No FFI functions are importable from `auths_core::` root
- [ ] WASM verifier check passes
- [ ] WebCryptoProvider test cases pass in browser environment
- [ ] WASM binding tests pass via wasm-pack test

## References

- `crates/auths-crypto/src/webcrypto_provider.rs:26-42` — current TODO stub
- `crates/auths-crypto/src/provider.rs:85-93` — CryptoProvider trait definition
- `crates/auths-crypto/src/ring_provider.rs:22-48` — reference Ring implementation
- `crates/auths-core/src/lib.rs:80-85` — wildcard re-exports to remove
- `crates/auths-core/src/storage/mod.rs:17-29` — platform struct re-exports
- `crates/auths-verifier/src/wasm.rs` — 7 wasm_bindgen functions (500+ lines, zero tests)
- `crates/auths-crypto/tests/cases/provider.rs` — Ring provider test pattern to mirror
- RFC 8032 Section 7.1 — Ed25519 test vectors
- MDN SubtleCrypto importKey/verify docs
- wasm-bindgen issue #2833 (JsFuture !Send)
