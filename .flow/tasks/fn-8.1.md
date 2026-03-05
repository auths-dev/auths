# fn-8.1 Implement WebCryptoProvider::verify_ed25519()

## Description
## Implement WebCryptoProvider::verify_ed25519()

The WASM crypto provider's `verify_ed25519()` at `crates/auths-crypto/src/webcrypto_provider.rs:26-42` is a TODO stub that always returns `Err(CryptoError::OperationFailed(...))`. This blocks the entire WASM story — browser SDKs, mobile WebView integrations, and the npm package.

### Changes required

#### 1. Add WASM dependencies to `auths-crypto/Cargo.toml`

Add optional deps gated behind the `wasm` feature:

```toml
[dependencies]
js-sys = { version = "0.3", optional = true }
wasm-bindgen = { version = "0.2", optional = true }
wasm-bindgen-futures = { version = "0.4", optional = true }

[dependencies.web-sys]
version = "0.3"
optional = true
features = ["Crypto", "CryptoKey", "SubtleCrypto"]

[features]
wasm = ["dep:js-sys", "dep:wasm-bindgen", "dep:wasm-bindgen-futures", "dep:web-sys"]
```

#### 2. Conditional `async_trait` on `CryptoProvider` trait

At `crates/auths-crypto/src/provider.rs:85`, the `#[async_trait]` macro adds `Send` bounds by default. `JsFuture` from `wasm-bindgen-futures` is `!Send`, so WASM compilation will fail. Fix with conditional compilation:

```rust
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait CryptoProvider: Send + Sync { ... }
```

Apply the same conditional attribute on every `impl CryptoProvider for ...` block (`RingCryptoProvider`, `WebCryptoProvider`, `MockCryptoProvider` in test-utils).

#### 3. Implement `verify_ed25519()` in `webcrypto_provider.rs`

Implementation pattern:
1. Validate pubkey length (already done in stub)
2. Get `SubtleCrypto` via `js_sys::global()` → `Reflect::get("crypto")` → `.subtle()` (supports Window + Worker contexts)
3. Import raw 32-byte public key: `subtle.import_key_with_str("raw", &uint8array, "Ed25519", false, &["verify"])`
4. Await the `Promise` via `JsFuture::from(promise).await`
5. Verify: `subtle.verify_with_str_and_u8_array_and_u8_array("Ed25519", &crypto_key, signature, message)`
6. Await and check boolean result: `result.as_bool().unwrap_or(false)`
7. Map errors: import failures → `CryptoError::OperationFailed`, verify false → `CryptoError::InvalidSignature`

#### Key references
- Ring reference impl: `crates/auths-crypto/src/ring_provider.rs:22-48`
- Mock impl: `crates/auths-test-utils/src/fakes/crypto.rs:53-66`
- WASM consumer: `crates/auths-verifier/src/wasm.rs:7,18-20`
- Existing tests: `crates/auths-crypto/tests/cases/provider.rs`

#### Pitfalls
- Ed25519 algorithm param is just the string `"Ed25519"` — no hash sub-field
- `importKey` returns a `Promise`, not a `CryptoKey` directly — must await
- `verify` resolves to a JS boolean, extract with `.as_bool().unwrap_or(false)`
- `Uint8Array::from(&pubkey[..])` for passing raw bytes to importKey
- Use `JsCast::unchecked_into()` to cast `JsValue` to `CryptoKey`
## Acceptance
- [ ] `WebCryptoProvider::verify_ed25519()` is implemented (no longer returns TODO error)
- [ ] `auths-crypto` compiles for wasm32: `cd crates/auths-crypto && cargo check --target wasm32-unknown-unknown --no-default-features --features wasm`
- [ ] `RingCryptoProvider` still compiles and all 5 native tests pass: `cargo nextest run -p auths-crypto`
- [ ] `MockCryptoProvider` in `auths-test-utils` still compiles
- [ ] Verifier WASM check passes: `cd crates/auths-verifier && cargo check --target wasm32-unknown-unknown --no-default-features --features wasm`
- [ ] `cargo check --workspace` passes (no cross-crate breakage)
- [ ] No `tokio` or `spawn_blocking` usage in the WASM code path
## Done summary
- Implemented `WebCryptoProvider::verify_ed25519()` using SubtleCrypto importKey + verify
- Added `web-sys`, `js-sys`, `wasm-bindgen`, `wasm-bindgen-futures` as optional deps behind `wasm` feature
- Added conditional `#[async_trait(?Send)]` on wasm32 for `CryptoProvider` trait (JsFuture is !Send)
- Used `js_sys::global()` for Window + Worker context compatibility
- Non-wasm32 fallback returns `CryptoError::OperationFailed` if compiled on native
- WASM compilation verified for both `auths-crypto` and `auths-verifier`
- Native compilation with all features verified
## Evidence
- Commits: 0e0d3ce386a7e61fa61a48ba6ca0d7cfdda4a450
- Tests: cargo check --target wasm32-unknown-unknown --no-default-features --features wasm (auths-crypto), cargo check --target wasm32-unknown-unknown --no-default-features --features wasm (auths-verifier), cargo build -p auths-crypto --all-features
- PRs:
