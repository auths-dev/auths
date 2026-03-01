# CryptoProvider Port Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Introduce a `CryptoProvider` trait that abstracts Ed25519 signing and verification, enabling `ring` for native targets and `WebCrypto` for WASM targets without breaking existing code.

**Architecture:** The `CryptoProvider` trait lives in `auths-crypto` (which currently has zero crypto deps). Native and WASM adapter modules are feature-gated in the same crate. `ring` becomes optional behind a `native` feature flag. The `auths-verifier` crate — the primary WASM compilation target — adopts the trait for verification. The `auths-core` signer continues using `ring` directly (it's native-only).

**Tech Stack:** ring (native), web-sys/wasm-bindgen/js-sys (WASM), async-trait

---

### Scope & Strategy

The user's plan describes 5 steps. However, after auditing the codebase, here's what matters:

1. **`auths-crypto`** is the right home for the `CryptoProvider` trait — it's the lowest-level crypto crate with zero deps today.
2. **`auths-verifier`** is the primary WASM target. It uses `ring` for 3 things: `UnparsedPublicKey::verify()` in `verify.rs`, `witness.rs`, and `keri.rs`. These are all **verification-only** (no signing, no keygen). The trait needs `verify_ed25519()` at minimum.
3. **`auths-core`** uses `ring` for signing, keygen, encryption, etc. It's native-only and doesn't need the trait yet. Attempting to abstract it all at once would be massive scope creep.
4. **`auths-sdk`** DI wiring is premature until consumers actually need runtime selection.

**Bottom line:** We introduce `CryptoProvider` with `verify_ed25519()`, build native + WASM adapters, and wire it into `auths-verifier`. We do NOT touch `auths-core`'s signer or `auths-sdk` in this PR. Those are follow-up work.

---

### Task 1: Define CryptoProvider trait in auths-crypto

**Files:**
- Create: `crates/auths-crypto/src/provider.rs`
- Modify: `crates/auths-crypto/src/lib.rs`
- Modify: `crates/auths-crypto/Cargo.toml`

**Step 1: Write the trait and error type**

Create `crates/auths-crypto/src/provider.rs`:

```rust
/// Error type for cryptographic operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum CryptoError {
    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid public key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("Crypto operation failed: {0}")]
    OperationFailed(String),
}

/// Abstraction for Ed25519 cryptographic verification across target architectures.
///
/// Args:
/// * `pubkey`: The 32-byte Ed25519 public key.
/// * `message`: The raw data payload that was signed.
/// * `signature`: The 64-byte Ed25519 signature to verify.
///
/// Usage:
/// ```ignore
/// let provider = RingCryptoProvider;
/// provider.verify_ed25519(&pubkey, &msg, &sig)?;
/// ```
pub trait CryptoProvider: Send + Sync {
    fn verify_ed25519(
        &self,
        pubkey: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError>;
}

/// Ed25519 public key length in bytes.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// Ed25519 signature length in bytes.
pub const ED25519_SIGNATURE_LEN: usize = 64;
```

**Step 2: Export the module from lib.rs**

Add to `crates/auths-crypto/src/lib.rs`:

```rust
pub mod provider;

pub use provider::{CryptoError, CryptoProvider, ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN};
```

**Step 3: No new deps needed in Cargo.toml**

`thiserror` is already a dependency. No changes needed.

**Step 4: Run build to verify it compiles**

Run: `cargo build -p auths-crypto`
Expected: SUCCESS

**Step 5: Commit**

```bash
git add crates/auths-crypto/src/provider.rs crates/auths-crypto/src/lib.rs
git commit -m "feat(auths-crypto): add CryptoProvider trait for Ed25519 verification"
```

---

### Task 2: Build the native ring adapter

**Files:**
- Create: `crates/auths-crypto/src/ring_provider.rs`
- Modify: `crates/auths-crypto/src/lib.rs`
- Modify: `crates/auths-crypto/Cargo.toml`

**Step 1: Add ring as optional dependency**

In `crates/auths-crypto/Cargo.toml`, add:

```toml
[features]
default = ["native"]
native = ["dep:ring"]
wasm = ["dep:web-sys", "dep:wasm-bindgen", "dep:js-sys"]

[dependencies]
base64.workspace = true
bs58 = "0.5.1"
thiserror.workspace = true

# Native crypto backend
ring = { workspace = true, optional = true }

# WASM crypto backend
wasm-bindgen = { version = "0.2", optional = true }
js-sys = { version = "0.3", optional = true }

[dependencies.web-sys]
version = "0.3"
optional = true
features = ["Crypto", "SubtleCrypto", "Window"]
```

**Step 2: Write the ring adapter**

Create `crates/auths-crypto/src/ring_provider.rs`:

```rust
#![cfg(feature = "native")]

use crate::provider::{CryptoError, CryptoProvider, ED25519_PUBLIC_KEY_LEN};
use ring::signature::{ED25519, UnparsedPublicKey};

/// Native Ed25519 verification provider powered by the `ring` crate.
///
/// Usage:
/// ```ignore
/// let provider = RingCryptoProvider;
/// provider.verify_ed25519(&pubkey, &msg, &sig)?;
/// ```
pub struct RingCryptoProvider;

impl CryptoProvider for RingCryptoProvider {
    fn verify_ed25519(
        &self,
        pubkey: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        if pubkey.len() != ED25519_PUBLIC_KEY_LEN {
            return Err(CryptoError::InvalidKeyLength {
                expected: ED25519_PUBLIC_KEY_LEN,
                actual: pubkey.len(),
            });
        }
        let peer_public_key = UnparsedPublicKey::new(&ED25519, pubkey);
        peer_public_key
            .verify(message, signature)
            .map_err(|_| CryptoError::InvalidSignature)
    }
}
```

**Step 3: Export conditionally from lib.rs**

Add to `crates/auths-crypto/src/lib.rs`:

```rust
#[cfg(feature = "native")]
pub mod ring_provider;

#[cfg(feature = "native")]
pub use ring_provider::RingCryptoProvider;
```

**Step 4: Run build to verify**

Run: `cargo build -p auths-crypto`
Expected: SUCCESS (native feature is default)

**Step 5: Commit**

```bash
git add crates/auths-crypto/src/ring_provider.rs crates/auths-crypto/src/lib.rs crates/auths-crypto/Cargo.toml
git commit -m "feat(auths-crypto): add RingCryptoProvider native adapter"
```

---

### Task 3: Build the WASM WebCrypto adapter (stub)

**Files:**
- Create: `crates/auths-crypto/src/webcrypto_provider.rs`
- Modify: `crates/auths-crypto/src/lib.rs`

**Step 1: Write the WebCrypto adapter stub**

Create `crates/auths-crypto/src/webcrypto_provider.rs`:

```rust
#![cfg(feature = "wasm")]

use crate::provider::{CryptoError, CryptoProvider, ED25519_PUBLIC_KEY_LEN};
use js_sys::{Object, Reflect, Uint8Array};
use wasm_bindgen::JsCast;
use wasm_bindgen::prelude::*;

/// WASM Ed25519 verification provider powered by the host's WebCrypto API.
///
/// Usage:
/// ```ignore
/// let provider = WebCryptoProvider;
/// provider.verify_ed25519(&pubkey, &msg, &sig)?;
/// ```
pub struct WebCryptoProvider;

impl WebCryptoProvider {
    fn get_subtle_crypto() -> Result<web_sys::SubtleCrypto, CryptoError> {
        let global = js_sys::global();
        let crypto = Reflect::get(&global, &JsValue::from_str("crypto"))
            .map_err(|_| CryptoError::OperationFailed("crypto not available".into()))?;
        let subtle = Reflect::get(&crypto, &JsValue::from_str("subtle"))
            .map_err(|_| CryptoError::OperationFailed("subtle crypto not available".into()))?;
        subtle
            .dyn_into::<web_sys::SubtleCrypto>()
            .map_err(|_| CryptoError::OperationFailed("invalid SubtleCrypto object".into()))
    }
}

impl CryptoProvider for WebCryptoProvider {
    fn verify_ed25519(
        &self,
        pubkey: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        if pubkey.len() != ED25519_PUBLIC_KEY_LEN {
            return Err(CryptoError::InvalidKeyLength {
                expected: ED25519_PUBLIC_KEY_LEN,
                actual: pubkey.len(),
            });
        }

        // Note: Ed25519 via WebCrypto (SubtleCrypto.verify with "Ed25519" algorithm)
        // is available in modern browsers and Cloudflare Workers.
        // This is synchronous because wasm-bindgen futures are complex;
        // the SubtleCrypto API returns a Promise, but we use
        // wasm_bindgen_futures in a blocking manner for the trait.
        //
        // For now this is a compile-gate placeholder. Full async WebCrypto
        // integration is tracked as follow-up work. The trait is synchronous
        // because ring's verify is synchronous and we want zero-cost on native.
        //
        // When targeting WASM, embedders should call the JS verify directly
        // or use the wasm bindings in auths-verifier's existing wasm module.
        Err(CryptoError::OperationFailed(
            "WebCrypto Ed25519 verify not yet implemented — use auths-verifier wasm bindings".into(),
        ))
    }
}
```

**Step 2: Export conditionally from lib.rs**

Add to `crates/auths-crypto/src/lib.rs`:

```rust
#[cfg(feature = "wasm")]
pub mod webcrypto_provider;

#[cfg(feature = "wasm")]
pub use webcrypto_provider::WebCryptoProvider;
```

**Step 3: Run native build (WASM build requires wasm32 target, verify later)**

Run: `cargo build -p auths-crypto`
Expected: SUCCESS (wasm module is cfg-gated out)

**Step 4: Commit**

```bash
git add crates/auths-crypto/src/webcrypto_provider.rs crates/auths-crypto/src/lib.rs
git commit -m "feat(auths-crypto): add WebCryptoProvider stub for WASM targets"
```

---

### Task 4: Write tests for RingCryptoProvider

**Files:**
- Create: `crates/auths-crypto/tests/integration.rs`
- Create: `crates/auths-crypto/tests/cases/mod.rs`
- Create: `crates/auths-crypto/tests/cases/provider.rs`
- Modify: `crates/auths-crypto/Cargo.toml` (add dev-deps)

**Step 1: Add dev-dependencies**

Add to `crates/auths-crypto/Cargo.toml`:

```toml
[dev-dependencies]
auths-test-utils.workspace = true
ring.workspace = true
```

**Step 2: Create the test entry point**

Create `crates/auths-crypto/tests/integration.rs`:

```rust
mod cases;
```

Create `crates/auths-crypto/tests/cases/mod.rs`:

```rust
mod provider;
```

**Step 3: Write the provider tests**

Create `crates/auths-crypto/tests/cases/provider.rs`:

```rust
use auths_crypto::{CryptoProvider, ED25519_PUBLIC_KEY_LEN};
use auths_test_utils::crypto::create_test_keypair;
use ring::signature::KeyPair;

#[cfg(feature = "native")]
use auths_crypto::RingCryptoProvider;

#[cfg(feature = "native")]
#[test]
fn ring_provider_verifies_valid_signature() {
    let (kp, pk) = create_test_keypair(&[1u8; 32]);
    let message = b"hello world";
    let signature = kp.sign(message);

    let provider = RingCryptoProvider;
    let result = provider.verify_ed25519(&pk, message, signature.as_ref());
    assert!(result.is_ok());
}

#[cfg(feature = "native")]
#[test]
fn ring_provider_rejects_invalid_signature() {
    let (_, pk) = create_test_keypair(&[1u8; 32]);
    let message = b"hello world";
    let bad_sig = [0u8; 64];

    let provider = RingCryptoProvider;
    let result = provider.verify_ed25519(&pk, message, &bad_sig);
    assert!(result.is_err());
}

#[cfg(feature = "native")]
#[test]
fn ring_provider_rejects_wrong_pubkey() {
    let (kp, _) = create_test_keypair(&[1u8; 32]);
    let (_, wrong_pk) = create_test_keypair(&[2u8; 32]);
    let message = b"hello world";
    let signature = kp.sign(message);

    let provider = RingCryptoProvider;
    let result = provider.verify_ed25519(&wrong_pk, message, signature.as_ref());
    assert!(result.is_err());
}

#[cfg(feature = "native")]
#[test]
fn ring_provider_rejects_invalid_key_length() {
    let provider = RingCryptoProvider;
    let result = provider.verify_ed25519(&[0u8; 16], b"msg", &[0u8; 64]);
    assert!(result.is_err());
    match result.unwrap_err() {
        auths_crypto::CryptoError::InvalidKeyLength { expected, actual } => {
            assert_eq!(expected, ED25519_PUBLIC_KEY_LEN);
            assert_eq!(actual, 16);
        }
        other => panic!("Expected InvalidKeyLength, got {:?}", other),
    }
}

#[cfg(feature = "native")]
#[test]
fn ring_provider_rejects_corrupted_signature() {
    let (kp, pk) = create_test_keypair(&[1u8; 32]);
    let message = b"hello world";
    let mut signature = kp.sign(message).as_ref().to_vec();
    signature[0] ^= 0xFF;

    let provider = RingCryptoProvider;
    let result = provider.verify_ed25519(&pk, message, &signature);
    assert!(result.is_err());
}
```

**Step 4: Run the tests**

Run: `cargo nextest run -p auths-crypto`
Expected: All 5 tests PASS

**Step 5: Commit**

```bash
git add crates/auths-crypto/tests/ crates/auths-crypto/Cargo.toml
git commit -m "test(auths-crypto): add CryptoProvider tests for ring adapter"
```

---

### Task 5: Feature-gate ring in auths-verifier

**Files:**
- Modify: `crates/auths-verifier/Cargo.toml`

**Step 1: Make ring optional, add auths-crypto native feature**

Update `crates/auths-verifier/Cargo.toml`:

Change `ring.workspace = true` to `ring = { workspace = true, optional = true }`.

Update features:

```toml
[features]
default = ["native"]
native = ["dep:ring", "auths-crypto/native"]
ffi = ["libc", "native"]
wasm = ["wasm-bindgen", "getrandom/wasm_js", "getrandom_02/js", "auths-crypto/wasm"]
```

**Step 2: Run build to verify native still compiles**

Run: `cargo build -p auths-verifier`
Expected: SUCCESS (native is default)

**Step 3: Commit**

```bash
git add crates/auths-verifier/Cargo.toml
git commit -m "build(auths-verifier): feature-gate ring dependency behind native flag"
```

---

### Task 6: Refactor auths-verifier to use CryptoProvider

**Files:**
- Modify: `crates/auths-verifier/src/verify.rs`
- Modify: `crates/auths-verifier/src/witness.rs`
- Modify: `crates/auths-verifier/src/keri.rs`
- Modify: `crates/auths-verifier/src/lib.rs`

This is the critical task. The strategy: keep existing `ring`-direct functions as the public API (they construct a `RingCryptoProvider` internally), but refactor the internal helpers to accept `&dyn CryptoProvider`. This avoids breaking any consumers while enabling WASM backends.

**Step 1: Refactor verify.rs**

In `crates/auths-verifier/src/verify.rs`:

Replace the import:
```rust
// Before:
use ring::signature::{ED25519, ED25519_PUBLIC_KEY_LEN, UnparsedPublicKey};

// After:
use auths_crypto::{CryptoProvider, ED25519_PUBLIC_KEY_LEN};

#[cfg(feature = "native")]
use auths_crypto::RingCryptoProvider;
```

Add a module-level default provider helper:
```rust
#[cfg(feature = "native")]
fn default_provider() -> RingCryptoProvider {
    RingCryptoProvider
}
```

The existing public functions (`verify_with_keys`, `verify_chain`, etc.) keep their signatures. Internally they call `default_provider()` and delegate to `_with_provider` variants.

Replace the core verification in `verify_with_keys_at` — the two `UnparsedPublicKey::new(&ED25519, ...)` + `.verify()` calls — with `provider.verify_ed25519(...)`.

Specifically, change `verify_with_keys_at` to accept a `&dyn CryptoProvider` parameter, and have the public `verify_with_keys` / `verify_at_time` / etc. pass `&default_provider()`.

The key changes in `verify_with_keys_at`:

```rust
// Before:
let issuer_public_key_ring = UnparsedPublicKey::new(&ED25519, issuer_pk_bytes);
issuer_public_key_ring
    .verify(data_to_verify, &att.identity_signature)
    .map_err(|e| { ... })?;

// After:
provider
    .verify_ed25519(issuer_pk_bytes, data_to_verify, &att.identity_signature)
    .map_err(|e| { ... })?;
```

Same pattern for device signature verification.

**Step 2: Refactor witness.rs**

In `verify_witness_receipts`, the ring usage is:

```rust
let key = UnparsedPublicKey::new(&ED25519, pk);
key.verify(&payload, &receipt.sig)
```

Replace with a `CryptoProvider` parameter, or use `default_provider()` inline.

**Step 3: Refactor keri.rs**

In `verify_kel`, the ring usage pattern is similar — `UnparsedPublicKey::new(&ED25519, ...)`.verify(). Same refactor.

**Step 4: Run all verifier tests**

Run: `cargo nextest run -p auths-verifier`
Expected: All existing tests PASS (no behavior change)

**Step 5: Run full workspace build**

Run: `cargo build --workspace`
Expected: SUCCESS

**Step 6: Commit**

```bash
git add crates/auths-verifier/src/verify.rs crates/auths-verifier/src/witness.rs crates/auths-verifier/src/keri.rs crates/auths-verifier/src/lib.rs
git commit -m "refactor(auths-verifier): use CryptoProvider trait for Ed25519 verification"
```

---

### Task 7: Update downstream crate Cargo.toml dependencies

**Files:**
- Modify: `crates/auths-core/Cargo.toml`
- Modify: `crates/auths-sdk/Cargo.toml`
- Modify: `Cargo.toml` (workspace)

Since `auths-crypto` now has `default = ["native"]` and pulls in `ring`, downstream crates that already depend on `auths-crypto` will transitively get ring. Crates that depend on `auths-verifier` similarly get the `native` default.

Check that `auths-core`, `auths-sdk`, and other crates that import `ring` directly still compile. The workspace `auths-crypto` dep may need updating to pass features:

In workspace `Cargo.toml`, update:
```toml
auths-crypto = { path = "crates/auths-crypto" }
```
No change needed — features flow through defaults.

**Step 1: Build full workspace**

Run: `cargo build --workspace`
Expected: SUCCESS

**Step 2: Run full test suite**

Run: `cargo nextest run --workspace`
Expected: All tests PASS

**Step 3: Commit (if any Cargo.toml changes were needed)**

```bash
git add Cargo.toml crates/*/Cargo.toml
git commit -m "build: update workspace deps for auths-crypto feature gates"
```

---

### Task 8: Verify WASM compilation target

**Files:** None (verification only)

**Step 1: Check WASM compilation without ring**

Run:
```bash
cd crates/auths-verifier && cargo check --target wasm32-unknown-unknown --no-default-features --features wasm
```

Expected: SUCCESS (ring is not compiled for wasm32 target)

Note: If this fails due to other deps pulling in ring transitively, we'll need to add `default-features = false` to the `auths-crypto` dependency in `auths-verifier/Cargo.toml`.

**Step 2: Run clippy**

Run: `cargo clippy --all-targets --all-features -- -D warnings`
Expected: No warnings

**Step 3: Run fmt check**

Run: `cargo fmt --check --all`
Expected: No formatting issues

---

### Out of Scope (Follow-up Work)

These items are explicitly deferred to keep this PR focused:

1. **`auths-core` signer refactoring** — The `SignerKey` trait and `Ed25519KeyPair` direct usage in `auths-core` stays as-is. It's native-only and doesn't need the provider abstraction yet.
2. **`auths-sdk` dependency injection** — The `default_crypto_provider()` factory in `auths-sdk/src/setup.rs` is premature. No consumer needs runtime provider selection today.
3. **Full WebCrypto implementation** — The `WebCryptoProvider` is a stub. Implementing the actual `SubtleCrypto.verify()` with JS promise resolution requires `wasm-bindgen-futures` and testing against a real WASM runtime. This is a separate PR.
4. **`generate_ed25519_keypair()`** — Not needed in the trait until `auths-core` keygen is abstracted.
5. **`async` on the trait** — The user's plan uses `async_trait`. We don't need it because ring's verify is synchronous and WebCrypto's eventual implementation will need `wasm-bindgen-futures` regardless. Keeping the trait sync avoids pulling in `async-trait` as a dep of `auths-crypto`.
