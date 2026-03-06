# Remaining Items to v0.1.0

Cross-referenced against `v1_launch.md` milestones. Distribution intentionally last.
Last verified: 2026-03-06.

---

## Overview

| Epic | Title | Tasks Remaining | Milestone |
|------|-------|-----------------|-----------|
| ~~HTTP orchestration~~ | ~~Push HTTP from CLI to SDK~~ | ~~**DONE**~~ | — |
| Epic 1 | Code Safety: unwrap/anyhow removal | 6 | $10M — ship blocker |
| Epic 2 | FFI & Mobile Readiness | 9 | $20M — mobile |
| Epic 3 | Distribution & Installation | TBD | last |

**Already done**: `clippy.toml` allowlists, all 4 integration test `#![allow(...)]` headers,
all CLI→SDK HTTP extraction (artifact publish, platform claim, device pairing).

---

## Epic 1 — Code Safety: unwrap/anyhow Removal

**Why**: A single `unwrap()` panic in a Git hook kills a developer's commit mid-push. `anyhow`
in library crates blocks safe FFI error mapping (C callers need integer error codes, see
`crates/auths-verifier/src/ffi.rs`). Required before v0.1.0.

**Scope**: `auths-core`, `auths-verifier`, `auths-id`. `auths-sdk` is already clean.

---

### Task 1.1 — Remove anyhow from auths-core runtime dependencies

**Files**:
- `crates/auths-core/src/api/runtime.rs` (lines 46, 52, 590, 598, 643)
- `crates/auths-core/src/error.rs`
- `crates/auths-core/Cargo.toml` (line 42: `anyhow = "1.0"` in `[dependencies]`)

**Context**: The only production `anyhow` usage in library crates is in
`register_keys_with_macos_agent_internal()` — DER parsing, key conversion, temp file I/O,
and ssh-add execution using `anyhow::Context`, `anyhow::Result`, and `anyhow::bail!`.

**Change**: Add variants to `AgentError` in `crates/auths-core/src/error.rs`:
```rust
#[error("ssh-add execution failed: {0}")]
SshAddFailed(String),
#[error("key conversion failed: {0}")]
KeyConversionFailed(String),
```

Replace anyhow at call sites in `runtime.rs`:
```rust
// before
let key = parse_key(&bytes).context("failed to parse DER key")?;
anyhow::bail!("unsupported key type: {}", key_type);

// after
let key = parse_key(&bytes).map_err(|e| AgentError::KeyConversionFailed(e.to_string()))?;
return Err(AgentError::SshAddFailed(format!("unsupported key type: {}", key_type)));
```

Move `anyhow` from `[dependencies]` to `[dev-dependencies]` in
`crates/auths-core/Cargo.toml`.

**Verify**: `cargo build -p auths-core && cargo nextest run -p auths-core`

---

### Task 1.2 — Fix unwraps in auths-verifier (FFI boundaries)

**Files**:
- `crates/auths-verifier/src/ffi.rs` (line 18: `.expect("FFI: failed to create tokio runtime")`)

**Note**: `wasm.rs` is already clean. `ffi.rs` has one genuine `expect` — it is intentionally
unrecoverable. Annotate rather than change behavior:

```rust
// ffi.rs — inside with_runtime()
// SAFETY: Tokio runtime creation is unrecoverable — process cannot function without it
#[allow(clippy::expect_used)]
static RT: Lazy<Runtime> = Lazy::new(|| {
    Builder::new_current_thread().build().expect("FFI: failed to create tokio runtime")
});
```

**Verify**:
```bash
cargo nextest run -p auths-verifier
cd crates/auths-verifier && cargo check --target wasm32-unknown-unknown --no-default-features --features wasm
```

---

### Task 1.3 — Fix unwraps in auths-id

**Files**:
- `crates/auths-id/src/witness.rs` (structurally guaranteed byte-slice conversions)
- `crates/auths-id/src/keri/incremental.rs` (line 284: `.expect("parent_count was 1")`)

**Pattern — guarded unwraps, eliminate entirely**:
```rust
// resolve.rs — before: starts_with guard then unwrap
if did.starts_with("did:keri:") {
    let suffix = did.strip_prefix("did:keri:").unwrap();
}

// after
if let Some(suffix) = did.strip_prefix("did:keri:") { ... }
```

**Pattern — structurally guaranteed, annotate with SAFETY**:
```rust
// witness.rs — git2::Oid is always 20 bytes
// SAFETY: git2::Oid is always exactly 20 bytes
#[allow(clippy::expect_used)]
let hash: [u8; 20] = oid.as_bytes().try_into().expect("git2::Oid is always 20 bytes");
```

```rust
// keri/incremental.rs:284 — parent_count validated on line ~282
// SAFETY: parent_count checked to be 1 on the line above
#[allow(clippy::expect_used)]
let parent = commit.parent(0).expect("parent_count was 1");
```

**Verify**: `cargo nextest run -p auths-id`

---

### Task 1.4 — Fix mutex lock unwraps in auths-core

**Files**:
- `crates/auths-core/src/config.rs` (lines 18, 24 — `RwLock` read/write unwraps)
- `crates/auths-core/src/signing.rs` — `CachedPassphraseProvider`, `UnifiedPassphraseProvider`
- `crates/auths-core/src/storage/memory.rs` (lines 120, 125, 129, 133, 142, 149, 197, 202, 206, 210, 219, 224, 235)
- `crates/auths-core/src/witness/server.rs` (Axum handlers at lines 487, 539, 560, 571)

**Policy**:
- Methods returning `Result<_, AgentError>` → `.map_err(|_| AgentError::MutexError("context".into()))?`
- Methods returning `()` (cache clear ops) → `.unwrap_or_else(|e| e.into_inner())`
- Axum handlers → return `StatusCode::INTERNAL_SERVER_ERROR` instead of panicking

```rust
// memory.rs — implements KeyStorage which returns Result<_, AgentError>
// before
self.store.lock().unwrap().insert(key, val);

// after
self.store.lock().map_err(|_| AgentError::MutexError("keychain store".into()))?.insert(key, val);
```

```rust
// signing.rs — clear_cache() returning ()
// before
self.cache.lock().unwrap().clear();

// after (best-effort, poisoning not fatal for a cache)
if let Ok(mut cache) = self.cache.lock() { cache.clear(); }
```

```rust
// witness/server.rs — Axum handler
// before
let storage = state.inner.storage.lock().unwrap();

// after
let storage = state.inner.storage.lock()
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
```

**Verify**: `cargo nextest run -p auths-core`

---

### Task 1.5 — Fix remaining unwraps in auths-core (crypto, FFI, witness)

**Files**:
- `crates/auths-core/src/crypto/provider_bridge.rs` (line 19: `.expect("failed to create fallback crypto runtime")`)
- `crates/auths-core/src/crypto/encryption.rs` (lines 256, 258, 260 — byte slice conversions)
- `crates/auths-core/src/crypto/secp256k1.rs` (lines 45, 94)
- `crates/auths-core/src/api/ffi.rs` (line 201: `.expect("FFI string inputs must be valid UTF-8")`)
- `crates/auths-core/src/witness/server.rs` (lines 212, 218, 228, 415 — JSON/signing ops)

**Pattern — static runtime (unrecoverable, annotate)**:
```rust
// provider_bridge.rs:19
// SAFETY: tokio runtime creation is unrecoverable — process cannot function without it
#[allow(clippy::expect_used)]
static FALLBACK_RT: Lazy<Runtime> = Lazy::new(|| {
    Builder::new_current_thread().build().expect("failed to create fallback crypto runtime")
});
```

**Pattern — byte slice after length validation (annotate)**:
```rust
// encryption.rs — length validated upstream
// SAFETY: slice length validated at the call site before this conversion
#[allow(clippy::expect_used)]
let arr: [u8; 4] = bytes[..4].try_into().expect("length validated above");
```

**Pattern — witness server JSON ops (propagate as HTTP 500)**:
```rust
// server.rs — before
let obj = receipt_json.as_object_mut().unwrap();

// after
let obj = receipt_json.as_object_mut()
    .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "receipt serialization failed"))?;
```

**Verify**: `cargo nextest run -p auths-core && cargo clippy -p auths-core --all-targets --all-features -- -D warnings`

---

### Task 1.6 — Enable deny lints in all 4 target crate lib.rs files

**Files**:
- `crates/auths-core/src/lib.rs`
- `crates/auths-verifier/src/lib.rs`
- `crates/auths-sdk/src/lib.rs`
- `crates/auths-id/src/lib.rs`

None of these currently have `#![deny(clippy::unwrap_used)]`. Add to each:
```rust
#![deny(clippy::unwrap_used)]
#![deny(clippy::expect_used)]
```

**Full verification suite**:
```bash
cargo fmt --check --all
cargo clippy --all-targets --all-features -- -D warnings
cargo nextest run --workspace
cargo test --all --doc
cd crates/auths-verifier && cargo check --target wasm32-unknown-unknown --no-default-features --features wasm
```

---

## Epic 2 — FFI & Mobile Readiness

**Why**: Required for the mobile authenticator ($20M milestone). Current blockers:
1. `CryptoProvider` is async-only — no sync path for native FFI without pulling in tokio
2. `AuthsContext` has 9 `Arc<dyn Trait>` fields — can't cross the uniffi boundary
3. `auths-mobile-ffi` duplicates crypto logic instead of depending on `auths-crypto`
4. `RegistryBackend` uses `&mut dyn FnMut` visitors — incompatible with uniffi
5. Key material crosses FFI as hex `String` — can't zeroize after handoff to Swift/Kotlin
6. `SystemTime::now()` called directly in FFI code — violates clock injection rule

**Target architecture**:
```
Mobile App (Swift/Kotlin)
    | uniffi callback_interface (keychain, passphrase)
    v
auths-ffi  (unified crate, uniffi 0.31)
    | concrete types, sync calls
    v
auths-sdk  (AuthsContext with injected impls)
    v
auths-core (sync crypto via SyncCryptoProvider)
    v
auths-crypto (RingCryptoProvider implements SyncCryptoProvider)
```

---

### Task 2.1 — Add SyncCryptoProvider trait to auths-crypto

**File**: `crates/auths-crypto/src/provider.rs`

`CryptoProvider` (line 85–138) is `async_trait` because `WebCryptoProvider` (WASM) needs
async. `RingCryptoProvider` wraps synchronous `ring` calls in async — pure overhead on
native targets.

Add a sync mirror trait:
```rust
// crates/auths-crypto/src/provider.rs
pub trait SyncCryptoProvider: Send + Sync {
    fn sign(&self, key: &[u8], msg: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn verify(&self, pk: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), CryptoError>;
    fn generate_keypair(&self) -> Result<KeyPair, CryptoError>;
    // mirror remaining CryptoProvider methods without async
}

impl SyncCryptoProvider for RingCryptoProvider {
    // trivial — ring calls are already sync; the async impl just wraps them
}
```

Keep `CryptoProvider` (async) unchanged. Update `provider_bridge.rs` to use
`SyncCryptoProvider` directly when available, bypassing the `FALLBACK_RT` / `block_in_place`
pattern.

**Verify**: `cargo check -p auths-crypto && cargo check -p auths-crypto --no-default-features`

---

### Task 2.2 — Feature-gate tokio in auths-core

**File**: `crates/auths-core/Cargo.toml` (line 29: `tokio = { version = "1", features = ["full"] }`)

`tokio` is a hard unconditional dependency — adds ~1–3MB to the iOS binary for functionality
mobile never uses. Current `[features]`: `default`, `test-utils`, `keychain-*`,
`crypto-secp256k1`, `keychain-pkcs11`, `witness-server`, `tls`. No `async-runtime` exists.

Add it:
```toml
[features]
default = ["async-runtime"]
async-runtime = ["dep:tokio"]

[dependencies]
tokio = { version = "1", features = ["full"], optional = true }
```

Gate these modules behind `#[cfg(feature = "async-runtime")]`:
- `crates/auths-core/src/crypto/provider_bridge.rs` — `FALLBACK_RT`, `block_in_place`
- `crates/auths-core/src/storage/linux_secret_service.rs` — `tokio::task::block_in_place`
- `crates/auths-core/src/storage/passphrase_cache.rs` (lines 364–459) — `block_in_place`

All existing consumers (`auths-sdk`, `auths-cli`, `auths-id`) continue working unchanged
(default features are on). Mobile FFI depends on `auths-core` with `default-features = false`.

**Verify**:
```bash
cargo check -p auths-core --no-default-features
cargo nextest run -p auths-core   # default features must still pass
```

---

### Task 2.3 — Eliminate crypto duplication in auths-mobile-ffi

**File**: `crates/auths-mobile-ffi/src/lib.rs` (148 lines, own `[workspace]`)

Currently reimplements Ed25519 key generation, signing, SAID computation, and DID generation
using raw `ring` (pinned at line 30 of its `Cargo.toml`) — all duplicated from `auths-crypto`.

```toml
# crates/auths-mobile-ffi/Cargo.toml — replace ring with auths-crypto
[dependencies]
auths-crypto = { path = "../../crates/auths-crypto", default-features = false, features = ["native"] }
# remove: ring = "0.17.14"
```

Replace duplicated operations with `RingCryptoProvider`'s `SyncCryptoProvider` impl. Keep
`IcpEvent` and KERI serialization logic (check if `auths-id` exports equivalents first).

**Verify**:
```bash
cd crates/auths-mobile-ffi && cargo check
cargo check --target aarch64-apple-ios
```

---

### Task 2.4 — Create FFI-safe facade types and RegistryBackend adapter

**Files**:
- `crates/auths-id/src/storage/registry/backend.rs` (lines 293–379) — `RegistryBackend` with
  `&mut dyn FnMut` visitors (incompatible with uniffi)
- `crates/auths-sdk/src/context.rs` (lines 92–114) — `AuthsContext` with 9 `Arc<dyn Trait>`
  fields (can't cross FFI boundary)

Wrap `RegistryBackend` with `Vec<T>` returns:
```rust
pub struct SimpleRegistryAdapter<B: RegistryBackend>(B);

impl<B: RegistryBackend> SimpleRegistryAdapter<B> {
    pub fn list_events(&self) -> Vec<Event> { ... }       // replaces visit_events(FnMut)
    pub fn list_devices(&self) -> Vec<DeviceInfo> { ... } // replaces visit_devices(FnMut)
    pub fn list_identities(&self) -> Vec<IdentityInfo> { ... }
}
```

Create `MobileContext` — concrete, uniffi-exportable:
```rust
#[derive(uniffi::Object)]
pub struct MobileContext {
    inner: Arc<Mutex<AuthsContext>>,  // not exposed across FFI
}

#[uniffi::export]
impl MobileContext {
    #[uniffi::constructor]
    pub fn new(config: MobileConfig, key_storage: Arc<dyn MobileKeyStorage>) -> Self;
    pub fn current_identity(&self) -> Result<IdentityInfo, MobileError>;
    pub fn sign_bytes(&self, data: Vec<u8>) -> Result<Vec<u8>, MobileError>;
}
```

Create `MobileVerifier` (sync):
```rust
#[derive(uniffi::Object)]
pub struct MobileVerifier;

#[uniffi::export]
impl MobileVerifier {
    pub fn verify_attestation(&self, json: Vec<u8>, pk: Vec<u8>) -> Result<VerificationReport, MobileError>;
    pub fn verify_chain(&self, chain_json: Vec<u8>, root_pk: Vec<u8>) -> Result<ChainReport, MobileError>;
}
```

All types crossing the boundary: `#[derive(uniffi::Record)]` with only primitives, `String`,
`Vec<u8>`, `Option<T>`, `Vec<T>`.

---

### Task 2.5 — Add uniffi callback_interfaces for platform keychain and passphrase

**Files**:
- `crates/auths-core/src/storage/keychain.rs` (lines 152–181) — `KeyStorage` trait
- `crates/auths-core/src/signing.rs` (lines 158–179) — `PassphraseProvider` trait
- `crates/auths-core/src/storage/android_keystore.rs` — current stub (returns errors)

```rust
// in auths-ffi — iOS uses Security.framework, Android uses Keystore
#[uniffi::export(with_foreign)]
pub trait MobileKeyStorage: Send + Sync {
    fn store_key(&self, identifier: String, key_data: Vec<u8>) -> Result<(), MobileError>;
    fn load_key(&self, identifier: String) -> Result<Vec<u8>, MobileError>;
    fn delete_key(&self, identifier: String) -> Result<(), MobileError>;
    fn has_key(&self, identifier: String) -> Result<bool, MobileError>;
}

#[uniffi::export(with_foreign)]
pub trait MobilePassphraseProvider: Send + Sync {
    fn get_passphrase(&self, prompt: String) -> Result<String, MobileError>;
}
```

Create Rust adapter structs that implement the core `KeyStorage` and `PassphraseProvider`
traits by delegating to the callback interfaces. Wire into `MobileContext::new()`.

---

### Task 2.6 — Unify FFI crates and upgrade to uniffi 0.31

**Current state** (two separate crates, both excluded from workspace, both on uniffi 0.28):
- `crates/auths-mobile-ffi/` — identity, signing, pairing
- `packages/auths-verifier-swift/` — verification only

Linking both in one app risks duplicate `ring`/`blake3` symbols at link time.

Create `crates/auths-ffi/`:
```toml
[lib]
crate-type = ["lib", "staticlib", "cdylib"]

[dependencies]
uniffi = { version = "0.31", features = ["build"] }
auths-crypto  = { path = "../auths-crypto", default-features = false, features = ["native"] }
auths-core    = { path = "../auths-core", default-features = false }
auths-verifier = { path = "../auths-verifier", default-features = false }
```

Key migration: `UniffiCustomTypeConverter` → `custom_type!` macro (breaking in uniffi 0.29).
Verify generated Swift 5.9+ and Kotlin 1.9+ bindings compile.

Update build scripts from `packages/auths-verifier-swift/`:
`build-swift.sh`, `build-xcframework.sh`, `build-android.sh` → point to `crates/auths-ffi/`.

Deprecate old crates with README noting migration path.

---

### Task 2.7 — Harden zeroization at FFI boundaries

**File**: `crates/auths-mobile-ffi/src/lib.rs`

Private key material currently crosses FFI as hex `String`:
- `IdentityResult.current_key_pkcs8_hex: String` (line 73) — private key
- `IdentityResult.next_key_pkcs8_hex: String` (line 75) — pre-rotated private key

Once in Swift/Kotlin as a `String`, Rust cannot zeroize it. Replace with opaque handles:

```rust
#[derive(uniffi::Record)]
pub struct KeyHandle { pub id: u64 }

static KEY_STORE: Lazy<Mutex<HashMap<u64, Zeroizing<Vec<u8>>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

// before: create_identity() -> IdentityResult { current_key_pkcs8_hex: String }
// after:  create_identity() -> IdentityResult { key_handle: KeyHandle }

pub fn sign_with_handle(handle: KeyHandle, data: Vec<u8>) -> Result<Vec<u8>, MobileError>;

// SAFETY: after export, Rust can no longer guarantee zeroization
pub fn export_key(handle: KeyHandle) -> Result<Vec<u8>, MobileError>;

pub fn release_key(handle: KeyHandle);
pub fn drop_all_keys();  // call on app background / logout
```

---

### Task 2.8 — Fix clock injection violations in FFI code

**File**: `crates/auths-mobile-ffi/src/lib.rs` (line 677)

`complete_pairing()` calls `std::time::SystemTime::now()` directly — violates CLAUDE.md
("Never add `Utc::now()` to domain or core logic — inject it instead").

```rust
// before
let now_unix = std::time::SystemTime::now()
    .duration_since(std::time::UNIX_EPOCH)...;

// after — FFI caller injects current time (consistent with CLI boundary pattern)
pub fn complete_pairing(
    session_id: String,
    response: PairingResponsePayload,
    now_unix_secs: u64,
) -> Result<(), MobileError>;
```

Audit the unified `auths-ffi` crate for any remaining `SystemTime::now()` or `Utc::now()`
calls before marking done.

---

### Task 2.9 — Add CI for FFI cross-compilation and binary size tracking

**File**: `.github/workflows/ci.yml`

`auths-mobile-ffi` and `auths-verifier-swift` are currently excluded from the workspace and
have no CI coverage — drift is undetectable.

Add job (macOS runner):
```yaml
ffi-cross-compile:
  runs-on: macos-latest
  steps:
    - uses: actions/checkout@v4
    - run: rustup target add aarch64-apple-ios aarch64-apple-ios-sim
    - run: cargo check --target aarch64-apple-ios --manifest-path crates/auths-ffi/Cargo.toml
    - run: cargo check --target aarch64-apple-ios-sim --manifest-path crates/auths-ffi/Cargo.toml
    - run: cargo test --manifest-path crates/auths-ffi/Cargo.toml
    - name: Binary size check
      run: |
        cargo build --release --target aarch64-apple-ios --manifest-path crates/auths-ffi/Cargo.toml
        SIZE=$(stat -f%z target/aarch64-apple-ios/release/libauths_ffi.a)
        echo "FFI staticlib size: ${SIZE} bytes"
        [ "$SIZE" -lt 5242880 ] || (echo "FAIL: exceeds 5MB threshold" && exit 1)
    - run: cargo install cargo-ndk
    - run: cargo ndk -t arm64-v8a check --manifest-path crates/auths-ffi/Cargo.toml
```

---

## Epic 3 — Distribution & Installation

**Held until all code is working and stable.**

| Task | Description |
|------|-------------|
| 3.1 | Set up `cargo dist` release workflow (Linux x86_64/aarch64, macOS aarch64, Windows x86_64) |
| 3.2 | Homebrew formula and tap (`brew install auths-dev/tap/auths`) |
| 3.3 | Publish `auths-verifier` to crates.io (`#[non_exhaustive]` on public enums first) |
| 3.4 | Publish `auths-python` to PyPI via `maturin publish` |
| 3.5 | Publish `@auths/verifier` WASM bundle to npm |
| 3.6 | Wire release workflow into GitHub Actions — tag push triggers all publishes |
| 3.7 | Bump version from `0.0.1-rc.7` to `0.1.0` across workspace |

---

## Recommended Order

```
Epic 1 (code safety, 6 tasks)  →  Epic 2 (FFI/mobile, 9 tasks)  →  Epic 3 (distribution)
```

Epic 1 must land before Epic 2 — the FFI crate needs panic-free library crates underneath it.
Epic 3 is gated on both above being done.
