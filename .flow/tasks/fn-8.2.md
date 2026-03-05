# fn-8.2 Seal public API surface of auths-core

## Description

## Seal public API surface of auths-core

`crates/auths-core/src/lib.rs:80-85` has three wildcard re-exports that leak internal types:

```rust
pub use api::*;      // Exports FFI functions (unsafe C ABI) at crate root
pub use config::*;   // Exports config types and global-state functions
pub use storage::*;  // Exports all platform keychain structs
```

Grep confirms zero downstream usages of any of these via the short `auths_core::` path — everything used downstream is already explicitly imported via module-qualified paths.

### Changes required

#### 1. Remove wildcard re-exports from `lib.rs:80-85`

Delete:
```rust
pub use api::*;
pub use config::*;
pub use storage::*;
```

No explicit replacements needed — downstream code already uses module-qualified imports like `auths_core::storage::keychain::KeyAlias`, `auths_core::config::EnvironmentConfig`, etc.

#### 2. Make platform keychain structs `pub(crate)` in `storage/mod.rs`

At `crates/auths-core/src/storage/mod.rs:17-29`, change the platform-specific re-exports from `pub use` to `pub(crate) use`:

```rust
// Before:
pub use macos_keychain::MacOSKeychain;
pub use windows_credential::WindowsCredentialStorage;
pub use android_keystore::AndroidKeystoreStorage;
pub use ios_keychain::IOSKeychain;

// After:
pub(crate) use macos_keychain::MacOSKeychain;
pub(crate) use windows_credential::WindowsCredentialStorage;
pub(crate) use android_keystore::AndroidKeystoreStorage;
pub(crate) use ios_keychain::IOSKeychain;
```

Keep these public (they are used downstream):
- `KeyStorage` trait
- `get_platform_keychain()` / `get_platform_keychain_with_config()`
- `KeyAlias`, `IdentityDID`
- `MemoryStorage` / `MemoryKeychainHandle` / `MEMORY_KEYCHAIN` (used in SDK tests)
- `EncryptedFileStorage` (may be used by file-fallback feature consumers)

#### 3. Validate no downstream breakage

Run `cargo check --workspace` and `cargo nextest run --workspace` to confirm nothing breaks.

#### Key references
- `crates/auths-core/src/lib.rs:80-85` — wildcard re-exports to remove
- `crates/auths-core/src/storage/mod.rs:17-29` — platform struct re-exports to restrict
- `crates/auths-core/src/storage/keychain.rs:230-257` — `get_platform_keychain()` (stays public)
- `crates/auths-core/src/api/mod.rs:7-8` — `pub use ffi::*` and `pub use runtime::*` (out of scope for this task)

#### Out of scope
- Sealing sub-wildcards inside `api/mod.rs` (separate task)
- Gating `memory` module behind `test-utils` feature
- `KeriSequence` visibility (confirmed as legitimate public type)
- `IdentityDID` double-path cleanup (tracked as v1_launch Task 0.3)
## Acceptance
- [ ] `pub use api::*`, `pub use config::*`, `pub use storage::*` removed from `auths-core/src/lib.rs`
- [ ] Platform keychain structs (`MacOSKeychain`, `WindowsCredentialStorage`, `AndroidKeystoreStorage`, `IOSKeychain`) are `pub(crate)` in `storage/mod.rs`
- [ ] `cargo check --workspace` passes (no downstream breakage)
- [ ] `cargo nextest run --workspace` passes
- [ ] `get_platform_keychain()` and `KeyStorage` trait remain publicly accessible via `auths_core::storage::keychain::`
- [ ] `MemoryStorage` / `MemoryKeychainHandle` remain publicly accessible for test consumers
## Done summary
- Removed `pub use api::*`, `pub use config::*`, `pub use storage::*` from `auths-core/src/lib.rs`
- Made platform keychain structs `pub(crate)` in `storage/mod.rs`: MacOSKeychain, IOSKeychain, AndroidKeystoreStorage, LinuxSecretServiceStorage, WindowsCredentialStorage
- Kept public: KeyStorage, EncryptedFileStorage, MemoryStorage (used downstream)
- Verified no downstream breakage in auths-core, auths-cli, auths-sdk
## Evidence
- Commits: 131a16cb9f80c7a39d3176146745281edce1eb9e
- Tests: cargo build -p auths-core --all-features, cargo build -p auths-cli, cargo build -p auths-sdk
- PRs:
