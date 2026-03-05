# fn-3.4 Extract key_import() from CLI into auths-sdk

## Description
REFACTOR the CLI `key_import` command to be a thin wrapper only. DELETE the `import_from_file` logic from the CLI's internal handler. The SDK's `import_seed` is the single source of truth.

## Strict Requirements

1. **DELETE** the seed-reading, PKCS#8 generation, encryption, and keychain storage logic from `auths-cli/src/commands/key.rs:302-382`. Replace with a single call to the SDK function.
2. **SDK function is canonical**: `auths_sdk::keys::import_seed()` accepts `&Zeroizing<[u8; 32]>` seed + passphrase, stores in keychain. No file I/O. No `println!`. No terminal interaction.
3. **Default keychain**: The SDK function defaults to the File keychain backend unless another `AuthsContext` is explicitly provided. No "guess the platform" logic inside the import function.
4. **CLI becomes wrapper only**: The CLI reads the file, calls the SDK, prints the result. Three lines of logic, max.
5. **`KeyImportError`**: `thiserror` enum. No `anyhow`.
6. **All secret material** wrapped in `Zeroizing<>`.

## Implementation

1. Create `crates/auths-sdk/src/keys.rs`:
   ```rust
   pub fn import_seed(
       seed: &Zeroizing<[u8; 32]>,
       passphrase: &Zeroizing<String>,
       alias: &str,
       context: &AuthsContext,
   ) -> Result<PublicKeyInfo, KeyImportError>
   ```
2. Reuse `auths_core::crypto::signer::encrypt_keypair()` for encryption
3. Reuse `context.key_storage().store_key()` for persistence
4. DELETE all crypto logic from CLI handler -- it calls SDK only

## Key Files
- `crates/auths-cli/src/commands/key.rs:302-382` -- DELETE internal logic, replace with SDK call
- `crates/auths-core/src/crypto/signer.rs` -- `encrypt_keypair()` (reuse, don't duplicate)
- `crates/auths-core/src/storage/keychain.rs:141-170` -- `KeyStorage` trait
- `crates/auths-sdk/src/context.rs:79` -- `AuthsContext`
## Problem

`key_import()` in the CLI reads a 32-byte seed from a file, generates PKCS#8 DER, encrypts with passphrase, and stores in keychain. This is entirely a presentation-layer function with no SDK equivalent. Phase 2 requires Heartwood's `rad auth` to call this logic programmatically -- passing seed bytes directly from memory, not from a file.

## Implementation

1. Create `crates/auths-sdk/src/keys.rs` (or add to existing module)
2. Add `import_seed(seed: &Zeroizing<[u8; 32]>, passphrase: &Zeroizing<String>, alias: &str, context: &AuthsContext) -> Result<DevicePublicKey, KeyImportError>`
3. The function should:
   - Generate Ed25519 keypair from seed (reuse `auths_core::crypto::signer` functions)
   - Encrypt with passphrase (reuse `encrypt_keypair()`)
   - Store in keychain via `context.key_storage().store_key()`
   - Return the derived public key / DID
4. All parameters use `Zeroizing<>` wrappers for secret material
5. No file I/O, no `println!`, no terminal interaction
6. Define `KeyImportError` as a `thiserror` enum (not `anyhow`)

## Key Files
- `crates/auths-cli/src/commands/key.rs:302-382` -- source implementation to extract
- `crates/auths-core/src/crypto/signer.rs` -- `encrypt_keypair()`, key generation
- `crates/auths-core/src/storage/keychain.rs:141-170` -- `KeyStorage` trait
- `crates/auths-sdk/src/context.rs:79` -- `AuthsContext` dependency container

## After Extraction
- Update `auths-cli/src/commands/key.rs` to call the new SDK function
- CLI function becomes a thin wrapper: read file -> call SDK -> print result

## Code Quality
- **DRY**: Do not repeat logic; extract shared patterns into helper functions or traits.
- **Modular Design**: Avoid monolithic functions. Decompose complex logic into small, focused, and testable units.
- **Strictness**: Adhere to the "Zero-Debt" mandate—if old code is redundant, delete it; do not leave "TODO" or "Legacy" stubs.

## Acceptance
- [ ] `auths_sdk::keys::import_seed()` exists, accepts `&Zeroizing<[u8; 32]>`
- [ ] No file I/O in SDK function
- [ ] Defaults to File keychain backend
- [ ] `KeyImportError` uses `thiserror` (no `anyhow`)
- [ ] CLI `key_import()` is wrapper only -- reads file, calls SDK, prints result
- [ ] All crypto/keychain logic DELETED from CLI handler
- [ ] All secret material wrapped in `Zeroizing<>`
- [ ] Unit test: import seed, verify derived public key
- [ ] `cargo nextest run -p auths-sdk -p auths-cli` passes
## Done summary
Created auths-sdk::keys::import_seed() with KeyImportError thiserror enum. CLI key_import() is now a thin wrapper: read seed file, prompt passphrase, call SDK, print result. Removed der/pkcs8/OID_ED25519/encrypt_keypair imports from CLI.
## Evidence
- Commits:
- Tests:
- PRs:
