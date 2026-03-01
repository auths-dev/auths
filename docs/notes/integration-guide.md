# Integration Guide

This guide shows how to integrate `auths-core` and `auths-verifier` into your Rust applications.

## Cargo.toml Setup

### auths-core (Signing & Key Management)

```toml
[dependencies]
auths_core = { git = "https://github.com/bordumb/auths" }

# Platform-specific features (pick one or more):
[target.'cfg(target_os = "linux")'.dependencies]
auths_core = { git = "https://github.com/bordumb/auths", features = ["keychain-linux-secretservice"] }

[target.'cfg(target_os = "windows")'.dependencies]
auths_core = { git = "https://github.com/bordumb/auths", features = ["keychain-windows"] }
```

**Available features:**
- `keychain-linux-secretservice` — Use Linux Secret Service (GNOME Keyring)
- `keychain-windows` — Use Windows Credential Manager
- `keychain-file-fallback` — Encrypted file storage for headless environments
- `crypto-secp256k1` — Enable secp256k1/BIP340 Schnorr for Nostr
- `test-utils` — Export test utilities (InMemoryKeyStorage)

macOS/iOS keychain support is enabled by default.

### auths-verifier (Verification Only)

```toml
[dependencies]
auths_verifier = { git = "https://github.com/bordumb/auths" }

# For WASM targets:
auths_verifier = { git = "https://github.com/bordumb/auths", features = ["wasm"] }
```

The verifier is lightweight and has no platform-specific dependencies.

## Creating a Signer

### Using the Platform Keychain

```rust
use auths_core::storage::keychain::get_platform_keychain;
use auths_core::signing::{StorageSigner, SecureSigner, PassphraseProvider};
use auths_core::error::AgentError;

// Implement a passphrase provider for your application
struct MyPassphraseProvider;

impl PassphraseProvider for MyPassphraseProvider {
    fn get_passphrase(&self, prompt: &str) -> Result<String, AgentError> {
        // In a real app: show dialog, read from terminal, etc.
        println!("{}", prompt);
        Ok("user-entered-passphrase".to_string())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get the platform-appropriate keychain
    let keychain = get_platform_keychain()?;

    // Create a signer
    let signer = StorageSigner::new(keychain);

    // Sign a message
    let provider = MyPassphraseProvider;
    let message = b"data to sign";
    let signature = signer.sign_with_alias("my-key-alias", &provider, message)?;

    println!("Signature: {} bytes", signature.len());
    Ok(())
}
```

### Using the Callback Provider

For GUI applications or FFI, use `CallbackPassphraseProvider`:

```rust
use auths_core::signing::CallbackPassphraseProvider;

let provider = CallbackPassphraseProvider::new(|prompt| {
    // Show a dialog, call FFI, etc.
    show_passphrase_dialog(prompt)
});
```

### Using the Cached Provider

For agent-style applications that shouldn't prompt repeatedly:

```rust
use auths_core::signing::CachedPassphraseProvider;
use std::sync::Arc;
use std::time::Duration;

let inner = Arc::new(MyPassphraseProvider);
let cached = CachedPassphraseProvider::new(inner, Duration::from_secs(300));

// First call prompts, subsequent calls within 5 minutes use cache
let sig1 = signer.sign_with_alias("key", &cached, b"msg1")?;
let sig2 = signer.sign_with_alias("key", &cached, b"msg2")?; // No prompt

// Clear cache on logout/lock
cached.clear_cache();
```

## Signing Operations

### Sign Bytes

```rust
use auths_core::signing::SecureSigner;

let signature = signer.sign_with_alias(
    "my-key-alias",
    &passphrase_provider,
    b"raw bytes to sign"
)?;
```

### Sign for a DID

If you have keys associated with an identity DID:

```rust
let signature = signer.sign_for_identity(
    "did:key:z6Mk...",
    &passphrase_provider,
    b"message"
)?;
```

## Verification

### Verify an Attestation Chain

```rust
use auths_verifier::{verify_chain, ChainLink, VerificationStatus};

// Attestation chain from Git storage
let attestations: Vec<Attestation> = load_attestations_from_git()?;

let report = verify_chain(&attestations)?;

match report.status {
    VerificationStatus::Valid => {
        println!("Chain is valid!");
        for link in &report.chain {
            println!("  {} -> {}", link.issuer, link.subject);
        }
    }
    VerificationStatus::Expired { at } => {
        println!("Chain expired at {}", at);
    }
    VerificationStatus::Revoked { at } => {
        println!("Chain was revoked");
    }
    VerificationStatus::InvalidSignature { step } => {
        println!("Invalid signature at step {}", step);
    }
    VerificationStatus::BrokenChain { missing_link } => {
        println!("Chain broken: missing {}", missing_link);
    }
}
```

### Verify with Capability Requirement

```rust
use auths_verifier::{verify_with_capability, Capability};

let report = verify_with_capability(
    &attestations,
    Capability::SignCommit,  // Required capability
)?;

if report.is_valid() {
    println!("Device is authorized to sign commits");
}
```

### Check Device Authorization

```rust
use auths_verifier::is_device_authorized;

let authorized = is_device_authorized(
    "did:key:z6MkDevice...",  // Device DID to check
    &attestations,
)?;

if authorized {
    println!("Device is authorized");
}
```

## Error Handling

### Matching on AgentError

```rust
use auths_core::error::AgentError;

match result {
    Ok(signature) => { /* success */ }
    Err(AgentError::KeyNotFound) => {
        eprintln!("Key not found. Run 'auths key list' to see available keys.");
    }
    Err(AgentError::IncorrectPassphrase) => {
        eprintln!("Wrong passphrase. Please try again.");
    }
    Err(AgentError::BackendUnavailable { backend, reason }) => {
        eprintln!("Keychain {} unavailable: {}", backend, reason);
        eprintln!("Run 'auths doctor' to diagnose.");
    }
    Err(AgentError::UserInputCancelled) => {
        eprintln!("Operation cancelled by user.");
    }
    Err(e) => {
        eprintln!("Error: {}", e);
    }
}
```

### Error Types Reference

| Error | When | User Action |
|-------|------|-------------|
| `KeyNotFound` | Alias doesn't exist | Check `auths key list` |
| `IncorrectPassphrase` | Wrong passphrase | Retry with correct passphrase |
| `BackendUnavailable` | Keychain not accessible | Run `auths doctor` |
| `StorageLocked` | Keychain locked | Unlock system keychain |
| `UserInputCancelled` | User cancelled prompt | N/A |
| `AgentLocked` | Agent idle timeout | Run `auths agent unlock` |

For the complete list of error codes and programmatic handling, see [Error Codes](errors.md).

## Testing

### Using InMemoryKeyStorage

Enable the `test-utils` feature to access test utilities:

```toml
[dev-dependencies]
auths_core = { git = "...", features = ["test-utils"] }
```

```rust
#[cfg(test)]
mod tests {
    use auths_core::storage::memory::get_test_memory_keychain;
    use auths_core::signing::StorageSigner;

    #[test]
    fn test_signing() {
        // Get a fresh in-memory keychain (cleared between tests)
        let keychain = get_test_memory_keychain();
        let signer = StorageSigner::new(keychain);

        // Store a test key
        keychain.store_key(
            "test-alias",
            "did:key:z6MkTest...",
            &encrypted_key_bytes,
        ).unwrap();

        // Now test signing
        let sig = signer.sign_with_alias(
            "test-alias",
            &MockPassphraseProvider::new("test-pass"),
            b"test message"
        ).unwrap();

        assert_eq!(sig.len(), 64); // Ed25519 signature
    }
}
```

### Mock PassphraseProvider

```rust
struct MockPassphraseProvider {
    passphrase: String,
}

impl MockPassphraseProvider {
    fn new(passphrase: &str) -> Self {
        Self { passphrase: passphrase.to_string() }
    }
}

impl PassphraseProvider for MockPassphraseProvider {
    fn get_passphrase(&self, _prompt: &str) -> Result<String, AgentError> {
        Ok(self.passphrase.clone())
    }
}
```

## Platform-Specific Notes

### macOS

- Uses Keychain Services with Secure Enclave integration
- Keys are stored in the login keychain by default
- May prompt for keychain access permission

### Linux

- Requires `keychain-linux-secretservice` feature
- Uses D-Bus Secret Service (GNOME Keyring, KWallet)
- Fallback to encrypted file if unavailable

### Windows

- Requires `keychain-windows` feature
- Uses Windows Credential Manager (DPAPI)

### Headless/CI

Enable `keychain-file-fallback` for environments without a keychain:

```toml
auths_core = { git = "...", features = ["keychain-file-fallback"] }
```

Or set the environment variable:
```bash
export AUTHS_KEYCHAIN_BACKEND=memory  # For tests
export AUTHS_KEYCHAIN_BACKEND=file    # For encrypted file storage
```

## See Also

- [Quickstart](quickstart.md) — Getting started with the CLI
- [Threat Model](../security/threat-model.md) — Security considerations
- [Error Codes](errors.md) — Complete error code reference
- [API Reference](https://docs.rs/auths_core) — Full API documentation
