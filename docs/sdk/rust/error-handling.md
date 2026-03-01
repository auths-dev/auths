# Error Handling

Auths follows a strict error discipline: **`thiserror` enums in Core/SDK, `anyhow` only at the CLI/server presentation boundary.** The SDK never uses `Box<dyn Error>` or `anyhow::Error`.

## Translation Boundary

The CLI and API servers define a clear translation boundary where domain errors are wrapped with operational context:

```rust
// CLI layer (presentation) -- anyhow is allowed here
let signature = sign_artifact(&config, data)
    .with_context(|| format!("Failed to sign artifact for namespace: {}", config.namespace))?;
```

Domain errors flow up from the SDK as typed enums. The CLI wraps them with `anyhow::Context` for logging and diagnostics, but never discards the typed error.

## SDK Error Types

All SDK error enums are `#[non_exhaustive]`, allowing new variants to be added in future minor versions without breaking downstream code.

### SetupError

Errors from identity setup operations (developer, CI, agent).

```rust
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SetupError {
    #[error("identity already exists: {did}")]
    IdentityAlreadyExists { did: String },

    #[error("keychain unavailable ({backend}): {reason}")]
    KeychainUnavailable { backend: String, reason: String },

    #[error("crypto error: {0}")]
    CryptoError(#[source] auths_core::AgentError),

    #[error("storage error: {0}")]
    StorageError(#[source] SdkStorageError),

    #[error("git config error: {0}")]
    GitConfigError(String),

    #[error("registration failed: {0}")]
    RegistrationFailed(#[source] RegistrationError),

    #[error("platform verification failed: {0}")]
    PlatformVerificationFailed(String),
}
```

**Recovery patterns:**

```rust
match result {
    Err(SetupError::IdentityAlreadyExists { did }) => {
        // Reuse existing identity or prompt user
    }
    Err(SetupError::KeychainUnavailable { backend, reason }) => {
        // Fall back to file-based keychain
    }
    Err(e) => return Err(e.into()),
    Ok(result) => { /* success */ }
}
```

### DeviceError

Errors from device linking and revocation operations.

```rust
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DeviceError {
    #[error("identity not found: {did}")]
    IdentityNotFound { did: String },

    #[error("device not found: {did}")]
    DeviceNotFound { did: String },

    #[error("attestation error: {0}")]
    AttestationError(String),

    #[error("crypto error: {0}")]
    CryptoError(#[source] auths_core::AgentError),

    #[error("storage error: {0}")]
    StorageError(#[source] SdkStorageError),
}
```

### DeviceExtensionError

Errors from device authorization extension operations.

```rust
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DeviceExtensionError {
    #[error("identity not found")]
    IdentityNotFound,

    #[error("no attestation found for device {device_did}")]
    NoAttestationFound { device_did: String },

    #[error("device {device_did} is already revoked")]
    AlreadyRevoked { device_did: String },

    #[error("attestation creation failed: {0}")]
    AttestationFailed(String),

    #[error("storage error: {0}")]
    StorageError(String),
}
```

### RotationError

Errors from identity rotation operations.

```rust
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RotationError {
    #[error("identity not found at {path}")]
    IdentityNotFound { path: std::path::PathBuf },

    #[error("key not found: {0}")]
    KeyNotFound(String),

    #[error("key decryption failed: {0}")]
    KeyDecryptionFailed(String),

    #[error("KEL history error: {0}")]
    KelHistoryFailed(String),

    #[error("rotation failed: {0}")]
    RotationFailed(String),

    #[error("rotation event committed to KEL but keychain write failed -- manual recovery required: {0}")]
    PartialRotation(String),
}
```

`PartialRotation` is the most critical variant. It means the KEL event was written but the new key could not be persisted to the keychain. Recovery: re-run rotation with the same new key to replay the keychain write.

### RegistrationError

Errors from remote registry operations.

```rust
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum RegistrationError {
    #[error("identity already registered at this registry")]
    AlreadyRegistered,

    #[error("registration quota exceeded -- try again later")]
    QuotaExceeded,

    #[error("network error: {0}")]
    NetworkError(#[source] auths_core::ports::network::NetworkError),

    #[error("local data error: {0}")]
    LocalDataError(String),
}
```

### OrgError

Errors from organization member management workflows.

```rust
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OrgError {
    #[error("no admin with the given public key found in organization '{org}'")]
    AdminNotFound { org: String },

    #[error("member '{did}' not found in organization '{org}'")]
    MemberNotFound { org: String, did: String },

    #[error("member '{did}' is already revoked")]
    AlreadyRevoked { did: String },

    #[error("invalid capability '{cap}': {reason}")]
    InvalidCapability { cap: String, reason: String },

    #[error("invalid organization DID: {0}")]
    InvalidDid(String),

    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("storage error: {0}")]
    Storage(String),
}
```

### SdkStorageError

Opaque wrapper for storage errors originating from `auths-id` traits that currently return `anyhow::Result`. This preserves the full error display string until `auths-id` storage traits are migrated to typed errors.

```rust
#[derive(Debug, thiserror::Error)]
pub enum SdkStorageError {
    #[error("storage operation failed: {0}")]
    OperationFailed(String),
}
```

## Signing-Specific Errors

### SigningError

```rust
#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("identity is frozen: {0}")]
    IdentityFrozen(String),

    #[error("key resolution failed: {0}")]
    KeyResolution(String),

    #[error("signing operation failed: {0}")]
    SigningFailed(String),

    #[error("invalid passphrase")]
    InvalidPassphrase,

    #[error("PEM encoding failed: {0}")]
    PemEncoding(String),
}
```

### ArtifactSigningError

```rust
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ArtifactSigningError {
    #[error("identity not found in configured identity storage")]
    IdentityNotFound,

    #[error("key resolution failed: {0}")]
    KeyResolutionFailed(String),

    #[error("key decryption failed: {0}")]
    KeyDecryptionFailed(String),

    #[error("digest computation failed: {0}")]
    DigestFailed(String),

    #[error("attestation creation failed: {0}")]
    AttestationFailed(String),

    #[error("attestation re-signing failed: {0}")]
    ResignFailed(String),
}
```

## Verifier Error Types

### AttestationError

Defined in `auths-verifier`, this covers all verification failures:

```rust
#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    #[error("Signature verification failed: {0}")]
    VerificationError(String),

    #[error("Missing required capability: required {required:?}, available {available:?}")]
    MissingCapability { required: Capability, available: Vec<Capability> },

    #[error("Signing failed: {0}")]
    SigningError(String),

    #[error("DID resolution failed: {0}")]
    DidResolutionError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("Input too large: {0}")]
    InputTooLarge(String),

    #[error("Internal error: {0}")]
    InternalError(String),

    #[error("Organizational Attestation verification failed: {0}")]
    OrgVerificationFailed(String),

    #[error("Organizational Attestation expired")]
    OrgAttestationExpired,

    #[error("Organizational DID resolution failed: {0}")]
    OrgDidResolutionFailed(String),

    #[error("Bundle is {age_secs}s old (max {max_secs}s). Refresh with: auths id export-bundle")]
    BundleExpired { age_secs: u64, max_secs: u64 },
}
```

### AuthsErrorInfo Trait

Every `AttestationError` variant implements the `AuthsErrorInfo` trait for structured error codes and actionable suggestions:

```rust
pub trait AuthsErrorInfo {
    fn error_code(&self) -> &'static str;
    fn suggestion(&self) -> Option<&'static str>;
}
```

Error codes follow the `AUTHS_*` naming convention:

| Variant | Error Code |
|---|---|
| `VerificationError` | `AUTHS_VERIFICATION_ERROR` |
| `MissingCapability` | `AUTHS_MISSING_CAPABILITY` |
| `SigningError` | `AUTHS_SIGNING_ERROR` |
| `DidResolutionError` | `AUTHS_DID_RESOLUTION_ERROR` |
| `SerializationError` | `AUTHS_SERIALIZATION_ERROR` |
| `InvalidInput` | `AUTHS_INVALID_INPUT` |
| `CryptoError` | `AUTHS_CRYPTO_ERROR` |
| `InputTooLarge` | `AUTHS_INPUT_TOO_LARGE` |
| `InternalError` | `AUTHS_INTERNAL_ERROR` |
| `OrgVerificationFailed` | `AUTHS_ORG_VERIFICATION_FAILED` |
| `OrgAttestationExpired` | `AUTHS_ORG_ATTESTATION_EXPIRED` |
| `OrgDidResolutionFailed` | `AUTHS_ORG_DID_RESOLUTION_FAILED` |
| `BundleExpired` | `AUTHS_BUNDLE_EXPIRED` |

## Core Error Types

### AgentError

The foundational error type in `auths-core`, used as `#[source]` by several SDK error variants:

```rust
// Referenced as auths_core::AgentError in SDK error types
// Wraps cryptographic, keychain, and input validation errors.
// Key variants include:
// - KeyNotFound
// - IncorrectPassphrase
// - UserInputCancelled
// - InvalidInput(String)
// - SigningFailed(String)
// - CryptoError(String)
// - StorageError(String)
```

## From Implementations

The SDK provides automatic conversions between error types:

```rust
impl From<auths_core::AgentError> for SetupError { ... }     // -> SetupError::CryptoError
impl From<RegistrationError> for SetupError { ... }          // -> SetupError::RegistrationFailed
impl From<auths_core::AgentError> for DeviceError { ... }    // -> DeviceError::CryptoError
impl From<NetworkError> for RegistrationError { ... }        // -> RegistrationError::NetworkError
```

## Best Practices

1. **Match on specific variants** for recovery logic. Use `_` or `..` for forward compatibility since all enums are `#[non_exhaustive]`.

2. **Never discard typed errors** at the CLI boundary. Wrap with `anyhow::Context`, not `anyhow!()`:
   ```rust
   setup_developer(config, &ctx, ...).context("developer setup failed")?;
   ```

3. **Use `PartialRotation` as a recovery signal.** The KEL is already ahead of the keychain. Re-running rotation with the same key replays the keychain write.

4. **Check `RegistrationError::QuotaExceeded`** to implement retry-with-backoff at the CLI layer.
