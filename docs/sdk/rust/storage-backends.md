# Storage Backends

Auths stores all identity data and attestations as Git refs. The SDK interacts with storage exclusively through trait abstractions, enabling custom backends for testing, cloud deployments, or alternative storage engines.

## Storage Architecture

```text
~/.auths/                    (Git repository)
  refs/
    auths/
      identity               (identity commit)
      devices/
        nodes/
          <sanitized_did>/
            signatures        (attestation commits per device)
    keri/
      <prefix>/              (KERI event log)
```

All identity data lives in Git. The `~/.auths` directory is a bare Git repository managed by `auths-id` storage implementations.

## Core Storage Traits

### IdentityStorage

Defined in `auths_id::storage::identity`, this trait abstracts the creation and retrieval of the managed identity.

```rust
pub trait IdentityStorage {
    fn create_identity(
        &self,
        controller_did: &str,
        metadata: Option<serde_json::Value>,
    ) -> Result<(), anyhow::Error>;

    fn load_identity(&self) -> Result<ManagedIdentity, anyhow::Error>;

    fn get_identity_ref(&self) -> Result<String, anyhow::Error>;
}
```

**`create_identity`** creates or updates the identity reference with the controller DID and optional arbitrary metadata. The structure and interpretation of the `metadata` JSON is the caller's responsibility.

**`load_identity`** returns a `ManagedIdentity` struct:

```rust
pub struct ManagedIdentity {
    pub controller_did: IdentityDID,   // e.g. "did:keri:E..."
    pub storage_id: String,            // e.g. repository directory name
    pub metadata: Option<serde_json::Value>,
}
```

**`get_identity_ref`** returns the configured Git reference used for the identity commit (e.g. `"refs/auths/identity"`).

### AttestationSource

Defined in `auths_id::storage::attestation`, this trait abstracts reading attestations from storage.

```rust
pub trait AttestationSource {
    fn load_attestations_for_device(
        &self,
        device_did: &DeviceDID,
    ) -> Result<Vec<Attestation>, anyhow::Error>;

    fn load_all_attestations(&self) -> Result<Vec<Attestation>, anyhow::Error>;

    fn load_all_attestations_paginated(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<Vec<Attestation>, anyhow::Error>;

    fn discover_device_dids(&self) -> Result<Vec<DeviceDID>, anyhow::Error>;
}
```

**`load_attestations_for_device`** loads all attestations for a specific device DID by reading the history of its attestation ref.

**`load_all_attestations`** discovers all device DIDs and loads their attestations. Calls `load_all_attestations_paginated(usize::MAX, 0)` internally.

**`load_all_attestations_paginated`** loads attestations for a bounded page of devices. The `limit` controls the maximum number of devices to process, and `offset` skips that many devices from the discovered list. This avoids loading the entire device set at once when thousands of devices exist.

**`discover_device_dids`** finds device DIDs by globbing attestation ref patterns based on the storage layout configuration.

### AttestationSink

Defined in `auths_id::attestation::export`, this trait abstracts writing attestations to storage.

```rust
pub trait AttestationSink {
    fn export(&self, attestation: &VerifiedAttestation) -> Result<()>;

    fn sync_index(&self, _attestation: &Attestation) {}
}
```

**`export`** accepts a `VerifiedAttestation` (enforcing at the type level that signatures were checked before storage) and persists it.

**`sync_index`** updates any secondary index after an attestation mutation. The default implementation is a no-op. Adapters backed by a searchable index (e.g. SQLite) override this.

### KeyStorage

Defined in `auths_core::storage::keychain`, this trait abstracts platform-specific key storage.

```rust
pub trait KeyStorage: Send + Sync {
    fn store_key(
        &self,
        alias: &KeyAlias,
        identity_did: &IdentityDID,
        encrypted_key_data: &[u8],
    ) -> Result<(), AgentError>;

    fn load_key(
        &self,
        alias: &KeyAlias,
    ) -> Result<(IdentityDID, Vec<u8>), AgentError>;

    fn delete_key(&self, alias: &KeyAlias) -> Result<(), AgentError>;

    fn list_aliases(&self) -> Result<Vec<KeyAlias>, AgentError>;

    fn list_aliases_for_identity(
        &self,
        identity_did: &IdentityDID,
    ) -> Result<Vec<KeyAlias>, AgentError>;

    fn get_identity_for_alias(
        &self,
        alias: &KeyAlias,
    ) -> Result<IdentityDID, AgentError>;

    fn backend_name(&self) -> &'static str;
}
```

## Git-Backed Implementations

### GitIdentityStorage

The standard `IdentityStorage` implementation backed by a Git repository.

```rust
use auths_id::storage::identity::GitIdentityStorage;
use auths_id::storage::layout::StorageLayoutConfig;

// With default layout (refs/auths/identity, identity.json blob)
let storage = GitIdentityStorage::new_with_defaults("/home/user/.auths");

// With custom layout (e.g. for Radicle compatibility)
let config = StorageLayoutConfig { /* ... */ };
let storage = GitIdentityStorage::new("/home/user/.auths", config);
```

### GitAttestationStorage

The standard `AttestationSource` implementation backed by a Git repository.

```rust
use auths_id::storage::attestation::GitAttestationStorage;

// With default layout
let source = GitAttestationStorage::new_with_defaults("/home/user/.auths");

// With custom layout
let source = GitAttestationStorage::new("/home/user/.auths", config);
```

### GitRefSink

The standard `AttestationSink` implementation that exports attestations as JSON commits under device-specific Git refs.

```rust
use auths_id::attestation::export::GitRefSink;

// With defaults (JSON encoder, default layout)
let sink = GitRefSink::with_defaults("/home/user/.auths");

// With custom layout
let sink = GitRefSink::with_config("/home/user/.auths", config);

// With custom encoder and layout
use std::sync::Arc;
let sink = GitRefSink::new(
    "/home/user/.auths",
    Arc::new(my_custom_encoder),
    config,
);
```

## Platform Keychain Backends

The `get_platform_keychain()` function returns the appropriate keychain for the current platform:

| Platform | Backend | Notes |
|---|---|---|
| macOS | `MacOSKeychain` (Security Framework) | Default on macOS |
| iOS | `IOSKeychain` (Keychain Services) | Default on iOS |
| Linux | `LinuxSecretServiceStorage` | Requires `keychain-linux-secretservice` feature |
| Linux (fallback) | `EncryptedFileStorage` | Requires `keychain-file-fallback` feature |
| Windows | `WindowsCredentialStorage` | Requires `keychain-windows` feature |
| Android | `AndroidKeystoreStorage` | Default on Android |
| CI/Test | `MemoryKeychainHandle` | In-memory, not for production |

### Environment Variable Override

Set `AUTHS_KEYCHAIN_BACKEND` to override the platform default:

- `"file"` -- encrypted file storage at `~/.auths/keys.enc`
- `"memory"` -- in-memory storage (testing only)

```rust
use auths_core::storage::keychain::get_platform_keychain;

let keychain = get_platform_keychain()?;
println!("Using: {}", keychain.backend_name());
```

## StorageLayoutConfig

All Git storage implementations accept a `StorageLayoutConfig` that controls ref paths and blob filenames. This allows different storage layouts (e.g. Radicle's `xyz.radicle.agent` layout) to coexist.

The default layout uses:

- Identity ref: `refs/auths/identity`
- Attestation refs: `refs/auths/devices/nodes/<sanitized_did>/signatures`
- Identity blob: `identity.json`
- Attestation blob: `attestation.json`

## Implementing Custom Backends

### Custom IdentityStorage

```rust
use auths_id::storage::identity::IdentityStorage;
use auths_id::identity::helpers::ManagedIdentity;
use auths_core::storage::keychain::IdentityDID;

struct SqliteIdentityStorage { /* ... */ }

impl IdentityStorage for SqliteIdentityStorage {
    fn create_identity(
        &self,
        controller_did: &str,
        metadata: Option<serde_json::Value>,
    ) -> Result<(), anyhow::Error> {
        // INSERT INTO identities (did, metadata) VALUES (?, ?)
        todo!()
    }

    fn load_identity(&self) -> Result<ManagedIdentity, anyhow::Error> {
        // SELECT did, metadata FROM identities LIMIT 1
        todo!()
    }

    fn get_identity_ref(&self) -> Result<String, anyhow::Error> {
        Ok("sqlite://identities".to_string())
    }
}
```

### Custom AttestationSource

```rust
use auths_id::storage::attestation::AttestationSource;
use auths_verifier::core::Attestation;
use auths_verifier::types::DeviceDID;

struct HttpAttestationSource {
    base_url: String,
}

impl AttestationSource for HttpAttestationSource {
    fn load_attestations_for_device(
        &self,
        device_did: &DeviceDID,
    ) -> Result<Vec<Attestation>, anyhow::Error> {
        // GET /attestations?device={device_did}
        todo!()
    }

    fn load_all_attestations(&self) -> Result<Vec<Attestation>, anyhow::Error> {
        // GET /attestations
        todo!()
    }

    fn discover_device_dids(&self) -> Result<Vec<DeviceDID>, anyhow::Error> {
        // GET /devices
        todo!()
    }
}
```

### Custom KeyStorage

```rust
use auths_core::storage::keychain::{KeyStorage, KeyAlias, IdentityDID};
use auths_core::error::AgentError;

struct VaultKeyStorage {
    client: vault::Client,
}

impl KeyStorage for VaultKeyStorage {
    fn store_key(
        &self,
        alias: &KeyAlias,
        identity_did: &IdentityDID,
        encrypted_key_data: &[u8],
    ) -> Result<(), AgentError> {
        // vault.kv_put("auths/keys/{alias}", data)
        todo!()
    }

    fn load_key(
        &self,
        alias: &KeyAlias,
    ) -> Result<(IdentityDID, Vec<u8>), AgentError> {
        // vault.kv_get("auths/keys/{alias}")
        todo!()
    }

    fn delete_key(&self, alias: &KeyAlias) -> Result<(), AgentError> {
        todo!()
    }

    fn list_aliases(&self) -> Result<Vec<KeyAlias>, AgentError> {
        todo!()
    }

    fn list_aliases_for_identity(
        &self,
        identity_did: &IdentityDID,
    ) -> Result<Vec<KeyAlias>, AgentError> {
        todo!()
    }

    fn get_identity_for_alias(
        &self,
        alias: &KeyAlias,
    ) -> Result<IdentityDID, AgentError> {
        todo!()
    }

    fn backend_name(&self) -> &'static str {
        "HashiCorp Vault"
    }
}
```

## Wiring Into AuthsContext

Once you have implementations of the storage traits, wire them into `AuthsContext`:

```rust
use std::sync::Arc;
use auths_sdk::context::AuthsContext;
use auths_core::ports::clock::SystemClock;

let ctx = AuthsContext::builder()
    .registry(Arc::new(my_registry_backend))
    .key_storage(Arc::new(my_keychain))
    .clock(Arc::new(SystemClock))
    .identity_storage(Arc::new(my_identity_storage))
    .attestation_sink(Arc::new(my_attestation_sink))
    .attestation_source(Arc::new(my_attestation_source))
    .passphrase_provider(Arc::new(my_passphrase_provider))
    .build();
```

## SDK Port Traits

The SDK defines additional port traits in `auths_sdk::ports` for I/O adapters:

### ArtifactSource

```rust
pub trait ArtifactSource: Send + Sync {
    fn digest(&self) -> Result<ArtifactDigest, ArtifactError>;
    fn metadata(&self) -> Result<ArtifactMetadata, ArtifactError>;
}
```

### GitConfigProvider

```rust
pub trait GitConfigProvider: Send + Sync {
    fn set(&self, key: &str, value: &str) -> Result<(), GitConfigError>;
}
```

### EventSink

```rust
pub trait EventSink: Send + Sync + 'static {
    fn emit(&self, payload: &str);
    fn flush(&self);
}
```

Implement `EventSink` to route SDK audit events to a logging backend, SIEM, or stdout. The default is `NoopSink` which discards all events.
