# Identity Operations

The `auths-sdk` crate provides orchestration functions for identity lifecycle operations. All functions accept typed config structs and an `AuthsContext` carrying injected infrastructure adapters. They never prompt for input, print to stdout, or call `process::exit()`.

## AuthsContext

Every SDK operation requires an `AuthsContext`, which is built using a typestate builder pattern. The `registry`, `key_storage`, and `clock` fields are compile-time required; omitting any of them is a compile error.

```rust
use std::sync::Arc;
use auths_sdk::context::AuthsContext;

let ctx = AuthsContext::builder()
    .registry(Arc::new(my_registry))
    .key_storage(Arc::new(my_keychain))
    .clock(Arc::new(SystemClock))
    .identity_storage(Arc::new(my_identity_storage))
    .attestation_sink(Arc::new(my_attestation_sink))
    .attestation_source(Arc::new(my_attestation_source))
    .passphrase_provider(Arc::new(my_passphrase_provider)) // defaults to noop
    .event_sink(Arc::new(my_telemetry_sink))                // defaults to noop
    .uuid_provider(Arc::new(my_uuid_provider))              // defaults to random v4
    .build();
```

### AuthsContext Fields

| Field | Type | Required | Default |
|---|---|---|---|
| `registry` | `Arc<dyn RegistryBackend + Send + Sync>` | Yes | -- |
| `key_storage` | `Arc<dyn KeyStorage + Send + Sync>` | Yes | -- |
| `clock` | `Arc<dyn ClockProvider + Send + Sync>` | Yes | -- |
| `identity_storage` | `Arc<dyn IdentityStorage + Send + Sync>` | Yes (runtime) | panics on build |
| `attestation_sink` | `Arc<dyn AttestationSink + Send + Sync>` | Yes (runtime) | panics on build |
| `attestation_source` | `Arc<dyn AttestationSource + Send + Sync>` | Yes (runtime) | panics on build |
| `passphrase_provider` | `Arc<dyn PassphraseProvider + Send + Sync>` | No | `NoopPassphraseProvider` |
| `event_sink` | `Arc<dyn EventSink>` | No | `NoopSink` |
| `uuid_provider` | `Arc<dyn UuidProvider + Send + Sync>` | No | `SystemUuidProvider` |

## Developer Identity Setup

`setup_developer()` provisions a new developer identity with device linking, optional platform verification, Git signing configuration, and registry publication.

### Function Signature

```rust
pub fn setup_developer(
    config: DeveloperSetupConfig,
    ctx: &AuthsContext,
    keychain: &(dyn KeyStorage + Send + Sync),
    signer: &dyn SecureSigner,
    passphrase_provider: &dyn PassphraseProvider,
    git_config: Option<&dyn GitConfigProvider>,
) -> Result<SetupResult, SetupError>
```

### Configuration

```rust
use auths_sdk::types::{
    DeveloperSetupConfig, GitSigningScope, IdentityConflictPolicy, PlatformVerification,
};
use auths_core::storage::keychain::KeyAlias;

let config = DeveloperSetupConfig::builder(KeyAlias::new("work-laptop")?)
    .with_platform(PlatformVerification::GitHub {
        access_token: "ghp_abc123".into(),
    })
    .with_git_signing_scope(GitSigningScope::Global)
    .with_conflict_policy(IdentityConflictPolicy::ReuseExisting)
    .with_registration("https://registry.auths.dev")
    .with_witness_config(witness_cfg)
    .with_metadata(serde_json::json!({"team": "platform"}))
    .with_sign_binary_path(PathBuf::from("/usr/local/bin/auths-sign"))
    .build();
```

### IdentityConflictPolicy

Controls what happens when an identity already exists at the configured path:

| Variant | Behavior |
|---|---|
| `IdentityConflictPolicy::Error` | Returns `SetupError::IdentityAlreadyExists` (default) |
| `IdentityConflictPolicy::ReuseExisting` | Silently reuses the existing identity |
| `IdentityConflictPolicy::ForceNew` | Overwrites with a new identity |

### Result

```rust
pub struct SetupResult {
    pub identity_did: String,           // e.g. "did:keri:E..."
    pub device_did: String,             // e.g. "did:key:z6Mk..."
    pub key_alias: KeyAlias,
    pub platform_claim: Option<PlatformClaimResult>,
    pub git_signing_configured: bool,
    pub registered: Option<RegistrationOutcome>,
}
```

## CI/Ephemeral Identity Setup

`setup_ci()` provisions an ephemeral identity for automated CI pipelines. It uses an in-memory keychain and produces environment variable export lines.

### Function Signature

```rust
pub fn setup_ci(
    config: CiSetupConfig,
    ctx: &AuthsContext,
) -> Result<CiSetupResult, SetupError>
```

### Configuration

```rust
use auths_sdk::types::{CiSetupConfig, CiEnvironment};

let config = CiSetupConfig {
    ci_environment: CiEnvironment::GitHubActions,
    passphrase: std::env::var("AUTHS_PASSPHRASE").unwrap(),
    registry_path: PathBuf::from("/tmp/.auths"),
    keychain: Box::new(memory_keychain),
};
```

Supported `CiEnvironment` variants: `GitHubActions`, `GitLabCi`, `Custom { name: String }`, `Unknown`.

### Result

```rust
pub struct CiSetupResult {
    pub identity_did: String,
    pub device_did: String,
    pub env_block: Vec<String>,   // Shell `export` lines for CI env vars
}
```

## Agent Identity Setup

`setup_agent()` provisions a delegated agent identity with scoped capabilities and optional expiration.

### Function Signature

```rust
pub fn setup_agent(
    config: AgentSetupConfig,
    ctx: &AuthsContext,
    keychain: Box<dyn KeyStorage + Send + Sync>,
    passphrase_provider: &dyn PassphraseProvider,
) -> Result<AgentSetupResult, SetupError>
```

### Configuration

```rust
use auths_sdk::types::AgentSetupConfig;
use auths_core::storage::keychain::KeyAlias;

let config = AgentSetupConfig::builder(
    KeyAlias::new("deploy-bot")?,
    PathBuf::from("/home/user/.auths"),
)
    .with_parent_did("did:keri:Eabc123")
    .with_capabilities(vec!["sign-commit".into(), "sign-release".into()])
    .with_expiry(86400)  // 24 hours
    .dry_run(false)
    .build();
```

### Result

```rust
pub struct AgentSetupResult {
    pub agent_did: String,
    pub parent_did: String,
    pub capabilities: Vec<String>,
}
```

## Device Linking

`link_device()` creates a signed attestation that binds a new device key to an existing identity.

### Function Signature

```rust
pub fn link_device(
    config: DeviceLinkConfig,
    ctx: &AuthsContext,
    clock: &dyn ClockProvider,
) -> Result<DeviceLinkResult, DeviceError>
```

### Configuration

```rust
use auths_sdk::types::DeviceLinkConfig;

let config = DeviceLinkConfig {
    identity_key_alias: KeyAlias::new("my-identity")?,
    device_key_alias: Some(KeyAlias::new("macbook-pro")?),
    device_did: None,
    capabilities: vec!["sign-commit".into()],
    expires_in: Some(31_536_000),
    note: Some("Work laptop".into()),
    payload: None,
};
```

### Result

```rust
pub struct DeviceLinkResult {
    pub device_did: String,
    pub attestation_id: String,
}
```

## Device Revocation

`revoke_device()` creates a signed revocation record that invalidates a device's attestation.

```rust
pub fn revoke_device(
    device_did: &str,
    identity_key_alias: &KeyAlias,
    ctx: &AuthsContext,
    note: Option<String>,
    clock: &dyn ClockProvider,
) -> Result<(), DeviceError>
```

## Device Authorization Extension

`extend_device_authorization()` creates a new attestation with an extended expiry for an existing device.

```rust
pub fn extend_device_authorization(
    config: DeviceExtensionConfig,
    ctx: &AuthsContext,
    clock: &dyn ClockProvider,
) -> Result<DeviceExtensionResult, DeviceExtensionError>
```

### Configuration

```rust
use auths_sdk::types::DeviceExtensionConfig;

let config = DeviceExtensionConfig {
    repo_path: PathBuf::from("/home/user/.auths"),
    device_did: "did:key:z6Mk...".into(),
    days: 365,
    identity_key_alias: KeyAlias::new("my-identity")?,
    device_key_alias: KeyAlias::new("my-device")?,
};
```

## Key Rotation

`rotate_identity()` performs a KERI key rotation, replacing the current signing key with the pre-committed next key and generating a new forward-looking commitment.

### Function Signature

```rust
pub fn rotate_identity(
    config: RotationConfig,
    ctx: &AuthsContext,
    clock: &dyn ClockProvider,
) -> Result<RotationResult, RotationError>
```

### Configuration

```rust
use auths_sdk::types::RotationConfig;

let config = RotationConfig {
    repo_path: PathBuf::from("/home/user/.auths"),
    identity_key_alias: Some(KeyAlias::new("main")?),
    next_key_alias: None, // auto-generated as "<alias>-rotated-<timestamp>"
};
```

### Result

```rust
pub struct RotationResult {
    pub controller_did: String,
    pub new_key_fingerprint: String,       // hex-encoded first 8 bytes
    pub previous_key_fingerprint: String,  // hex-encoded first 8 bytes
}
```

### Rotation Internals

Rotation is a three-phase process:

1. **`compute_rotation_event()`** -- Pure, deterministic construction of the KERI `RotEvent`. Signs the event with the pre-committed next key.
2. **`apply_rotation()`** -- Side-effecting KEL append and keychain write. Non-atomic: if the KEL write succeeds but the keychain write fails, a `RotationError::PartialRotation` is returned with a recovery path.
3. **`rotate_identity()`** -- High-level orchestrator that calls both phases in order.

## Clock Injection

All SDK functions that involve timestamps accept a `ClockProvider` or read from `AuthsContext.clock`. The SDK layer calls `clock.now()` and passes the value down to domain functions. `Utc::now()` is banned in `auths-core` and `auths-id` source code.

```rust
use auths_core::ports::clock::{ClockProvider, SystemClock};

// Production: real wall clock
let clock = SystemClock;

// Tests: deterministic fixed time
struct FixedClock(DateTime<Utc>);
impl ClockProvider for FixedClock {
    fn now(&self) -> DateTime<Utc> { self.0 }
}
```
