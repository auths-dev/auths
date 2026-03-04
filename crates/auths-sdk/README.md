# Auths SDK

Application services layer for Auths identity operations. Orchestrates identity management, device linking, signing, and registry operations behind trait-based ports — no I/O, no prompts, no `process::exit()`.

## Architecture

```
auths-cli  →  auths-sdk  →  auths-core + auths-id
(I/O adapter)  (orchestration)  (domain)
```

The SDK sits between presentation layers (CLI, FFI, WASM, desktop) and domain crates. All infrastructure dependencies are injected via `AuthsContext`, making the SDK embeddable in any runtime without pulling in tokio, git2, or filesystem access.

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
auths-sdk = { path = "../auths-sdk" }
# or from the workspace:
auths-sdk.workspace = true
```

## Quick Start

Every SDK operation requires an `AuthsContext` — a runtime dependency container holding injected adapters for storage, key management, clock, and telemetry.

```rust
use std::sync::Arc;
use auths_sdk::AuthsContext;

let ctx = AuthsContext::builder()
    .registry(Arc::new(my_registry))
    .key_storage(Arc::new(my_keychain))
    .clock(Arc::new(SystemClock))
    .identity_storage(Arc::new(my_identity_storage))
    .attestation_sink(Arc::new(my_attestation_store))
    .attestation_source(Arc::new(my_attestation_store))
    .build()?;
```

Then call any SDK workflow:

```rust
use auths_sdk::setup::setup_developer;
use auths_sdk::types::DeveloperSetupConfig;

let config = DeveloperSetupConfig::builder("work-laptop".into())
    .with_git_signing_scope(GitSigningScope::Global)
    .build();

let result = setup_developer(config, &ctx)?;
```

---

## AuthsContext

The `AuthsContext` builder uses a typestate pattern — `build()` is only available once the three required fields (`registry`, `key_storage`, `clock`) are set. Optional fields have sensible defaults.

| Field | Required | Default | Description |
|---|---|---|---|
| `registry` | Yes | — | KERI registry storage backend |
| `key_storage` | Yes | — | Platform keychain or in-memory fake |
| `clock` | Yes | — | Wall-clock provider (`SystemClock` or `MockClock`) |
| `identity_storage` | Yes | — | Identity load/save adapter |
| `attestation_sink` | Yes | — | Attestation write adapter |
| `attestation_source` | Yes | — | Attestation read adapter |
| `event_sink` | No | `NoopSink` | Telemetry/audit event sink |
| `passphrase_provider` | No | Error on use | Key decryption passphrase source |
| `uuid_provider` | No | `SystemUuidProvider` | UUID v4 generator |
| `agent_signing` | No | `NoopAgentProvider` | Agent-based signing delegation |

---

## Modules

### Identity Setup (`setup`)

Provision new identities for developer, CI, and agent environments.

```rust
use auths_sdk::setup::{setup_developer, setup_ci, setup_agent};
use auths_sdk::types::{DeveloperSetupConfig, CiSetupConfig, AgentSetupConfig};

// Developer identity with platform verification
let config = DeveloperSetupConfig::builder("main".into())
    .with_platform(PlatformVerification::GitHub {
        access_token: "ghp_abc123".into(),
    })
    .with_registration("https://registry.auths.dev")
    .build();
let result = setup_developer(config, &ctx)?;

// Ephemeral CI identity (in-memory keychain, no platform keychain needed)
let ci_config = CiSetupConfig {
    ci_environment: CiEnvironment::GitHubActions,
    passphrase: std::env::var("AUTHS_PASSPHRASE")?,
    registry_path: PathBuf::from("/tmp/.auths"),
    keychain: Box::new(memory_keychain),
};
let result = setup_ci(ci_config, &ctx)?;

// Scoped agent identity with capabilities and expiry
let agent_config = AgentSetupConfig::builder("deploy-bot".into(), "~/.auths")
    .with_parent_did("did:keri:Eabc123")
    .with_capabilities(vec![Capability::sign_commit()])
    .with_expiry(86400)
    .build();
let result = setup_agent(agent_config, &ctx)?;
```

### Device Management (`device`)

Link, revoke, extend, and resolve device authorizations.

```rust
use auths_sdk::device::{link_device, revoke_device, extend_device};
use auths_sdk::types::{DeviceLinkConfig, DeviceExtensionConfig};

// Link a new device
let config = DeviceLinkConfig {
    identity_key_alias: "main".into(),
    device_key_alias: Some("macbook-pro".into()),
    device_did: None,
    capabilities: vec!["sign-commit".into()],
    expires_in_days: Some(365),
    note: Some("Work laptop".into()),
    payload: None,
};
let result = link_device(config, &ctx)?;

// Extend a device authorization
let ext_config = DeviceExtensionConfig {
    repo_path: PathBuf::from("~/.auths"),
    device_did: "did:key:z6Mk...".into(),
    days: 90,
    identity_key_alias: "main".into(),
    device_key_alias: "macbook-pro".into(),
};
let result = extend_device(ext_config, &ctx)?;
```

### Signing (`signing`)

Sign artifacts and commits programmatically.

```rust
use auths_sdk::signing::sign_artifact;
```

### Pairing (`pairing`)

Device pairing orchestration over ephemeral ECDH sessions (QR code / short code flows).

### Registration (`registration`)

Publish identities to a remote registry for public DID discovery.

### Platform Verification (`platform`)

Create and verify platform identity claims (GitHub, GitLab).

### Key Management (`keys`)

Import and manage key material in the platform keychain.

---

## Workflows

Higher-level orchestrations combining multiple SDK operations.

| Workflow | Module | Description |
|---|---|---|
| Identity provisioning | `workflows::provision` | Full identity lifecycle setup |
| Key rotation | `workflows::rotation` | KERI pre-rotation with keychain persistence |
| Artifact signing | `workflows::artifact` | Digest computation + attestation creation |
| Git audit | `workflows::audit` | Signing compliance reports over commit ranges |
| Diagnostics | `workflows::diagnostics` | System health checks (keychain, git, identity) |
| Org management | `workflows::org` | Add/revoke/list organization members |
| Policy diff | `workflows::policy_diff` | Compare authorization policy versions |
| Commit signing | `workflows::signing` | Three-tier fallback (agent → auto-start → direct) |

---

## Port Traits

The SDK defines port traits that presentation layers must implement. This keeps the SDK free of filesystem, subprocess, and network dependencies.

| Port | Module | Description |
|---|---|---|
| `AgentSigningPort` | `ports::agent` | Delegate signing to a running agent daemon |
| `ArtifactSource` | `ports::artifact` | Compute digests and read artifact metadata |
| `DiagnosticProvider` | `ports::diagnostics` | System health check data |
| `GitLogProvider` | `ports::git` | Read git log entries for audit workflows |
| `GitConfigProvider` | `ports::git_config` | Set git config keys without subprocess calls |

The CLI implements these ports as thin adapters over system binaries and platform APIs. Alternative runtimes (WASM, cloud, mobile) provide their own implementations.

---

## Error Handling

All SDK operations return domain-specific `thiserror` enums. `anyhow` is not used in this crate.

| Error Type | Used By | Key Variants |
|---|---|---|
| `SetupError` | Identity setup | `IdentityAlreadyExists`, `KeychainUnavailable`, `CryptoError` |
| `DeviceError` | Device link/revoke | `IdentityNotFound`, `DeviceNotFound`, `AttestationError` |
| `DeviceExtensionError` | Device extend | `AlreadyRevoked`, `NoAttestationFound` |
| `RotationError` | Key rotation | `KeyNotFound`, `PartialRotation`, `KelHistoryFailed` |
| `RegistrationError` | Registry publish | `AlreadyRegistered`, `QuotaExceeded`, `NetworkError` |
| `OrgError` | Org management | `AdminNotFound`, `MemberNotFound`, `InvalidCapability` |

CLI and server crates wrap these with `anyhow::Context` at the translation boundary:

```rust
// In auths-cli (presentation layer)
let signature = sign_artifact(&config, data)
    .with_context(|| format!("Failed to sign artifact for namespace: {}", ns))?;
```

---

## Testing

Enable the `test-utils` feature for test helpers:

```toml
[dev-dependencies]
auths-sdk = { workspace = true, features = ["test-utils"] }
```

The `testing` module (behind `test-utils` feature) provides mock implementations and builders for constructing test `AuthsContext` instances without real keychain or filesystem access.

Tests live in `tests/integration.rs` with submodules under `tests/cases/`. Add new test files as `tests/cases/<topic>.rs` and re-export from `tests/cases/mod.rs`.

---

## Design Principles

- **No I/O in the SDK** — all filesystem, network, and subprocess access is injected via port traits
- **No interactive prompts** — the SDK never reads stdin, opens browsers, or prints to stdout
- **Typed errors only** — `thiserror` enums with `#[non_exhaustive]`, no `anyhow` or `Box<dyn Error>`
- **Clock injection** — all time-sensitive operations accept `now: DateTime<Utc>` from the context clock; zero `Utc::now()` calls in SDK code
- **Config as plain data** — config structs are serializable PODs with builders; `AuthsContext` carries the trait objects separately
- **Deny unsafe patterns** — `#![deny(clippy::unwrap_used, clippy::expect_used)]` enforced crate-wide; `#![deny(clippy::print_stdout, clippy::print_stderr, clippy::exit)]`
