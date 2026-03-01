# Enterprise Hexagonal Refactoring Plan

> Technical Due Diligence Audit & M&A Readiness Transformation
> Date: 2026-02-26

## Executive Summary

This plan details the transformation of the auths codebase from a developer-centric CLI tool into an enterprise-grade, headless-first identity and policy engine. The goal: make the Core IP (KERI identity verification, decentralized policy evaluation, cryptographic challenge-response pipelines) fully embeddable by tier-one identity providers (Okta, Ping Identity, Cloudflare).

The codebase already has **strong architectural foundations** — 21 crates, a ports/adapters pattern in `auths-core` with `StorageDriver` and `NetworkDriver` traits, dedicated `auths-infra-git` and `auths-infra-http` adapter crates, and a well-structured `auths-sdk` orchestration layer. However, the audit reveals **35 business logic violations in auths-cli**, **pervasive side-effect pollution** across core crates, and **deep git2 coupling** in `auths-id` that prevents WASM compilation.

---

## Current Architecture (What's Good)

```
auths-crypto          → (no inter-crate deps, pure crypto)
auths-policy          → (no inter-crate deps, pure policy AST)
auths-telemetry       → (no inter-crate deps, event pipeline)
auths-verifier        → auths-crypto (minimal, FFI/WASM ready)

auths-core            → auths-verifier
  └─ ports/storage/   → RefReader, RefWriter, BlobReader, BlobWriter, EventLogReader, EventLogWriter
  └─ ports/network/   → IdentityResolver, WitnessClient, RegistryClient

auths-infra-git       → auths-core (GitBlobStore, GitEventLog, GitRefStore)
auths-infra-http      → auths-core (HttpIdentityResolver, HttpWitnessClient, HttpRegistryClient)

auths-id              → auths-core, auths-crypto, auths-policy, auths-verifier
auths-sdk             → auths-core, auths-id, auths-crypto, auths-verifier
auths-cli             → auths-sdk, auths-core, auths-id, auths-infra-git, auths-infra-http
```

---

## Audit Findings Summary

| Category | Violation Count | Severity | Crates Affected |
|----------|----------------|----------|-----------------|
| Business logic in CLI | 35 instances | CRITICAL | auths-cli |
| println!/eprintln! in core | 20+ instances | CRITICAL | auths-core, auths-id |
| std::env::var in core | 12 instances | HIGH | auths-core, auths-id, auths-sdk |
| std::process::Command in core | 3 instances | HIGH | auths-core, auths-sdk |
| std::fs:: in core | 25+ instances | HIGH | auths-core, auths-id |
| Hardcoded stdout in telemetry | 1 critical path | MEDIUM | auths-telemetry |
| git2 coupling in auths-id | 23 files | CRITICAL | auths-id |
| Utc::now() in core | 10+ instances | LOW | auths-core |

---

---

### Story 2.3: Eliminate Environment Variable Coupling from Core

**All `std::env::var` occurrences outside CLI/servers:**

| File | Lines | Variable |
|------|-------|----------|
| `crates/auths-core/src/paths.rs` | 19, 68, 75 | `AUTHS_HOME` |
| `crates/auths-core/src/storage/encrypted_file.rs` | 110, 488 | `AUTHS_PASSPHRASE` |
| `crates/auths-core/src/storage/keychain.rs` | 79, 157, 163 | `AUTHS_KEYCHAIN_BACKEND`, `AUTHS_KEYCHAIN_FILE`, `AUTHS_PASSPHRASE` |
| `crates/auths-core/src/api/runtime.rs` | 539 | `SSH_AUTH_SOCK` |
| `crates/auths-id/src/keri/cache.rs` | 64, 359 | `AUTHS_HOME` |
| `crates/auths-id/src/keri/kel.rs` | 626 | `AUTHS_HOME` |
| `crates/auths-sdk/src/setup.rs` | (doc comments only) | `AUTHS_PASSPHRASE` |

**Fix pattern** — Replace env reads with a unified `AppConfig` context injected once at the SDK boundary.

> **Architectural note — avoid prop drilling**: Naively replacing each `std::env::var` with an explicit function parameter creates "prop drilling" where every intermediate function in the call chain must accept and forward config values it doesn't use. Instead, define a single `EnvironmentConfig` struct injected once at the SDK entry point and threaded via a shared reference (`&EnvironmentConfig` or `Arc<EnvironmentConfig>`). Individual subsystems (keychain, paths, crypto) read only the fields they need from this shared context. This avoids both the global state anti-pattern AND the prop-drilling anti-pattern.

> **Builder pattern**: To make isolated test setups easy without writing monolithic instantiation blocks, `EnvironmentConfig` implements the Builder pattern. Tests construct partial configurations fluently; production code uses `from_env()` at the CLI boundary.

```rust
// crates/auths-sdk/src/config.rs — NEW — Unified configuration context
/// All environment-sourced configuration, parsed once at the boundary.
///
/// Args:
/// * `auths_home`: Override for ~/.auths directory. Parsed from AUTHS_HOME.
/// * `keychain`: Keychain backend selection and credentials.
/// * `ssh_agent_socket`: Path to SSH agent socket. Parsed from SSH_AUTH_SOCK.
///
/// Usage:
/// ```ignore
/// // Production (CLI main):
/// let config = EnvironmentConfig::from_env()?;
/// let sdk = AuthsSdk::new(&config);
///
/// // Test:
/// let config = EnvironmentConfig::builder()
///     .auths_home("/tmp/test-auths")
///     .keychain_backend(KeychainBackend::Memory)
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct EnvironmentConfig {
    pub auths_home: Option<PathBuf>,
    pub keychain: KeychainConfig,
    pub ssh_agent_socket: Option<PathBuf>,
    pub passphrase: Option<String>,
}

impl EnvironmentConfig {
    pub fn builder() -> EnvironmentConfigBuilder {
        EnvironmentConfigBuilder::default()
    }
}

#[derive(Debug, Default)]
pub struct EnvironmentConfigBuilder {
    auths_home: Option<PathBuf>,
    keychain_backend: Option<KeychainBackend>,
    keychain_file_path: Option<PathBuf>,
    ssh_agent_socket: Option<PathBuf>,
    passphrase: Option<String>,
}

impl EnvironmentConfigBuilder {
    pub fn auths_home(mut self, path: impl Into<PathBuf>) -> Self {
        self.auths_home = Some(path.into());
        self
    }
    pub fn keychain_backend(mut self, backend: KeychainBackend) -> Self {
        self.keychain_backend = Some(backend);
        self
    }
    pub fn passphrase(mut self, passphrase: impl Into<String>) -> Self {
        self.passphrase = Some(passphrase.into());
        self
    }
    // ... other setters ...
    pub fn build(self) -> EnvironmentConfig {
        EnvironmentConfig {
            auths_home: self.auths_home,
            keychain: KeychainConfig {
                backend: self.keychain_backend.unwrap_or_default(),
                file_path: self.keychain_file_path,
            },
            ssh_agent_socket: self.ssh_agent_socket,
            passphrase: self.passphrase,
        }
    }
}

#[derive(Debug, Clone)]
pub struct KeychainConfig {
    pub backend: KeychainBackend,
    pub file_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Default)]
pub enum KeychainBackend {
    #[default]
    System,
    File,
    Memory,
}
```

> **Configuration layering**: Manual `std::env::var` parsing solves the immediate coupling issue, but enterprise providers require hierarchical configuration with a deterministic merge order. Instead of hand-mapping env vars, use [figment](https://docs.rs/figment) (or `config-rs`) to define a layered configuration pipeline:
>
> 1. **Hardcoded defaults** (compiled into the binary)
> 2. **Config file** (`~/.auths/auths.toml` or `/etc/auths/auths.toml`)
> 3. **Environment variables** (`AUTHS_HOME`, `AUTHS_KEYCHAIN_BACKEND`, etc.)
> 4. **CLI argument overrides** (highest priority)
>
> This is standard for enterprise deployments where ops teams need file-based config for fleet management, while developers override via env vars and CLI flags.

```rust
// crates/auths-cli/src/main.rs — Layered config via figment
use figment::{Figment, providers::{Serialized, Toml, Env, Format}};

fn build_config(cli_overrides: &CliArgs) -> Result<EnvironmentConfig> {
    let config: EnvironmentConfig = Figment::new()
        // Layer 1: Hardcoded defaults
        .merge(Serialized::defaults(EnvironmentConfig::default()))
        // Layer 2: Config file (optional)
        .merge(Toml::file("~/.auths/auths.toml").nested())
        // Layer 3: Environment variables (AUTHS_ prefix)
        .merge(Env::prefixed("AUTHS_").split("_"))
        // Layer 4: CLI argument overrides (highest priority)
        .merge(Serialized::defaults(cli_overrides.to_config_overrides()))
        .extract()
        .context("Failed to load configuration")?;
    Ok(config)
}
```

```rust
// For non-CLI consumers (e.g., embedded SDK in a cloud service), figment is not required.
// They construct EnvironmentConfig directly via the builder:
let config = EnvironmentConfig::builder()
    .auths_home("/opt/auths")
    .keychain_backend(KeychainBackend::Memory)
    .build();
```

```rust
// Subsystems read from the shared context — no prop drilling
// crates/auths-core/src/storage/keychain.rs (after)
pub fn create_keychain(config: &KeychainConfig) -> Result<Box<dyn KeyStorage>, KeychainError> {
    match config.backend {
        KeychainBackend::System => { ... }
        KeychainBackend::File => { ... }
        KeychainBackend::Memory => { ... }
    }
}
```

**Files to change:**
- `crates/auths-sdk/src/config.rs` — **NEW** — `EnvironmentConfig` and sub-config structs
- `crates/auths-sdk/src/lib.rs` — Add `pub mod config;`, update SDK entry points to accept `&EnvironmentConfig`
- `crates/auths-core/src/paths.rs` — Accept `auths_home: Option<&Path>` parameter instead of reading env
- `crates/auths-core/src/storage/encrypted_file.rs` — Accept passphrase via parameter
- `crates/auths-core/src/storage/keychain.rs` — Accept `&KeychainConfig` struct
- `crates/auths-core/src/api/runtime.rs` — Accept SSH socket path from config
- `crates/auths-id/src/keri/cache.rs` — Accept home path via parameter
- `crates/auths-id/src/keri/kel.rs` — Accept home path via parameter
- `crates/auths-cli/src/main.rs` — Parse env vars here, build `EnvironmentConfig`, pass to SDK
- `crates/auths-sdk/src/types.rs` — Reference `EnvironmentConfig` fields from setup configs

### Story 2.4: Remove std::process::Command from Core/SDK

**Violations:**

| File | Lines | Command |
|------|-------|---------|
| `crates/auths-core/src/api/runtime.rs` | 659 | `Command::new("ssh-add")` |
| `crates/auths-core/src/testing/builder.rs` | 191 | `Command::new("git")` |
| `crates/auths-sdk/src/setup.rs` | 311 | `Command::new("git")` |

**Fix**:
- `runtime.rs` — Define `SshAgentProvider` trait in `auths-core::ports`, implement in CLI
- `testing/builder.rs` — Acceptable in test-only code; add `#[cfg(test)]` guard if not present
- `setup.rs` — Define `GitConfigProvider` trait in SDK ports, implement in CLI

> **Test harness exemption**: The strict ban on `std::process::Command` applies to production code in core/SDK crates. However, test utilities and infrastructure scripts (like integration test setups that initialize fresh Git repositories) legitimately require subprocess execution. The `auths-test-utils` crate is explicitly whitelisted — it is a `[dev-dependencies]`-only crate and never compiles into production binaries. Ensure CI grep checks and clippy lint denials exclude `auths-test-utils` so the headless testing infrastructure is not broken by its own guardrails. The `#[cfg(test)]` modules within production crates are also exempt (clippy respects this automatically).

**Files to change:**
- `crates/auths-core/src/ports/ssh_agent.rs` — **NEW** — `SshAgentProvider` trait
- `crates/auths-core/src/api/runtime.rs` — Use injected provider
- `crates/auths-sdk/src/ports/git_config.rs` — **NEW** — `GitConfigProvider` trait
- `crates/auths-sdk/src/setup.rs` — Use injected provider
- `crates/auths-cli/src/adapters/ssh_agent.rs` — **NEW** — System adapter
- `crates/auths-cli/src/adapters/git_config.rs` — **NEW** — System adapter

### Story 2.5: Decouple Telemetry Sinks

**Why**: `crates/auths-telemetry/src/emitter.rs` hardcodes `tokio::io::BufWriter::new(tokio::io::stdout())` (line 79). Embedding the SDK requires telemetry routable to arbitrary sinks.

**Files to change:**
- `crates/auths-telemetry/src/ports.rs` — **NEW** — `EventSink` trait definition
- `crates/auths-telemetry/src/sinks/mod.rs` — **NEW** — Sink module root
- `crates/auths-telemetry/src/sinks/stdout.rs` — **NEW** — `StdoutSink` adapter (current behavior)
- `crates/auths-telemetry/src/sinks/memory.rs` — **NEW** — `MemorySink` for testing
- `crates/auths-telemetry/src/emitter.rs` — Accept `EventSink`, remove hardcoded stdout
- `crates/auths-telemetry/src/lib.rs` — Update exports

> **Distributed Trace Propagation (W3C Trace Context)**: Tier-one enterprise deployments mandate distributed tracing to correlate identity evaluations across microservices. Currently, the codebase has no OpenTelemetry integration — `auths-registry-server` generates isolated UUID v4 trace IDs in `middleware/trace.rs`, and `AuditEvent` in `auths-telemetry/src/event.rs` has no trace correlation field. When standardizing the `EventSink` pipeline:
>
> 1. Add an optional `trace_id: Option<String>` field to `AuditEvent` to carry W3C `traceparent` IDs.
> 2. When a request enters `auths-auth-server` or `auths-registry-server`, extract the W3C `traceparent` header (if present) and propagate the trace ID into a `tracing::Span` field.
> 3. The SDK orchestration layer must accept an optional trace context parameter so that any `emit_telemetry()` calls within domain workflows can attach the originating request's trace ID.
> 4. This does NOT require adding `opentelemetry` as a dependency to core crates. The trace ID is just a string propagated through the `EventSink` interface. Full OpenTelemetry collector integration (OTLP export, span batching) is a presentation-layer concern wired in the server crates.
>
> This ensures a SOC analyst can correlate a SIEM alert (e.g., "attestation_parse_failure") back to the specific HTTP request that triggered it, across service boundaries.

**Port definition:**
```rust
// crates/auths-telemetry/src/ports.rs
#[async_trait::async_trait]
pub trait EventSink: Send + Sync + 'static {
    async fn emit(&self, payload: &str) -> Result<(), SinkError>;
    async fn flush(&self) -> Result<(), SinkError>;
}
```

**Refactored emitter:**
```rust
// crates/auths-telemetry/src/emitter.rs (after)
pub fn init_telemetry_with_sink(
    capacity: usize,
    sink: Box<dyn EventSink>,
) -> TelemetryShutdown {
    // ... spawn background worker using injected sink ...
}

pub fn init_telemetry(capacity: usize) -> TelemetryShutdown {
    init_telemetry_with_sink(capacity, Box::new(StdoutSink::new()))
}
```

### Story 2.6: Audit Policy Purity

**Why**: `auths-policy` must evaluate deterministic rules. Verify no hidden I/O or `Utc::now()` calls.

**Current state**: `auths-policy` has **no inter-crate dependencies** and **no detected side effects**. The `EvalContext` correctly injects `now: DateTime<Utc>`.

**However**, `auths-core` policy modules have `Utc::now()` calls:

| File | Lines | Context |
|------|-------|---------|
| `crates/auths-core/src/pairing/token.rs` | 81, 93 | Pairing expiry |
| `crates/auths-core/src/witness/storage.rs` | 97, 157 | Witness timestamps |
| `crates/auths-core/src/trust/pinned.rs` | 276 | Trust pin first_seen |
| `crates/auths-core/src/trust/resolve.rs` | 146, 217 | Trust resolution first_seen |

**Fix**: Rather than injecting `now: DateTime<Utc>` into every function signature (which pushes prop drilling up the call stack), define a `ClockProvider` trait in `auths-core::ports`. The SDK injects a `SystemClock` in production and a `MockClock` in tests. This is consistent with the port-adapter pattern used for storage and network — time is just another external dependency.

```rust
// crates/auths-core/src/ports/clock.rs — NEW
/// Provides the current timestamp. Abstracted for deterministic testing.
///
/// Usage:
/// ```ignore
/// let clock: &dyn ClockProvider = &SystemClock;
/// let now = clock.now();
/// ```
pub trait ClockProvider: Send + Sync {
    fn now(&self) -> DateTime<Utc>;
}

pub struct SystemClock;

impl ClockProvider for SystemClock {
    fn now(&self) -> DateTime<Utc> {
        Utc::now()
    }
}
```

```rust
// crates/auths-test-utils/src/fakes/clock.rs — NEW
pub struct MockClock {
    frozen: DateTime<Utc>,
}

impl MockClock {
    pub fn frozen_at(time: DateTime<Utc>) -> Self {
        Self { frozen: time }
    }
}

impl ClockProvider for MockClock {
    fn now(&self) -> DateTime<Utc> {
        self.frozen
    }
}
```

**Files to change:**
- `crates/auths-core/src/ports/clock.rs` — **NEW** — `ClockProvider` trait + `SystemClock`
- `crates/auths-core/src/ports/mod.rs` — Add `pub mod clock;`
- `crates/auths-test-utils/src/fakes/clock.rs` — **NEW** — `MockClock`
- `crates/auths-core/src/pairing/token.rs` — Accept `&dyn ClockProvider` instead of calling `Utc::now()`
- `crates/auths-core/src/witness/storage.rs` — Accept `&dyn ClockProvider`
- `crates/auths-core/src/trust/pinned.rs` — Accept `&dyn ClockProvider`
- `crates/auths-core/src/trust/resolve.rs` — Accept `&dyn ClockProvider`

---

## Epic 3: Abstract Git-Backed Identity Storage

**Objective**: Eliminate the hard dependency on `git2` within `auths-id` so the identity engine can compile to `wasm32-unknown-unknown` for edge deployments.

**Success Metrics**: `auths-id` compiles with `wasm32-unknown-unknown`. Zero direct `git2` references in `auths-id`.

**Current state**: 23 files in `auths-id` directly import `git2`. The crate defines its own storage traits (`IdentityStorage`, `AttestationSource`, `AttestationSink`, `RegistryBackend`) but all implementations are git2-specific.

### Story 3.1: Define Abstract RegistryDriver Port

**Why**: `auths-id` bypasses the `StorageDriver` traits in `auths-core`. The `PackedRegistryBackend` uses `git2` and blocking file I/O directly. To run on Cloudflare Workers, identity logic must use abstract interfaces.

**Files to change:**
- `crates/auths-id/src/ports/mod.rs` — **NEW** — Port module root
- `crates/auths-id/src/ports/registry.rs` — **NEW** — `RegistryDriver` trait

**Note**: `auths-id` already has a `RegistryBackend` trait in `crates/auths-id/src/storage/registry/backend.rs` (lines 268-601). The task is to:
1. Make this trait generic (remove git2 types from signatures)
2. Ensure all return types are domain types, not `git2::Error`
3. Move the trait to a ports module

**Port definition:**

> **Documentation mandate**: The trait must clearly document expected state transitions and error conditions for every method using the standard `Description / Args / Usage` format. This is the contract that fakes and real adapters must both honor — ambiguity here causes contract test failures downstream.

```rust
// crates/auths-id/src/ports/registry.rs

/// Abstraction over identity and attestation storage.
///
/// Implementations must guarantee:
/// - `append_event` is linearizable per prefix (no concurrent appends to same prefix).
/// - `get_event` returns `None` for non-existent prefix/sequence, never errors.
/// - `store_attestation` overwrites any existing attestation for the same device DID.
/// - All methods return domain `RegistryError`, never storage-backend-specific errors.
pub trait RegistryDriver: Send + Sync {
    /// Retrieves a KERI event by prefix and sequence number.
    ///
    /// Args:
    /// * `prefix`: The KERI identifier prefix (e.g., "EXq5YqaL...").
    /// * `sequence`: Zero-based event sequence number.
    ///
    /// Returns `Ok(None)` if prefix or sequence does not exist.
    /// Returns `Err(RegistryError::Storage)` on backend failure.
    fn get_event(&self, prefix: &str, sequence: u64) -> Result<Option<KeriEvent>, RegistryError>;

    /// Appends a new event to the KEL for the given prefix.
    ///
    /// Args:
    /// * `prefix`: The KERI identifier prefix.
    /// * `event`: The event to append. Must have `sequence == current_length`.
    ///
    /// Returns `Err(RegistryError::SequenceGap)` if event.sequence != next expected.
    /// Returns `Err(RegistryError::DuplicateEvent)` if sequence already exists.
    fn append_event(&self, prefix: &str, event: &KeriEvent) -> Result<(), RegistryError>;

    fn get_key_state(&self, prefix: &str) -> Result<Option<KeyState>, RegistryError>;
    fn store_attestation(&self, device_did: &str, attestation: &Attestation) -> Result<(), RegistryError>;
    fn load_attestation(&self, device_did: &str) -> Result<Option<Attestation>, RegistryError>;
    // ... all operations from current RegistryBackend, but with domain-only types
}
```

### Story 3.2: Extract git2 Adapter from auths-id

**Why**: All git2-specific code must move out of `auths-id` into the existing `auths-infra-git` crate

**23 files with direct git2 imports in auths-id:**

| File | git2 usage |
|------|-----------|
| `src/storage/registry/packed.rs` | `git2::{Oid, Repository, Signature, Tree}` — Main backend |
| `src/storage/registry/tree_ops.rs` | Tree manipulation |
| `src/storage/registry/backend.rs` | Error wrapping `git2::Error` |
| `src/storage/identity.rs` | `git2::{ErrorCode, Repository, Signature}` |
| `src/storage/keri.rs` | `git2::{Commit, ErrorCode, Oid, Repository, Signature}` |
| `src/storage/attestation.rs` | `git2::{ErrorCode, Repository, Tree}` |
| `src/storage/git_refs.rs` | `git2::Repository` |
| `src/attestation/export.rs` | `git2::{Repository, Signature, Tree}` |
| `src/keri/cache.rs` | Filesystem operations (not git2 directly) |
| `src/freeze.rs` | `std::fs` operations |
| `src/agent_identity.rs` | `std::fs` operations |
| + ~12 more files | Various git2 operations |

**Files to change:**
- `crates/auths-infra-git/src/registry.rs` — **NEW** — Move `PackedRegistryBackend` here
- `crates/auths-infra-git/src/identity_storage.rs` — **NEW** — Move `GitIdentityStorage` here
- `crates/auths-infra-git/src/attestation_storage.rs` — **NEW** — Move git2-based attestation ops
- `crates/auths-infra-git/src/keri_storage.rs` — **NEW** — Move KEL git storage
- `crates/auths-infra-git/Cargo.toml` — Add `auths-id` dependency for trait impls
- `crates/auths-id/Cargo.toml` — **REMOVE** `git2` dependency
- `crates/auths-id/src/storage/` — Refactor all modules to use traits instead of git2 directly

**Dependency after refactor:**
```
auths-id (pure domain, no git2)
  ↑
auths-infra-git (implements RegistryDriver with git2)
  ↑
auths-cli / auths-registry-server (wires adapter to domain)
```

### Story 3.3: Abstract Filesystem Operations in auths-id

**Files with direct `std::fs` usage in auths-id:**

| File | Lines | Operation |
|------|-------|-----------|
| `src/storage/registry/packed.rs` | 342, 417-418, 433 | Dir creation, file write/rename/read |
| `src/keri/cache.rs` | 19+ | Full fs module import |
| `src/freeze.rs` | 70, 80, 89, 98 | Read, remove, write freeze state |
| `src/agent_identity.rs` | 186, 356 | Dir creation, config file write |

**Fix**: These filesystem operations should use the `BlobReader`/`BlobWriter` ports from `auths-core`

> **Error mapping mandate**: When replacing `std::fs` operations with port-based abstractions, map all `std::io::Error` variants into domain-specific `thiserror` enums. Never leak `std::io::Error` through the abstraction boundary. Example:
> ```rust
> #[derive(Debug, thiserror::Error)]
> pub enum StorageError {
>     #[error("resource not found: {path}")]
>     NotFound { path: String },
>     #[error("permission denied: {path}")]
>     PermissionDenied { path: String },
>     #[error("concurrent modification detected")]
>     ConcurrentModification,
>     #[error("storage backend failure: {0}")]
>     Backend(String),
> }
> ```
> This allows consuming code to programmatically react to failure modes without `downcast_ref::<std::io::Error>()`.

### Story 3.4: Registry State Migration Pipeline

**Why**: Abstracting `RegistryDriver` away from `git2` (Stories 3.1–3.3) creates a data portability gap. Legacy users store identity state in the local `~/.auths` git repository. An enterprise platform embedding the SDK with a `PostgresRegistryAdapter` needs a way to hydrate state from the git backend — and vice versa. The existing `auths-cli/src/commands/id/migrate.rs` handles GPG/SSH key migration into auths identities, but there is no backend-to-backend registry state transfer mechanism.

> **Design note — driver-level bridge, not format-level**: This is NOT a file export/import (like JSON dump). It operates at the `RegistryDriver` trait level — reading events, key states, and attestations from one driver and writing them to another. This means any two `RegistryDriver` implementations are automatically interoperable without format-specific serialization code.

**Files to change:**
- `crates/auths-sdk/src/workflows/migration.rs` — **NEW** — `migrate_registry()` pipeline
- `crates/auths-sdk/src/workflows/mod.rs` — Add `pub mod migration;`
- `crates/auths-id/src/ports/registry.rs` — Add `list_prefixes()` and `list_device_dids()` methods to `RegistryDriver` trait

**Port extension:**
```rust
// Added to RegistryDriver trait (crates/auths-id/src/ports/registry.rs)
/// Lists all known KERI identifier prefixes in the registry.
fn list_prefixes(&self) -> Result<Vec<String>, RegistryError>;

/// Lists all device DIDs that have stored attestations.
fn list_device_dids(&self) -> Result<Vec<String>, RegistryError>;
```

**Migration pipeline:**
```rust
// crates/auths-sdk/src/workflows/migration.rs
/// Migrates complete registry state between two storage backends.
///
/// Reads all KERI event logs and attestations from the source driver
/// and writes them to the destination. Operates at the trait level,
/// making any two RegistryDriver implementations interoperable.
///
/// Args:
/// * `source`: The driver to read state from.
/// * `destination`: The driver to write state to.
///
/// Usage:
/// ```ignore
/// let git_driver = Git2RegistryAdapter::open(&repo_path)?;
/// let pg_driver = PostgresRegistryAdapter::connect(&db_url).await?;
/// migrate_registry(&git_driver, &pg_driver)?;
/// ```
pub fn migrate_registry(
    source: &dyn RegistryDriver,
    destination: &dyn RegistryDriver,
) -> Result<MigrationReport, MigrationError> {
    let prefixes = source.list_prefixes()?;
    for prefix in &prefixes {
        transfer_event_log(source, destination, prefix)?;
        if let Some(key_state) = source.get_key_state(prefix)? {
            // Transfer derived key state
        }
    }
    let device_dids = source.list_device_dids()?;
    for did in &device_dids {
        transfer_attestation(source, destination, did)?;
    }
    Ok(MigrationReport { prefixes_migrated: prefixes.len(), devices_migrated: device_dids.len() })
}
```

### Story 4.2: Formalize InMemorySessionStore

**Why**: `auths-auth-server` has an ad-hoc `InMemorySessionStore` used in fuzz tests. This should be formalized in `auths-test-utils`.

**Files to change:**
- `crates/auths-test-utils/src/fakes/session.rs` — **NEW** — `InMemorySessionStore`
- `crates/auths-auth-server/src/adapters/memory_store.rs` — Import from test-utils instead of defining locally

### Story 4.3: Create MemoryEventSink

**Files to change:**
- `crates/auths-test-utils/src/fakes/telemetry.rs` — **NEW** — `MemoryEventSink`

```rust
// crates/auths-test-utils/src/fakes/telemetry.rs
// EventSink is async — use runtime-agnostic async_lock::Mutex for WASM compatibility
pub struct MemoryEventSink {
    events: Arc<async_lock::Mutex<Vec<String>>>,
}

#[async_trait::async_trait]
impl EventSink for MemoryEventSink {
    async fn emit(&self, payload: &str) -> Result<(), SinkError> {
        self.events.lock().await.push(payload.to_string());
        Ok(())
    }

    async fn flush(&self) -> Result<(), SinkError> {
        Ok(())
    }
}
```

### Story 4.4: Create FakeGitLogProvider with Bidirectional Stream Assertions

**Why**: The current test infrastructure (`auths-test-utils`) has no subprocess mocking — only `InMemoryStorage` for storage ports. Multiple production code paths rely on piped `stdin`/`stdout` subprocesses: `ssh-keygen` verification in `auths-cli/src/commands/verify_commit.rs` and `auths-registry-server/src/routes/verify_commit.rs`, plus `run_with_stdin()` in `xtask/src/shell.rs`. The `FakeGitLogProvider` and related fakes must not merely mock static stdout strings — they must support bidirectional byte stream assertions.

> **Bidirectional mock design**: Build test harness utilities as small, composable mock functions rather than monolithic mock objects. Each mock function configures a single expected request/response pair, allowing tests to flexibly compose expected bidirectional byte streams:
>
> ```rust
> // crates/auths-test-utils/src/fakes/git.rs
> pub struct FakeGitLogProvider {
>     commits: Vec<CommitRecord>,
> }
>
> impl FakeGitLogProvider {
>     pub fn with_commits(commits: Vec<CommitRecord>) -> Self {
>         Self { commits }
>     }
> }
>
> // For subprocess-dependent code paths (ssh-keygen, git), provide composable stream mocks:
> // crates/auths-test-utils/src/fakes/subprocess.rs — NEW
> pub struct MockSubprocess {
>     expected_stdin: Option<Vec<u8>>,
>     stdout_response: Vec<u8>,
>     exit_code: i32,
> }
>
> impl MockSubprocess {
>     pub fn expecting_stdin(mut self, data: &[u8]) -> Self {
>         self.expected_stdin = Some(data.to_vec());
>         self
>     }
>
>     pub fn responding_with(mut self, data: &[u8]) -> Self {
>         self.stdout_response = data.to_vec();
>         self
>     }
>
>     /// Validates that the byte stream piped into stdin matches expectations.
>     pub fn assert_stdin_received(&self, actual: &[u8]) {
>         if let Some(expected) = &self.expected_stdin {
>             assert_eq!(actual, expected.as_slice(),
>                 "subprocess stdin mismatch");
>         }
>     }
> }
> ```
>
> This composable approach lets tests assert against the exact bytes the SDK pipes into subprocesses — catching serialization regressions, encoding mismatches, and protocol changes that static stdout-only mocks would miss.

**Files to change:**
- `crates/auths-test-utils/src/fakes/git.rs` — **NEW** — `FakeGitLogProvider`
- `crates/auths-test-utils/src/fakes/subprocess.rs` — **NEW** — `MockSubprocess` composable stream mock

### Story 4.5: Contract Tests for Fake-to-Real Behavioral Parity

**Why**: Relying entirely on `FakeRegistryDriver` for headless testing is ideal for speed, but carries the risk of the fake silently drifting from the behavior of the real `PackedRegistryBackend` (or `Git2LogProvider`, `InMemorySessionStore`, etc.). If the fake accepts an input the real adapter rejects — or returns a different shape — SDK tests pass green while production breaks. This is the classic "mock drift" problem that undermines confidence in the test suite.

**Solution**: Introduce shared **contract test suites** — a single set of integration tests parameterized over the trait, run against BOTH the fake and the real adapter. If a contract test passes against `FakeRegistryDriver` but fails against `Git2RegistryAdapter`, the fake is wrong and must be updated. This guarantees absolute behavioral parity.

**Pattern:**
```rust
// crates/auths-test-utils/src/contracts/registry.rs — NEW
/// Contract test suite that any RegistryDriver implementation must pass.
/// Run against both FakeRegistryDriver and Git2RegistryAdapter.
///
/// Usage:
/// ```ignore
/// registry_driver_contract_tests!(FakeRegistryDriver::new());
/// registry_driver_contract_tests!(Git2RegistryAdapter::open(&temp_repo)?);
/// ```
#[macro_export]
macro_rules! registry_driver_contract_tests {
    ($driver_expr:expr) => {
        #[test]
        fn contract_append_then_get_event() {
            let driver = $driver_expr;
            let event = test_inception_event();
            driver.append_event("EXq5", &event).unwrap();
            let retrieved = driver.get_event("EXq5", 0).unwrap();
            assert_eq!(retrieved, Some(event));
        }

        #[test]
        fn contract_get_nonexistent_returns_none() {
            let driver = $driver_expr;
            let retrieved = driver.get_event("nonexistent", 0).unwrap();
            assert_eq!(retrieved, None);
        }

        #[test]
        fn contract_store_then_load_attestation() {
            let driver = $driver_expr;
            let att = test_attestation();
            driver.store_attestation("did:key:z6Mk...", &att).unwrap();
            let loaded = driver.load_attestation("did:key:z6Mk...").unwrap();
            assert_eq!(loaded, Some(att));
        }

        // ... exhaustive contract covering all RegistryDriver methods,
        // edge cases (duplicate appends, concurrent access), and error paths
    };
}
```

```rust
// crates/auths-test-utils/tests/cases/fake_registry_contract.rs
use auths_test_utils::fakes::FakeRegistryDriver;
use auths_test_utils::registry_driver_contract_tests;

registry_driver_contract_tests!(FakeRegistryDriver::new());

// crates/auths-infra-git/tests/cases/git2_registry_contract.rs
use auths_infra_git::Git2RegistryAdapter;
use auths_test_utils::registry_driver_contract_tests;

registry_driver_contract_tests!({
    let tmp = auths_test_utils::git::init_test_repo();
    Git2RegistryAdapter::open(tmp.path()).unwrap()
});
```

**Contract suites to create:**

| Contract Suite | Trait | Implementations Tested |
|---------------|-------|----------------------|
| `registry_driver_contract_tests!` | `RegistryDriver` | `FakeRegistryDriver`, `Git2RegistryAdapter` |
| `git_log_provider_contract_tests!` | `GitLogProvider` | `FakeGitLogProvider`, `Git2LogProvider` |
| `event_sink_contract_tests!` | `EventSink` | `MemoryEventSink`, `StdoutSink` |
| `session_store_contract_tests!` | `SessionStore` | `InMemorySessionStore`, `PostgresSessionStore` |

> **Isolation note**: Contract test macros live in `auths-test-utils` which is a `[dev-dependencies]`-only crate. Since `auths-test-utils` is never a production dependency of any crate, the contract test code and macros are guaranteed zero leakage into production binaries. The `contracts` module is gated behind `#[cfg(test)]` re-exports in consuming crates. Usage documentation goes in `TESTING_STRATEGY.md` (already exists in the repo) rather than creating a new file.

**Files to change:**
- `crates/auths-test-utils/src/contracts/mod.rs` — **NEW** — Contract module root
- `crates/auths-test-utils/src/contracts/registry.rs` — **NEW** — `registry_driver_contract_tests!` macro
- `crates/auths-test-utils/src/contracts/git_log.rs` — **NEW** — `git_log_provider_contract_tests!` macro
- `crates/auths-test-utils/src/contracts/event_sink.rs` — **NEW** — `event_sink_contract_tests!` macro
- `crates/auths-test-utils/src/contracts/session.rs` — **NEW** — `session_store_contract_tests!` macro
- `crates/auths-test-utils/src/lib.rs` — Add `pub mod contracts;`
- `crates/auths-infra-git/tests/cases/` — Add contract test invocations for git2 adapters
- `TESTING_STRATEGY.md` — Add section documenting contract test usage and how to add new contracts

**CI enforcement**: Contract tests run in CI alongside unit tests. A failing contract test on the real adapter means the trait semantics are under-specified. A failing contract test on the fake means the fake has drifted and must be corrected.

### Story 4.6: Migrate SDK Integration Tests to Fakes

**Files to change:**
- `crates/auths-sdk/tests/integration.rs` — Rewrite using fakes
- `crates/auths-sdk/tests/cases/` — Add test cases using FakeRegistryDriver

---

## Epic 5: CI Guardrails & Regression Prevention

**Objective**: Encode architectural boundaries into CI to prevent future regressions.

### Story 5.1: Enforce Architectural Boundaries via Clippy Lints

> **Why not shell grep**: Shell `grep` is brittle — it flags legitimate rustdoc examples, string literals containing "println", and inline comments. It also cannot distinguish between test code and production code reliably. Instead, use Clippy's built-in AST-level lints which understand Rust syntax and respect `#[cfg(test)]` boundaries.

**Approach**: Add `#![deny(...)]` attributes to the `lib.rs` of each core crate. Clippy catches violations at compile time during `cargo clippy`, which already runs in CI.

**Files to change:**
- `crates/auths-core/src/lib.rs` — Add lint denials
- `crates/auths-id/src/lib.rs` — Add lint denials
- `crates/auths-policy/src/lib.rs` — Add lint denials
- `crates/auths-verifier/src/lib.rs` — Add lint denials
- `crates/auths-sdk/src/lib.rs` — Add lint denials

**Lint configuration (add to top of each `lib.rs`):**
```rust
// crates/auths-core/src/lib.rs (and auths-id, auths-policy, auths-verifier, auths-sdk)
#![deny(clippy::print_stdout)]
#![deny(clippy::print_stderr)]
#![deny(clippy::exit)]
#![deny(clippy::dbg_macro)]
```

These lints are AST-aware:
- `clippy::print_stdout` — catches `print!()`, `println!()` but NOT `write!()` to arbitrary writers
- `clippy::print_stderr` — catches `eprint!()`, `eprintln!()`
- `clippy::exit` — catches `std::process::exit()`
- `clippy::dbg_macro` — catches leftover `dbg!()` calls

They automatically respect `#[cfg(test)]` — test modules can still use `println!` for debugging.

**Additional CI enforcement** — For checks that Clippy cannot express (reverse dependencies, env var reads), keep targeted grep checks:

```yaml
# Ban env var reads in core crates (no clippy lint for this)
- name: Check no env vars in core
  run: |
    if grep -rn 'std::env::var\b' \
      crates/auths-core/src crates/auths-id/src crates/auths-policy/src \
      crates/auths-verifier/src crates/auths-sdk/src \
      --include='*.rs' | grep -v '#\[cfg(test)\]' | grep -v '/// '; then
      echo "ERROR: env var reads found in core crates"
      exit 1
    fi

# Ban reverse dependencies (structural, not code-level)
- name: Check no reverse deps
  run: |
    if grep -rE 'auths.cli|auths.auth.server' \
      crates/auths-sdk crates/auths-core \
      --include='*.toml'; then
      echo "ERROR: reverse dependency detected"
      exit 1
    fi
```

### Story 5.2: Create ARCHITECTURE.md

**Why**: As strict interface contracts, port definitions, and layered dependency rules are established, acquiring engineering teams need a high-level map of the system. The directory structure and trait definitions are the primary source of truth, but a concise `ARCHITECTURE.md` at the repo root provides the 10-minute onboarding path for due diligence engineers evaluating the IP.

**Content requirements** (keep minimal — the code is the documentation):
- **Layer diagram**: Presentation → SDK/Orchestration → Core/Domain → Ports → Adapters
- **Dependency direction rule**: "Dependencies point inward. Adapters depend on Core. Core never depends on Adapters."
- **Port inventory**: Table of all trait ports with their crate location and known implementations
- **Crate purpose table**: One-line description per crate, grouped by architectural layer
- **What goes where**: Decision guide for "I'm adding feature X — which crate does it belong in?"

> **Documentation standards mandate**: All auxiliary documentation (`ARCHITECTURE.md`, `TESTING_STRATEGY.md` updates, contract test usage docs) must adhere strictly to `.md` format. Keep documentation lean — the structural decomposition of the code and clear variable/function naming bears the primary burden of explanation. Reserve documentation blocks strictly for API contracts using the established format (`/// Description`, `/// Args:`, `/// Usage:`). Do not add inline process-explaining comments to new code per CLAUDE.md conventions — if a function's purpose is unclear, rename it or decompose it structurally rather than commenting it.

**Files to change:**
- `ARCHITECTURE.md` — **NEW** — High-level architectural map for acquiring engineering teams

### Story 5.3: Add cargo-deny Rules

**Files to change:**
- `deny.toml` — **NEW** or modify existing — Ban git2 from auths-id, auths-core, auths-policy

### Story 5.4: API Stability Contract (MSRV & SemVer Policy)

**Why**: For tier-one identity providers (Okta, Cloudflare) to depend on `auths-sdk` and `auths-core`, these crates need a predictable API evolution policy. Currently, only `auths-oidc-bridge` and `auths-registry-server` declare `rust-version = "1.85"` in their `Cargo.toml` — the workspace root and all core crates have no MSRV. There is a `CHANGELOG.md` but no formal SemVer policy for the public-facing trait ports.

**Changes:**

1. **Define workspace-level MSRV** — Add `rust-version = "1.93"` to the `[workspace.package]` section in the root `Cargo.toml` (matching the CI toolchain). All crates inherit this via `rust-version.workspace = true`.

2. **Create `RELEASES.md`** — Strict SemVer policy for public-facing crates:
   - **Major version bump required** for: any change to `RegistryDriver`, `EventSink`, `GitLogProvider`, `ArtifactSource`, `ClockProvider` trait signatures; removal of any public type or function from `auths-core` or `auths-sdk`.
   - **Minor version bump** for: new methods with default implementations on existing traits; new public types/functions; new feature flags.
   - **Patch version bump** for: bug fixes, documentation, internal refactors with no public API change.
   - **Stability tiers**: `auths-core` and `auths-sdk` are "stable" (SemVer-enforced). `auths-cli`, server crates, and `auths-test-utils` are "unstable" (may break between minor versions).

3. **CI enforcement** — Add `cargo-semver-checks` to CI to automatically detect accidental breaking changes in stable crates.

**Files to change:**
- `Cargo.toml` (workspace root) — Add `rust-version = "1.93"` to `[workspace.package]`
- `RELEASES.md` — **NEW** — SemVer policy for public trait ports and stable crates
- `.github/workflows/ci.yml` — Add `cargo-semver-checks` step for `auths-core` and `auths-sdk`

---

## PR Sequencing Plan

Ordered to minimize risk and merge conflicts. Each PR is independently shippable.

| PR | Scope | Risk | Depends On |
|----|-------|------|------------|
| **PR-1** | Define SDK Ports (`GitLogProvider`, `ArtifactReader`, `SystemDiagnosticProvider`, `EventSink`) | Low | — |
| **PR-2** | Extract SSH crypto functions from CLI to `auths-core::crypto::ssh` | Medium | — |
| **PR-3** | Implement Adapters: `Git2LogProvider` in `auths-infra-git`, `LocalFileArtifact` in CLI | Low | PR-1 |
| **PR-4** | Replace println!/eprintln! with tracing in `auths-core` and `auths-id` | Low | — |
| **PR-5** | Decouple telemetry sinks (EventSink trait, StdoutSink, MemorySink) | Medium | PR-1 |
| **PR-6** | Migrate audit logic from CLI to SDK workflow | High | PR-1, PR-3 |
| **PR-7** | Migrate artifact hashing from CLI to SDK | Medium | PR-1, PR-3 |
| **PR-8** | Purge `std::env::var` from core/SDK; introduce unified `EnvironmentConfig` context at SDK boundary | High | — |
| **PR-9** | Define `RegistryDriver` trait in `auths-id::ports` | Low | — |
| **PR-10** | Extract git2 adapter from `auths-id` to `auths-infra-git` | High | PR-9 |
| **PR-10.1** | Registry state migration pipeline (`migrate_registry()`) | Medium | PR-9, PR-10 |
| **PR-11** | Create Fakes library (`FakeRegistryDriver`, `InMemorySessionStore`, `MemoryEventSink`) | Low | PR-1, PR-9 |
| **PR-12** | Contract test suites (`registry_driver_contract_tests!`, etc.) run against both fakes and real adapters | Medium | PR-10, PR-11 |
| **PR-13** | Migrate SDK tests to Fakes | Medium | PR-11, PR-12 |
| **PR-14** | CI guardrails (clippy lint denials, grep checks, cargo-deny) | Low | PR-4, PR-8 |
| **PR-15** | `ARCHITECTURE.md` — high-level boundary map for M&A due diligence | Low | PR-1, PR-9 |
| **PR-16** | API stability contract: workspace MSRV, `RELEASES.md` SemVer policy, `cargo-semver-checks` in CI | Low | PR-1, PR-9 |

---

## File Inventory

### New Files (44)

| File | Epic | Purpose |
|------|------|---------|
| `crates/auths-core/src/crypto/ssh/mod.rs` | 1 | SSH module root, re-exports public API |
| `crates/auths-core/src/crypto/ssh/keys.rs` | 1 | PKCS#8 parsing, seed extraction, pubkey derivation |
| `crates/auths-core/src/crypto/ssh/encoding.rs` | 1 | SSH wire format encoding (pubkey blob, signature blob) |
| `crates/auths-core/src/crypto/ssh/signatures.rs` | 1 | SSHSIG creation, signed data construction, PEM output |
| `crates/auths-core/src/ports/clock.rs` | 2 | ClockProvider trait + SystemClock |
| `crates/auths-test-utils/src/fakes/clock.rs` | 2 | MockClock for deterministic time testing |
| `crates/auths-sdk/src/ports/mod.rs` | 1 | Port module root |
| `crates/auths-sdk/src/ports/git.rs` | 1 | GitLogProvider trait |
| `crates/auths-sdk/src/ports/artifact.rs` | 1 | ArtifactReader trait |
| `crates/auths-sdk/src/ports/diagnostics.rs` | 1 | SystemDiagnosticProvider trait |
| `crates/auths-sdk/src/ports/git_config.rs` | 2 | GitConfigProvider trait |
| `crates/auths-sdk/src/workflows/mod.rs` | 1 | Workflow module root |
| `crates/auths-sdk/src/workflows/audit.rs` | 1 | AuditWorkflow |
| `crates/auths-sdk/src/workflows/artifact.rs` | 1 | Artifact digest workflow |
| `crates/auths-sdk/src/workflows/diagnostics.rs` | 1 | Health check engine |
| `crates/auths-sdk/src/signing.rs` | 1 | Signing orchestration |
| `crates/auths-sdk/src/pairing.rs` | 1 | Pairing workflow |
| `crates/auths-cli/src/adapters/mod.rs` | 1 | Adapter module root |
| `crates/auths-infra-git/src/audit.rs` | 1 | Git2LogProvider (git2-backed audit adapter) |
| `crates/auths-cli/src/adapters/local_file.rs` | 1 | LocalFileArtifact |
| `crates/auths-cli/src/adapters/system_diagnostic.rs` | 1 | System diagnostic adapter |
| `crates/auths-cli/src/adapters/ssh_agent.rs` | 2 | SSH agent adapter |
| `crates/auths-cli/src/adapters/git_config.rs` | 2 | Git config adapter |
| `crates/auths-telemetry/src/ports.rs` | 2 | EventSink trait |
| `crates/auths-telemetry/src/sinks/mod.rs` | 2 | Sink module root |
| `crates/auths-telemetry/src/sinks/stdout.rs` | 2 | StdoutSink |
| `crates/auths-telemetry/src/sinks/memory.rs` | 2 | MemorySink |
| `crates/auths-id/src/ports/mod.rs` | 3 | Port module root |
| `crates/auths-id/src/ports/registry.rs` | 3 | RegistryDriver trait |
| `crates/auths-infra-git/src/registry.rs` | 3 | PackedRegistryBackend (moved) |
| `crates/auths-test-utils/src/fakes/mod.rs` | 4 | Fakes module root |
| `crates/auths-test-utils/src/fakes/registry.rs` | 4 | FakeRegistryDriver |
| `crates/auths-test-utils/src/fakes/telemetry.rs` | 4 | MemoryEventSink |
| `crates/auths-test-utils/src/fakes/session.rs` | 4 | InMemorySessionStore |
| `crates/auths-test-utils/src/fakes/git.rs` | 4 | FakeGitLogProvider |
| `crates/auths-test-utils/src/fakes/subprocess.rs` | 4 | MockSubprocess composable stream mock |
| `crates/auths-sdk/src/config.rs` | 2 | EnvironmentConfig (unified config context) |
| `crates/auths-test-utils/src/contracts/mod.rs` | 4 | Contract test module root |
| `crates/auths-test-utils/src/contracts/registry.rs` | 4 | registry_driver_contract_tests! macro |
| `crates/auths-test-utils/src/contracts/git_log.rs` | 4 | git_log_provider_contract_tests! macro |
| `crates/auths-test-utils/src/contracts/event_sink.rs` | 4 | event_sink_contract_tests! macro |
| `crates/auths-test-utils/src/contracts/session.rs` | 4 | session_store_contract_tests! macro |
| `crates/auths-sdk/src/workflows/migration.rs` | 3 | Registry state migration pipeline (`migrate_registry()`) |
| `ARCHITECTURE.md` | 5 | High-level architectural map for M&A due diligence |
| `RELEASES.md` | 5 | SemVer policy for public trait ports and stable crates |

### Files to Modify (37+)

| File | Epic | Change |
|------|------|--------|
| `crates/auths-core/src/crypto/mod.rs` | 1 | Add `pub mod ssh` |
| `crates/auths-core/src/pairing/qr.rs` | 2 | Replace println! with struct return |
| `crates/auths-core/src/storage/keychain.rs` | 2 | Replace eprintln! with tracing; accept KeychainConfig |
| `crates/auths-core/src/paths.rs` | 2 | Accept auths_home parameter |
| `crates/auths-core/src/storage/encrypted_file.rs` | 2 | Accept passphrase via parameter |
| `crates/auths-core/src/api/runtime.rs` | 2 | Use injected SshAgentProvider; accept config |
| `crates/auths-core/src/ports/mod.rs` | 2 | Add `pub mod clock;` |
| `crates/auths-core/src/pairing/token.rs` | 2 | Accept `&dyn ClockProvider` instead of `Utc::now()` |
| `crates/auths-core/src/witness/storage.rs` | 2 | Accept `&dyn ClockProvider` |
| `crates/auths-core/src/trust/pinned.rs` | 2 | Accept `&dyn ClockProvider` |
| `crates/auths-core/src/trust/resolve.rs` | 2 | Accept `&dyn ClockProvider` |
| `crates/auths-id/src/storage/identity.rs` | 2 | Replace println!/eprintln! with tracing |
| `crates/auths-id/src/attestation/load.rs` | 2 | Replace eprintln! with tracing |
| `crates/auths-id/src/storage/attestation.rs` | 2 | Replace eprintln! with tracing |
| `crates/auths-id/src/keri/cache.rs` | 2 | Accept home path parameter |
| `crates/auths-id/src/keri/kel.rs` | 2 | Accept home path parameter |
| `crates/auths-id/src/lib.rs` | 3 | Add `pub mod ports` |
| `crates/auths-id/Cargo.toml` | 3 | Remove git2 dependency |
| `crates/auths-id/src/storage/registry/packed.rs` | 3 | Move to auths-infra-git |
| `crates/auths-id/src/storage/registry/tree_ops.rs` | 3 | Move to auths-infra-git |
| `crates/auths-id/src/storage/registry/backend.rs` | 3 | Extract trait, move impl |
| `crates/auths-id/src/storage/identity.rs` | 3 | Use trait instead of git2 |
| `crates/auths-id/src/storage/keri.rs` | 3 | Use trait instead of git2 |
| `crates/auths-id/src/storage/attestation.rs` | 3 | Use trait instead of git2 |
| `crates/auths-id/src/storage/git_refs.rs` | 3 | Use trait instead of git2 |
| `crates/auths-id/src/attestation/export.rs` | 3 | Use trait instead of git2 |
| `crates/auths-id/src/freeze.rs` | 3 | Use storage port |
| `crates/auths-id/src/agent_identity.rs` | 3 | Use storage port |
| `crates/auths-infra-git/Cargo.toml` | 3 | Add auths-id dependency |
| `crates/auths-cli/src/bin/sign.rs` | 1 | Remove crypto functions, import from core |
| `crates/auths-cli/src/commands/audit.rs` | 1 | Thin wrapper calling SDK |
| `crates/auths-cli/src/commands/artifact/file.rs` | 1 | Use adapter |
| `crates/auths-cli/src/commands/artifact/sign.rs` | 1 | Use adapter |
| `crates/auths-cli/src/commands/doctor.rs` | 1 | Use SDK workflow |
| `crates/auths-cli/src/commands/device/verify_attestation.rs` | 1 | Import capability parsing from domain |
| `crates/auths-sdk/src/lib.rs` | 1 | Add ports, workflows modules |
| `crates/auths-sdk/src/setup.rs` | 2 | Use injected GitConfigProvider |
| `crates/auths-sdk/src/types.rs` | 2 | Add config fields |
| `crates/auths-telemetry/src/emitter.rs` | 2 | Accept EventSink |
| `crates/auths-telemetry/src/lib.rs` | 2 | Update exports |
| `crates/auths-core/src/lib.rs` | 5 | Add `#![deny(clippy::print_stdout, clippy::print_stderr, clippy::exit)]` |
| `crates/auths-id/src/lib.rs` | 5 | Add `#![deny(clippy::print_stdout, clippy::print_stderr, clippy::exit)]` |
| `crates/auths-policy/src/lib.rs` | 5 | Add `#![deny(clippy::print_stdout, clippy::print_stderr, clippy::exit)]` |
| `crates/auths-verifier/src/lib.rs` | 5 | Add `#![deny(clippy::print_stdout, clippy::print_stderr, clippy::exit)]` |
| `.github/workflows/ci.yml` | 5 | Add targeted grep checks for env vars and reverse deps; add `cargo-semver-checks` |
| `Cargo.toml` (workspace root) | 5 | Add `rust-version = "1.93"` to `[workspace.package]` |
| `crates/auths-cli/Cargo.toml` | 2 | Add `figment` dependency for layered configuration |
| `crates/auths-test-utils/Cargo.toml` | 4 | Add `async-lock` dependency for WASM-compatible async fakes |
| `crates/auths-telemetry/src/event.rs` | 2 | Add optional `trace_id` field to `AuditEvent` for W3C trace propagation |

---

## Code Standards (Enforced)

1. **DRY & Separated**: Business workflows entirely separated from I/O. No monolithic functions.
2. **Documentation**: Rustdoc mandatory for all exported SDK/Core items. `/// Description`, `/// Args:`, `/// Usage:` blocks per CLAUDE.md conventions.
3. **Minimalism**: No inline comments explaining process. Use structural decomposition. Per CLAUDE.md: only comment opinionated decisions.
4. **Domain-Specific Errors**: `thiserror` enums only. No `anyhow::Error` or `Box<dyn Error>` in Core/SDK. Example: `DomainError::InvalidSignature`, `StorageError::ConcurrentModification`.
5. **`thiserror`/`anyhow` Translation Boundary**: The ban on `anyhow` in Core/SDK is strict, but the CLI and API servers (`auths-auth-server`, `auths-registry-server`) **must** define a clear translation boundary where domain errors are wrapped with operational context. The CLI and server crates continue using `anyhow::Context` to collect system-level information (paths, environment, subprocess output), but always wrap the domain `thiserror` errors cleanly — never discard the typed error:
    ```rust
    // auths-cli/src/commands/sign.rs (Presentation Layer)
    // Converts the strict thiserror SigningError into a contextualized anyhow::Error
    let signature = sign_artifact(&config, data)
        .with_context(|| format!("Failed to sign artifact for namespace: {}", config.namespace))?;
    ```
    The existing SDK error types (`SetupError`, `DeviceError`, `RegistrationError` in `crates/auths-sdk/src/error.rs`) currently wrap `anyhow::Error` in their `StorageError` and `NetworkError` variants (e.g., `StorageError(#[source] anyhow::Error)`). These must be migrated to domain-specific `thiserror` variants during Epic 1/2 execution — the `anyhow` wrapping is a transitional pattern, not a permanent design. The `map_storage_err()` and `map_device_storage_err()` helper functions should be replaced with direct `From` impls on the domain storage errors.
6. **No reverse dependencies**: Core and SDK must never reference presentation layer crates.
