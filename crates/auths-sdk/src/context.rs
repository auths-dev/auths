//! Runtime dependency container for auths-sdk operations.
//!
//! [`AuthsContext`] carries all injected infrastructure adapters. Config structs
//! (e.g. [`crate::types::CreateDeveloperIdentityConfig`]) remain Plain Old Data with no
//! trait objects.

use std::sync::Arc;

use auths_core::ports::clock::ClockProvider;
use auths_core::ports::id::{SystemUuidProvider, UuidProvider};
use auths_core::signing::PassphraseProvider;
use auths_core::storage::keychain::KeyStorage;
use auths_id::attestation::export::AttestationSink;
use auths_id::ports::registry::RegistryBackend;
use auths_id::storage::attestation::AttestationSource;
use auths_id::storage::identity::IdentityStorage;

use crate::ports::agent::{AgentSigningPort, NoopAgentProvider};

/// Re-export the canonical `EventSink` trait from `auths-telemetry`.
pub use auths_telemetry::EventSink;

struct NoopSink;

impl EventSink for NoopSink {
    fn emit(&self, _payload: &str) {}
    fn flush(&self) {}
}

struct NoopPassphraseProvider;

impl PassphraseProvider for NoopPassphraseProvider {
    fn get_passphrase(
        &self,
        _prompt: &str,
    ) -> Result<zeroize::Zeroizing<String>, auths_core::AgentError> {
        Err(auths_core::AgentError::SigningFailed(
            "no passphrase provider configured — call .passphrase_provider(...) on AuthsContextBuilder".into(),
        ))
    }
}

/// All runtime dependencies for auths-sdk operations.
///
/// Construct via [`AuthsContext::builder()`]. Config structs carry serializable
/// data; `AuthsContext` carries injected infrastructure adapters. This separation
/// allows the SDK to operate as a headless, storage-agnostic library that can be
/// embedded in cloud SaaS, WASM, or C-FFI runtimes without pulling in tokio,
/// git2, or std::fs.
///
/// Usage:
/// ```ignore
/// use std::sync::Arc;
/// use auths_sdk::context::AuthsContext;
///
/// let ctx = AuthsContext::builder()
///     .registry(Arc::new(my_registry))
///     .key_storage(Arc::new(my_keychain))
///     .clock(Arc::new(SystemClock))
///     .identity_storage(Arc::new(my_identity_storage))
///     .attestation_sink(Arc::new(my_store.clone()))
///     .attestation_source(Arc::new(my_store))
///     .build();
/// sdk::initialize(config, &ctx)?;
/// ```
pub struct AuthsContext {
    /// Pre-initialized registry storage backend.
    pub registry: Arc<dyn RegistryBackend + Send + Sync>,
    /// Platform keychain or test fake for key material storage.
    pub key_storage: Arc<dyn KeyStorage + Send + Sync>,
    /// Wall-clock provider for deterministic testing.
    pub clock: Arc<dyn ClockProvider + Send + Sync>,
    /// Telemetry sink (defaults to [`NoopSink`] when not specified).
    pub event_sink: Arc<dyn EventSink>,
    /// Identity storage adapter (load/save managed identity).
    pub identity_storage: Arc<dyn IdentityStorage + Send + Sync>,
    /// Attestation sink for writing signed attestations.
    pub attestation_sink: Arc<dyn AttestationSink + Send + Sync>,
    /// Attestation source for reading existing attestations.
    pub attestation_source: Arc<dyn AttestationSource + Send + Sync>,
    /// Passphrase provider for key decryption during signing operations.
    /// Defaults to [`NoopPassphraseProvider`] — set via `.passphrase_provider(...)` when
    /// SDK functions need to sign with encrypted key material.
    pub passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
    /// UUID generator port. Defaults to [`SystemUuidProvider`] (random v4 UUIDs).
    /// Override with a deterministic stub in tests.
    pub uuid_provider: Arc<dyn UuidProvider + Send + Sync>,
    /// Agent-based signing port for delegating operations to a running agent process.
    /// Defaults to [`NoopAgentProvider`] (all operations return `Unavailable`)
    /// when not called. Set this on Unix platforms where the auths-agent daemon
    /// is available.
    pub agent_signing: Arc<dyn AgentSigningPort + Send + Sync>,
}

impl AuthsContext {
    /// Creates a builder for [`AuthsContext`].
    ///
    /// All six required fields (`registry`, `key_storage`, `clock`,
    /// `identity_storage`, `attestation_sink`, `attestation_source`) are enforced
    /// at compile time — the `build()` method is only available once all six are set.
    ///
    /// Usage:
    /// ```ignore
    /// let ctx = AuthsContext::builder()
    ///     .registry(Arc::new(my_registry))
    ///     .key_storage(Arc::new(my_keychain))
    ///     .clock(Arc::new(SystemClock))
    ///     .identity_storage(Arc::new(my_identity_storage))
    ///     .attestation_sink(Arc::new(my_store.clone()))
    ///     .attestation_source(Arc::new(my_store))
    ///     .build();
    /// ```
    pub fn builder() -> AuthsContextBuilder<Missing, Missing, Missing, Missing, Missing, Missing> {
        AuthsContextBuilder {
            registry: Missing,
            key_storage: Missing,
            clock: Missing,
            identity_storage: Missing,
            attestation_sink: Missing,
            attestation_source: Missing,
            event_sink: None,
            passphrase_provider: None,
            uuid_provider: None,
            agent_signing: None,
        }
    }
}

/// Typestate marker: required field not yet set.
pub struct Missing;

/// Typestate marker: required field has been set.
pub struct Set<T>(T);

/// Typestate builder for [`AuthsContext`].
///
/// Call [`AuthsContext::builder()`] to obtain an instance. The `build()` method
/// is only available once all six required fields have been supplied — omitting any
/// produces a compile-time error.
pub struct AuthsContextBuilder<R, K, C, IS, AS, ASrc> {
    registry: R,
    key_storage: K,
    clock: C,
    identity_storage: IS,
    attestation_sink: AS,
    attestation_source: ASrc,
    event_sink: Option<Arc<dyn EventSink>>,
    passphrase_provider: Option<Arc<dyn PassphraseProvider + Send + Sync>>,
    uuid_provider: Option<Arc<dyn UuidProvider + Send + Sync>>,
    agent_signing: Option<Arc<dyn AgentSigningPort + Send + Sync>>,
}

// ── Required field setters (each transitions one typestate slot) ──────────────

impl<K, C, IS, AS, ASrc> AuthsContextBuilder<Missing, K, C, IS, AS, ASrc> {
    /// Set the registry storage backend.
    ///
    /// Args:
    /// * `registry`: Pre-initialized registry backend.
    ///
    /// Usage:
    /// ```ignore
    /// builder.registry(Arc::new(my_git_backend))
    /// ```
    pub fn registry(
        self,
        registry: Arc<dyn RegistryBackend + Send + Sync>,
    ) -> AuthsContextBuilder<Set<Arc<dyn RegistryBackend + Send + Sync>>, K, C, IS, AS, ASrc> {
        AuthsContextBuilder {
            registry: Set(registry),
            key_storage: self.key_storage,
            clock: self.clock,
            identity_storage: self.identity_storage,
            attestation_sink: self.attestation_sink,
            attestation_source: self.attestation_source,
            event_sink: self.event_sink,
            passphrase_provider: self.passphrase_provider,
            uuid_provider: self.uuid_provider,
            agent_signing: self.agent_signing,
        }
    }
}

impl<R, C, IS, AS, ASrc> AuthsContextBuilder<R, Missing, C, IS, AS, ASrc> {
    /// Set the key storage backend.
    ///
    /// Args:
    /// * `key_storage`: Platform keychain or in-memory test fake.
    ///
    /// Usage:
    /// ```ignore
    /// builder.key_storage(Arc::new(my_keychain))
    /// ```
    pub fn key_storage(
        self,
        key_storage: Arc<dyn KeyStorage + Send + Sync>,
    ) -> AuthsContextBuilder<R, Set<Arc<dyn KeyStorage + Send + Sync>>, C, IS, AS, ASrc> {
        AuthsContextBuilder {
            registry: self.registry,
            key_storage: Set(key_storage),
            clock: self.clock,
            identity_storage: self.identity_storage,
            attestation_sink: self.attestation_sink,
            attestation_source: self.attestation_source,
            event_sink: self.event_sink,
            passphrase_provider: self.passphrase_provider,
            uuid_provider: self.uuid_provider,
            agent_signing: self.agent_signing,
        }
    }
}

impl<R, K, IS, AS, ASrc> AuthsContextBuilder<R, K, Missing, IS, AS, ASrc> {
    /// Set the clock provider.
    ///
    /// Args:
    /// * `clock`: Wall-clock implementation (`SystemClock` in production,
    ///   `MockClock` in tests).
    ///
    /// Usage:
    /// ```ignore
    /// builder.clock(Arc::new(SystemClock))
    /// ```
    pub fn clock(
        self,
        clock: Arc<dyn ClockProvider + Send + Sync>,
    ) -> AuthsContextBuilder<R, K, Set<Arc<dyn ClockProvider + Send + Sync>>, IS, AS, ASrc> {
        AuthsContextBuilder {
            registry: self.registry,
            key_storage: self.key_storage,
            clock: Set(clock),
            identity_storage: self.identity_storage,
            attestation_sink: self.attestation_sink,
            attestation_source: self.attestation_source,
            event_sink: self.event_sink,
            passphrase_provider: self.passphrase_provider,
            uuid_provider: self.uuid_provider,
            agent_signing: self.agent_signing,
        }
    }
}

impl<R, K, C, AS, ASrc> AuthsContextBuilder<R, K, C, Missing, AS, ASrc> {
    /// Set the identity storage adapter.
    ///
    /// Args:
    /// * `storage`: Pre-initialized identity storage implementation.
    ///
    /// Usage:
    /// ```ignore
    /// builder.identity_storage(Arc::new(my_identity_storage))
    /// ```
    pub fn identity_storage(
        self,
        storage: Arc<dyn IdentityStorage + Send + Sync>,
    ) -> AuthsContextBuilder<R, K, C, Set<Arc<dyn IdentityStorage + Send + Sync>>, AS, ASrc> {
        AuthsContextBuilder {
            registry: self.registry,
            key_storage: self.key_storage,
            clock: self.clock,
            identity_storage: Set(storage),
            attestation_sink: self.attestation_sink,
            attestation_source: self.attestation_source,
            event_sink: self.event_sink,
            passphrase_provider: self.passphrase_provider,
            uuid_provider: self.uuid_provider,
            agent_signing: self.agent_signing,
        }
    }
}

impl<R, K, C, IS, ASrc> AuthsContextBuilder<R, K, C, IS, Missing, ASrc> {
    /// Set the attestation sink adapter.
    ///
    /// Args:
    /// * `sink`: Pre-initialized attestation sink implementation.
    ///
    /// Usage:
    /// ```ignore
    /// builder.attestation_sink(Arc::new(my_attestation_store))
    /// ```
    pub fn attestation_sink(
        self,
        sink: Arc<dyn AttestationSink + Send + Sync>,
    ) -> AuthsContextBuilder<R, K, C, IS, Set<Arc<dyn AttestationSink + Send + Sync>>, ASrc> {
        AuthsContextBuilder {
            registry: self.registry,
            key_storage: self.key_storage,
            clock: self.clock,
            identity_storage: self.identity_storage,
            attestation_sink: Set(sink),
            attestation_source: self.attestation_source,
            event_sink: self.event_sink,
            passphrase_provider: self.passphrase_provider,
            uuid_provider: self.uuid_provider,
            agent_signing: self.agent_signing,
        }
    }
}

impl<R, K, C, IS, AS> AuthsContextBuilder<R, K, C, IS, AS, Missing> {
    /// Set the attestation source adapter.
    ///
    /// Args:
    /// * `source`: Pre-initialized attestation source implementation.
    ///
    /// Usage:
    /// ```ignore
    /// builder.attestation_source(Arc::new(my_attestation_store))
    /// ```
    pub fn attestation_source(
        self,
        source: Arc<dyn AttestationSource + Send + Sync>,
    ) -> AuthsContextBuilder<R, K, C, IS, AS, Set<Arc<dyn AttestationSource + Send + Sync>>> {
        AuthsContextBuilder {
            registry: self.registry,
            key_storage: self.key_storage,
            clock: self.clock,
            identity_storage: self.identity_storage,
            attestation_sink: self.attestation_sink,
            attestation_source: Set(source),
            event_sink: self.event_sink,
            passphrase_provider: self.passphrase_provider,
            uuid_provider: self.uuid_provider,
            agent_signing: self.agent_signing,
        }
    }
}

// ── Optional field setters (available at any typestate, return Self) ──────────

impl<R, K, C, IS, AS, ASrc> AuthsContextBuilder<R, K, C, IS, AS, ASrc> {
    /// Set an optional event sink.
    ///
    /// Defaults to a no-op sink (all events discarded) when not called.
    ///
    /// Args:
    /// * `sink`: Any type implementing [`EventSink`].
    ///
    /// Usage:
    /// ```ignore
    /// builder.event_sink(Arc::new(my_sink))
    /// ```
    pub fn event_sink(mut self, sink: Arc<dyn EventSink>) -> Self {
        self.event_sink = Some(sink);
        self
    }

    /// Set the passphrase provider for key decryption during signing operations.
    ///
    /// Defaults to a noop provider that returns an error. Set this when SDK
    /// workflow functions will perform signing with encrypted key material.
    ///
    /// Args:
    /// * `provider`: Any type implementing [`PassphraseProvider`].
    ///
    /// Usage:
    /// ```ignore
    /// builder.passphrase_provider(Arc::new(PrefilledPassphraseProvider::new(passphrase)))
    /// ```
    pub fn passphrase_provider(
        mut self,
        provider: Arc<dyn PassphraseProvider + Send + Sync>,
    ) -> Self {
        self.passphrase_provider = Some(provider);
        self
    }

    /// Set the UUID provider.
    ///
    /// Defaults to [`SystemUuidProvider`] (random v4 UUIDs) when not called.
    /// Override with a deterministic stub in tests.
    ///
    /// Args:
    /// * `provider`: Any type implementing [`UuidProvider`].
    ///
    /// Usage:
    /// ```ignore
    /// builder.uuid_provider(Arc::new(my_uuid_stub))
    /// ```
    pub fn uuid_provider(mut self, provider: Arc<dyn UuidProvider + Send + Sync>) -> Self {
        self.uuid_provider = Some(provider);
        self
    }

    /// Set the agent signing port for delegating signing to a running agent process.
    ///
    /// Defaults to a noop provider (all operations return `Unavailable`)
    /// when not called. Set this on Unix platforms where the auths-agent daemon
    /// is available.
    ///
    /// Args:
    /// * `provider`: Any type implementing [`AgentSigningPort`].
    ///
    /// Usage:
    /// ```ignore
    /// builder.agent_signing(Arc::new(CliAgentAdapter::new(socket_path)))
    /// ```
    pub fn agent_signing(mut self, provider: Arc<dyn AgentSigningPort + Send + Sync>) -> Self {
        self.agent_signing = Some(provider);
        self
    }
}

// ── Infallible build — only available when all six required fields are set ────

impl
    AuthsContextBuilder<
        Set<Arc<dyn RegistryBackend + Send + Sync>>,
        Set<Arc<dyn KeyStorage + Send + Sync>>,
        Set<Arc<dyn ClockProvider + Send + Sync>>,
        Set<Arc<dyn IdentityStorage + Send + Sync>>,
        Set<Arc<dyn AttestationSink + Send + Sync>>,
        Set<Arc<dyn AttestationSource + Send + Sync>>,
    >
{
    /// Build the [`AuthsContext`].
    ///
    /// Infallible — only callable once all six required fields are set.
    /// Omitting any required field is a compile-time error.
    ///
    /// Usage:
    /// ```ignore
    /// let ctx = AuthsContext::builder()
    ///     .registry(Arc::new(my_registry))
    ///     .key_storage(Arc::new(my_keychain))
    ///     .clock(Arc::new(SystemClock))
    ///     .identity_storage(Arc::new(my_identity_storage))
    ///     .attestation_sink(Arc::new(my_store.clone()))
    ///     .attestation_source(Arc::new(my_store))
    ///     .build();
    /// ```
    pub fn build(self) -> AuthsContext {
        AuthsContext {
            registry: self.registry.0,
            key_storage: self.key_storage.0,
            clock: self.clock.0,
            identity_storage: self.identity_storage.0,
            attestation_sink: self.attestation_sink.0,
            attestation_source: self.attestation_source.0,
            event_sink: self.event_sink.unwrap_or_else(|| Arc::new(NoopSink)),
            passphrase_provider: self
                .passphrase_provider
                .unwrap_or_else(|| Arc::new(NoopPassphraseProvider)),
            uuid_provider: self
                .uuid_provider
                .unwrap_or_else(|| Arc::new(SystemUuidProvider)),
            agent_signing: self
                .agent_signing
                .unwrap_or_else(|| Arc::new(NoopAgentProvider)),
        }
    }
}
