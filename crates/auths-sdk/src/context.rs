//! Runtime dependency container for auths-sdk operations.
//!
//! [`AuthsContext`] carries all injected infrastructure adapters. Config structs
//! (e.g. [`crate::types::DeveloperSetupConfig`]) remain Plain Old Data with no
//! trait objects.

use std::fmt;
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

/// A required builder field was not set before calling `build()`.
#[derive(Debug, Clone)]
pub struct BuilderError(pub &'static str);

impl fmt::Display for BuilderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "missing required builder field: {}", self.0)
    }
}

impl std::error::Error for BuilderError {}

/// Fire-and-forget sink for structured telemetry payloads emitted by SDK operations.
///
/// Implement this trait to route SDK audit events to a logging backend, SIEM, or
/// stdout. The default implementation ([`NoopSink`]) discards all events.
///
/// Usage:
/// ```ignore
/// struct StderrSink;
/// impl auths_sdk::context::EventSink for StderrSink {
///     fn emit(&self, payload: &str) { eprintln!("{payload}"); }
///     fn flush(&self) {}
/// }
/// ```
pub trait EventSink: Send + Sync + 'static {
    /// Emit a JSON-serialized event payload. Must not block.
    fn emit(&self, payload: &str);

    /// Block until all previously emitted payloads have been written.
    fn flush(&self);
}

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
///     .build();
/// sdk::setup_developer(config, &ctx)?;
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
    /// Defaults to [`NoopAgentProvider`] — set via `.agent_signing(...)` when the
    /// platform supports agent-based signing (Unix with auths-agent).
    pub agent_signing: Arc<dyn AgentSigningPort + Send + Sync>,
}

impl AuthsContext {
    /// Creates a builder for [`AuthsContext`].
    ///
    /// Required fields are `registry`, `key_storage`, and `clock`. Omitting any
    /// of these produces a compile-time error — the `build()` method is only
    /// available once all three are set.
    ///
    /// Usage:
    /// ```ignore
    /// let ctx = AuthsContext::builder()
    ///     .registry(Arc::new(my_registry))
    ///     .key_storage(Arc::new(my_keychain))
    ///     .clock(Arc::new(SystemClock))
    ///     .build();
    /// ```
    pub fn builder() -> AuthsContextBuilder<Missing, Missing, Missing> {
        AuthsContextBuilder {
            registry: Missing,
            key_storage: Missing,
            clock: Missing,
            event_sink: None,
            identity_storage: None,
            attestation_sink: None,
            attestation_source: None,
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
/// is only available once `registry`, `key_storage`, and `clock` have all been
/// supplied.
pub struct AuthsContextBuilder<R, K, C> {
    registry: R,
    key_storage: K,
    clock: C,
    event_sink: Option<Arc<dyn EventSink>>,
    identity_storage: Option<Arc<dyn IdentityStorage + Send + Sync>>,
    attestation_sink: Option<Arc<dyn AttestationSink + Send + Sync>>,
    attestation_source: Option<Arc<dyn AttestationSource + Send + Sync>>,
    passphrase_provider: Option<Arc<dyn PassphraseProvider + Send + Sync>>,
    uuid_provider: Option<Arc<dyn UuidProvider + Send + Sync>>,
    agent_signing: Option<Arc<dyn AgentSigningPort + Send + Sync>>,
}

impl<K, C> AuthsContextBuilder<Missing, K, C> {
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
    ) -> AuthsContextBuilder<Set<Arc<dyn RegistryBackend + Send + Sync>>, K, C> {
        AuthsContextBuilder {
            registry: Set(registry),
            key_storage: self.key_storage,
            clock: self.clock,
            event_sink: self.event_sink,
            identity_storage: self.identity_storage,
            attestation_sink: self.attestation_sink,
            attestation_source: self.attestation_source,
            passphrase_provider: self.passphrase_provider,
            uuid_provider: self.uuid_provider,
            agent_signing: self.agent_signing,
        }
    }
}

impl<R, C> AuthsContextBuilder<R, Missing, C> {
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
    ) -> AuthsContextBuilder<R, Set<Arc<dyn KeyStorage + Send + Sync>>, C> {
        AuthsContextBuilder {
            registry: self.registry,
            key_storage: Set(key_storage),
            clock: self.clock,
            event_sink: self.event_sink,
            identity_storage: self.identity_storage,
            attestation_sink: self.attestation_sink,
            attestation_source: self.attestation_source,
            passphrase_provider: self.passphrase_provider,
            uuid_provider: self.uuid_provider,
            agent_signing: self.agent_signing,
        }
    }
}

impl<R, K> AuthsContextBuilder<R, K, Missing> {
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
    ) -> AuthsContextBuilder<R, K, Set<Arc<dyn ClockProvider + Send + Sync>>> {
        AuthsContextBuilder {
            registry: self.registry,
            key_storage: self.key_storage,
            clock: Set(clock),
            event_sink: self.event_sink,
            identity_storage: self.identity_storage,
            attestation_sink: self.attestation_sink,
            attestation_source: self.attestation_source,
            passphrase_provider: self.passphrase_provider,
            uuid_provider: self.uuid_provider,
            agent_signing: self.agent_signing,
        }
    }
}

impl<R, K, C> AuthsContextBuilder<R, K, C> {
    /// Set an optional event sink.
    ///
    /// Defaults to [`NoopSink`] (all events discarded) when not called.
    ///
    /// Args:
    /// * `sink`: Any type implementing [`EventSink`].
    ///
    /// Usage:
    /// ```ignore
    /// builder.event_sink(Arc::new(my_sink))
    /// ```
    pub fn event_sink(self, sink: Arc<dyn EventSink>) -> AuthsContextBuilder<R, K, C> {
        AuthsContextBuilder {
            registry: self.registry,
            key_storage: self.key_storage,
            clock: self.clock,
            event_sink: Some(sink),
            identity_storage: self.identity_storage,
            attestation_sink: self.attestation_sink,
            attestation_source: self.attestation_source,
            passphrase_provider: self.passphrase_provider,
            uuid_provider: self.uuid_provider,
            agent_signing: self.agent_signing,
        }
    }

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
    ) -> AuthsContextBuilder<R, K, C> {
        AuthsContextBuilder {
            registry: self.registry,
            key_storage: self.key_storage,
            clock: self.clock,
            event_sink: self.event_sink,
            identity_storage: Some(storage),
            attestation_sink: self.attestation_sink,
            attestation_source: self.attestation_source,
            passphrase_provider: self.passphrase_provider,
            uuid_provider: self.uuid_provider,
            agent_signing: self.agent_signing,
        }
    }

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
    ) -> AuthsContextBuilder<R, K, C> {
        AuthsContextBuilder {
            registry: self.registry,
            key_storage: self.key_storage,
            clock: self.clock,
            event_sink: self.event_sink,
            identity_storage: self.identity_storage,
            attestation_sink: Some(sink),
            attestation_source: self.attestation_source,
            passphrase_provider: self.passphrase_provider,
            uuid_provider: self.uuid_provider,
            agent_signing: self.agent_signing,
        }
    }

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
    ) -> AuthsContextBuilder<R, K, C> {
        AuthsContextBuilder {
            registry: self.registry,
            key_storage: self.key_storage,
            clock: self.clock,
            event_sink: self.event_sink,
            identity_storage: self.identity_storage,
            attestation_sink: self.attestation_sink,
            attestation_source: Some(source),
            passphrase_provider: self.passphrase_provider,
            uuid_provider: self.uuid_provider,
            agent_signing: self.agent_signing,
        }
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
        self,
        provider: Arc<dyn PassphraseProvider + Send + Sync>,
    ) -> AuthsContextBuilder<R, K, C> {
        AuthsContextBuilder {
            registry: self.registry,
            key_storage: self.key_storage,
            clock: self.clock,
            event_sink: self.event_sink,
            identity_storage: self.identity_storage,
            attestation_sink: self.attestation_sink,
            attestation_source: self.attestation_source,
            passphrase_provider: Some(provider),
            uuid_provider: self.uuid_provider,
            agent_signing: self.agent_signing,
        }
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
    pub fn uuid_provider(
        self,
        provider: Arc<dyn UuidProvider + Send + Sync>,
    ) -> AuthsContextBuilder<R, K, C> {
        AuthsContextBuilder {
            registry: self.registry,
            key_storage: self.key_storage,
            clock: self.clock,
            event_sink: self.event_sink,
            identity_storage: self.identity_storage,
            attestation_sink: self.attestation_sink,
            attestation_source: self.attestation_source,
            passphrase_provider: self.passphrase_provider,
            uuid_provider: Some(provider),
            agent_signing: self.agent_signing,
        }
    }

    /// Set the agent signing port for delegating signing to a running agent process.
    ///
    /// Defaults to [`NoopAgentProvider`] (all operations return `Unavailable`)
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
    pub fn agent_signing(
        self,
        provider: Arc<dyn AgentSigningPort + Send + Sync>,
    ) -> AuthsContextBuilder<R, K, C> {
        AuthsContextBuilder {
            registry: self.registry,
            key_storage: self.key_storage,
            clock: self.clock,
            event_sink: self.event_sink,
            identity_storage: self.identity_storage,
            attestation_sink: self.attestation_sink,
            attestation_source: self.attestation_source,
            passphrase_provider: self.passphrase_provider,
            uuid_provider: self.uuid_provider,
            agent_signing: Some(provider),
        }
    }
}

impl
    AuthsContextBuilder<
        Set<Arc<dyn RegistryBackend + Send + Sync>>,
        Set<Arc<dyn KeyStorage + Send + Sync>>,
        Set<Arc<dyn ClockProvider + Send + Sync>>,
    >
{
    /// Build the [`AuthsContext`].
    ///
    /// Only callable once `registry`, `key_storage`, and `clock` have been set.
    /// Omitting any of these fields produces a compile-time error.
    ///
    /// Usage:
    /// ```ignore
    /// let ctx = AuthsContext::builder()
    ///     .registry(Arc::new(my_registry))
    ///     .key_storage(Arc::new(my_keychain))
    ///     .clock(Arc::new(SystemClock))
    ///     .build();
    /// ```
    pub fn build(self) -> Result<AuthsContext, BuilderError> {
        Ok(AuthsContext {
            registry: self.registry.0,
            key_storage: self.key_storage.0,
            clock: self.clock.0,
            event_sink: self.event_sink.unwrap_or_else(|| Arc::new(NoopSink)),
            identity_storage: self
                .identity_storage
                .ok_or(BuilderError("identity_storage"))?,
            attestation_sink: self
                .attestation_sink
                .ok_or(BuilderError("attestation_sink"))?,
            attestation_source: self
                .attestation_source
                .ok_or(BuilderError("attestation_source"))?,
            passphrase_provider: self
                .passphrase_provider
                .unwrap_or_else(|| Arc::new(NoopPassphraseProvider)),
            uuid_provider: self
                .uuid_provider
                .unwrap_or_else(|| Arc::new(SystemUuidProvider)),
            agent_signing: self
                .agent_signing
                .unwrap_or_else(|| Arc::new(NoopAgentProvider)),
        })
    }
}
