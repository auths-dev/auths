//! Agent-based signing port for delegating cryptographic operations to a running agent process.
//!
//! The agent signing port abstracts the IPC-based signing protocol so that
//! the SDK workflow layer remains platform-independent. On Unix, the CLI
//! wires a concrete adapter that speaks the auths-agent wire protocol over
//! a Unix domain socket. On Windows, WASM, and other targets the
//! `NoopAgentProvider` is used instead.

/// Errors from agent signing operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AgentSigningError {
    /// The agent is not available on this platform or is not installed.
    #[error("agent unavailable: {0}")]
    Unavailable(String),

    /// The agent socket exists but the connection failed.
    #[error("agent connection failed: {0}")]
    ConnectionFailed(String),

    /// The agent accepted the request but signing failed.
    #[error("agent signing failed: {0}")]
    SigningFailed(String),

    /// The agent could not be started.
    #[error("agent startup failed: {0}")]
    StartupFailed(String),
}

/// Port for delegating signing operations to a running agent process.
///
/// Implementations must convert the agent's native response format into an
/// SSHSIG PEM string (`-----BEGIN SSH SIGNATURE----- … -----END SSH SIGNATURE-----`)
/// so that callers receive the same format as [`crate::signing::sign_with_seed`].
///
/// Args:
/// * Trait methods accept namespace identifiers, public key bytes, and raw data to sign.
///
/// Usage:
/// ```ignore
/// let pem = agent.try_sign("git", &pubkey_bytes, &commit_data)?;
/// agent.ensure_running()?;
/// agent.add_identity("git", &pkcs8_der_bytes)?;
/// ```
pub trait AgentSigningPort: Send + Sync + 'static {
    /// Attempt to sign `data` via the running agent.
    ///
    /// Returns an SSHSIG PEM string on success. The adapter is responsible for
    /// converting raw signature bytes from the agent wire protocol into PEM.
    ///
    /// Args:
    /// * `namespace`: The SSH namespace for the signature (e.g. `"git"`).
    /// * `pubkey`: The public key identifying the signing key (carries curve type).
    /// * `data`: The raw bytes to sign.
    fn try_sign(
        &self,
        namespace: &str,
        pubkey: &auths_verifier::DevicePublicKey,
        data: &[u8],
    ) -> Result<String, AgentSigningError>;

    /// Start the agent daemon if it is not already running.
    ///
    /// Implementations should suppress all stdout/stderr output (quiet mode).
    fn ensure_running(&self) -> Result<(), AgentSigningError>;

    /// Load a decrypted PKCS#8 DER-encoded keypair into the running agent.
    ///
    /// Args:
    /// * `namespace`: The namespace to associate with the loaded key.
    /// * `pkcs8_der`: Decrypted PKCS#8 DER bytes — the output of keychain
    ///   decryption (i.e. `decrypt_keypair()` result), not a raw seed or
    ///   encrypted blob.
    fn add_identity(&self, namespace: &str, pkcs8_der: &[u8]) -> Result<(), AgentSigningError>;
}

/// Transport abstraction for the agent listener.
///
/// Separates the connection-acceptance mechanism (Unix socket, TCP, in-process
/// channel) from the signing state machine (`AgentCore` / `AgentHandle`).
/// The CLI provides a Unix socket implementation; tests can use a direct
/// in-process adapter that bypasses IPC entirely.
///
/// Usage:
/// ```ignore
/// struct InProcessTransport { handle: Arc<AgentHandle> }
///
/// impl AgentTransport for InProcessTransport {
///     fn serve(&self) -> Result<(), AgentTransportError> {
///         // Drive the handle directly without a socket
///         Ok(())
///     }
///     fn is_available(&self) -> bool { true }
///     fn socket_path(&self) -> Option<&Path> { None }
/// }
/// ```
pub trait AgentTransport: Send + Sync + 'static {
    /// Start accepting connections and serving agent requests.
    ///
    /// This method blocks until the agent is shut down. Implementations
    /// should delegate to the `AgentHandle` for key operations.
    ///
    /// Args: none (connection details are configured at construction time).
    fn serve(&self) -> Result<(), AgentTransportError>;

    /// Check whether the transport backend is available on this platform.
    ///
    /// Returns `false` on platforms that lack Unix domain socket support
    /// or when the required runtime dependencies are missing.
    fn is_available(&self) -> bool;

    /// Return the filesystem path of the listener socket, if applicable.
    ///
    /// In-process transports return `None`.
    fn socket_path(&self) -> Option<&std::path::Path>;
}

/// Errors from agent transport operations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AgentTransportError {
    /// The transport binding failed (e.g. socket already in use).
    #[error("bind failed: {0}")]
    BindFailed(String),

    /// An I/O error during connection handling.
    #[error("transport I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// The agent handle reported an error.
    #[error("agent error: {0}")]
    AgentError(String),
}

/// No-op agent provider for platforms without agent support.
///
/// All methods return [`AgentSigningError::Unavailable`].
pub struct NoopAgentProvider;

impl AgentSigningPort for NoopAgentProvider {
    fn try_sign(
        &self,
        _namespace: &str,
        _pubkey: &auths_verifier::DevicePublicKey,
        _data: &[u8],
    ) -> Result<String, AgentSigningError> {
        Err(AgentSigningError::Unavailable(
            "agent not supported on this platform".into(),
        ))
    }

    fn ensure_running(&self) -> Result<(), AgentSigningError> {
        Err(AgentSigningError::Unavailable(
            "agent not supported on this platform".into(),
        ))
    }

    fn add_identity(&self, _namespace: &str, _pkcs8_der: &[u8]) -> Result<(), AgentSigningError> {
        Err(AgentSigningError::Unavailable(
            "agent not supported on this platform".into(),
        ))
    }
}
