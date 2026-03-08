use thiserror::Error;

/// Errors from the pairing daemon.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DaemonError {
    /// Cryptographic token generation failed.
    #[error("failed to generate pairing token")]
    TokenGenerationFailed,

    /// TCP listener could not bind to the requested address.
    #[error("failed to bind TCP listener: {0}")]
    BindFailed(#[source] std::io::Error),

    /// mDNS advertisement or discovery failed.
    #[error("mDNS error: {0}")]
    MdnsError(String),

    /// Network interface detection failed.
    #[error("failed to detect network interfaces: {0}")]
    NetworkDetectionFailed(#[source] std::io::Error),

    /// A pairing protocol error.
    #[error(transparent)]
    Pairing(#[from] auths_core::pairing::PairingError),
}
