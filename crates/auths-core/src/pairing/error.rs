use thiserror::Error;

/// Errors that can occur during the pairing protocol.
///
/// Wraps protocol-level errors from `auths-pairing-protocol` and adds
/// transport-specific variants used by the CLI.
#[derive(Debug, Error)]
pub enum PairingError {
    /// A protocol-level error (expired token, bad signature, etc.).
    #[error(transparent)]
    Protocol(#[from] auths_pairing_protocol::ProtocolError),

    /// QR code generation failed.
    #[error("QR code generation failed: {0}")]
    QrCodeFailed(String),

    /// Network error during relay communication.
    #[error("Relay error: {0}")]
    RelayError(String),

    /// Local LAN server error.
    #[error("Local server error: {0}")]
    LocalServerError(String),

    /// mDNS advertisement or discovery error.
    #[error("mDNS error: {0}")]
    MdnsError(String),

    /// No peer found on the local network.
    #[error("No peer found on local network")]
    NoPeerFound,

    /// LAN pairing timed out waiting for a response.
    #[error("LAN pairing timed out")]
    LanTimeout,
}

impl From<serde_json::Error> for PairingError {
    fn from(e: serde_json::Error) -> Self {
        PairingError::Protocol(auths_pairing_protocol::ProtocolError::Serialization(
            e.to_string(),
        ))
    }
}
