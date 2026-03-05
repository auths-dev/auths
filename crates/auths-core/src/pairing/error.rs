use thiserror::Error;

/// Errors that can occur during the pairing protocol.
///
/// Wraps protocol-level errors from `auths-pairing-protocol` and adds
/// transport-specific variants used by the CLI.
#[derive(Debug, Error)]
pub enum PairingError {
    #[error(transparent)]
    Protocol(#[from] auths_pairing_protocol::ProtocolError),

    #[error("QR code generation failed: {0}")]
    QrCodeFailed(String),

    #[error("Relay error: {0}")]
    RelayError(String),

    #[error("Local server error: {0}")]
    LocalServerError(String),

    #[error("mDNS error: {0}")]
    MdnsError(String),

    #[error("No peer found on local network")]
    NoPeerFound,

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
