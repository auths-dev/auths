//! Domain errors for SSH cryptographic operations.

/// Errors from SSH key construction, signing, and encoding operations.
///
/// Usage:
/// ```ignore
/// match result {
///     Err(CryptoError::SshKeyConstruction(msg)) => { /* key creation failed */ }
///     Err(CryptoError::InvalidSeedLength(n)) => { /* wrong seed size */ }
///     Ok(pem) => { /* success */ }
/// }
/// ```
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// SSH key construction failed.
    #[error("SSH key construction failed: {0}")]
    SshKeyConstruction(String),

    /// Signing operation failed.
    #[error("signing failed: {0}")]
    SigningFailed(String),

    /// PEM encoding failed.
    #[error("PEM encoding failed: {0}")]
    PemEncoding(String),

    /// The seed has an unexpected length.
    #[error("invalid seed length: expected 32, got {0}")]
    InvalidSeedLength(usize),

    /// The key format is invalid.
    #[error("invalid key format: {0}")]
    InvalidKeyFormat(String),
}

impl From<auths_crypto::CryptoError> for CryptoError {
    fn from(e: auths_crypto::CryptoError) -> Self {
        CryptoError::InvalidKeyFormat(e.to_string())
    }
}
