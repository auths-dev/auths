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
#[non_exhaustive]
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

impl auths_crypto::AuthsErrorInfo for CryptoError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::SshKeyConstruction(_) => "AUTHS-E3301",
            Self::SigningFailed(_) => "AUTHS-E3302",
            Self::PemEncoding(_) => "AUTHS-E3303",
            Self::InvalidSeedLength(_) => "AUTHS-E3304",
            Self::InvalidKeyFormat(_) => "AUTHS-E3305",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::InvalidSeedLength(_) => Some("Ensure the seed is exactly 32 bytes"),
            Self::InvalidKeyFormat(_) => Some("Check that the key file is a valid Ed25519 key"),
            _ => None,
        }
    }
}

impl From<auths_crypto::CryptoError> for CryptoError {
    fn from(e: auths_crypto::CryptoError) -> Self {
        CryptoError::InvalidKeyFormat(e.to_string())
    }
}
