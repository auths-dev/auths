use thiserror::Error;

/// Errors arising during producer signer authority checks.
#[derive(Debug, Error)]
pub enum AuthorityError {
    /// Signer key is not bound to any active identity DID.
    #[error("Signer key is not bound to any active identity DID: {0}")]
    UnboundKey(String),

    /// Signer key has been revoked in the identity KEL.
    #[error("Signer key has been revoked in identity KEL: {0}")]
    RevokedKey(String),

    /// Registry lookup or storage query failed.
    #[error("Registry error: {0}")]
    Registry(String),
}
