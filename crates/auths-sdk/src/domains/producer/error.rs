use thiserror::Error;

/// Errors arising during producer signer authority checks.
#[derive(Debug, Error)]
pub enum AuthorityError {
    #[error("Signer key is not bound to any active identity DID: {0}")]
    UnboundKey(String),

    #[error("Signer key has been revoked in identity KEL: {0}")]
    RevokedKey(String),

    #[error("Registry error: {0}")]
    Registry(String),
}
