//! Port for resolving identity public keys from a DID.

use std::fmt;

use async_trait::async_trait;

/// Errors that can occur when resolving an identity's current key.
#[derive(Debug)]
pub enum ResolveError {
    /// The identity was not found in the registry.
    NotFound(String),
    /// The registry server is unavailable or returned an unexpected error.
    RegistryUnavailable(String),
    /// The KEL data was invalid or could not be parsed.
    InvalidKel(String),
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResolveError::NotFound(msg) => write!(f, "identity not found: {msg}"),
            ResolveError::RegistryUnavailable(msg) => write!(f, "registry unavailable: {msg}"),
            ResolveError::InvalidKel(msg) => write!(f, "invalid KEL: {msg}"),
        }
    }
}

/// Resolves the current signing public key for a DID.
///
/// Implementations fetch the identity's key event log and extract the
/// current Ed25519 public key (raw 32 bytes).
#[async_trait]
pub trait IdentityResolver: Send + Sync {
    /// Resolve the current 32-byte Ed25519 public key for the given DID.
    async fn resolve_current_key(&self, did: &str) -> Result<Vec<u8>, ResolveError>;
}

#[async_trait]
impl IdentityResolver for Box<dyn IdentityResolver> {
    async fn resolve_current_key(&self, did: &str) -> Result<Vec<u8>, ResolveError> {
        self.as_ref().resolve_current_key(did).await
    }
}
