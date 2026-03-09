//! Git SSH key encoding utilities.

use ssh_key::PublicKey as SshPublicKey;
use ssh_key::public::Ed25519PublicKey;
use thiserror::Error;

/// Errors from SSH key encoding operations.
#[derive(Debug, Error)]
pub enum GitIntegrationError {
    /// Raw public key bytes have an unexpected length.
    #[error("invalid Ed25519 public key length: expected 32, got {0}")]
    InvalidKeyLength(usize),
    /// SSH key encoding failed.
    #[error("failed to encode SSH public key: {0}")]
    SshKeyEncoding(String),
}

/// Convert raw Ed25519 public key bytes to an OpenSSH public key string.
///
/// Args:
/// * `public_key_bytes`: 32-byte Ed25519 public key.
///
/// Usage:
/// ```ignore
/// let openssh = public_key_to_ssh(&bytes)?;
/// ```
pub fn public_key_to_ssh(public_key_bytes: &[u8]) -> Result<String, GitIntegrationError> {
    if public_key_bytes.len() != 32 {
        return Err(GitIntegrationError::InvalidKeyLength(
            public_key_bytes.len(),
        ));
    }
    let ed25519_pk = Ed25519PublicKey::try_from(public_key_bytes)
        .map_err(|e| GitIntegrationError::SshKeyEncoding(e.to_string()))?;
    let ssh_pk = SshPublicKey::from(ed25519_pk);
    ssh_pk
        .to_openssh()
        .map_err(|e| GitIntegrationError::SshKeyEncoding(e.to_string()))
}
