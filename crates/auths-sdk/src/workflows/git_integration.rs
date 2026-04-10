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
/// * `public_key_bytes`: 32-byte Ed25519 or 33-byte P-256 compressed public key.
///
/// Usage:
/// ```ignore
/// let openssh = public_key_to_ssh(&bytes)?;
/// ```
pub fn public_key_to_ssh(public_key_bytes: &[u8]) -> Result<String, GitIntegrationError> {
    match public_key_bytes.len() {
        32 => {
            // Ed25519
            let ed25519_pk = Ed25519PublicKey::try_from(public_key_bytes)
                .map_err(|e| GitIntegrationError::SshKeyEncoding(e.to_string()))?;
            let ssh_pk = SshPublicKey::from(ed25519_pk);
            ssh_pk
                .to_openssh()
                .map_err(|e| GitIntegrationError::SshKeyEncoding(e.to_string()))
        }
        33 => {
            // P-256 compressed SEC1 — decompress to uncompressed for SSH encoding
            use p256::ecdsa::VerifyingKey;
            use ssh_key::public::{EcdsaPublicKey, KeyData};

            let vk = VerifyingKey::from_sec1_bytes(public_key_bytes).map_err(|e| {
                GitIntegrationError::SshKeyEncoding(format!("P-256 key parse: {e}"))
            })?;

            // SSH needs the uncompressed SEC1 point (65 bytes: 04 || x || y)
            let uncompressed = vk.to_encoded_point(false);
            let ecdsa_pk = EcdsaPublicKey::from_sec1_bytes(uncompressed.as_bytes())
                .map_err(|e| GitIntegrationError::SshKeyEncoding(format!("ECDSA SSH key: {e}")))?;

            let ssh_pk = SshPublicKey::from(KeyData::Ecdsa(ecdsa_pk));
            ssh_pk
                .to_openssh()
                .map_err(|e| GitIntegrationError::SshKeyEncoding(e.to_string()))
        }
        other => Err(GitIntegrationError::InvalidKeyLength(other)),
    }
}
