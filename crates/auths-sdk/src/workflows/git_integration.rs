//! Git SSH key encoding utilities.

use ssh_key::PublicKey as SshPublicKey;
use ssh_key::public::Ed25519PublicKey;
use thiserror::Error;

/// Errors from SSH key encoding operations.
#[derive(Debug, Error)]
pub enum GitIntegrationError {
    /// Raw public key bytes have an unexpected length.
    #[error("invalid public key length: expected 32 (Ed25519), 33/65 (P-256), got {0}")]
    InvalidKeyLength(usize),
    /// SSH key encoding failed.
    #[error("failed to encode SSH public key: {0}")]
    SshKeyEncoding(String),
}

/// Convert a device public key to an OpenSSH public key string.
///
/// Args:
/// * `key`: Device public key carrying its curve type.
///
/// Usage:
/// ```ignore
/// let openssh = public_key_to_ssh(&device_pk)?;
/// ```
pub fn public_key_to_ssh(
    key: &auths_verifier::DevicePublicKey,
) -> Result<String, GitIntegrationError> {
    match key.curve() {
        auths_crypto::CurveType::Ed25519 => {
            let ed25519_pk = Ed25519PublicKey::try_from(key.as_bytes())
                .map_err(|e| GitIntegrationError::SshKeyEncoding(e.to_string()))?;
            let ssh_pk = SshPublicKey::from(ed25519_pk);
            ssh_pk
                .to_openssh()
                .map_err(|e| GitIntegrationError::SshKeyEncoding(e.to_string()))
        }
        auths_crypto::CurveType::P256 => {
            use ssh_key::public::{EcdsaPublicKey, KeyData};

            let uncompressed_bytes = if key.len() == 33 {
                use p256::ecdsa::VerifyingKey;
                let vk = VerifyingKey::from_sec1_bytes(key.as_bytes()).map_err(|e| {
                    GitIntegrationError::SshKeyEncoding(format!("P-256 key parse: {e}"))
                })?;
                vk.to_encoded_point(false).as_bytes().to_vec()
            } else {
                key.as_bytes().to_vec()
            };

            let ecdsa_pk = EcdsaPublicKey::from_sec1_bytes(&uncompressed_bytes)
                .map_err(|e| GitIntegrationError::SshKeyEncoding(format!("ECDSA SSH key: {e}")))?;

            let ssh_pk = SshPublicKey::from(KeyData::Ecdsa(ecdsa_pk));
            ssh_pk
                .to_openssh()
                .map_err(|e| GitIntegrationError::SshKeyEncoding(e.to_string()))
        }
    }
}
