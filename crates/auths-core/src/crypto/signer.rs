//! Signing key types.

use crate::config::current_algorithm;
use crate::crypto::encryption::{decrypt_bytes, encrypt_bytes};
use crate::crypto::provider_bridge;
use crate::error::AgentError;
use auths_crypto::SecureSeed;
use ssh_agent_lib::ssh_key::Algorithm as SshAlgorithm;
use zeroize::Zeroizing;

/// A trait implemented by key types that can sign messages and return their public key.
pub trait SignerKey: Send + Sync + 'static {
    /// Returns the public key bytes of this key.
    fn public_key_bytes(&self) -> Vec<u8>;

    /// Returns the key kind (i.e., SSH algorithm) of this key.
    fn kind(&self) -> SshAlgorithm;

    /// Signs a message and returns the signature bytes.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, AgentError>;
}

/// SignerKey implementation backed by a SecureSeed, routing through CryptoProvider.
pub struct SeedSignerKey {
    seed: SecureSeed,
    public_key: [u8; 32],
}

impl SeedSignerKey {
    /// Create a `SignerKey` from a seed and pre-computed public key.
    pub fn new(seed: SecureSeed, public_key: [u8; 32]) -> Self {
        Self { seed, public_key }
    }

    /// Create a `SignerKey` by deriving the public key from the seed.
    pub fn from_seed(seed: SecureSeed) -> Result<Self, AgentError> {
        let public_key =
            provider_bridge::ed25519_public_key_from_seed_sync(&seed).map_err(|e| {
                AgentError::CryptoError(format!("Failed to derive public key from seed: {}", e))
            })?;
        Ok(Self { seed, public_key })
    }
}

impl SignerKey for SeedSignerKey {
    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.to_vec()
    }

    fn kind(&self) -> SshAlgorithm {
        SshAlgorithm::Ed25519
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, AgentError> {
        provider_bridge::sign_ed25519_sync(&self.seed, message)
            .map_err(|e| AgentError::CryptoError(format!("Ed25519 signing failed: {}", e)))
    }
}

/// Extract a SecureSeed from key bytes in various formats.
///
/// Delegates to [`auths_crypto::parse_ed25519_seed`].
pub fn extract_seed_from_key_bytes(bytes: &[u8]) -> Result<SecureSeed, AgentError> {
    auths_crypto::parse_ed25519_seed(bytes)
        .map_err(|e| AgentError::KeyDeserializationError(format!("{}", e)))
}

/// Extract a SecureSeed and public key from key bytes.
///
/// For PKCS#8 v2 the public key is extracted from the DER. For other formats,
/// the public key is derived from the seed via CryptoProvider.
pub fn load_seed_and_pubkey(bytes: &[u8]) -> Result<(SecureSeed, [u8; 32]), AgentError> {
    let (seed, maybe_pk) = auths_crypto::parse_ed25519_key_material(bytes)
        .map_err(|e| AgentError::KeyDeserializationError(format!("{}", e)))?;

    let pubkey = match maybe_pk {
        Some(pk) => pk,
        None => provider_bridge::ed25519_public_key_from_seed_sync(&seed).map_err(|e| {
            AgentError::CryptoError(format!("Failed to derive public key from seed: {}", e))
        })?,
    };

    Ok((seed, pubkey))
}

/// Encrypts a raw serialized keypair using the configured encryption algorithm and passphrase.
pub fn encrypt_keypair(raw: &[u8], passphrase: &str) -> Result<Vec<u8>, AgentError> {
    encrypt_bytes(raw, passphrase, current_algorithm())
}

/// Decrypts a previously encrypted keypair using the configured encryption algorithm and passphrase.
pub fn decrypt_keypair(
    encrypted: &[u8],
    passphrase: &str,
) -> Result<Zeroizing<Vec<u8>>, AgentError> {
    Ok(Zeroizing::new(decrypt_bytes(encrypted, passphrase)?))
}
