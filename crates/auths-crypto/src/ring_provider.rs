use async_trait::async_trait;

use crate::provider::{CryptoError, CryptoProvider, ED25519_PUBLIC_KEY_LEN, SecureSeed};
use ring::rand::SystemRandom;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};

/// Native Ed25519 provider powered by the `ring` crate.
///
/// Offloads CPU-bound operations to Tokio's blocking pool via
/// `spawn_blocking` to prevent async reactor starvation under load.
///
/// Usage:
/// ```ignore
/// use auths_crypto::{CryptoProvider, RingCryptoProvider};
///
/// let provider = RingCryptoProvider;
/// provider.verify_ed25519(&pubkey, &msg, &sig).await.unwrap();
/// ```
pub struct RingCryptoProvider;

#[async_trait]
impl CryptoProvider for RingCryptoProvider {
    async fn verify_ed25519(
        &self,
        pubkey: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        if pubkey.len() != ED25519_PUBLIC_KEY_LEN {
            return Err(CryptoError::InvalidKeyLength {
                expected: ED25519_PUBLIC_KEY_LEN,
                actual: pubkey.len(),
            });
        }

        let pubkey = pubkey.to_vec();
        let message = message.to_vec();
        let signature = signature.to_vec();

        tokio::task::spawn_blocking(move || {
            let peer_public_key = UnparsedPublicKey::new(&ED25519, &pubkey);
            peer_public_key
                .verify(&message, &signature)
                .map_err(|_| CryptoError::InvalidSignature)
        })
        .await
        .map_err(|_| CryptoError::OperationFailed("Verification task panicked".into()))?
    }

    async fn sign_ed25519(
        &self,
        seed: &SecureSeed,
        message: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let seed_bytes = *seed.as_bytes();
        let message = message.to_vec();

        // Keypair is re-materialized from the raw seed on each call.
        // This trades minor CPU overhead for a pure, ring-free domain layer.
        tokio::task::spawn_blocking(move || {
            let keypair = Ed25519KeyPair::from_seed_unchecked(&seed_bytes)
                .map_err(|e| CryptoError::InvalidPrivateKey(format!("{e}")))?;
            Ok(keypair.sign(&message).as_ref().to_vec())
        })
        .await
        .map_err(|_| CryptoError::OperationFailed("Signing task panicked".into()))?
    }

    async fn generate_ed25519_keypair(&self) -> Result<(SecureSeed, [u8; 32]), CryptoError> {
        tokio::task::spawn_blocking(move || {
            let rng = SystemRandom::new();
            let pkcs8_doc = Ed25519KeyPair::generate_pkcs8(&rng)
                .map_err(|_| CryptoError::OperationFailed("Key generation failed".into()))?;
            let keypair = Ed25519KeyPair::from_pkcs8(pkcs8_doc.as_ref())
                .map_err(|e| CryptoError::OperationFailed(format!("Parse generated key: {e}")))?;

            let public_key: [u8; 32] = keypair
                .public_key()
                .as_ref()
                .try_into()
                .map_err(|_| CryptoError::OperationFailed("Public key not 32 bytes".into()))?;

            // Extract the raw 32-byte seed from the PKCS#8 DER encoding.
            // Ring's Ed25519 PKCS#8 v2 places the seed at bytes [16..48].
            let pkcs8_bytes = pkcs8_doc.as_ref();
            let seed: [u8; 32] = pkcs8_bytes[16..48]
                .try_into()
                .map_err(|_| CryptoError::OperationFailed("Seed extraction failed".into()))?;

            Ok((SecureSeed::new(seed), public_key))
        })
        .await
        .map_err(|_| CryptoError::OperationFailed("Keygen task panicked".into()))?
    }

    async fn ed25519_public_key_from_seed(
        &self,
        seed: &SecureSeed,
    ) -> Result<[u8; 32], CryptoError> {
        let seed_bytes = *seed.as_bytes();

        tokio::task::spawn_blocking(move || {
            let keypair = Ed25519KeyPair::from_seed_unchecked(&seed_bytes)
                .map_err(|e| CryptoError::InvalidPrivateKey(format!("{e}")))?;
            keypair
                .public_key()
                .as_ref()
                .try_into()
                .map_err(|_| CryptoError::OperationFailed("Public key not 32 bytes".into()))
        })
        .await
        .map_err(|_| CryptoError::OperationFailed("Public key extraction panicked".into()))?
    }
}
