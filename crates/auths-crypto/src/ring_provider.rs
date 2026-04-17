// INVARIANT: sanctioned crypto boundary — the one place ring is allowed to
// live. All curve-dispatched verify / sign / keypair-generate paths bottom
// out here. Permanent allow; do NOT remove in fn-114.40.
#![allow(clippy::disallowed_methods)]

use async_trait::async_trait;

use crate::provider::{CryptoError, CryptoProvider, ED25519_PUBLIC_KEY_LEN, SecureSeed};
use ring::rand::SystemRandom;
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};

/// Native crypto provider powered by `ring` (Ed25519) and `p256` (ECDSA P-256).
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

impl RingCryptoProvider {
    /// Generate a P-256 keypair. Returns (seed, compressed_public_key).
    pub fn p256_generate() -> Result<(SecureSeed, Vec<u8>), CryptoError> {
        use p256::ecdsa::SigningKey;
        use p256::elliptic_curve::rand_core::OsRng;

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);

        // Compressed SEC1 public key (33 bytes: 0x02/0x03 + x-coordinate)
        let compressed = verifying_key.to_encoded_point(true);
        let pubkey_bytes = compressed.as_bytes().to_vec();

        // Extract the raw 32-byte scalar as the seed
        let scalar_bytes = signing_key.to_bytes();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&scalar_bytes);

        Ok((SecureSeed::new(seed), pubkey_bytes))
    }

    /// Sign with P-256. Returns 64-byte raw r||s.
    pub fn p256_sign(seed: &[u8; 32], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use p256::ecdsa::{SigningKey, signature::Signer};

        let signing_key = SigningKey::from_slice(seed)
            .map_err(|e| CryptoError::InvalidPrivateKey(format!("P-256: {e}")))?;

        let signature: p256::ecdsa::Signature = signing_key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }

    /// Verify an Ed25519 signature synchronously. Pubkey must be 32 raw bytes.
    pub fn ed25519_verify(
        pubkey: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        // INVARIANT: sanctioned ring usage inside auths-crypto per the crate's
        // permanent `#![allow(clippy::disallowed_methods)]` carve-out.
        let pk = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, pubkey);
        pk.verify(message, signature)
            .map_err(|_| CryptoError::InvalidSignature)
    }

    /// Verify a P-256 signature. Accepts 33-byte compressed or 65-byte uncompressed pubkey.
    pub fn p256_verify(pubkey: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
        use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};

        let vk = VerifyingKey::from_sec1_bytes(pubkey)
            .map_err(|e| CryptoError::OperationFailed(format!("P-256 key parse: {e}")))?;

        let sig = Signature::from_slice(signature)
            .map_err(|e| CryptoError::OperationFailed(format!("P-256 sig parse: {e}")))?;

        vk.verify(message, &sig)
            .map_err(|_| CryptoError::InvalidSignature)
    }

    /// Derive compressed public key from P-256 seed.
    pub fn p256_public_key_from_seed(seed: &[u8; 32]) -> Result<Vec<u8>, CryptoError> {
        use p256::ecdsa::SigningKey;

        let signing_key = SigningKey::from_slice(seed)
            .map_err(|e| CryptoError::InvalidPrivateKey(format!("P-256: {e}")))?;
        let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);
        let compressed = verifying_key.to_encoded_point(true);
        Ok(compressed.as_bytes().to_vec())
    }
}

#[async_trait]
impl CryptoProvider for RingCryptoProvider {
    async fn verify_p256(
        &self,
        pubkey: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        Self::p256_verify(pubkey, message, signature)
    }

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
