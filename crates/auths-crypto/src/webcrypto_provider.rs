use async_trait::async_trait;

use crate::provider::{CryptoError, CryptoProvider, ED25519_PUBLIC_KEY_LEN, SecureSeed};

/// WASM Ed25519 provider (stub).
///
/// Verification will be implemented via `SubtleCrypto.verify()`.
/// Signing and key generation are not available on WASM targets and return
/// [`CryptoError::UnsupportedTarget`] — callers can pattern-match on this
/// variant to implement fallback strategies (e.g., remote signing service).
///
/// Usage:
/// ```ignore
/// use auths_crypto::{CryptoProvider, WebCryptoProvider};
///
/// let provider = WebCryptoProvider;
/// match provider.sign_ed25519(&seed, b"msg").await {
///     Err(CryptoError::UnsupportedTarget) => { /* expected on WASM */ }
///     _ => unreachable!(),
/// }
/// ```
pub struct WebCryptoProvider;

#[async_trait]
impl CryptoProvider for WebCryptoProvider {
    async fn verify_ed25519(
        &self,
        pubkey: &[u8],
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        if pubkey.len() != ED25519_PUBLIC_KEY_LEN {
            return Err(CryptoError::InvalidKeyLength {
                expected: ED25519_PUBLIC_KEY_LEN,
                actual: pubkey.len(),
            });
        }
        // TODO(tracking): Implement via SubtleCrypto.verify() with wasm-bindgen-futures
        Err(CryptoError::OperationFailed(
            "WebCrypto Ed25519 verify not yet implemented".into(),
        ))
    }

    async fn sign_ed25519(
        &self,
        _seed: &SecureSeed,
        _message: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        Err(CryptoError::UnsupportedTarget)
    }

    async fn generate_ed25519_keypair(&self) -> Result<(SecureSeed, [u8; 32]), CryptoError> {
        Err(CryptoError::UnsupportedTarget)
    }

    async fn ed25519_public_key_from_seed(
        &self,
        _seed: &SecureSeed,
    ) -> Result<[u8; 32], CryptoError> {
        Err(CryptoError::UnsupportedTarget)
    }
}
