use async_trait::async_trait;
use auths_crypto::{CryptoError, CryptoProvider, SecureSeed};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// Configurable mock for [`CryptoProvider`] used in headless testing.
///
/// Returns `Ok(())` or `Err(InvalidSignature)` based on configuration,
/// and tracks invocation counts so tests can assert verification was called.
///
/// Usage:
/// ```ignore
/// use std::sync::Arc;
/// use auths_test_utils::fakes::crypto::MockCryptoProvider;
///
/// let provider = Arc::new(MockCryptoProvider::accepting());
/// // pass Arc::clone(&provider) to the system under test
/// assert_eq!(provider.call_count(), 1);
/// ```
pub struct MockCryptoProvider {
    should_verify: AtomicBool,
    call_count: AtomicUsize,
}

impl MockCryptoProvider {
    pub fn accepting() -> Self {
        Self {
            should_verify: AtomicBool::new(true),
            call_count: AtomicUsize::new(0),
        }
    }

    pub fn rejecting() -> Self {
        Self {
            should_verify: AtomicBool::new(false),
            call_count: AtomicUsize::new(0),
        }
    }

    pub fn set_should_verify(&self, value: bool) {
        self.should_verify.store(value, Ordering::SeqCst);
    }

    pub fn call_count(&self) -> usize {
        self.call_count.load(Ordering::SeqCst)
    }

    pub fn reset_call_count(&self) {
        self.call_count.store(0, Ordering::SeqCst);
    }
}

#[async_trait]
impl CryptoProvider for MockCryptoProvider {
    async fn verify_ed25519(
        &self,
        _pubkey: &[u8],
        _message: &[u8],
        _signature: &[u8],
    ) -> Result<(), CryptoError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        if self.should_verify.load(Ordering::SeqCst) {
            Ok(())
        } else {
            Err(CryptoError::InvalidSignature)
        }
    }

    async fn sign_ed25519(
        &self,
        _seed: &SecureSeed,
        _message: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        Ok(vec![0u8; 64])
    }

    async fn generate_ed25519_keypair(&self) -> Result<(SecureSeed, [u8; 32]), CryptoError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        Ok((SecureSeed::new([0u8; 32]), [0u8; 32]))
    }

    async fn ed25519_public_key_from_seed(
        &self,
        _seed: &SecureSeed,
    ) -> Result<[u8; 32], CryptoError> {
        self.call_count.fetch_add(1, Ordering::SeqCst);
        Ok([0u8; 32])
    }
}
