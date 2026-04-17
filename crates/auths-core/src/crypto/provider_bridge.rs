//! Sync bridge for calling async CryptoProvider from synchronous code.
//!
//! All production crypto operations in auths-core route through these helpers,
//! which delegate to `RingCryptoProvider` (via the `CryptoProvider` trait).

use auths_crypto::{CryptoError, CryptoProvider, RingCryptoProvider, SecureSeed};
use once_cell::sync::Lazy;

fn provider() -> RingCryptoProvider {
    RingCryptoProvider
}

/// Fallback runtime for contexts where no tokio runtime is active (e.g. FFI).
#[allow(clippy::expect_used)] // tokio runtime creation is genuinely fatal if it fails
static FALLBACK_RT: Lazy<tokio::runtime::Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create fallback crypto runtime")
});

fn run_sync<F, T>(future: F) -> T
where
    F: std::future::Future<Output = T>,
{
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        tokio::task::block_in_place(|| handle.block_on(future))
    } else {
        FALLBACK_RT.block_on(future)
    }
}

/// Verify an Ed25519 signature synchronously.
pub fn verify_ed25519_sync(
    pubkey: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    run_sync(provider().verify_ed25519(pubkey, message, signature))
}

/// Generate a fresh Ed25519 keypair synchronously.
pub fn generate_ed25519_keypair_sync() -> Result<(SecureSeed, [u8; 32]), CryptoError> {
    run_sync(provider().generate_ed25519_keypair())
}
