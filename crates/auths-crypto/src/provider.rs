//! Pluggable cryptographic abstraction for Ed25519 operations.
//!
//! Defines the [`CryptoProvider`] trait for Ed25519 verification, signing, and
//! key generation — enabling `ring` on native targets and `WebCrypto` on WASM.

use async_trait::async_trait;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Error type for cryptographic operations.
///
/// Usage:
/// ```ignore
/// match result {
///     Err(CryptoError::InvalidSignature) => { /* signature did not verify */ }
///     Err(CryptoError::UnsupportedTarget) => { /* not available on this platform */ }
///     Err(CryptoError::OperationFailed(msg)) => { /* backend error */ }
///     Ok(()) => { /* success */ }
/// }
/// ```
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum CryptoError {
    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid public key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("Invalid private key: {0}")]
    InvalidPrivateKey(String),

    #[error("Crypto operation failed: {0}")]
    OperationFailed(String),

    #[error("Operation not supported on current compilation target")]
    UnsupportedTarget,
}

impl crate::AuthsErrorInfo for CryptoError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::InvalidSignature => "AUTHS-E1001",
            Self::InvalidKeyLength { .. } => {
                "
            "
            }
            Self::InvalidPrivateKey(_) => "AUTHS-E1003",
            Self::OperationFailed(_) => "AUTHS-E1004",
            Self::UnsupportedTarget => "AUTHS-E1005",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::InvalidSignature => Some("The signature does not match the data or public key"),
            Self::InvalidKeyLength { .. } => Some("Ensure the key is exactly 32 bytes for Ed25519"),
            Self::UnsupportedTarget => {
                Some("This operation is not available on the current platform")
            }
            _ => None,
        }
    }
}

/// Zeroize-on-drop wrapper for a raw 32-byte Ed25519 seed.
///
/// This is the portable key representation that crosses the [`CryptoProvider`]
/// boundary. No ring types leak through the trait — only this raw seed.
/// The provider materializes the internal keypair from the seed on each call.
///
/// Usage:
/// ```ignore
/// let (seed, pubkey) = provider.generate_ed25519_keypair().await?;
/// let sig = provider.sign_ed25519(&seed, b"hello").await?;
/// // seed is securely zeroed when dropped
/// ```
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureSeed([u8; 32]);

impl SecureSeed {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for SecureSeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecureSeed([REDACTED])")
    }
}

/// Abstraction for Ed25519 cryptographic operations across target architectures.
///
/// All method signatures use primitive Rust types or [`SecureSeed`] — no
/// ring-specific types. This ensures domain crates (`auths-core`, `auths-sdk`)
/// compile without any ring dependency.
///
/// Usage:
/// ```ignore
/// use auths_crypto::CryptoProvider;
///
/// async fn roundtrip(provider: &dyn CryptoProvider) {
///     let (seed, pk) = provider.generate_ed25519_keypair().await.unwrap();
///     let sig = provider.sign_ed25519(&seed, b"msg").await.unwrap();
///     provider.verify_ed25519(&pk, b"msg", &sig).await.unwrap();
/// }
/// ```
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
pub trait CryptoProvider: Send + Sync {
    /// Verify an Ed25519 signature against a public key and message.
    async fn verify_ed25519(
        &self,
        pubkey: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError>;

    /// Sign a message using a raw 32-byte Ed25519 seed.
    ///
    /// The provider materializes the internal keypair from the seed on each
    /// call. This trades minor CPU overhead for a pure, ring-free domain layer.
    ///
    /// Args:
    /// * `seed`: Raw 32-byte Ed25519 private key seed.
    /// * `message`: The data to sign.
    ///
    /// Usage:
    /// ```ignore
    /// let sig = provider.sign_ed25519(&seed, b"hello").await?;
    /// assert_eq!(sig.len(), 64);
    /// ```
    async fn sign_ed25519(&self, seed: &SecureSeed, message: &[u8])
    -> Result<Vec<u8>, CryptoError>;

    /// Generate a fresh Ed25519 keypair.
    ///
    /// Returns the raw 32-byte seed and 32-byte public key.
    ///
    /// Usage:
    /// ```ignore
    /// let (seed, pubkey) = provider.generate_ed25519_keypair().await?;
    /// assert_eq!(pubkey.len(), 32);
    /// ```
    async fn generate_ed25519_keypair(&self) -> Result<(SecureSeed, [u8; 32]), CryptoError>;

    /// Derive the 32-byte public key from a raw seed.
    ///
    /// Args:
    /// * `seed`: Raw 32-byte Ed25519 private key seed.
    ///
    /// Usage:
    /// ```ignore
    /// let pk = provider.ed25519_public_key_from_seed(&seed).await?;
    /// assert_eq!(pk.len(), 32);
    /// ```
    async fn ed25519_public_key_from_seed(
        &self,
        seed: &SecureSeed,
    ) -> Result<[u8; 32], CryptoError>;
}

/// Errors from hex seed decoding.
///
/// Usage:
/// ```ignore
/// match decode_seed_hex("bad") {
///     Err(SeedDecodeError::InvalidHex(_)) => { /* not valid hex */ }
///     Err(SeedDecodeError::WrongLength { .. }) => { /* not 32 bytes */ }
///     Ok(seed) => { /* use seed */ }
/// }
/// ```
#[derive(Debug, thiserror::Error)]
pub enum SeedDecodeError {
    /// The input string is not valid hexadecimal.
    #[error("invalid hex encoding: {0}")]
    InvalidHex(hex::FromHexError),

    /// The decoded bytes are not exactly 32 bytes.
    #[error("expected {expected} bytes, got {got}")]
    WrongLength {
        /// Expected byte count (always 32).
        expected: usize,
        /// Actual byte count after decoding.
        got: usize,
    },
}

/// Decodes a hex-encoded Ed25519 seed (64 hex chars = 32 bytes) into a [`SecureSeed`].
///
/// Args:
/// * `hex_str`: Hex-encoded seed string (must be exactly 64 characters).
///
/// Usage:
/// ```ignore
/// let seed = decode_seed_hex("abcdef01...")?;
/// ```
pub fn decode_seed_hex(hex_str: &str) -> Result<SecureSeed, SeedDecodeError> {
    let bytes = hex::decode(hex_str).map_err(SeedDecodeError::InvalidHex)?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| SeedDecodeError::WrongLength {
            expected: 32,
            got: v.len(),
        })?;
    Ok(SecureSeed::new(arr))
}

/// Ed25519 public key length in bytes.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// Ed25519 signature length in bytes.
pub const ED25519_SIGNATURE_LEN: usize = 64;
