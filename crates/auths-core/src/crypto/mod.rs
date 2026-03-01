//! Cryptographic primitives.

pub mod encryption;
pub mod provider_bridge;
pub mod said;
pub mod signer;
pub mod ssh;

#[cfg(feature = "crypto-secp256k1")]
pub mod secp256k1;

pub use said::{compute_next_commitment, compute_said, verify_commitment};
pub use signer::SignerKey;

#[cfg(feature = "crypto-secp256k1")]
pub use secp256k1::Secp256k1KeyPair;

/// Supported encryption algorithms for keypair encryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    /// AES-256-GCM encryption (default tier).
    AesGcm256,
    /// ChaCha20-Poly1305 encryption (pro tier).
    ChaCha20Poly1305,
}

impl EncryptionAlgorithm {
    /// Returns the numeric tag byte for this algorithm.
    pub fn tag(&self) -> u8 {
        match self {
            EncryptionAlgorithm::AesGcm256 => 1,
            EncryptionAlgorithm::ChaCha20Poly1305 => 2,
        }
    }

    /// Parse an algorithm from its numeric tag byte.
    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(EncryptionAlgorithm::AesGcm256),
            2 => Some(EncryptionAlgorithm::ChaCha20Poly1305),
            _ => None,
        }
    }
}
