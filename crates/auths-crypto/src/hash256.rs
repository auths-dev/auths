//! Typed newtype for 32-byte hash digests.
//!
//! `Hash256` is a generic 32-byte digest container — SHA-256, Blake3, or any
//! 32-byte content address. It is NOT a signing key and must not be typed as
//! one. This newtype disambiguates at the type level so the Rust compiler
//! distinguishes hash values from Ed25519 signing-key byte arrays.
//!
//! Wire format is unchanged: `#[serde(transparent)]` preserves byte-identical
//! serialization with the prior bare `[u8; 32]`.

use serde::{Deserialize, Serialize};

/// 32-byte hash digest (SHA-256, Blake3, or any content address).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Hash256([u8; 32]);

impl Hash256 {
    /// Wrap a raw 32-byte digest.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consume into the underlying bytes.
    pub fn into_inner(self) -> [u8; 32] {
        self.0
    }
}

impl From<[u8; 32]> for Hash256 {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Hash256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
