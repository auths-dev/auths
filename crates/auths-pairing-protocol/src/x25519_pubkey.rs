//! Typed newtype for X25519 ECDH public keys.
//!
//! X25519 public keys are 32 bytes by primitive definition (a Curve25519 field
//! element). They are NOT Ed25519 signing keys and must not be typed as one.
//! This newtype exists so the Rust type system distinguishes the two — callers
//! can't accidentally pass an X25519 ECDH key where an Ed25519 signing key is
//! expected, and vice versa.
//!
//! Wire format is unchanged: `#[serde(transparent)]` preserves byte-identical
//! serialization with the prior bare `[u8; 32]`.

use serde::{Deserialize, Serialize};

/// X25519 ECDH public key (32 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct X25519PublicKey([u8; 32]);

impl X25519PublicKey {
    /// Wrap a raw 32-byte X25519 public key.
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

impl From<[u8; 32]> for X25519PublicKey {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for X25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
