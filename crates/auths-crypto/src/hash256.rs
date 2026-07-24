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

    /// Parse a 64-character hex string (with an optional prefix such as `"sha256:"`) into a `Hash256`.
    pub fn from_hex_prefixed(s: &str, expected_prefix: Option<&str>) -> Result<Self, String> {
        let clean = match expected_prefix {
            Some(prefix) => s
                .strip_prefix(prefix)
                .ok_or_else(|| format!("expected prefix '{prefix}'")),
            None => {
                if let Some(stripped) = s.strip_prefix("sha256:") {
                    Ok(stripped)
                } else {
                    Ok(s)
                }
            }
        }?;

        let bytes = hex::decode(clean).map_err(|e| format!("invalid hex: {e}"))?;
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| "hash digest must be exactly 32 bytes (64 hex characters)".to_string())?;

        Ok(Self(array))
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
