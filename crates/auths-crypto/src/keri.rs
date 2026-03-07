//! KERI CESR Ed25519 key parsing.
//!
//! Decodes KERI-encoded public keys: 'D' derivation code prefix + base64url-no-pad
//! encoded 32-byte Ed25519 key, as defined by the KERI CESR specification.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

/// Errors from decoding a KERI-encoded Ed25519 public key.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeriDecodeError {
    #[error("Invalid KERI prefix: expected 'D' for Ed25519, got '{0}'")]
    InvalidPrefix(char),
    #[error("Missing KERI prefix: empty string")]
    EmptyInput,
    #[error("Base64url decode failed: {0}")]
    DecodeError(String),
    #[error("Invalid Ed25519 key length: expected 32 bytes, got {0}")]
    InvalidLength(usize),
}

/// A validated KERI Ed25519 public key (32 bytes).
///
/// Args:
/// * The inner `[u8; 32]` is the raw Ed25519 public key bytes, decoded from
///   a KERI CESR-encoded string with 'D' derivation code prefix.
///
/// Usage:
/// ```
/// use auths_crypto::KeriPublicKey;
///
/// let key = KeriPublicKey::parse("DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
/// assert_eq!(key.as_bytes(), &[0u8; 32]);
/// ```
#[derive(Debug)]
pub struct KeriPublicKey([u8; 32]);

impl KeriPublicKey {
    /// Parses a KERI-encoded Ed25519 public key string into a validated type.
    ///
    /// The input must be a 'D'-prefixed base64url-no-pad encoded 32-byte Ed25519 key,
    /// as defined by the KERI CESR specification.
    ///
    /// Args:
    /// * `encoded`: The KERI-encoded string (e.g., `"D<base64url>"`).
    ///
    /// Usage:
    /// ```
    /// use auths_crypto::KeriPublicKey;
    ///
    /// let key = KeriPublicKey::parse("DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
    /// let raw = key.as_bytes();
    /// ```
    pub fn parse(encoded: &str) -> Result<Self, KeriDecodeError> {
        let payload = validate_and_strip_prefix(encoded)?;
        let bytes = decode_base64url(payload)?;
        let array = enforce_key_length(bytes)?;
        Ok(Self(array))
    }

    /// Returns the raw 32-byte Ed25519 public key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consumes self and returns the inner 32-byte array.
    pub fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

fn validate_and_strip_prefix(encoded: &str) -> Result<&str, KeriDecodeError> {
    match encoded.strip_prefix('D') {
        Some(payload) => Ok(payload),
        None => match encoded.chars().next() {
            Some(c) => Err(KeriDecodeError::InvalidPrefix(c)),
            None => Err(KeriDecodeError::EmptyInput),
        },
    }
}

fn decode_base64url(payload: &str) -> Result<Vec<u8>, KeriDecodeError> {
    URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|e| KeriDecodeError::DecodeError(e.to_string()))
}

fn enforce_key_length(bytes: Vec<u8>) -> Result<[u8; 32], KeriDecodeError> {
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| KeriDecodeError::InvalidLength(len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_all_zeros() {
        let key = KeriPublicKey::parse("DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        assert_eq!(key.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn roundtrip_into_bytes() {
        let key = KeriPublicKey::parse("DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
        let bytes = key.into_bytes();
        assert_eq!(bytes, [0u8; 32]);
    }

    #[test]
    fn rejects_empty_input() {
        let err = KeriPublicKey::parse("").unwrap_err();
        assert_eq!(err, KeriDecodeError::EmptyInput);
    }

    #[test]
    fn rejects_wrong_prefix() {
        let err = KeriPublicKey::parse("Xsomething").unwrap_err();
        assert!(matches!(err, KeriDecodeError::InvalidPrefix('X')));
    }

    #[test]
    fn rejects_invalid_base64() {
        let err = KeriPublicKey::parse("D!!!invalid!!!").unwrap_err();
        assert!(matches!(err, KeriDecodeError::DecodeError(_)));
    }
}
