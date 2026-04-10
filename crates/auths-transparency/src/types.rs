use std::fmt;

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::error::TransparencyError;

/// SHA-256 Merkle hash (32 bytes).
///
/// Args:
/// * Inner `[u8; 32]` — raw SHA-256 digest.
///
/// Usage:
/// ```ignore
/// let hash = MerkleHash::from_bytes([0u8; 32]);
/// let hex_str = hash.to_string(); // lowercase hex
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct MerkleHash([u8; 32]);

impl MerkleHash {
    /// The all-zero hash, used as a sentinel for empty trees.
    pub const EMPTY: Self = Self([0u8; 32]);

    /// Wrap raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Construct from a hex string.
    pub fn from_hex(s: &str) -> Result<Self, TransparencyError> {
        let bytes = hex::decode(s).map_err(|e| TransparencyError::InvalidProof(e.to_string()))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| TransparencyError::InvalidProof("hash must be 32 bytes".into()))?;
        Ok(Self(arr))
    }

    /// Raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Encode as standard base64 (with padding). Used in C2SP checkpoint note body.
    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.0)
    }

    /// Decode from standard base64 (with padding).
    pub fn from_base64(s: &str) -> Result<Self, TransparencyError> {
        let bytes = STANDARD
            .decode(s)
            .map_err(|e| TransparencyError::InvalidProof(format!("base64 decode: {e}")))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| TransparencyError::InvalidProof("hash must be 32 bytes".into()))?;
        Ok(Self(arr))
    }

    /// Plain SHA-256 (no domain separation). Used for key-ID computation.
    pub fn sha256(data: &[u8]) -> Self {
        let digest = Sha256::digest(data);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Self(out)
    }
}

impl fmt::Debug for MerkleHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MerkleHash({})", self)
    }
}

impl fmt::Display for MerkleHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl Serialize for MerkleHash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for MerkleHash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

impl AsRef<[u8]> for MerkleHash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Validated log origin string (e.g., `"auths.dev/log"`).
///
/// Must be non-empty ASCII with no control characters.
///
/// Args:
/// * Inner `String` — validated ASCII origin.
///
/// Usage:
/// ```ignore
/// let origin = LogOrigin::new("auths.dev/log")?;
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct LogOrigin(String);

impl LogOrigin {
    /// Create a new log origin, validating that it is non-empty ASCII.
    pub fn new(s: &str) -> Result<Self, TransparencyError> {
        if s.is_empty() {
            return Err(TransparencyError::InvalidOrigin("must not be empty".into()));
        }
        if !s.is_ascii() {
            return Err(TransparencyError::InvalidOrigin("must be ASCII".into()));
        }
        if s.bytes().any(|b| b < 0x20) {
            return Err(TransparencyError::InvalidOrigin(
                "must not contain control characters".into(),
            ));
        }
        Ok(Self(s.to_string()))
    }

    /// Create from a compile-time constant. Panics if invalid.
    ///
    /// Only for use in `default_config()` and similar contexts where the
    /// string is a known-good constant.
    #[allow(clippy::expect_used)] // INVARIANT: only called with compile-time ASCII constants
    pub fn new_unchecked(s: &str) -> Self {
        Self::new(s).expect("LogOrigin::new_unchecked called with invalid origin")
    }

    /// The inner string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LogOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for LogOrigin {
    type Error = TransparencyError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::new(&s)
    }
}

impl From<LogOrigin> for String {
    fn from(o: LogOrigin) -> Self {
        o.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_hash_hex_roundtrip() {
        let bytes = [0xabu8; 32];
        let h = MerkleHash::from_bytes(bytes);
        let hex_str = h.to_string();
        let h2 = MerkleHash::from_hex(&hex_str).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn merkle_hash_json_roundtrip() {
        let h = MerkleHash::from_bytes([0x42u8; 32]);
        let json = serde_json::to_string(&h).unwrap();
        let h2: MerkleHash = serde_json::from_str(&json).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn log_origin_rejects_empty() {
        assert!(LogOrigin::new("").is_err());
    }

    #[test]
    fn log_origin_rejects_non_ascii() {
        assert!(LogOrigin::new("日本語").is_err());
    }

    #[test]
    fn log_origin_rejects_control_chars() {
        assert!(LogOrigin::new("auths\x00log").is_err());
    }

    #[test]
    fn log_origin_valid() {
        let o = LogOrigin::new("auths.dev/log").unwrap();
        assert_eq!(o.as_str(), "auths.dev/log");
    }
}
