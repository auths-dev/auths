//! Backend-agnostic event hash type.
//!
//! This module provides [`EventHash`], a 20-byte hash type used to identify
//! KEL events without depending on any specific storage backend (e.g., git2).
//!
//! # Why 20 Bytes?
//!
//! Git uses SHA-1 (20 bytes) for object identifiers. This type is sized to
//! be compatible with Git OIDs while remaining backend-agnostic.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

/// A 20-byte hash identifying a KEL event.
///
/// Serializes as a 40-character lowercase hex string, matching the encoding
/// used by `git2::Oid::to_string()`. This ensures JSON payloads, API schemas,
/// and cache files remain compatible when migrating from `git2::Oid`.
///
/// # Args
///
/// The inner `[u8; 20]` represents the raw SHA-1 bytes.
///
/// # Usage
///
/// ```rust
/// use auths_core::witness::EventHash;
///
/// // From raw bytes
/// let bytes = [0u8; 20];
/// let hash = EventHash::from_bytes(bytes);
/// assert_eq!(hash.as_bytes(), &bytes);
///
/// // From hex string
/// let hash = EventHash::from_hex("0000000000000000000000000000000000000001").unwrap();
/// assert_eq!(hash.to_hex(), "0000000000000000000000000000000000000001");
///
/// // Serde: serializes as hex string, not integer array
/// let json = serde_json::to_string(&hash).unwrap();
/// assert_eq!(json, r#""0000000000000000000000000000000000000001""#);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct EventHash([u8; 20]);

impl EventHash {
    /// Create an EventHash from raw bytes.
    #[inline]
    pub const fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    /// Get the raw bytes of this hash.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// Create an EventHash from a hex string.
    ///
    /// Returns `None` if the string is not exactly 40 hex characters.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auths_core::witness::EventHash;
    ///
    /// let hash = EventHash::from_hex("0123456789abcdef0123456789abcdef01234567");
    /// assert!(hash.is_some());
    ///
    /// // Wrong length
    /// assert!(EventHash::from_hex("0123").is_none());
    ///
    /// // Invalid characters
    /// assert!(EventHash::from_hex("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_none());
    /// ```
    pub fn from_hex(s: &str) -> Option<Self> {
        if s.len() != 40 {
            return None;
        }

        let mut bytes = [0u8; 20];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hi = hex_digit(chunk[0])?;
            let lo = hex_digit(chunk[1])?;
            bytes[i] = (hi << 4) | lo;
        }

        Some(Self(bytes))
    }

    /// Convert this hash to a lowercase hex string.
    ///
    /// # Example
    ///
    /// ```rust
    /// use auths_core::witness::EventHash;
    ///
    /// let hash = EventHash::from_bytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
    ///                                   10, 11, 12, 13, 14, 15, 16, 17, 18, 19]);
    /// assert_eq!(hash.to_hex(), "000102030405060708090a0b0c0d0e0f10111213");
    /// ```
    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(40);
        for byte in &self.0 {
            s.push(HEX_CHARS[(byte >> 4) as usize]);
            s.push(HEX_CHARS[(byte & 0xf) as usize]);
        }
        s
    }
}

/// Hex characters for encoding.
const HEX_CHARS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

/// Convert a hex character to its numeric value.
#[inline]
fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

impl fmt::Debug for EventHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EventHash({})", self.to_hex())
    }
}

impl fmt::Display for EventHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Error returned when parsing an `EventHash` from a hex string fails.
///
/// # Args
///
/// * `InvalidLength` — the input was not exactly 40 hex characters
/// * `InvalidChar` — the input contained a non-hex character
///
/// # Usage
///
/// ```rust
/// use auths_core::witness::EventHash;
/// use std::str::FromStr;
///
/// assert!(EventHash::from_str("not-hex").is_err());
/// ```
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum EventHashParseError {
    /// The input string was not exactly 40 hex characters.
    #[error("expected 40 hex characters, got {0}")]
    InvalidLength(usize),
    /// The input contained a non-hex character at the given position.
    #[error("invalid hex character at position {position}: {ch:?}")]
    InvalidChar {
        /// Zero-based index of the first invalid character.
        position: usize,
        /// The character that failed hex decoding.
        ch: char,
    },
}

impl FromStr for EventHash {
    type Err = EventHashParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 40 {
            return Err(EventHashParseError::InvalidLength(s.len()));
        }
        let mut bytes = [0u8; 20];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hi = hex_digit(chunk[0]).ok_or(EventHashParseError::InvalidChar {
                position: i * 2,
                ch: chunk[0] as char,
            })?;
            let lo = hex_digit(chunk[1]).ok_or(EventHashParseError::InvalidChar {
                position: i * 2 + 1,
                ch: chunk[1] as char,
            })?;
            bytes[i] = (hi << 4) | lo;
        }
        Ok(Self(bytes))
    }
}

impl Serialize for EventHash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for EventHash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse::<EventHash>().map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bytes_roundtrip() {
        let bytes = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ];
        let hash = EventHash::from_bytes(bytes);
        assert_eq!(hash.as_bytes(), &bytes);
    }

    #[test]
    fn from_hex_valid() {
        let hash = EventHash::from_hex("0000000000000000000000000000000000000001").unwrap();
        let mut expected = [0u8; 20];
        expected[19] = 1;
        assert_eq!(hash.as_bytes(), &expected);
    }

    #[test]
    fn from_hex_all_zeros() {
        let hash = EventHash::from_hex("0000000000000000000000000000000000000000").unwrap();
        assert_eq!(hash.as_bytes(), &[0u8; 20]);
    }

    #[test]
    fn from_hex_uppercase() {
        let hash = EventHash::from_hex("ABCDEF0123456789ABCDEF0123456789ABCDEF01").unwrap();
        assert!(
            hash.to_hex()
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        );
    }

    #[test]
    fn from_hex_wrong_length() {
        assert!(EventHash::from_hex("0123").is_none());
        assert!(EventHash::from_hex("").is_none());
        assert!(EventHash::from_hex("00000000000000000000000000000000000000001").is_none());
    }

    #[test]
    fn from_hex_invalid_chars() {
        assert!(EventHash::from_hex("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").is_none());
        assert!(EventHash::from_hex("0000000000000000000000000000000000000g01").is_none());
    }

    #[test]
    fn to_hex_roundtrip() {
        let original = "0123456789abcdef0123456789abcdef01234567";
        let hash = EventHash::from_hex(original).unwrap();
        assert_eq!(hash.to_hex(), original);
    }

    #[test]
    fn debug_format() {
        let hash = EventHash::from_hex("0000000000000000000000000000000000000001").unwrap();
        let debug = format!("{:?}", hash);
        assert!(debug.contains("EventHash"));
        assert!(debug.contains("0000000000000000000000000000000000000001"));
    }

    #[test]
    fn display_format() {
        let hash = EventHash::from_hex("0000000000000000000000000000000000000001").unwrap();
        assert_eq!(
            format!("{}", hash),
            "0000000000000000000000000000000000000001"
        );
    }

    #[test]
    fn equality() {
        let a = EventHash::from_hex("0000000000000000000000000000000000000001").unwrap();
        let b = EventHash::from_hex("0000000000000000000000000000000000000001").unwrap();
        let c = EventHash::from_hex("0000000000000000000000000000000000000002").unwrap();

        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn hash_trait() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        let a = EventHash::from_hex("0000000000000000000000000000000000000001").unwrap();
        let b = EventHash::from_hex("0000000000000000000000000000000000000002").unwrap();

        set.insert(a);
        set.insert(b);
        set.insert(a); // duplicate

        assert_eq!(set.len(), 2);
    }
}
