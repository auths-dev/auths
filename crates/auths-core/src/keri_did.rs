//! Newtype for `did:keri:<prefix>` identifiers.
//!
//! Parsing and validation happen at construction time so downstream code
//! can rely on the invariant without re-parsing.

use std::fmt;

use serde::{Deserialize, Serialize};

const PREFIX: &str = "did:keri:";

/// A validated `did:keri:<prefix>` identifier.
///
/// The inner string always starts with `"did:keri:"` followed by a non-empty
/// KERI prefix. Construction is fallible — use [`KeriDid::parse`] or
/// [`TryFrom<String>`].
///
/// Usage:
/// ```ignore
/// let did = KeriDid::parse("did:keri:EXq5abc")?;
/// assert_eq!(did.prefix(), "EXq5abc");
/// assert_eq!(did.as_str(), "did:keri:EXq5abc");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct KeriDid(String);

impl KeriDid {
    /// Parse a `did:keri:` string, returning an error if the format is invalid.
    ///
    /// Args:
    /// * `s`: A string that must start with `"did:keri:"` followed by a non-empty prefix.
    ///
    /// Usage:
    /// ```ignore
    /// let did = KeriDid::parse("did:keri:EXq5")?;
    /// ```
    pub fn parse(s: &str) -> Result<Self, KeriDidError> {
        let keri_prefix = s.strip_prefix(PREFIX).ok_or(KeriDidError::MissingPrefix)?;
        if keri_prefix.is_empty() {
            return Err(KeriDidError::EmptyPrefix);
        }
        Ok(Self(s.to_string()))
    }

    /// Build a `KeriDid` from a raw KERI prefix (without the `did:keri:` scheme).
    ///
    /// Args:
    /// * `prefix`: The bare KERI prefix string (e.g. `"EXq5abc"`).
    ///
    /// Usage:
    /// ```ignore
    /// let did = KeriDid::from_prefix("EXq5abc");
    /// assert_eq!(did.as_str(), "did:keri:EXq5abc");
    /// ```
    pub fn from_prefix(prefix: &str) -> Result<Self, KeriDidError> {
        if prefix.is_empty() {
            return Err(KeriDidError::EmptyPrefix);
        }
        Ok(Self(format!("{}{}", PREFIX, prefix)))
    }

    /// Returns the KERI prefix portion (everything after `did:keri:`).
    pub fn prefix(&self) -> &str {
        // Safe: invariant established at construction
        &self.0[PREFIX.len()..]
    }

    /// Returns the full DID string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for KeriDid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for KeriDid {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<KeriDid> for String {
    fn from(did: KeriDid) -> Self {
        did.0
    }
}

impl TryFrom<String> for KeriDid {
    type Error = KeriDidError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let keri_prefix = s.strip_prefix(PREFIX).ok_or(KeriDidError::MissingPrefix)?;
        if keri_prefix.is_empty() {
            return Err(KeriDidError::EmptyPrefix);
        }
        Ok(Self(s))
    }
}

impl TryFrom<&str> for KeriDid {
    type Error = KeriDidError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

/// Error from parsing an invalid `did:keri:` string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeriDidError {
    /// The `did:keri:` prefix is absent.
    #[error("not a did:keri: identifier")]
    MissingPrefix,

    /// The prefix portion is empty.
    #[error("did:keri: prefix is empty")]
    EmptyPrefix,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid() {
        let did = KeriDid::parse("did:keri:EXq5abc123").unwrap();
        assert_eq!(did.prefix(), "EXq5abc123");
        assert_eq!(did.as_str(), "did:keri:EXq5abc123");
        assert_eq!(did.to_string(), "did:keri:EXq5abc123");
    }

    #[test]
    fn from_prefix_valid() {
        let did = KeriDid::from_prefix("EXq5abc123").unwrap();
        assert_eq!(did.as_str(), "did:keri:EXq5abc123");
        assert_eq!(did.prefix(), "EXq5abc123");
    }

    #[test]
    fn rejects_non_keri() {
        assert_eq!(
            KeriDid::parse("did:key:z6Mk123"),
            Err(KeriDidError::MissingPrefix)
        );
    }

    #[test]
    fn rejects_empty_prefix() {
        assert_eq!(KeriDid::parse("did:keri:"), Err(KeriDidError::EmptyPrefix));
    }

    #[test]
    fn rejects_missing_scheme() {
        assert_eq!(KeriDid::parse("EXq5abc"), Err(KeriDidError::MissingPrefix));
    }

    #[test]
    fn from_prefix_rejects_empty() {
        assert_eq!(KeriDid::from_prefix(""), Err(KeriDidError::EmptyPrefix));
    }

    #[test]
    fn try_from_string() {
        let did: KeriDid = "did:keri:EXq5".to_string().try_into().unwrap();
        assert_eq!(did.prefix(), "EXq5");
    }

    #[test]
    fn into_string() {
        let did = KeriDid::parse("did:keri:EXq5").unwrap();
        let s: String = did.into();
        assert_eq!(s, "did:keri:EXq5");
    }

    #[test]
    fn serde_roundtrip() {
        let did = KeriDid::parse("did:keri:EXq5abc").unwrap();
        let json = serde_json::to_string(&did).unwrap();
        assert_eq!(json, r#""did:keri:EXq5abc""#);
        let parsed: KeriDid = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, did);
    }

    #[test]
    fn serde_rejects_invalid() {
        let result: Result<KeriDid, _> = serde_json::from_str(r#""did:key:z6Mk""#);
        assert!(result.is_err());
    }
}
