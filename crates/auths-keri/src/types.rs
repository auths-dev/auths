use std::borrow::Borrow;
use std::fmt;

use serde::{Deserialize, Serialize};

// ── KERI Identifier Newtypes ────────────────────────────────────────────────

/// Error when constructing KERI newtypes with invalid values.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
#[error("Invalid KERI {type_name}: {reason}")]
pub struct KeriTypeError {
    /// Which KERI type failed validation.
    pub type_name: &'static str,
    /// Why validation failed.
    pub reason: String,
}

/// Shared validation for KERI self-addressing identifiers.
///
/// Both `Prefix` and `Said` must start with 'E' (Blake3-256 derivation code).
fn validate_keri_derivation_code(s: &str, type_label: &'static str) -> Result<(), KeriTypeError> {
    if s.is_empty() {
        return Err(KeriTypeError {
            type_name: type_label,
            reason: "must not be empty".into(),
        });
    }
    if !s.starts_with('E') {
        return Err(KeriTypeError {
            type_name: type_label,
            reason: format!(
                "must start with 'E' (Blake3 derivation code), got '{}'",
                &s[..s.len().min(10)]
            ),
        });
    }
    Ok(())
}

/// Strongly-typed KERI identifier prefix (e.g., `"ETest123..."`).
///
/// A prefix is the self-addressing identifier derived from the inception event's
/// Blake3 hash. Always starts with 'E' (Blake3-256 derivation code).
///
/// Args:
/// * Inner `String` should start with `'E'` (enforced by `new()`, not by serde).
///
/// Usage:
/// ```ignore
/// let prefix = Prefix::new("ETest123abc".to_string())?;
/// assert_eq!(prefix.as_str(), "ETest123abc");
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[repr(transparent)]
pub struct Prefix(String);

impl Prefix {
    /// Validates and wraps a KERI prefix string.
    pub fn new(s: String) -> Result<Self, KeriTypeError> {
        validate_keri_derivation_code(&s, "Prefix")?;
        Ok(Self(s))
    }

    /// Wraps a prefix string without validation (for trusted internal paths).
    pub fn new_unchecked(s: String) -> Self {
        Self(s)
    }

    /// Returns the inner string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes self and returns the inner String.
    pub fn into_inner(self) -> String {
        self.0
    }

    /// Returns true if the inner string is empty (placeholder during event construction).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Prefix {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for Prefix {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl From<Prefix> for String {
    fn from(p: Prefix) -> String {
        p.0
    }
}

impl PartialEq<str> for Prefix {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for Prefix {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<Prefix> for str {
    fn eq(&self, other: &Prefix) -> bool {
        self == other.0
    }
}

impl PartialEq<Prefix> for &str {
    fn eq(&self, other: &Prefix) -> bool {
        *self == other.0
    }
}

/// KERI Self-Addressing Identifier (SAID).
///
/// A Blake3 hash that uniquely identifies a KERI event. Creates the
/// hash chain: each event's `p` (previous) field is the prior event's SAID.
///
/// Structurally identical to `Prefix` (both start with 'E') but semantically
/// distinct — a prefix identifies an *identity*, a SAID identifies an *event*.
///
/// Args:
/// * Inner `String` should start with `'E'` (enforced by `new()`, not by serde).
///
/// Usage:
/// ```ignore
/// let said = Said::new("ESAID123".to_string())?;
/// assert_eq!(said.as_str(), "ESAID123");
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[repr(transparent)]
pub struct Said(String);

impl Said {
    /// Validates and wraps a KERI SAID string.
    pub fn new(s: String) -> Result<Self, KeriTypeError> {
        validate_keri_derivation_code(&s, "Said")?;
        Ok(Self(s))
    }

    /// Wraps a SAID string without validation (for `compute_said()` output and storage loads).
    pub fn new_unchecked(s: String) -> Self {
        Self(s)
    }

    /// Returns the inner string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes self and returns the inner String.
    pub fn into_inner(self) -> String {
        self.0
    }

    /// Returns true if the inner string is empty (placeholder during event construction).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Display for Said {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Said {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for Said {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl From<Said> for String {
    fn from(s: Said) -> String {
        s.0
    }
}

impl PartialEq<str> for Said {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for Said {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<Said> for str {
    fn eq(&self, other: &Said) -> bool {
        self == other.0
    }
}

impl PartialEq<Said> for &str {
    fn eq(&self, other: &Said) -> bool {
        *self == other.0
    }
}
