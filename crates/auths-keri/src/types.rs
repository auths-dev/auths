use std::borrow::Borrow;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::keys::{KeriDecodeError, KeriPublicKey};

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

/// Validate a CESR derivation code for AIDs (Prefix).
///
/// Accepts any valid CESR primitive prefix: uppercase letter or digit.
/// `D` = Ed25519, `E` = Blake3-256, `1` = secp256k1, etc.
fn validate_prefix_derivation_code(s: &str) -> Result<(), KeriTypeError> {
    if s.is_empty() {
        return Err(KeriTypeError {
            type_name: "Prefix",
            reason: "must not be empty".into(),
        });
    }
    let first = s.as_bytes()[0];
    if !first.is_ascii_uppercase() && !first.is_ascii_digit() {
        return Err(KeriTypeError {
            type_name: "Prefix",
            reason: format!(
                "must start with a CESR derivation code (uppercase letter or digit), got '{}'",
                &s[..s.len().min(10)]
            ),
        });
    }
    Ok(())
}

/// Validate a CESR derivation code for SAIDs (digest only).
///
/// SAIDs are always digests — currently only Blake3-256 (`E`).
fn validate_said_derivation_code(s: &str) -> Result<(), KeriTypeError> {
    if s.is_empty() {
        return Err(KeriTypeError {
            type_name: "Said",
            reason: "must not be empty".into(),
        });
    }
    if !s.starts_with('E') {
        return Err(KeriTypeError {
            type_name: "Said",
            reason: format!(
                "must start with 'E' (Blake3 derivation code), got '{}'",
                &s[..s.len().min(10)]
            ),
        });
    }
    Ok(())
}

/// Strongly-typed KERI identifier prefix (e.g., `"ETest123..."`, `"DKey456..."`).
///
/// A prefix is the autonomous identifier (AID) for a KERI identity. For
/// self-addressing AIDs it starts with `E` (Blake3-256 digest of the inception
/// event); for key-based AIDs it starts with `D` (Ed25519 public key) or
/// another CESR derivation code.
///
/// Args:
/// * Inner `String` must start with a valid CESR derivation code (uppercase
///   letter or digit). Enforced by `new()`, not by serde.
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
    ///
    /// Accepts any valid CESR derivation code (`D` for Ed25519, `E` for Blake3,
    /// `1` for secp256k1, etc.). See [`validate_prefix_derivation_code`] for details.
    pub fn new(s: String) -> Result<Self, KeriTypeError> {
        validate_prefix_derivation_code(&s)?;
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
    ///
    /// Only accepts `E` prefix (digest derivation codes).
    pub fn new(s: String) -> Result<Self, KeriTypeError> {
        validate_said_derivation_code(&s)?;
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

// ── Fraction ────────────────────────────────────────────────────────────────

/// Exact rational number for weighted threshold arithmetic.
///
/// Uses integer cross-multiplication for comparison — NOT floating point.
/// This ensures `1/3 + 1/3 + 1/3` equals exactly `1`.
///
/// Usage:
/// ```
/// use auths_keri::Fraction;
/// let f: Fraction = "1/3".parse().unwrap();
/// assert_eq!(f.numerator, 1);
/// assert_eq!(f.denominator, 3);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Fraction {
    /// Numerator of the fraction.
    pub numerator: u64,
    /// Denominator of the fraction (must be > 0).
    pub denominator: u64,
}

/// Error when parsing a `Fraction` from a string.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum FractionError {
    /// Missing the `/` separator.
    #[error("missing '/' separator in fraction: {0:?}")]
    MissingSeparator(String),
    /// Numerator or denominator is not a valid integer.
    #[error("invalid integer in fraction: {0}")]
    InvalidInt(String),
    /// Denominator is zero.
    #[error("fraction denominator must not be zero")]
    ZeroDenominator,
}

impl Fraction {
    /// Check if the sum of the given fractions is >= 1, using exact integer arithmetic.
    ///
    /// Uses cross-multiplication to avoid floating-point imprecision.
    /// `1/3 + 1/3 + 1/3` returns `true` (exactly 1).
    ///
    /// Usage:
    /// ```
    /// use auths_keri::Fraction;
    /// let thirds: Vec<Fraction> = vec!["1/3".parse().unwrap(); 3];
    /// let refs: Vec<&Fraction> = thirds.iter().collect();
    /// assert!(Fraction::sum_meets_one(&refs));
    /// ```
    pub fn sum_meets_one(fractions: &[&Fraction]) -> bool {
        if fractions.is_empty() {
            return false;
        }
        // Accumulate as num/den using: a/b + c/d = (a*d + c*b) / (b*d)
        // Use u128 to avoid overflow with u64 numerators/denominators.
        let mut num: u128 = 0;
        let mut den: u128 = 1;
        for f in fractions {
            // num/den + f.numerator/f.denominator
            // = (num * f.denominator + f.numerator * den) / (den * f.denominator)
            num = num * (f.denominator as u128) + (f.numerator as u128) * den;
            den *= f.denominator as u128;
        }
        // Check num/den >= 1, i.e., num >= den
        num >= den
    }
}

impl FromStr for Fraction {
    type Err = FractionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (num_str, den_str) = s
            .split_once('/')
            .ok_or_else(|| FractionError::MissingSeparator(s.to_string()))?;
        let numerator: u64 = num_str
            .parse()
            .map_err(|_| FractionError::InvalidInt(num_str.to_string()))?;
        let denominator: u64 = den_str
            .parse()
            .map_err(|_| FractionError::InvalidInt(den_str.to_string()))?;
        if denominator == 0 {
            return Err(FractionError::ZeroDenominator);
        }
        Ok(Self {
            numerator,
            denominator,
        })
    }
}

impl fmt::Display for Fraction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.numerator, self.denominator)
    }
}

impl Serialize for Fraction {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Fraction {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

// ── Threshold ───────────────────────────────────────────────────────────────

/// KERI signing/backer threshold.
///
/// Simple thresholds are hex-encoded integers (`"1"`, `"2"`, `"a"`).
/// Weighted thresholds are clause lists of fractions (`[["1/2","1/2"]]`).
/// Clauses are ANDed; each is satisfied when the sum of verified weights >= 1.
///
/// Usage:
/// ```
/// use auths_keri::Threshold;
/// let t: Threshold = serde_json::from_str("\"2\"").unwrap();
/// assert_eq!(t.simple_value(), Some(2));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Threshold {
    /// M-of-N threshold (hex-encoded integer in JSON).
    Simple(u64),
    /// Fractionally weighted threshold (list of clause lists in JSON).
    /// Clauses are ANDed; each is satisfied when sum of verified weights >= 1.
    Weighted(Vec<Vec<Fraction>>),
}

impl Threshold {
    /// Get the simple threshold value, if this is a simple threshold.
    pub fn simple_value(&self) -> Option<u64> {
        match self {
            Threshold::Simple(v) => Some(*v),
            Threshold::Weighted(_) => None,
        }
    }

    /// Check if the threshold is satisfied by the given set of verified key indices.
    ///
    /// For `Simple(n)`: at least `n` unique indices must be verified.
    /// For `Weighted(clauses)`: ALL clauses must be independently satisfied.
    /// A clause is satisfied when the sum of weights at verified indices >= 1.
    ///
    /// Args:
    /// * `verified_indices` - Indices of keys whose signatures have been verified.
    /// * `key_count` - Total number of keys in the key list (for bounds checking).
    ///
    /// Usage:
    /// ```
    /// use auths_keri::Threshold;
    /// let t = Threshold::Simple(2);
    /// assert!(t.is_satisfied(&[0, 1], 3));
    /// assert!(!t.is_satisfied(&[0], 3));
    /// ```
    pub fn is_satisfied(&self, verified_indices: &[u32], key_count: usize) -> bool {
        // Deduplicate indices and filter out-of-range
        let mut unique: std::collections::HashSet<u32> = std::collections::HashSet::new();
        for &idx in verified_indices {
            if (idx as usize) < key_count {
                unique.insert(idx);
            }
        }

        match self {
            Threshold::Simple(required) => unique.len() as u64 >= *required,
            Threshold::Weighted(clauses) => {
                // ALL clauses must be satisfied (ANDed)
                for clause in clauses {
                    let verified_fractions: Vec<&Fraction> = clause
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| unique.contains(&(*i as u32)))
                        .map(|(_, f)| f)
                        .collect();
                    if !Fraction::sum_meets_one(&verified_fractions) {
                        return false;
                    }
                }
                true
            }
        }
    }
}

impl Serialize for Threshold {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Threshold::Simple(v) => serializer.serialize_str(&format!("{v:x}")),
            Threshold::Weighted(clauses) => clauses.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for Threshold {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = serde_json::Value::deserialize(deserializer)?;
        match value {
            serde_json::Value::String(s) => {
                let v = u64::from_str_radix(&s, 16).map_err(|_| {
                    serde::de::Error::custom(format!("invalid hex threshold: {s:?}"))
                })?;
                Ok(Threshold::Simple(v))
            }
            serde_json::Value::Array(arr) => {
                let clauses: Vec<Vec<Fraction>> = arr
                    .into_iter()
                    .map(|clause| match clause {
                        serde_json::Value::Array(weights) => weights
                            .into_iter()
                            .map(|w| match w {
                                serde_json::Value::String(s) => {
                                    s.parse().map_err(serde::de::Error::custom)
                                }
                                _ => Err(serde::de::Error::custom("weight must be a string")),
                            })
                            .collect::<Result<Vec<_>, _>>(),
                        _ => Err(serde::de::Error::custom("clause must be an array")),
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(Threshold::Weighted(clauses))
            }
            _ => Err(serde::de::Error::custom(
                "threshold must be a hex string or array of clause arrays",
            )),
        }
    }
}

impl Default for Threshold {
    fn default() -> Self {
        Threshold::Simple(0)
    }
}

// ── CesrKey ─────────────────────────────────────────────────────────────────

/// A CESR-encoded public key (e.g., `D` + base64url Ed25519, `1AAI` + base64url P-256).
///
/// Wraps the qualified string form. Use `parse()` to extract
/// the curve-tagged `KeriPublicKey` for cryptographic operations.
///
/// Usage:
/// ```
/// use auths_keri::CesrKey;
/// let key = CesrKey::new_unchecked("DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into());
/// assert!(key.parse().is_ok());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[repr(transparent)]
pub struct CesrKey(String);

impl CesrKey {
    /// Wrap a qualified key string without validation.
    pub fn new_unchecked(s: String) -> Self {
        Self(s)
    }

    /// Parse the inner CESR string, dispatching on the derivation code prefix.
    ///
    /// Supports Ed25519 (`D` prefix) and P-256 (`1AAJ`/`1AAI` prefix).
    /// Returns `Err(UnsupportedKeyType)` for unknown prefixes.
    pub fn parse(&self) -> Result<KeriPublicKey, KeriDecodeError> {
        KeriPublicKey::parse(&self.0)
    }

    /// Get the raw CESR-qualified string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes self and returns the inner String.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for CesrKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for CesrKey {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

// ── ConfigTrait ─────────────────────────────────────────────────────────────

/// KERI configuration trait codes.
///
/// These control identity behavior at inception and may be updated at rotation
/// (for `RB`/`NRB` only). If two conflicting traits appear, the latter supersedes.
///
/// Usage:
/// ```
/// use auths_keri::ConfigTrait;
/// let traits: Vec<ConfigTrait> = serde_json::from_str(r#"["EO","DND"]"#).unwrap();
/// assert!(traits.contains(&ConfigTrait::EstablishmentOnly));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum ConfigTrait {
    /// Establishment-Only: only establishment events in KEL.
    #[serde(rename = "EO")]
    EstablishmentOnly,
    /// Do-Not-Delegate: cannot act as delegator.
    #[serde(rename = "DND")]
    DoNotDelegate,
    /// Delegate-Is-Delegator: delegated AID treated same as delegator.
    #[serde(rename = "DID")]
    DelegateIsDelegator,
    /// Registrar Backers: backer list provides registrar backer AIDs.
    #[serde(rename = "RB")]
    RegistrarBackers,
    /// No Registrar Backers: switch back to witnesses.
    #[serde(rename = "NRB")]
    NoRegistrarBackers,
}

// ── VersionString ───────────────────────────────────────────────────────────

/// KERI v1.x version string: `KERI10JSON{hhhhhh}_` (17 chars).
///
/// The size field is the total serialized byte count of the event.
///
/// Usage:
/// ```
/// use auths_keri::VersionString;
/// let vs = VersionString::json(256);
/// assert_eq!(vs.to_string(), "KERI10JSON000100_");
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionString {
    /// Serialization kind (e.g., "JSON", "CBOR").
    pub kind: String,
    /// Serialized byte count.
    pub size: u32,
}

impl VersionString {
    /// Create a version string for JSON serialization with the given byte count.
    pub fn json(size: u32) -> Self {
        Self {
            kind: "JSON".to_string(),
            size,
        }
    }

    /// Create a placeholder version string (size = 0, to be updated after serialization).
    pub fn placeholder() -> Self {
        Self {
            kind: "JSON".to_string(),
            size: 0,
        }
    }
}

impl Default for VersionString {
    fn default() -> Self {
        Self::placeholder()
    }
}

impl fmt::Display for VersionString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "KERI10{}{:06x}_", self.kind, self.size)
    }
}

impl Serialize for VersionString {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for VersionString {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        // Full 17-char format: "KERI10JSON000100_"
        if s.len() >= 17 && s.ends_with('_') {
            let size_hex = &s[10..16];
            let size = u32::from_str_radix(size_hex, 16).map_err(|_| {
                serde::de::Error::custom(format!("invalid version string size: {size_hex:?}"))
            })?;
            let kind = s[6..10].to_string();
            Ok(Self { kind, size })
        } else if s.starts_with("KERI10") && s.len() >= 10 {
            // Legacy format without size — accept for backwards compat
            let kind = s[6..s.len().min(10)].to_string();
            Ok(Self { kind, size: 0 })
        } else {
            Err(serde::de::Error::custom(format!(
                "invalid KERI version string: {s:?}"
            )))
        }
    }
}

// ── JsonSchema impls for custom serde types ─────────────────────────────────

#[cfg(feature = "schema")]
mod schema_impls {
    use super::*;

    impl schemars::JsonSchema for Fraction {
        fn schema_name() -> String {
            "Fraction".to_string()
        }
        fn json_schema(_gen: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
            schemars::schema::SchemaObject {
                instance_type: Some(schemars::schema::InstanceType::String.into()),
                ..Default::default()
            }
            .into()
        }
    }

    impl schemars::JsonSchema for Threshold {
        fn schema_name() -> String {
            "Threshold".to_string()
        }
        fn json_schema(_gen: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
            // Union: string (hex integer) or array of arrays of strings (weighted)
            schemars::schema::Schema::Bool(true)
        }
    }

    impl schemars::JsonSchema for crate::events::Seal {
        fn schema_name() -> String {
            "Seal".to_string()
        }
        fn json_schema(_gen: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
            // Untagged union of seal variants — accept any object
            schemars::schema::Schema::Bool(true)
        }
    }

    impl schemars::JsonSchema for VersionString {
        fn schema_name() -> String {
            "VersionString".to_string()
        }
        fn json_schema(_gen: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
            schemars::schema::SchemaObject {
                instance_type: Some(schemars::schema::InstanceType::String.into()),
                ..Default::default()
            }
            .into()
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // ── Fraction ────────────────────────────────────────────────────────

    #[test]
    fn fraction_parse_valid() {
        let f: Fraction = "1/3".parse().unwrap();
        assert_eq!(f.numerator, 1);
        assert_eq!(f.denominator, 3);
    }

    #[test]
    fn fraction_parse_rejects_zero_denominator() {
        let err = "1/0".parse::<Fraction>().unwrap_err();
        assert_eq!(err, FractionError::ZeroDenominator);
    }

    #[test]
    fn fraction_parse_rejects_missing_separator() {
        assert!("42".parse::<Fraction>().is_err());
    }

    #[test]
    fn fraction_serde_roundtrip() {
        let f = Fraction {
            numerator: 1,
            denominator: 2,
        };
        let json = serde_json::to_string(&f).unwrap();
        assert_eq!(json, "\"1/2\"");
        let parsed: Fraction = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, f);
    }

    #[test]
    fn fraction_display() {
        let f = Fraction {
            numerator: 3,
            denominator: 4,
        };
        assert_eq!(f.to_string(), "3/4");
    }

    // ── Threshold ───────────────────────────────────────────────────────

    #[test]
    fn threshold_simple_from_hex() {
        let t: Threshold = serde_json::from_str("\"a\"").unwrap();
        assert_eq!(t, Threshold::Simple(10));
        assert_eq!(t.simple_value(), Some(10));
    }

    #[test]
    fn threshold_simple_serialize_as_hex() {
        let t = Threshold::Simple(16);
        let json = serde_json::to_string(&t).unwrap();
        assert_eq!(json, "\"10\""); // 16 decimal = 10 hex
    }

    #[test]
    fn threshold_simple_roundtrip() {
        let t = Threshold::Simple(2);
        let json = serde_json::to_string(&t).unwrap();
        let parsed: Threshold = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, t);
    }

    #[test]
    fn threshold_weighted_roundtrip() {
        let json = r#"[["1/2","1/2"],["1/3","1/3","1/3"]]"#;
        let t: Threshold = serde_json::from_str(json).unwrap();
        assert!(t.simple_value().is_none());
        if let Threshold::Weighted(clauses) = &t {
            assert_eq!(clauses.len(), 2);
            assert_eq!(clauses[0].len(), 2);
            assert_eq!(clauses[1].len(), 3);
            assert_eq!(clauses[0][0].numerator, 1);
            assert_eq!(clauses[0][0].denominator, 2);
        } else {
            panic!("expected Weighted");
        }
        let reserialized = serde_json::to_string(&t).unwrap();
        let reparsed: Threshold = serde_json::from_str(&reserialized).unwrap();
        assert_eq!(reparsed, t);
    }

    #[test]
    fn threshold_rejects_invalid_hex() {
        let result = serde_json::from_str::<Threshold>("\"xyz\"");
        assert!(result.is_err());
    }

    // ── Fraction arithmetic ─────────────────────────────────────────────

    #[test]
    fn fraction_sum_one_third_times_three() {
        let f: Fraction = "1/3".parse().unwrap();
        assert!(Fraction::sum_meets_one(&[&f, &f, &f]));
    }

    #[test]
    fn fraction_sum_two_thirds_not_enough() {
        let f: Fraction = "1/3".parse().unwrap();
        assert!(!Fraction::sum_meets_one(&[&f, &f]));
    }

    #[test]
    fn fraction_sum_halves() {
        let f: Fraction = "1/2".parse().unwrap();
        assert!(Fraction::sum_meets_one(&[&f, &f]));
        assert!(!Fraction::sum_meets_one(&[&f]));
    }

    #[test]
    fn fraction_sum_empty_is_false() {
        assert!(!Fraction::sum_meets_one(&[]));
    }

    // ── Threshold::is_satisfied ─────────────────────────────────────────

    #[test]
    fn threshold_simple_satisfied() {
        let t = Threshold::Simple(2);
        assert!(t.is_satisfied(&[0, 1], 3));
        assert!(t.is_satisfied(&[0, 1, 2], 3));
        assert!(!t.is_satisfied(&[0], 3));
    }

    #[test]
    fn threshold_simple_zero_always_satisfied() {
        let t = Threshold::Simple(0);
        assert!(t.is_satisfied(&[], 3));
    }

    #[test]
    fn threshold_simple_deduplicates_indices() {
        let t = Threshold::Simple(2);
        // Same index twice doesn't count as 2
        assert!(!t.is_satisfied(&[0, 0], 3));
    }

    #[test]
    fn threshold_simple_rejects_out_of_range() {
        let t = Threshold::Simple(1);
        // Index 5 is out of range for 3 keys
        assert!(!t.is_satisfied(&[5], 3));
    }

    #[test]
    fn threshold_weighted_two_of_three() {
        // [["1/2","1/2","1/2"]] — any 2 of 3
        let t: Threshold = serde_json::from_str(r#"[["1/2","1/2","1/2"]]"#).unwrap();
        assert!(t.is_satisfied(&[0, 1], 3));
        assert!(t.is_satisfied(&[1, 2], 3));
        assert!(!t.is_satisfied(&[0], 3));
    }

    #[test]
    fn threshold_weighted_with_reserves() {
        // [["1/2","1/2","1/2","1/4","1/4"]] — 2 main OR 1 main + 2 reserves
        let t: Threshold = serde_json::from_str(r#"[["1/2","1/2","1/2","1/4","1/4"]]"#).unwrap();
        assert!(t.is_satisfied(&[0, 1], 5)); // 2 main
        assert!(t.is_satisfied(&[0, 3, 4], 5)); // 1 main + 2 reserves
        assert!(!t.is_satisfied(&[3, 4], 5)); // reserves only: 1/4+1/4=1/2 < 1
    }

    #[test]
    fn threshold_weighted_multi_clause_and() {
        // [["1/2","1/2"],["1/3","1/3","1/3"]] — both clauses must be satisfied
        let t: Threshold = serde_json::from_str(r#"[["1/2","1/2"],["1/3","1/3","1/3"]]"#).unwrap();
        // Indices 0,1 satisfy clause 1 (1/2+1/2=1), but clause 2 needs 2 of {0,1,2}
        // Index 0 in clause 2 = 1/3, index 1 in clause 2 = 1/3 → 2/3 < 1
        assert!(!t.is_satisfied(&[0, 1], 3));
        // Indices 0,1,2 satisfy both clauses
        assert!(t.is_satisfied(&[0, 1, 2], 3));
    }

    // ── CesrKey ─────────────────────────────────────────────────────────

    #[test]
    fn cesr_key_roundtrip() {
        let key_str = "DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let key = CesrKey::new_unchecked(key_str.to_string());
        let json = serde_json::to_string(&key).unwrap();
        let parsed: CesrKey = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.as_str(), key_str);
    }

    #[test]
    fn cesr_key_parse_valid() {
        let key =
            CesrKey::new_unchecked("DAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string());
        assert!(key.parse().is_ok());
    }

    #[test]
    fn cesr_key_parse_invalid() {
        let key = CesrKey::new_unchecked("not-a-valid-key".to_string());
        assert!(key.parse().is_err());
    }

    // ── ConfigTrait ─────────────────────────────────────────────────────

    #[test]
    fn config_trait_serde_roundtrip() {
        let traits = vec![ConfigTrait::EstablishmentOnly, ConfigTrait::DoNotDelegate];
        let json = serde_json::to_string(&traits).unwrap();
        assert_eq!(json, r#"["EO","DND"]"#);
        let parsed: Vec<ConfigTrait> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, traits);
    }

    #[test]
    fn config_trait_all_variants_roundtrip() {
        let all = vec![
            ConfigTrait::EstablishmentOnly,
            ConfigTrait::DoNotDelegate,
            ConfigTrait::DelegateIsDelegator,
            ConfigTrait::RegistrarBackers,
            ConfigTrait::NoRegistrarBackers,
        ];
        let json = serde_json::to_string(&all).unwrap();
        assert_eq!(json, r#"["EO","DND","DID","RB","NRB"]"#);
        let parsed: Vec<ConfigTrait> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, all);
    }

    // ── VersionString ───────────────────────────────────────────────────

    #[test]
    fn version_string_display() {
        let vs = VersionString::json(256);
        assert_eq!(vs.to_string(), "KERI10JSON000100_");
    }

    #[test]
    fn version_string_placeholder() {
        let vs = VersionString::placeholder();
        assert_eq!(vs.to_string(), "KERI10JSON000000_");
        assert_eq!(vs.size, 0);
    }

    #[test]
    fn version_string_parse_full() {
        let vs: VersionString = serde_json::from_str("\"KERI10JSON000100_\"").unwrap();
        assert_eq!(vs.kind, "JSON");
        assert_eq!(vs.size, 256);
    }

    #[test]
    fn version_string_parse_legacy() {
        let vs: VersionString = serde_json::from_str("\"KERI10JSON\"").unwrap();
        assert_eq!(vs.kind, "JSON");
        assert_eq!(vs.size, 0); // legacy has no size
    }

    #[test]
    fn version_string_roundtrip() {
        let vs = VersionString::json(1024);
        let json = serde_json::to_string(&vs).unwrap();
        let parsed: VersionString = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, vs);
    }

    #[test]
    fn version_string_rejects_invalid() {
        assert!(serde_json::from_str::<VersionString>("\"INVALID\"").is_err());
    }
}
