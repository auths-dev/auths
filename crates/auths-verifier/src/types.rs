//! Verification types: reports, statuses, and device DIDs.

use crate::witness::WitnessQuorum;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// ============================================================================
// Verification Report Types
// ============================================================================

/// Machine-readable verification result containing status, chain details, and warnings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VerificationReport {
    /// The overall verification status
    pub status: VerificationStatus,
    /// Details of each link in the verification chain
    pub chain: Vec<ChainLink>,
    /// Non-fatal warnings encountered during verification
    pub warnings: Vec<String>,
    /// Optional witness quorum result (present when witness verification was performed)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub witness_quorum: Option<WitnessQuorum>,
}

impl VerificationReport {
    /// Returns true only when the verification status is Valid.
    pub fn is_valid(&self) -> bool {
        matches!(self.status, VerificationStatus::Valid)
    }

    /// Creates a new valid VerificationReport with the given chain.
    pub fn valid(chain: Vec<ChainLink>) -> Self {
        Self {
            status: VerificationStatus::Valid,
            chain,
            warnings: Vec::new(),
            witness_quorum: None,
        }
    }

    /// Creates a new VerificationReport with the given status and chain.
    pub fn with_status(status: VerificationStatus, chain: Vec<ChainLink>) -> Self {
        Self {
            status,
            chain,
            warnings: Vec::new(),
            witness_quorum: None,
        }
    }
}

/// Verification outcome indicating success or the type of failure.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum VerificationStatus {
    /// The attestation(s) are valid
    Valid,
    /// The attestation has expired
    Expired {
        /// When the attestation expired
        at: DateTime<Utc>,
    },
    /// The attestation has been revoked
    Revoked {
        /// When the attestation was revoked (if known)
        at: Option<DateTime<Utc>>,
    },
    /// A signature in the chain is invalid
    InvalidSignature {
        /// The step in the chain where the invalid signature was found (0-indexed)
        step: usize,
    },
    /// The chain has a broken link (issuer→subject mismatch or missing attestation)
    BrokenChain {
        /// Description of the missing link
        missing_link: String,
    },
    /// Insufficient witness receipts to meet quorum threshold
    InsufficientWitnesses {
        /// Number of witnesses required
        required: usize,
        /// Number of witnesses that verified successfully
        verified: usize,
    },
}

/// A single link in a verification chain, representing one attestation's verification result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ChainLink {
    /// The issuer DID of this attestation
    pub issuer: String,
    /// The subject DID of this attestation
    pub subject: String,
    /// Whether this link's signature is valid
    pub valid: bool,
    /// Error message if verification failed
    pub error: Option<String>,
}

impl ChainLink {
    /// Creates a new valid chain link.
    pub fn valid(issuer: String, subject: String) -> Self {
        Self {
            issuer,
            subject,
            valid: true,
            error: None,
        }
    }

    /// Creates a new invalid chain link with an error message.
    pub fn invalid(issuer: String, subject: String, error: String) -> Self {
        Self {
            issuer,
            subject,
            valid: false,
            error: Some(error),
        }
    }
}

// ============================================================================
// DID Types
// ============================================================================

use std::borrow::Borrow;
use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

// ============================================================================
// IdentityDID Type
// ============================================================================

/// Strongly-typed wrapper for identity DIDs (e.g., `"did:keri:E..."`).
///
/// Usage:
/// ```rust
/// # use auths_verifier::IdentityDID;
/// let did = IdentityDID::parse("did:keri:Eabc123").unwrap();
/// assert_eq!(did.as_str(), "did:keri:Eabc123");
///
/// let s: String = did.into_inner();
/// ```
#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[repr(transparent)]
pub struct IdentityDID(String);

impl IdentityDID {
    /// Wraps a DID string without validation (for trusted internal paths).
    pub fn new_unchecked<S: Into<String>>(s: S) -> Self {
        Self(s.into())
    }

    /// Validates and parses a `did:keri:` string into an `IdentityDID`.
    ///
    /// Args:
    /// * `s`: A DID string that must start with `did:keri:` followed by a non-empty KERI prefix.
    ///
    /// Usage:
    /// ```rust
    /// # use auths_verifier::IdentityDID;
    /// let did = IdentityDID::parse("did:keri:EPrefix123").unwrap();
    /// assert_eq!(did.as_str(), "did:keri:EPrefix123");
    /// ```
    pub fn parse(s: &str) -> Result<Self, DidParseError> {
        match s.strip_prefix("did:keri:") {
            Some("") => Err(DidParseError::EmptyIdentifier),
            Some(_) => Ok(Self(s.to_string())),
            None => Err(DidParseError::InvalidIdentityPrefix(s.to_string())),
        }
    }

    /// Builds an `IdentityDID` from a raw KERI prefix string.
    ///
    /// Args:
    /// * `prefix`: The KERI prefix without the `did:keri:` scheme (e.g., `"EOrg123"`).
    ///
    /// Usage:
    /// ```rust
    /// # use auths_verifier::IdentityDID;
    /// let did = IdentityDID::from_prefix("EOrg123").unwrap();
    /// assert_eq!(did.as_str(), "did:keri:EOrg123");
    /// ```
    pub fn from_prefix(prefix: &str) -> Result<Self, DidParseError> {
        if prefix.is_empty() {
            return Err(DidParseError::EmptyIdentifier);
        }
        Ok(Self(format!("did:keri:{}", prefix)))
    }

    /// Returns the KERI prefix portion of the DID (after `did:keri:`).
    ///
    /// Usage:
    /// ```rust
    /// # use auths_verifier::IdentityDID;
    /// let did = IdentityDID::parse("did:keri:EOrg123").unwrap();
    /// assert_eq!(did.prefix(), "EOrg123");
    /// ```
    pub fn prefix(&self) -> &str {
        self.0.strip_prefix("did:keri:").unwrap_or(&self.0)
    }

    /// Returns the DID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes self and returns the inner String.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for IdentityDID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for IdentityDID {
    type Err = DidParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<&str> for IdentityDID {
    type Error = DidParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

impl TryFrom<String> for IdentityDID {
    type Error = DidParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

impl From<IdentityDID> for String {
    fn from(did: IdentityDID) -> String {
        did.0
    }
}

impl<'de> serde::Deserialize<'de> for IdentityDID {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

impl Deref for IdentityDID {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for IdentityDID {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for IdentityDID {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl PartialEq<str> for IdentityDID {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for IdentityDID {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<IdentityDID> for str {
    fn eq(&self, other: &IdentityDID) -> bool {
        self == other.0
    }
}

impl PartialEq<IdentityDID> for &str {
    fn eq(&self, other: &IdentityDID) -> bool {
        *self == other.0
    }
}

// ============================================================================
// DeviceDID Type
// ============================================================================

/// Wrapper around a device DID string that ensures Git-safe ref formatting.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct DeviceDID(String);

impl DeviceDID {
    /// Wraps a DID string without validation (for trusted internal paths).
    pub fn new_unchecked<S: Into<String>>(s: S) -> Self {
        DeviceDID(s.into())
    }

    /// Validates and parses a `did:key:z` string into a `DeviceDID`.
    ///
    /// Args:
    /// * `s`: A DID string that must start with `did:key:z` followed by non-empty base58 content.
    ///
    /// Usage:
    /// ```rust
    /// # use auths_verifier::DeviceDID;
    /// let did = DeviceDID::parse("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").unwrap();
    /// assert_eq!(did.as_str(), "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK");
    /// ```
    pub fn parse(s: &str) -> Result<Self, DidParseError> {
        match s.strip_prefix("did:key:z") {
            Some("") => Err(DidParseError::EmptyIdentifier),
            Some(_) => Ok(Self(s.to_string())),
            None => Err(DidParseError::InvalidDevicePrefix(s.to_string())),
        }
    }

    /// Constructs a `did:key:z...` identifier from a public key and its curve type.
    ///
    /// Args:
    /// * `pubkey`: Raw public key bytes (32 for Ed25519, 33 for P-256 compressed).
    /// * `curve`: The curve type of the key.
    pub fn from_public_key(pubkey: &[u8], curve: auths_crypto::CurveType) -> Self {
        match curve {
            auths_crypto::CurveType::Ed25519 => {
                let mut prefixed = vec![0xED, 0x01];
                prefixed.extend_from_slice(pubkey);
                let encoded = bs58::encode(prefixed).into_string();
                Self(format!("did:key:z{}", encoded))
            }
            auths_crypto::CurveType::P256 => {
                let mut prefixed = vec![0x80, 0x24];
                prefixed.extend_from_slice(pubkey);
                let encoded = bs58::encode(prefixed).into_string();
                Self(format!("did:key:z{}", encoded))
            }
        }
    }

    /// Constructs a `did:key:z...` identifier from a [`auths_crypto::TypedSignerKey`].
    ///
    /// Single curve-dispatching constructor that replaces the manual
    /// `match curve { Ed25519 => from_ed25519, P256 => p256_pubkey_to_did_key }`
    /// pattern at SDK / FFI call sites. Picks the right multicodec varint per
    /// the signer's typed curve, so callers never re-derive curve from byte
    /// length.
    ///
    /// Usage:
    /// ```ignore
    /// let did = DeviceDID::from_typed_pubkey(&typed_signer);
    /// ```
    pub fn from_typed_pubkey(signer: &auths_crypto::TypedSignerKey) -> Self {
        Self::from_public_key(signer.public_key(), signer.curve())
    }

    /// Returns a sanitized version of the DID for use in Git refs,
    /// replacing all non-alphanumeric characters with `_`.
    pub fn ref_name(&self) -> String {
        self.0
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect()
    }

    /// Compares a sanitized DID ref name to this real DeviceDID.
    /// Used to match Git refs to known device DIDs.
    pub fn matches_sanitized_ref(&self, ref_name: &str) -> bool {
        self.ref_name() == ref_name
    }

    /// Tries to reverse-lookup a real DID from a sanitized string,
    /// given a list of known real DIDs.
    pub fn from_sanitized<'a>(
        sanitized: &str,
        known_dids: &'a [DeviceDID],
    ) -> Option<&'a DeviceDID> {
        known_dids.iter().find(|did| did.ref_name() == sanitized)
    }

    /// Optionally expose the inner raw DID
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for DeviceDID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for DeviceDID {
    type Err = DidParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<&str> for DeviceDID {
    type Error = DidParseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

impl TryFrom<String> for DeviceDID {
    type Error = DidParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

impl From<DeviceDID> for String {
    fn from(did: DeviceDID) -> String {
        did.0
    }
}

impl<'de> serde::Deserialize<'de> for DeviceDID {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

impl Deref for DeviceDID {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// ============================================================================
// DID Utility Functions
// ============================================================================

/// Convert a hex-encoded Ed25519 public key to a `did:key:` device DID.
///
/// The hex string must decode to exactly 32 bytes.
///
/// ```rust
/// # use auths_verifier::types::signer_hex_to_did;
/// let did = signer_hex_to_did("d75a980182b10ab7d54bfed3c964073a0ee172f3daa3f4a18446b7ddc8").unwrap_err();
/// // (example key is wrong length — a real 32-byte hex key would succeed)
/// ```
pub fn signer_hex_to_did(hex_key: &str) -> Result<DeviceDID, DidConversionError> {
    signer_hex_to_did_with_curve(hex_key, auths_crypto::CurveType::P256)
}

/// Convert a hex-encoded public key to a `did:key:` device DID with explicit curve.
///
/// ```rust
/// # use auths_verifier::types::signer_hex_to_did_with_curve;
/// # use auths_crypto::CurveType;
/// let did = signer_hex_to_did_with_curve("d75a980182b10ab7d54bfed3c964073a0ee172f3daa3f4a18446b7ddc8", CurveType::P256).unwrap_err();
/// ```
pub fn signer_hex_to_did_with_curve(
    hex_key: &str,
    curve: auths_crypto::CurveType,
) -> Result<DeviceDID, DidConversionError> {
    let bytes = hex::decode(hex_key).map_err(|e| DidConversionError::InvalidHex(e.to_string()))?;
    Ok(DeviceDID::from_public_key(&bytes, curve))
}

/// Validate a DID string (accepts both `did:keri:` and `did:key:` formats).
///
/// Returns `true` if the DID has a recognized scheme and non-empty identifier.
pub fn validate_did(did_str: &str) -> bool {
    if let Some(rest) = did_str.strip_prefix("did:keri:") {
        !rest.is_empty()
    } else if let Some(rest) = did_str.strip_prefix("did:key:") {
        !rest.is_empty()
    } else {
        false
    }
}

/// Errors from DID conversion operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DidConversionError {
    /// The input is not valid hexadecimal.
    #[error("invalid hex: {0}")]
    InvalidHex(String),
    /// The decoded key is not 32 bytes.
    #[error("expected 32-byte Ed25519 key, got {0} bytes")]
    WrongKeyLength(usize),
}

/// Errors from DID string parsing and validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum DidParseError {
    /// DeviceDID must start with `did:key:z`.
    #[error("DeviceDID must start with 'did:key:z', got: {0}")]
    InvalidDevicePrefix(String),
    /// IdentityDID must start with `did:keri:`.
    #[error("IdentityDID must start with 'did:keri:', got: {0}")]
    InvalidIdentityPrefix(String),
    /// The method-specific identifier portion is empty.
    #[error("DID method-specific identifier is empty")]
    EmptyIdentifier,
    /// Generic DID format validation failure (used by `CanonicalDid`).
    #[error("{0}")]
    InvalidFormat(String),
    /// DID string contains control characters.
    #[error("DID contains control characters")]
    ControlCharacters,
}

// ============================================================================
// CanonicalDid Type
// ============================================================================

/// A validated, canonical DID that accepts any method (`did:keri:`, `did:key:`, etc.).
///
/// Use this for fields that can hold either identity or device DIDs,
/// such as attestation issuers which may be `did:keri:` or `did:key:`.
///
/// Constructed via `parse()` which enforces:
/// - Starts with `did:`
/// - Has at least method and id segments: `did:method:id`
/// - Lowercased method (KERI, key methods are case-sensitive in id, not method)
/// - No trailing whitespace or control characters
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(transparent)]
pub struct CanonicalDid(String);

impl CanonicalDid {
    /// Parse and validate a DID string into canonical form.
    pub fn parse(raw: &str) -> Result<Self, DidParseError> {
        if raw.chars().any(|c| c.is_control()) {
            return Err(DidParseError::ControlCharacters);
        }
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(DidParseError::EmptyIdentifier);
        }
        let parts: Vec<&str> = trimmed.splitn(3, ':').collect();
        if parts.len() < 3 || parts[0] != "did" || parts[1].is_empty() || parts[2].is_empty() {
            return Err(DidParseError::InvalidFormat(format!(
                "invalid DID format: '{}'",
                trimmed
            )));
        }
        let canonical = format!("did:{}:{}", parts[1].to_lowercase(), parts[2]);
        Ok(Self(canonical))
    }

    /// Wraps a DID string without validation (for trusted internal paths).
    pub fn new_unchecked<S: Into<String>>(s: S) -> Self {
        Self(s.into())
    }

    /// Returns the canonical DID as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the method-specific identifier (the part after `did:method:`).
    pub fn method_specific_id(&self) -> &str {
        self.0.splitn(3, ':').nth(2).unwrap_or("")
    }

    /// Validates that this DID uses the `keri` method with a valid KERI prefix.
    pub fn require_keri(self) -> Result<Self, DidParseError> {
        let parts: Vec<&str> = self.0.splitn(3, ':').collect();
        if parts[1] != "keri" {
            return Err(DidParseError::InvalidFormat(format!(
                "expected did:keri: DID, got did:{}:",
                parts[1]
            )));
        }
        let id = parts[2];
        if id.len() < 2 || id.len() > 128 {
            return Err(DidParseError::InvalidFormat(
                "invalid KERI prefix: length must be 2–128 characters".into(),
            ));
        }
        if !id.starts_with(|c: char| c.is_ascii_uppercase()) {
            return Err(DidParseError::InvalidFormat(format!(
                "invalid KERI prefix: must start with an uppercase derivation code, got '{}'",
                &id[..1]
            )));
        }
        Ok(self)
    }

    /// Consumes self and returns the inner String.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl TryFrom<String> for CanonicalDid {
    type Error = DidParseError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

impl TryFrom<&str> for CanonicalDid {
    type Error = DidParseError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

impl From<CanonicalDid> for String {
    fn from(d: CanonicalDid) -> Self {
        d.0
    }
}

impl fmt::Display for CanonicalDid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Deref for CanonicalDid {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for CanonicalDid {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for CanonicalDid {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl<'de> serde::Deserialize<'de> for CanonicalDid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

impl PartialEq<str> for CanonicalDid {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for CanonicalDid {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl From<IdentityDID> for CanonicalDid {
    fn from(did: IdentityDID) -> Self {
        Self(did.into_inner())
    }
}

impl From<DeviceDID> for CanonicalDid {
    fn from(did: DeviceDID) -> Self {
        Self(did.0)
    }
}

// ============================================================================
// AssuranceLevel Type
// ============================================================================

/// Cryptographic assurance level of a platform identity claim.
///
/// Variants are ordered from weakest to strongest so that `Ord` comparisons
/// reflect trust strength: `SelfAsserted < TokenVerified < Authenticated < Sovereign`.
///
/// Usage:
/// ```rust
/// # use auths_verifier::types::AssuranceLevel;
/// assert!(AssuranceLevel::Sovereign > AssuranceLevel::Authenticated);
/// assert!(AssuranceLevel::SelfAsserted < AssuranceLevel::TokenVerified);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AssuranceLevel {
    /// Self-reported identity, signed only by the claimant's own key (e.g., PyPI).
    SelfAsserted,
    /// Bearer token validated against a platform API at time of claim (e.g., npm).
    TokenVerified,
    /// OAuth/OIDC challenge-response proving account control (e.g., GitHub).
    Authenticated,
    /// End-to-end cryptographic identity chain with no third-party trust (auths native).
    Sovereign,
}

/// Error returned when parsing an `AssuranceLevel` from a string fails.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "invalid assurance level '{0}': expected one of: sovereign, authenticated, token_verified, self_asserted"
)]
pub struct AssuranceLevelParseError(pub String);

impl AssuranceLevel {
    /// Human-readable label for display.
    pub fn label(&self) -> &'static str {
        match self {
            Self::SelfAsserted => "Self-Asserted",
            Self::TokenVerified => "Token-Verified",
            Self::Authenticated => "Authenticated",
            Self::Sovereign => "Sovereign",
        }
    }

    /// Numeric score (1–4) for the assurance level.
    pub fn score(&self) -> u8 {
        match self {
            Self::SelfAsserted => 1,
            Self::TokenVerified => 2,
            Self::Authenticated => 3,
            Self::Sovereign => 4,
        }
    }
}

impl fmt::Display for AssuranceLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

impl FromStr for AssuranceLevel {
    type Err = AssuranceLevelParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "sovereign" => Ok(Self::Sovereign),
            "authenticated" => Ok(Self::Authenticated),
            "token_verified" => Ok(Self::TokenVerified),
            "self_asserted" => Ok(Self::SelfAsserted),
            _ => Err(AssuranceLevelParseError(s.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_keri::Said;

    #[test]
    fn report_without_witness_quorum_deserializes() {
        // JSON from before witness_quorum field existed
        let json = r#"{
            "status": {"type": "Valid"},
            "chain": [],
            "warnings": []
        }"#;
        let report: VerificationReport = serde_json::from_str(json).unwrap();
        assert!(report.is_valid());
        assert!(report.witness_quorum.is_none());
    }

    #[test]
    fn insufficient_witnesses_serializes_correctly() {
        let status = VerificationStatus::InsufficientWitnesses {
            required: 3,
            verified: 1,
        };
        let json = serde_json::to_string(&status).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["type"], "InsufficientWitnesses");
        assert_eq!(parsed["required"], 3);
        assert_eq!(parsed["verified"], 1);

        // Roundtrip
        let roundtripped: VerificationStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(roundtripped, status);
    }

    #[test]
    fn report_with_witness_quorum_roundtrips() {
        use crate::witness::{WitnessQuorum, WitnessReceiptResult};

        let report = VerificationReport {
            status: VerificationStatus::Valid,
            chain: vec![],
            warnings: vec![],
            witness_quorum: Some(WitnessQuorum {
                required: 2,
                verified: 2,
                receipts: vec![
                    WitnessReceiptResult {
                        witness_id: "did:key:w1".into(),
                        receipt_said: Said::new_unchecked("EReceipt1".into()),
                        verified: true,
                    },
                    WitnessReceiptResult {
                        witness_id: "did:key:w2".into(),
                        receipt_said: Said::new_unchecked("EReceipt2".into()),
                        verified: true,
                    },
                ],
            }),
        };

        let json = serde_json::to_string(&report).unwrap();
        let parsed: VerificationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, parsed);
        assert!(parsed.witness_quorum.is_some());
        assert_eq!(parsed.witness_quorum.unwrap().verified, 2);
    }

    #[test]
    fn report_without_witness_quorum_skips_in_json() {
        let report = VerificationReport::valid(vec![]);
        let json = serde_json::to_string(&report).unwrap();
        // witness_quorum should be omitted from JSON when None
        assert!(!json.contains("witness_quorum"));
    }

    // ── AssuranceLevel Tests ──────────────────────────────────────────

    #[test]
    fn assurance_level_ordering() {
        assert!(AssuranceLevel::SelfAsserted < AssuranceLevel::TokenVerified);
        assert!(AssuranceLevel::TokenVerified < AssuranceLevel::Authenticated);
        assert!(AssuranceLevel::Authenticated < AssuranceLevel::Sovereign);
    }

    #[test]
    fn assurance_level_serde_roundtrip() {
        let variants = [
            AssuranceLevel::SelfAsserted,
            AssuranceLevel::TokenVerified,
            AssuranceLevel::Authenticated,
            AssuranceLevel::Sovereign,
        ];
        for level in variants {
            let json = serde_json::to_string(&level).unwrap();
            let parsed: AssuranceLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, level);
        }
    }

    #[test]
    fn assurance_level_serde_snake_case() {
        assert_eq!(
            serde_json::to_string(&AssuranceLevel::SelfAsserted).unwrap(),
            "\"self_asserted\""
        );
        assert_eq!(
            serde_json::to_string(&AssuranceLevel::TokenVerified).unwrap(),
            "\"token_verified\""
        );
        assert_eq!(
            serde_json::to_string(&AssuranceLevel::Authenticated).unwrap(),
            "\"authenticated\""
        );
        assert_eq!(
            serde_json::to_string(&AssuranceLevel::Sovereign).unwrap(),
            "\"sovereign\""
        );
    }

    #[test]
    fn assurance_level_from_str() {
        assert_eq!(
            "sovereign".parse::<AssuranceLevel>().unwrap(),
            AssuranceLevel::Sovereign
        );
        assert_eq!(
            "authenticated".parse::<AssuranceLevel>().unwrap(),
            AssuranceLevel::Authenticated
        );
        assert_eq!(
            "token_verified".parse::<AssuranceLevel>().unwrap(),
            AssuranceLevel::TokenVerified
        );
        assert_eq!(
            "self_asserted".parse::<AssuranceLevel>().unwrap(),
            AssuranceLevel::SelfAsserted
        );
        assert!("invalid".parse::<AssuranceLevel>().is_err());
    }

    #[test]
    fn assurance_level_from_str_case_insensitive() {
        assert_eq!(
            "SOVEREIGN".parse::<AssuranceLevel>().unwrap(),
            AssuranceLevel::Sovereign
        );
        assert_eq!(
            "Authenticated".parse::<AssuranceLevel>().unwrap(),
            AssuranceLevel::Authenticated
        );
    }

    #[test]
    fn assurance_level_score() {
        assert_eq!(AssuranceLevel::SelfAsserted.score(), 1);
        assert_eq!(AssuranceLevel::TokenVerified.score(), 2);
        assert_eq!(AssuranceLevel::Authenticated.score(), 3);
        assert_eq!(AssuranceLevel::Sovereign.score(), 4);
    }

    #[test]
    fn assurance_level_display() {
        assert_eq!(AssuranceLevel::SelfAsserted.to_string(), "Self-Asserted");
        assert_eq!(AssuranceLevel::TokenVerified.to_string(), "Token-Verified");
        assert_eq!(AssuranceLevel::Authenticated.to_string(), "Authenticated");
        assert_eq!(AssuranceLevel::Sovereign.to_string(), "Sovereign");
    }
}
