//! Core attestation types and canonical serialization.

use crate::error::AttestationError;
use crate::types::{DeviceDID, IdentityDID};
use chrono::{DateTime, Utc};
use hex;
use json_canon;
use log::debug;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

/// Maximum allowed size for a single attestation JSON input (64 KiB).
pub const MAX_ATTESTATION_JSON_SIZE: usize = 64 * 1024;

/// Maximum allowed size for JSON array inputs — chains, receipts, witness keys (1 MiB).
pub const MAX_JSON_BATCH_SIZE: usize = 1024 * 1024;

/// Maximum hex string length for Ed25519 public key (32 bytes × 2).
pub const MAX_PUBLIC_KEY_HEX_LEN: usize = 64;
/// Maximum hex string length for Ed25519 signature (64 bytes × 2).
pub const MAX_SIGNATURE_HEX_LEN: usize = 128;
/// Maximum hex string length for SHA-256 file hash (32 bytes × 2).
pub const MAX_FILE_HASH_HEX_LEN: usize = 64;

// Well-known capability strings (without auths: prefix for backward compat)
const SIGN_COMMIT: &str = "sign_commit";
const SIGN_RELEASE: &str = "sign_release";
const MANAGE_MEMBERS: &str = "manage_members";
const ROTATE_KEYS: &str = "rotate_keys";

// =============================================================================
// ResourceId newtype
// =============================================================================

/// A validated resource identifier linking an attestation to its storage ref.
///
/// Wraps a `String` with `#[serde(transparent)]` so JSON output is identical to bare `String`.
/// Prevents accidental substitution of a DID, Git ref, or other string where a
/// resource ID is expected.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(transparent)]
pub struct ResourceId(String);

impl ResourceId {
    /// Creates a new ResourceId.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Returns the inner string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for ResourceId {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ResourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for ResourceId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for ResourceId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl PartialEq<str> for ResourceId {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for ResourceId {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

impl PartialEq<String> for ResourceId {
    fn eq(&self, other: &String) -> bool {
        self.0 == *other
    }
}

// =============================================================================
// Role enum
// =============================================================================

/// Role classification for organization members.
///
/// Governs the default capability set assigned at member authorization time.
/// Serializes as lowercase strings: `"admin"`, `"member"`, `"readonly"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Full admin access with all capabilities.
    Admin,
    /// Standard member with signing capabilities.
    Member,
    /// Read-only access; no signing capabilities.
    Readonly,
}

impl Role {
    /// Returns the canonical string representation.
    pub fn as_str(&self) -> &str {
        match self {
            Role::Admin => "admin",
            Role::Member => "member",
            Role::Readonly => "readonly",
        }
    }

    /// Return the default capability set for this role.
    pub fn default_capabilities(&self) -> Vec<Capability> {
        match self {
            Role::Admin => vec![
                Capability::sign_commit(),
                Capability::sign_release(),
                Capability::manage_members(),
                Capability::rotate_keys(),
            ],
            Role::Member => vec![Capability::sign_commit(), Capability::sign_release()],
            Role::Readonly => vec![],
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Role {
    type Err = RoleParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "admin" => Ok(Role::Admin),
            "member" => Ok(Role::Member),
            "readonly" => Ok(Role::Readonly),
            other => Err(RoleParseError(other.to_string())),
        }
    }
}

/// Error returned when parsing an invalid role string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown role: '{0}' (expected admin, member, or readonly)")]
pub struct RoleParseError(String);

// =============================================================================
// Ed25519PublicKey newtype
// =============================================================================

/// A 32-byte Ed25519 public key.
///
/// Serializes as a hex string for JSON compatibility. Enforces exactly 32 bytes
/// at construction time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ed25519PublicKey([u8; 32]);

impl Ed25519PublicKey {
    /// Creates a new Ed25519PublicKey from a 32-byte array.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Creates a new Ed25519PublicKey from a byte slice.
    ///
    /// Args:
    /// * `slice`: Byte slice that must be exactly 32 bytes.
    ///
    /// Usage:
    /// ```ignore
    /// let pk = Ed25519PublicKey::try_from_slice(&bytes)?;
    /// ```
    pub fn try_from_slice(slice: &[u8]) -> Result<Self, Ed25519KeyError> {
        let arr: [u8; 32] = slice
            .try_into()
            .map_err(|_| Ed25519KeyError::InvalidLength(slice.len()))?;
        Ok(Self(arr))
    }

    /// Returns the inner 32-byte array.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns `true` if all 32 bytes are zero (used for unsigned org-member attestations).
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; 32]
    }
}

impl Serialize for Ed25519PublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Ed25519PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let bytes =
            hex::decode(&s).map_err(|e| serde::de::Error::custom(format!("invalid hex: {e}")))?;
        let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected 32 bytes, got {}", v.len()))
        })?;
        Ok(Self(arr))
    }
}

impl fmt::Display for Ed25519PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl AsRef<[u8]> for Ed25519PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for Ed25519PublicKey {
    fn schema_name() -> String {
        "Ed25519PublicKey".to_owned()
    }

    fn json_schema(_gen: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::String.into()),
            format: Some("hex".to_owned()),
            metadata: Some(Box::new(schemars::schema::Metadata {
                description: Some("Ed25519 public key (32 bytes, hex-encoded)".to_owned()),
                ..Default::default()
            })),
            ..Default::default()
        }
        .into()
    }
}

/// Error type for Ed25519 public key construction.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Ed25519KeyError {
    /// The byte slice is not exactly 32 bytes.
    #[error("expected 32 bytes, got {0}")]
    InvalidLength(usize),
    /// The hex string is not valid.
    #[error("invalid hex: {0}")]
    InvalidHex(String),
}

// =============================================================================
// Ed25519Signature newtype
// =============================================================================

/// A validated Ed25519 signature (64 bytes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed25519Signature([u8; 64]);

impl Ed25519Signature {
    /// Creates a signature from a 64-byte array.
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Self(bytes)
    }

    /// Attempts to create a signature from a byte slice, returning an error if the length is not 64.
    pub fn try_from_slice(slice: &[u8]) -> Result<Self, SignatureLengthError> {
        let arr: [u8; 64] = slice
            .try_into()
            .map_err(|_| SignatureLengthError(slice.len()))?;
        Ok(Self(arr))
    }

    /// Creates an all-zero signature, used as a placeholder.
    pub fn empty() -> Self {
        Self([0u8; 64])
    }

    /// Returns `true` if the signature is all zeros (placeholder).
    pub fn is_empty(&self) -> bool {
        self.0 == [0u8; 64]
    }

    /// Returns a reference to the underlying 64-byte array.
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl Default for Ed25519Signature {
    fn default() -> Self {
        Self::empty()
    }
}

impl std::fmt::Display for Ed25519Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl AsRef<[u8]> for Ed25519Signature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for Ed25519Signature {
    fn schema_name() -> String {
        "Ed25519Signature".to_owned()
    }

    fn json_schema(_gen: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::String.into()),
            format: Some("hex".to_owned()),
            metadata: Some(Box::new(schemars::schema::Metadata {
                description: Some("Ed25519 signature (64 bytes, hex-encoded)".to_owned()),
                ..Default::default()
            })),
            ..Default::default()
        }
        .into()
    }
}

impl serde::Serialize for Ed25519Signature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> serde::Deserialize<'de> for Ed25519Signature {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s.is_empty() {
            return Ok(Self::empty());
        }
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        Self::try_from_slice(&bytes).map_err(serde::de::Error::custom)
    }
}

/// Error when constructing an Ed25519Signature from a byte slice of wrong length.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("expected 64 bytes, got {0}")]
pub struct SignatureLengthError(pub usize);

// =============================================================================
// Capability types
// =============================================================================

/// Error type for capability parsing and validation.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CapabilityError {
    /// The capability string is empty.
    #[error("capability is empty")]
    Empty,
    /// The capability string exceeds the maximum length.
    #[error("capability exceeds 64 chars: {0}")]
    TooLong(usize),
    /// The capability string contains invalid characters.
    #[error("invalid characters in capability '{0}': only alphanumeric, ':', '-', '_' allowed")]
    InvalidChars(String),
    /// The capability uses the reserved 'auths:' namespace.
    #[error(
        "reserved namespace 'auths:' — use well-known constructors or choose a different prefix"
    )]
    ReservedNamespace,
}

/// A validated capability identifier.
///
/// Capabilities are the atomic unit of authorization in Auths.
/// They follow a namespace convention:
///
/// - Well-known capabilities: `sign_commit`, `sign_release`, `manage_members`, `rotate_keys`
/// - Custom capabilities: any valid string (alphanumeric + `:` + `-` + `_`, max 64 chars)
///
/// The `auths:` prefix is reserved for future well-known capabilities and cannot be
/// used in custom capabilities created via `parse()`.
///
/// # Examples
///
/// ```
/// use auths_verifier::Capability;
///
/// // Well-known capabilities
/// let cap = Capability::sign_commit();
/// assert_eq!(cap.as_str(), "sign_commit");
///
/// // Custom capabilities
/// let custom = Capability::parse("acme:deploy").unwrap();
/// assert_eq!(custom.as_str(), "acme:deploy");
///
/// // Reserved namespace is rejected
/// assert!(Capability::parse("auths:custom").is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(try_from = "String", into = "String")]
pub struct Capability(String);

impl Capability {
    /// Maximum length for capability strings.
    pub const MAX_LEN: usize = 64;

    /// Reserved namespace prefix for Auths well-known capabilities.
    const RESERVED_PREFIX: &'static str = "auths:";

    // ========================================================================
    // Well-known capability constructors
    // ========================================================================

    /// Creates the `sign_commit` capability.
    ///
    /// Grants permission to sign commits.
    #[inline]
    pub fn sign_commit() -> Self {
        Self(SIGN_COMMIT.to_string())
    }

    /// Creates the `sign_release` capability.
    ///
    /// Grants permission to sign releases.
    #[inline]
    pub fn sign_release() -> Self {
        Self(SIGN_RELEASE.to_string())
    }

    /// Creates the `manage_members` capability.
    ///
    /// Grants permission to add/remove members in an organization.
    #[inline]
    pub fn manage_members() -> Self {
        Self(MANAGE_MEMBERS.to_string())
    }

    /// Creates the `rotate_keys` capability.
    ///
    /// Grants permission to rotate keys for an identity.
    #[inline]
    pub fn rotate_keys() -> Self {
        Self(ROTATE_KEYS.to_string())
    }

    // ========================================================================
    // Parsing and validation
    // ========================================================================

    /// Parses and validates a capability string.
    ///
    /// This is the primary way to create custom capabilities. The input is
    /// trimmed and lowercased to produce a canonical form.
    ///
    /// # Validation Rules
    ///
    /// - Non-empty
    /// - Maximum 64 characters
    /// - Only alphanumeric characters, colons (`:`), hyphens (`-`), and underscores (`_`)
    /// - Cannot start with `auths:` (reserved namespace)
    ///
    /// # Examples
    ///
    /// ```
    /// use auths_verifier::Capability;
    ///
    /// // Valid custom capabilities
    /// assert!(Capability::parse("deploy").is_ok());
    /// assert!(Capability::parse("acme:deploy").is_ok());
    /// assert!(Capability::parse("org:team:action").is_ok());
    ///
    /// // Invalid capabilities
    /// assert!(Capability::parse("").is_err());           // empty
    /// assert!(Capability::parse("has space").is_err());  // invalid char
    /// assert!(Capability::parse("auths:custom").is_err()); // reserved namespace
    /// ```
    pub fn parse(raw: &str) -> Result<Self, CapabilityError> {
        let canonical = raw.trim().to_lowercase();

        if canonical.is_empty() {
            return Err(CapabilityError::Empty);
        }
        if canonical.len() > Self::MAX_LEN {
            return Err(CapabilityError::TooLong(canonical.len()));
        }
        if !canonical
            .chars()
            .all(|c| c.is_alphanumeric() || c == ':' || c == '-' || c == '_')
        {
            return Err(CapabilityError::InvalidChars(canonical));
        }
        if canonical.starts_with(Self::RESERVED_PREFIX) {
            return Err(CapabilityError::ReservedNamespace);
        }

        Ok(Self(canonical))
    }

    /// Creates a custom capability after validation.
    ///
    /// This is a convenience method that returns `Option<Self>` instead of `Result`.
    ///
    /// # Deprecated
    ///
    /// Prefer using `parse()` for better error handling.
    #[deprecated(since = "0.2.0", note = "Use parse() for better error handling")]
    pub fn custom(s: impl Into<String>) -> Option<Self> {
        Self::parse(&s.into()).ok()
    }

    /// Validates a custom capability string.
    ///
    /// # Deprecated
    ///
    /// This method is retained for backward compatibility. Use `parse()` instead.
    #[deprecated(since = "0.2.0", note = "Use parse() for validation")]
    pub fn validate_custom(s: &str) -> bool {
        Self::parse(s).is_ok()
    }

    // ========================================================================
    // Accessors
    // ========================================================================

    /// Returns the canonical string representation of this capability.
    ///
    /// This is the authoritative string form used for comparison, display,
    /// and serialization.
    #[inline]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns `true` if this is a well-known Auths capability.
    pub fn is_well_known(&self) -> bool {
        matches!(
            self.0.as_str(),
            SIGN_COMMIT | SIGN_RELEASE | MANAGE_MEMBERS | ROTATE_KEYS
        )
    }

    /// Returns the namespace portion of the capability (before first colon), if any.
    pub fn namespace(&self) -> Option<&str> {
        self.0.split(':').next().filter(|_| self.0.contains(':'))
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl TryFrom<String> for Capability {
    type Error = CapabilityError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let canonical = s.trim().to_lowercase();

        if canonical.is_empty() {
            return Err(CapabilityError::Empty);
        }
        if canonical.len() > Self::MAX_LEN {
            return Err(CapabilityError::TooLong(canonical.len()));
        }
        if !canonical
            .chars()
            .all(|c| c.is_alphanumeric() || c == ':' || c == '-' || c == '_')
        {
            return Err(CapabilityError::InvalidChars(canonical));
        }

        // During deserialization, allow well-known capabilities and auths: prefix
        // This ensures backward compatibility with existing attestations
        Ok(Self(canonical))
    }
}

impl std::str::FromStr for Capability {
    type Err = CapabilityError;

    /// Parses a capability string with CLI-friendly alias resolution.
    ///
    /// Normalizes the input (trim, lowercase, replace hyphens with underscores)
    /// and matches well-known capabilities before falling through to
    /// `Capability::parse()` for custom capability validation.
    ///
    /// Unlike the deprecated `parse_capability_cli`, this returns an error
    /// for unrecognized well-known names instead of silently defaulting.
    ///
    /// Args:
    /// * `s`: The capability string (e.g., "sign_commit", "Sign-Commit").
    ///
    /// Usage:
    /// ```
    /// use auths_verifier::Capability;
    /// let cap: Capability = "sign_commit".parse().unwrap();
    /// assert_eq!(cap.as_str(), "sign_commit");
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let normalized = s.trim().to_lowercase().replace('-', "_");
        match normalized.as_str() {
            "sign_commit" | "signcommit" => Ok(Capability::sign_commit()),
            "sign_release" | "signrelease" => Ok(Capability::sign_release()),
            "manage_members" | "managemembers" => Ok(Capability::manage_members()),
            "rotate_keys" | "rotatekeys" => Ok(Capability::rotate_keys()),
            _ => Capability::parse(&normalized),
        }
    }
}

impl From<Capability> for String {
    fn from(cap: Capability) -> Self {
        cap.0
    }
}

/// An identity bundle for stateless verification in CI/CD environments.
///
/// Contains all the information needed to verify commit signatures without
/// requiring access to the identity repository or daemon.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct IdentityBundle {
    /// The DID of the identity (e.g., "did:keri:...")
    pub identity_did: String,
    /// The public key in hex format for signature verification
    pub public_key_hex: String,
    /// Chain of attestations linking the signing key to the identity
    pub attestation_chain: Vec<Attestation>,
    /// UTC timestamp when this bundle was created
    pub bundle_timestamp: DateTime<Utc>,
    /// Maximum age in seconds before this bundle is considered stale
    pub max_valid_for_secs: u64,
}

impl IdentityBundle {
    /// Check that this bundle is still within its TTL.
    ///
    /// Args:
    /// * `now`: The current time, injected for deterministic verification.
    ///
    /// Usage:
    /// ```ignore
    /// bundle.check_freshness(Utc::now())?;
    /// ```
    pub fn check_freshness(&self, now: DateTime<Utc>) -> Result<(), AttestationError> {
        let age = (now - self.bundle_timestamp).num_seconds().max(0) as u64;
        if age > self.max_valid_for_secs {
            return Err(AttestationError::BundleExpired {
                age_secs: age,
                max_secs: self.max_valid_for_secs,
            });
        }
        Ok(())
    }
}

/// Represents a 2-way key attestation between a primary identity and a device key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Attestation {
    /// Schema version.
    pub version: u32,
    /// Record identifier linking this attestation to its storage ref.
    pub rid: ResourceId,
    /// DID of the issuing identity.
    pub issuer: IdentityDID,
    /// DID of the device being attested.
    pub subject: DeviceDID,
    /// Ed25519 public key of the device (32 bytes, hex-encoded in JSON).
    pub device_public_key: Ed25519PublicKey,
    /// Issuer's Ed25519 signature over the canonical attestation data (hex-encoded in JSON).
    #[serde(default, skip_serializing_if = "Ed25519Signature::is_empty")]
    pub identity_signature: Ed25519Signature,
    /// Device's Ed25519 signature over the canonical attestation data (hex-encoded in JSON).
    pub device_signature: Ed25519Signature,
    /// Timestamp when the attestation was revoked, if applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
    /// Expiration timestamp, if set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    /// Creation timestamp.
    pub timestamp: Option<DateTime<Utc>>,
    /// Optional human-readable note.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Optional arbitrary JSON payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,

    /// Role for org membership attestations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<Role>,

    /// Capabilities this attestation grants.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<Capability>,

    /// DID of the attestation that delegated authority (for chain tracking).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_by: Option<IdentityDID>,

    /// The type of entity that produced this signature (human, agent, workload).
    /// Included in the canonical JSON before signing — the signature covers this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_type: Option<SignerType>,
}

/// The type of entity that produced a signature.
///
/// Duplicated here (also in `auths-policy`) because `auths-verifier` is a
/// standalone minimal-dependency crate that cannot depend on `auths-policy`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum SignerType {
    /// A human user.
    Human,
    /// An autonomous AI agent.
    Agent,
    /// A CI/CD workload or service identity.
    Workload,
}

/// An attestation that has passed signature verification.
///
/// This type enforces at compile time that an attestation's signatures were verified
/// before it can be stored. It can only be constructed by:
/// - Verification functions (`verify_with_keys`, `verify_with_capability`)
/// - The `dangerous_from_unchecked` escape hatch (for self-signed attestations)
///
/// Does NOT implement `Deserialize` to prevent bypassing verification by
/// deserializing directly.
#[derive(Debug, Clone, Serialize)]
pub struct VerifiedAttestation(Attestation);

impl VerifiedAttestation {
    /// Access the inner attestation.
    pub fn inner(&self) -> &Attestation {
        &self.0
    }

    /// Consume and return the inner attestation.
    pub fn into_inner(self) -> Attestation {
        self.0
    }

    /// Construct a `VerifiedAttestation` without running verification.
    ///
    /// # Safety (logical)
    /// Only use this when you are the signer (e.g., you just created and signed
    /// the attestation) or in test code. Misuse defeats the purpose of this type.
    #[doc(hidden)]
    pub fn dangerous_from_unchecked(attestation: Attestation) -> Self {
        Self(attestation)
    }

    pub(crate) fn from_verified(attestation: Attestation) -> Self {
        Self(attestation)
    }
}

impl std::ops::Deref for VerifiedAttestation {
    type Target = Attestation;

    fn deref(&self) -> &Attestation {
        &self.0
    }
}

/// Data structure for canonicalizing standard attestations (link, extend).
#[derive(Serialize, Debug)]
pub struct CanonicalAttestationData<'a> {
    /// Schema version.
    pub version: u32,
    /// Record identifier.
    pub rid: &'a str,
    /// DID of the issuing identity.
    pub issuer: &'a IdentityDID,
    /// DID of the device being attested.
    pub subject: &'a DeviceDID,
    /// Raw Ed25519 public key of the device.
    #[serde(with = "hex::serde")]
    pub device_public_key: &'a [u8],
    /// Optional arbitrary JSON payload.
    pub payload: &'a Option<Value>,
    /// Creation timestamp.
    pub timestamp: &'a Option<DateTime<Utc>>,
    /// Expiration timestamp.
    pub expires_at: &'a Option<DateTime<Utc>>,
    /// Revocation timestamp.
    pub revoked_at: &'a Option<DateTime<Utc>>,
    /// Optional human-readable note.
    pub note: &'a Option<String>,

    /// Org membership role (included in signed envelope).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<&'a str>,
    /// Capabilities granted by this attestation (included in signed envelope).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<&'a Vec<Capability>>,
    /// DID of the delegating attestation (included in signed envelope).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegated_by: Option<&'a IdentityDID>,
    /// Type of signer (included in signed envelope).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_type: Option<&'a SignerType>,
}

/// Produce the canonical JSON bytes over which signatures are computed.
///
/// Args:
/// * `data`: The attestation data to canonicalize.
pub fn canonicalize_attestation_data(
    data: &CanonicalAttestationData,
) -> Result<Vec<u8>, AttestationError> {
    let canonical_json_string = json_canon::to_string(data).map_err(|e| {
        AttestationError::SerializationError(format!("Failed to create canonical JSON: {}", e))
    })?;
    debug!(
        "Generated canonical data (standard): {}",
        canonical_json_string
    );
    Ok(canonical_json_string.into_bytes())
}

impl Attestation {
    /// Returns `true` if this attestation has been revoked.
    pub fn is_revoked(&self) -> bool {
        self.revoked_at.is_some()
    }

    /// Deserializes an Attestation from JSON bytes.
    ///
    /// Returns an error if the input exceeds [`MAX_ATTESTATION_JSON_SIZE`] (64 KiB).
    pub fn from_json(json_bytes: &[u8]) -> Result<Self, AttestationError> {
        if json_bytes.len() > MAX_ATTESTATION_JSON_SIZE {
            return Err(AttestationError::InputTooLarge(format!(
                "attestation JSON is {} bytes, max {}",
                json_bytes.len(),
                MAX_ATTESTATION_JSON_SIZE
            )));
        }
        serde_json::from_slice(json_bytes)
            .map_err(|e| AttestationError::SerializationError(e.to_string()))
    }

    /// Formats the attestation contents for debug or inspection purposes.
    pub fn to_debug_string(&self) -> String {
        format!(
            "RID: {}\nIssuer DID: {}\nSubject DID: {}\nDevice PK: {}\nIdentity Sig: {}\nDevice Sig: {}\nRevoked At: {:?}\nExpires: {:?}\nNote: {:?}",
            self.rid,
            self.issuer,
            self.subject, // DeviceDID implements Display
            hex::encode(self.device_public_key.as_bytes()),
            hex::encode(self.identity_signature.as_bytes()),
            hex::encode(self.device_signature.as_bytes()),
            self.revoked_at,
            self.expires_at,
            self.note
        )
    }
}

// =============================================================================
// Threshold Signatures (FROST) - Future Implementation
// =============================================================================

/// Policy for threshold signature operations (M-of-N).
///
/// This struct defines the parameters for FROST (Flexible Round-Optimized
/// Schnorr Threshold) signature operations. FROST enables M-of-N threshold
/// signing where at least M participants must cooperate to produce a valid
/// signature, but no single participant can sign alone.
///
/// # Protocol Choice: FROST
///
/// FROST was chosen over alternatives for several reasons:
/// - **Ed25519 native**: Works with existing Ed25519 key infrastructure
/// - **Round-optimized**: Only 2 rounds for signing (vs 3+ for alternatives)
/// - **Rust ecosystem**: `frost-ed25519` crate from ZcashFoundation is mature
/// - **Security**: Proven secure under discrete log assumption
///
/// # Key Generation Approaches
///
/// Two approaches exist for generating threshold key shares:
///
/// 1. **Trusted Dealer**: One party generates the key and distributes shares
///    - Simpler to implement
///    - Single point of failure during key generation
///    - Appropriate for org-controlled scenarios
///
/// 2. **Distributed Key Generation (DKG)**: Participants jointly generate key
///    - No single party ever sees the full key
///    - More complex, requires additional round-trips
///    - Better for trustless scenarios
///
/// # Integration with Auths
///
/// Threshold policies can be attached to high-value operations like:
/// - `sign-release`: Release signing requires M-of-N approvers
/// - `rotate-keys`: Key rotation requires multi-party approval
/// - `manage-members`: Adding admins requires quorum
///
/// # Example
///
/// ```ignore
/// let policy = ThresholdPolicy {
///     threshold: 2,
///     signers: vec![
///         "did:key:alice".to_string(),
///         "did:key:bob".to_string(),
///         "did:key:carol".to_string(),
///     ],
///     policy_id: "release-signing-v1".to_string(),
///     scope: Some(Capability::sign_release()),
///     ceremony_endpoint: Some("wss://auths.example/ceremony".to_string()),
/// };
/// // 2-of-3: Any 2 of Alice, Bob, Carol can sign releases
/// ```
///
/// # Storage
///
/// Key shares are NOT stored in Git refs (they are secrets). Options:
/// - Platform keychain (macOS Keychain, Windows Credential Manager)
/// - Hardware security modules (HSMs)
/// - Secret managers (Vault, AWS Secrets Manager)
///
/// The policy itself (public info) is stored in Git at:
/// `refs/auths/policies/threshold/<policy_id>`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct ThresholdPolicy {
    /// Minimum signers required (M in M-of-N)
    pub threshold: u8,

    /// Total authorized signers (N in M-of-N) - DIDs of participants
    pub signers: Vec<String>,

    /// Unique identifier for this policy
    pub policy_id: String,

    /// Scope of operations this policy covers (optional)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Capability>,

    /// Ceremony coordination endpoint (e.g., WebSocket URL for signing rounds)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ceremony_endpoint: Option<String>,
}

impl ThresholdPolicy {
    /// Create a new threshold policy
    pub fn new(threshold: u8, signers: Vec<String>, policy_id: String) -> Self {
        Self {
            threshold,
            signers,
            policy_id,
            scope: None,
            ceremony_endpoint: None,
        }
    }

    /// Check if the policy parameters are valid
    pub fn is_valid(&self) -> bool {
        // Threshold must be at least 1
        if self.threshold < 1 {
            return false;
        }
        // Threshold cannot exceed number of signers
        if self.threshold as usize > self.signers.len() {
            return false;
        }
        // Must have at least one signer
        if self.signers.is_empty() {
            return false;
        }
        // Policy ID must not be empty
        if self.policy_id.is_empty() {
            return false;
        }
        true
    }

    /// Returns M (threshold) and N (total signers)
    pub fn m_of_n(&self) -> (u8, usize) {
        (self.threshold, self.signers.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // Capability serialization tests
    // ========================================================================

    #[test]
    fn capability_serializes_to_snake_case() {
        assert_eq!(
            serde_json::to_string(&Capability::sign_commit()).unwrap(),
            r#""sign_commit""#
        );
        assert_eq!(
            serde_json::to_string(&Capability::sign_release()).unwrap(),
            r#""sign_release""#
        );
        assert_eq!(
            serde_json::to_string(&Capability::manage_members()).unwrap(),
            r#""manage_members""#
        );
        assert_eq!(
            serde_json::to_string(&Capability::rotate_keys()).unwrap(),
            r#""rotate_keys""#
        );
    }

    #[test]
    fn capability_deserializes_from_snake_case() {
        assert_eq!(
            serde_json::from_str::<Capability>(r#""sign_commit""#).unwrap(),
            Capability::sign_commit()
        );
        assert_eq!(
            serde_json::from_str::<Capability>(r#""sign_release""#).unwrap(),
            Capability::sign_release()
        );
        assert_eq!(
            serde_json::from_str::<Capability>(r#""manage_members""#).unwrap(),
            Capability::manage_members()
        );
        assert_eq!(
            serde_json::from_str::<Capability>(r#""rotate_keys""#).unwrap(),
            Capability::rotate_keys()
        );
    }

    #[test]
    fn capability_custom_serializes_as_string() {
        let cap = Capability::parse("acme:deploy").unwrap();
        assert_eq!(serde_json::to_string(&cap).unwrap(), r#""acme:deploy""#);
    }

    #[test]
    fn capability_custom_deserializes_unknown_strings() {
        // Unknown strings become custom capabilities
        let cap: Capability = serde_json::from_str(r#""custom-capability""#).unwrap();
        assert_eq!(cap, Capability::parse("custom-capability").unwrap());
    }

    // ========================================================================
    // Capability parse() validation tests
    // ========================================================================

    #[test]
    fn capability_parse_accepts_valid_strings() {
        assert!(Capability::parse("deploy").is_ok());
        assert!(Capability::parse("acme:deploy").is_ok());
        assert!(Capability::parse("my-custom-cap").is_ok());
        assert!(Capability::parse("org:team:action").is_ok());
        assert!(Capability::parse("with_underscore").is_ok()); // underscore allowed
    }

    #[test]
    fn capability_parse_rejects_invalid_strings() {
        // Empty
        assert!(matches!(Capability::parse(""), Err(CapabilityError::Empty)));

        // Too long
        assert!(matches!(
            Capability::parse(&"a".repeat(65)),
            Err(CapabilityError::TooLong(65))
        ));

        // Invalid characters
        assert!(matches!(
            Capability::parse("has spaces"),
            Err(CapabilityError::InvalidChars(_))
        ));
        assert!(matches!(
            Capability::parse("has.dot"),
            Err(CapabilityError::InvalidChars(_))
        ));
    }

    #[test]
    fn capability_parse_rejects_reserved_namespace() {
        assert!(matches!(
            Capability::parse("auths:custom"),
            Err(CapabilityError::ReservedNamespace)
        ));
        assert!(matches!(
            Capability::parse("auths:sign_commit"),
            Err(CapabilityError::ReservedNamespace)
        ));
    }

    #[test]
    fn capability_parse_normalizes_to_lowercase() {
        let cap = Capability::parse("DEPLOY").unwrap();
        assert_eq!(cap.as_str(), "deploy");

        let cap = Capability::parse("ACME:Deploy").unwrap();
        assert_eq!(cap.as_str(), "acme:deploy");
    }

    #[test]
    fn capability_parse_trims_whitespace() {
        let cap = Capability::parse("  deploy  ").unwrap();
        assert_eq!(cap.as_str(), "deploy");
    }

    // ========================================================================
    // Capability equality and hashing tests
    // ========================================================================

    #[test]
    fn capability_is_hashable() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(Capability::sign_commit());
        set.insert(Capability::sign_release());
        set.insert(Capability::parse("test").unwrap());
        assert_eq!(set.len(), 3);
        assert!(set.contains(&Capability::sign_commit()));
    }

    #[test]
    fn capability_equality_with_different_construction_paths() {
        // Well-known constructor equals deserialized
        let from_constructor = Capability::sign_commit();
        let from_deser: Capability = serde_json::from_str(r#""sign_commit""#).unwrap();
        assert_eq!(from_constructor, from_deser);

        // Parse equals deserialized for custom capabilities
        let from_parse = Capability::parse("acme:deploy").unwrap();
        let from_deser: Capability = serde_json::from_str(r#""acme:deploy""#).unwrap();
        assert_eq!(from_parse, from_deser);
    }

    // ========================================================================
    // Capability display and accessor tests
    // ========================================================================

    #[test]
    fn capability_display_matches_canonical_form() {
        assert_eq!(Capability::sign_commit().to_string(), "sign_commit");
        assert_eq!(Capability::sign_release().to_string(), "sign_release");
        assert_eq!(Capability::manage_members().to_string(), "manage_members");
        assert_eq!(Capability::rotate_keys().to_string(), "rotate_keys");
        assert_eq!(
            Capability::parse("acme:deploy").unwrap().to_string(),
            "acme:deploy"
        );
    }

    #[test]
    fn capability_as_str_returns_canonical_form() {
        assert_eq!(Capability::sign_commit().as_str(), "sign_commit");
        assert_eq!(Capability::sign_release().as_str(), "sign_release");
        assert_eq!(Capability::manage_members().as_str(), "manage_members");
        assert_eq!(Capability::rotate_keys().as_str(), "rotate_keys");
        assert_eq!(
            Capability::parse("acme:deploy").unwrap().as_str(),
            "acme:deploy"
        );
    }

    #[test]
    fn capability_is_well_known() {
        assert!(Capability::sign_commit().is_well_known());
        assert!(Capability::sign_release().is_well_known());
        assert!(Capability::manage_members().is_well_known());
        assert!(Capability::rotate_keys().is_well_known());
        assert!(!Capability::parse("custom").unwrap().is_well_known());
    }

    #[test]
    fn capability_namespace() {
        assert_eq!(
            Capability::parse("acme:deploy").unwrap().namespace(),
            Some("acme")
        );
        assert_eq!(
            Capability::parse("org:team:action").unwrap().namespace(),
            Some("org")
        );
        assert_eq!(Capability::parse("deploy").unwrap().namespace(), None);
    }

    // ========================================================================
    // Capability vec serialization tests
    // ========================================================================

    #[test]
    fn capability_vec_serializes_as_array() {
        let caps = vec![Capability::sign_commit(), Capability::sign_release()];
        let json = serde_json::to_string(&caps).unwrap();
        assert_eq!(json, r#"["sign_commit","sign_release"]"#);
    }

    #[test]
    fn capability_vec_deserializes_from_array() {
        let json = r#"["sign_commit","manage_members","custom-cap"]"#;
        let caps: Vec<Capability> = serde_json::from_str(json).unwrap();
        assert_eq!(caps.len(), 3);
        assert_eq!(caps[0], Capability::sign_commit());
        assert_eq!(caps[1], Capability::manage_members());
        assert_eq!(caps[2], Capability::parse("custom-cap").unwrap());
    }

    // ========================================================================
    // Serde roundtrip tests (critical for backward compat)
    // ========================================================================

    #[test]
    fn capability_serde_roundtrip_well_known() {
        let caps = vec![
            Capability::sign_commit(),
            Capability::sign_release(),
            Capability::manage_members(),
            Capability::rotate_keys(),
        ];
        for cap in caps {
            let json = serde_json::to_string(&cap).unwrap();
            let roundtrip: Capability = serde_json::from_str(&json).unwrap();
            assert_eq!(cap, roundtrip);
        }
    }

    #[test]
    fn capability_serde_roundtrip_custom() {
        let caps = vec![
            Capability::parse("deploy").unwrap(),
            Capability::parse("acme:deploy").unwrap(),
            Capability::parse("org:team:action").unwrap(),
        ];
        for cap in caps {
            let json = serde_json::to_string(&cap).unwrap();
            let roundtrip: Capability = serde_json::from_str(&json).unwrap();
            assert_eq!(cap, roundtrip);
        }
    }

    // Tests for Attestation org fields (fn-6.2)

    #[test]
    fn attestation_old_json_without_org_fields_deserializes() {
        // Simulates an old attestation JSON without role, capabilities, delegated_by
        let old_json = r#"{
            "version": 1,
            "rid": "test-rid",
            "issuer": "did:key:issuer",
            "subject": "did:key:subject",
            "device_public_key": "0102030405060708091011121314151617181920212223242526272829303132",
            "identity_signature": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "device_signature": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "revoked_at": null,
            "timestamp": null
        }"#;

        let att: Attestation = serde_json::from_str(old_json).unwrap();

        // New fields should have defaults
        assert_eq!(att.role, None);
        assert!(att.capabilities.is_empty());
        assert_eq!(att.delegated_by, None);
    }

    #[test]
    fn attestation_with_org_fields_serializes_correctly() {
        use crate::types::DeviceDID;

        let att = Attestation {
            version: 1,
            rid: ResourceId::new("test-rid"),
            issuer: IdentityDID::new("did:key:issuer"),
            subject: DeviceDID::new("did:key:subject".to_string()),
            device_public_key: Ed25519PublicKey::from_bytes([0u8; 32]),
            identity_signature: Ed25519Signature::empty(),
            device_signature: Ed25519Signature::empty(),
            revoked_at: None,
            expires_at: None,
            timestamp: None,
            note: None,
            payload: None,
            role: Some(Role::Admin),
            capabilities: vec![Capability::sign_commit(), Capability::manage_members()],
            delegated_by: Some(IdentityDID::new("did:key:delegator")),
            signer_type: None,
        };

        let json = serde_json::to_string(&att).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["role"], "admin");
        assert_eq!(parsed["capabilities"][0], "sign_commit");
        assert_eq!(parsed["capabilities"][1], "manage_members");
        assert_eq!(parsed["delegated_by"], "did:key:delegator");
    }

    #[test]
    fn attestation_without_org_fields_omits_them_in_json() {
        use crate::types::DeviceDID;

        let att = Attestation {
            version: 1,
            rid: ResourceId::new("test-rid"),
            issuer: IdentityDID::new("did:key:issuer"),
            subject: DeviceDID::new("did:key:subject".to_string()),
            device_public_key: Ed25519PublicKey::from_bytes([0u8; 32]),
            identity_signature: Ed25519Signature::empty(),
            device_signature: Ed25519Signature::empty(),
            revoked_at: None,
            expires_at: None,
            timestamp: None,
            note: None,
            payload: None,
            role: None,
            capabilities: vec![],
            delegated_by: None,
            signer_type: None,
        };

        let json = serde_json::to_string(&att).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        // These fields should not be present in JSON
        assert!(parsed.get("role").is_none());
        assert!(parsed.get("capabilities").is_none());
        assert!(parsed.get("delegated_by").is_none());
    }

    #[test]
    fn attestation_with_org_fields_roundtrips() {
        use crate::types::DeviceDID;

        let original = Attestation {
            version: 1,
            rid: ResourceId::new("test-rid"),
            issuer: IdentityDID::new("did:key:issuer"),
            subject: DeviceDID::new("did:key:subject".to_string()),
            device_public_key: Ed25519PublicKey::from_bytes([0u8; 32]),
            identity_signature: Ed25519Signature::empty(),
            device_signature: Ed25519Signature::empty(),
            revoked_at: None,
            expires_at: None,
            timestamp: None,
            note: None,
            payload: None,
            role: Some(Role::Member),
            capabilities: vec![Capability::sign_commit(), Capability::sign_release()],
            delegated_by: Some(IdentityDID::new("did:key:admin")),
            signer_type: None,
        };

        let json = serde_json::to_string(&original).unwrap();
        let deserialized: Attestation = serde_json::from_str(&json).unwrap();

        assert_eq!(original.role, deserialized.role);
        assert_eq!(original.capabilities, deserialized.capabilities);
        assert_eq!(original.delegated_by, deserialized.delegated_by);
    }

    // Tests for ThresholdPolicy (fn-6.11)

    #[test]
    fn threshold_policy_new_creates_valid_policy() {
        let policy = ThresholdPolicy::new(
            2,
            vec![
                "did:key:alice".to_string(),
                "did:key:bob".to_string(),
                "did:key:carol".to_string(),
            ],
            "test-policy".to_string(),
        );

        assert_eq!(policy.threshold, 2);
        assert_eq!(policy.signers.len(), 3);
        assert_eq!(policy.policy_id, "test-policy");
        assert!(policy.scope.is_none());
        assert!(policy.ceremony_endpoint.is_none());
    }

    #[test]
    fn threshold_policy_is_valid_checks_constraints() {
        // Valid 2-of-3
        let valid = ThresholdPolicy::new(
            2,
            vec!["a".to_string(), "b".to_string(), "c".to_string()],
            "policy".to_string(),
        );
        assert!(valid.is_valid());

        // Invalid: threshold 0
        let zero_threshold = ThresholdPolicy::new(0, vec!["a".to_string()], "policy".to_string());
        assert!(!zero_threshold.is_valid());

        // Invalid: threshold > signers
        let too_high = ThresholdPolicy::new(
            3,
            vec!["a".to_string(), "b".to_string()],
            "policy".to_string(),
        );
        assert!(!too_high.is_valid());

        // Invalid: empty signers
        let no_signers = ThresholdPolicy::new(1, vec![], "policy".to_string());
        assert!(!no_signers.is_valid());

        // Invalid: empty policy_id
        let no_id = ThresholdPolicy::new(1, vec!["a".to_string()], "".to_string());
        assert!(!no_id.is_valid());
    }

    #[test]
    fn threshold_policy_m_of_n_returns_correct_values() {
        let policy = ThresholdPolicy::new(
            2,
            vec!["a".to_string(), "b".to_string(), "c".to_string()],
            "policy".to_string(),
        );
        let (m, n) = policy.m_of_n();
        assert_eq!(m, 2);
        assert_eq!(n, 3);
    }

    #[test]
    fn threshold_policy_serializes_correctly() {
        let mut policy = ThresholdPolicy::new(
            2,
            vec!["did:key:alice".to_string(), "did:key:bob".to_string()],
            "release-policy".to_string(),
        );
        policy.scope = Some(Capability::sign_release());
        policy.ceremony_endpoint = Some("wss://example.com/ceremony".to_string());

        let json = serde_json::to_string(&policy).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["threshold"], 2);
        assert_eq!(parsed["signers"][0], "did:key:alice");
        assert_eq!(parsed["policy_id"], "release-policy");
        assert_eq!(parsed["scope"], "sign_release");
        assert_eq!(parsed["ceremony_endpoint"], "wss://example.com/ceremony");
    }

    #[test]
    fn threshold_policy_without_optional_fields_omits_them() {
        let policy =
            ThresholdPolicy::new(1, vec!["did:key:alice".to_string()], "policy".to_string());

        let json = serde_json::to_string(&policy).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(parsed.get("scope").is_none());
        assert!(parsed.get("ceremony_endpoint").is_none());
    }

    #[test]
    fn threshold_policy_roundtrips() {
        let mut original = ThresholdPolicy::new(
            3,
            vec![
                "a".to_string(),
                "b".to_string(),
                "c".to_string(),
                "d".to_string(),
            ],
            "important-policy".to_string(),
        );
        original.scope = Some(Capability::rotate_keys());

        let json = serde_json::to_string(&original).unwrap();
        let deserialized: ThresholdPolicy = serde_json::from_str(&json).unwrap();

        assert_eq!(original, deserialized);
    }

    // Tests for IdentityBundle (CI/CD stateless verification)

    #[test]
    fn identity_bundle_serializes_correctly() {
        let bundle = IdentityBundle {
            identity_did: "did:keri:test123".to_string(),
            public_key_hex: "aabbccdd".to_string(),
            attestation_chain: vec![],
            bundle_timestamp: DateTime::parse_from_rfc3339("2099-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            max_valid_for_secs: 86400,
        };

        let json = serde_json::to_string(&bundle).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["identity_did"], "did:keri:test123");
        assert_eq!(parsed["public_key_hex"], "aabbccdd");
        assert!(parsed["attestation_chain"].as_array().unwrap().is_empty());
    }

    #[test]
    fn identity_bundle_deserializes_correctly() {
        let json = r#"{
            "identity_did": "did:keri:abc123",
            "public_key_hex": "112233",
            "attestation_chain": [],
            "bundle_timestamp": "2099-01-01T00:00:00Z",
            "max_valid_for_secs": 86400
        }"#;

        let bundle: IdentityBundle = serde_json::from_str(json).unwrap();

        assert_eq!(bundle.identity_did, "did:keri:abc123");
        assert_eq!(bundle.public_key_hex, "112233");
        assert!(bundle.attestation_chain.is_empty());
    }

    #[test]
    fn identity_bundle_roundtrips() {
        use crate::types::DeviceDID;

        let attestation = Attestation {
            version: 1,
            rid: ResourceId::new("test-rid"),
            issuer: IdentityDID::new("did:key:issuer"),
            subject: DeviceDID::new("did:key:subject".to_string()),
            device_public_key: Ed25519PublicKey::from_bytes([0u8; 32]),
            identity_signature: Ed25519Signature::empty(),
            device_signature: Ed25519Signature::empty(),
            revoked_at: None,
            expires_at: None,
            timestamp: None,
            note: None,
            payload: None,
            role: None,
            capabilities: vec![],
            delegated_by: None,
            signer_type: None,
        };

        let original = IdentityBundle {
            identity_did: "did:keri:example".to_string(),
            public_key_hex: "deadbeef".to_string(),
            attestation_chain: vec![attestation],
            bundle_timestamp: DateTime::parse_from_rfc3339("2099-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            max_valid_for_secs: 86400,
        };

        let json = serde_json::to_string(&original).unwrap();
        let deserialized: IdentityBundle = serde_json::from_str(&json).unwrap();

        assert_eq!(original.identity_did, deserialized.identity_did);
        assert_eq!(original.public_key_hex, deserialized.public_key_hex);
        assert_eq!(
            original.attestation_chain.len(),
            deserialized.attestation_chain.len()
        );
    }
}
