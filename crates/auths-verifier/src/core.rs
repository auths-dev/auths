//! Core attestation types and canonical serialization.

use crate::error::AttestationError;
use crate::types::{CanonicalDid, IdentityDID};
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

pub use auths_keri::capability::{
    Capability, CapabilityError, MANAGE_MEMBERS, ROTATE_KEYS, SIGN_COMMIT, SIGN_RELEASE,
};

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
// TypedSignature newtype (fn-114: was Ed25519Signature)
// =============================================================================

/// Attestation schema version.
///
/// Bumped to 2 in fn-114.15 as part of the curve-agnostic refactor (hard break,
/// pre-launch posture). Attestations serialized under older versions are not
/// readable — fn-114 has no v1 tolerant reader by design.
pub const ATTESTATION_VERSION: u32 = 2;

/// A validated 64-byte signature. Curve is determined by the companion
/// [`DevicePublicKey`] — both Ed25519 and ECDSA P-256 r||s are 64 bytes.
///
/// Previously named `Ed25519Signature`. The new name reflects that the byte
/// container is curve-agnostic; the receiver dispatches verify by looking at
/// the associated key's curve. If/when a curve with a different signature
/// length joins the workspace (e.g. ML-DSA-44 at 2420 bytes), this type
/// graduates to an enum variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedSignature([u8; 64]);

/// Transitional alias for pre-fn-114 callers. Removed in fn-114.40.
pub type Ed25519Signature = TypedSignature;

impl TypedSignature {
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

impl Default for TypedSignature {
    fn default() -> Self {
        Self::empty()
    }
}

impl std::fmt::Display for TypedSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl AsRef<[u8]> for TypedSignature {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for TypedSignature {
    fn schema_name() -> String {
        "TypedSignature".to_owned()
    }

    fn json_schema(_gen: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::String.into()),
            format: Some("hex".to_owned()),
            metadata: Some(Box::new(schemars::schema::Metadata {
                description: Some(
                    "Curve-agnostic 64-byte signature (Ed25519 or P-256 r||s, hex-encoded). \
                     Curve is determined by the companion DevicePublicKey."
                        .to_owned(),
                ),
                ..Default::default()
            })),
            ..Default::default()
        }
        .into()
    }
}

impl serde::Serialize for TypedSignature {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> serde::Deserialize<'de> for TypedSignature {
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

/// A device public key carrying its curve type explicitly.
///
/// Curve is stored alongside the raw key bytes so dispatch never relies on
/// key length — adding a new curve that shares a byte length (e.g. secp256k1,
/// also 33 bytes compressed) won't break existing match arms.
///
/// Accepted byte lengths per curve:
/// - Ed25519: 32
/// - P-256: 33 (compressed SEC1) or 65 (uncompressed SEC1)
#[derive(Debug, Clone)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct DevicePublicKey {
    #[cfg_attr(feature = "schema", schemars(skip))]
    curve: auths_crypto::CurveType,
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    bytes: Vec<u8>,
}

impl DevicePublicKey {
    /// Canonical SEC1 bytes for equality + hashing. P-256 is normalized to its 33-byte
    /// compressed form, so two encodings of the *same point* compare equal — the SSH
    /// wire format is 65-byte uncompressed while the KEL/CESR form is 33-byte compressed.
    /// Pure byte math: a compressed point is `[0x02|0x03 by Y-parity] || X`, and the
    /// Y-parity is the uncompressed point's final-byte LSB. Ed25519 is unchanged.
    fn canonical_sec1(&self) -> std::borrow::Cow<'_, [u8]> {
        if self.curve == auths_crypto::CurveType::P256
            && self.bytes.len() == 65
            && self.bytes[0] == 0x04
        {
            let mut compressed = vec![0u8; 33];
            compressed[0] = if self.bytes[64] & 1 == 0 { 0x02 } else { 0x03 };
            compressed[1..].copy_from_slice(&self.bytes[1..33]);
            std::borrow::Cow::Owned(compressed)
        } else {
            std::borrow::Cow::Borrowed(&self.bytes)
        }
    }
}

impl PartialEq for DevicePublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.curve == other.curve && self.canonical_sec1() == other.canonical_sec1()
    }
}

impl Eq for DevicePublicKey {}

impl std::hash::Hash for DevicePublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.curve.hash(state);
        self.canonical_sec1().hash(state);
    }
}

/// Error returned when constructing a `DevicePublicKey` with invalid key material.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidKeyError {
    /// The byte length is wrong for the specified curve.
    #[error("invalid key length for {curve}: expected {expected}, got {actual}")]
    InvalidLength {
        /// The curve that was specified.
        curve: auths_crypto::CurveType,
        /// The expected length(s) as a human-readable string.
        expected: &'static str,
        /// The actual byte count.
        actual: usize,
    },
}

impl DevicePublicKey {
    /// Create from a curve type and raw bytes, validating length per curve.
    ///
    /// Args:
    /// * `curve`: Which elliptic curve this key belongs to.
    /// * `bytes`: Raw public key bytes.
    ///
    /// Usage:
    /// ```ignore
    /// let pk = DevicePublicKey::try_new(CurveType::Ed25519, &key_bytes)?;
    /// ```
    pub fn try_new(curve: auths_crypto::CurveType, bytes: &[u8]) -> Result<Self, InvalidKeyError> {
        let valid = match curve {
            auths_crypto::CurveType::Ed25519 => bytes.len() == 32,
            auths_crypto::CurveType::P256 => bytes.len() == 33 || bytes.len() == 65,
        };
        if !valid {
            return Err(InvalidKeyError::InvalidLength {
                curve,
                expected: match curve {
                    auths_crypto::CurveType::Ed25519 => "32",
                    auths_crypto::CurveType::P256 => "33 or 65",
                },
                actual: bytes.len(),
            });
        }
        Ok(Self {
            curve,
            bytes: bytes.to_vec(),
        })
    }

    /// Create an Ed25519 device key from raw 32-byte key.
    pub fn ed25519(bytes: &[u8; 32]) -> Self {
        Self {
            curve: auths_crypto::CurveType::Ed25519,
            bytes: bytes.to_vec(),
        }
    }

    /// Create a P-256 device key from raw SEC1 bytes (33 compressed or 65 uncompressed).
    ///
    /// Returns `Err` if `bytes` is not 33 or 65 bytes.
    pub fn p256(bytes: &[u8]) -> Result<Self, InvalidKeyError> {
        Self::try_new(auths_crypto::CurveType::P256, bytes)
    }

    /// Returns the curve type.
    pub fn curve(&self) -> auths_crypto::CurveType {
        self.curve
    }

    /// Returns the raw key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns true if all bytes are zero.
    pub fn is_zero(&self) -> bool {
        self.bytes.iter().all(|&b| b == 0)
    }

    /// Returns the byte length.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns true if empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Verify a signature against this key, dispatching on curve.
    ///
    /// This is the single canonical verify method — every caller that holds
    /// a `DevicePublicKey` should call this rather than branching on curve
    /// themselves. Adding a new curve means updating this one impl; the
    /// compiler then flags every call site still assuming only Ed25519.
    ///
    /// Args:
    /// * `message`: Payload bytes that were signed.
    /// * `signature`: Raw signature bytes (64 for Ed25519 / P-256).
    /// * `provider`: Pluggable crypto provider (`RingCryptoProvider` native,
    ///   `WebCryptoProvider` wasm) — used for Ed25519. P-256 routes through
    ///   `RingCryptoProvider::p256_verify` on native.
    ///
    /// Usage:
    /// ```ignore
    /// issuer_pk.verify(&payload, &signature, provider).await?;
    /// ```
    pub async fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        provider: &dyn auths_crypto::CryptoProvider,
    ) -> Result<(), SignatureVerifyError> {
        let result = match self.curve {
            auths_crypto::CurveType::Ed25519 => {
                provider
                    .verify_ed25519(&self.bytes, message, signature)
                    .await
            }
            auths_crypto::CurveType::P256 => {
                provider.verify_p256(&self.bytes, message, signature).await
            }
        };
        result.map_err(|e| SignatureVerifyError::VerificationFailed(e.to_string()))
    }
}

/// Error returned by the typed ingestion helpers
/// [`decode_public_key_hex`] / [`decode_public_key_bytes`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PublicKeyDecodeError {
    /// The input hex string failed to decode.
    #[error("invalid hex: {0}")]
    InvalidHex(String),

    /// The decoded byte length does not match any supported curve (32 Ed25519,
    /// 33 or 65 P-256).
    #[error("invalid public key length {len} — expected 32 (Ed25519) or 33/65 (P-256)")]
    InvalidLength {
        /// Number of bytes supplied.
        len: usize,
    },

    /// `DevicePublicKey::try_new` rejected the bytes even after curve
    /// inference succeeded.
    #[error("DevicePublicKey validation failed: {0}")]
    Validation(String),
}

/// Decode a hex-encoded public key string into a typed, curve-tagged
/// `DevicePublicKey`.
///
/// Intended for external ingestion boundaries ONLY (FFI hex strings, WASM
/// entry points, `--signer-key` CLI flags). Internal code threads
/// `DevicePublicKey` end-to-end.
///
/// Args:
/// * `hex_str`: Hex-encoded public key (32, 33, or 65 bytes after decode).
/// * `curve`: The curve type for the key.
///
/// Usage:
/// ```ignore
/// let pk = decode_public_key_hex(user_supplied_hex, CurveType::P256)?;
/// issuer_pk.verify(msg, sig, provider).await?;
/// ```
pub fn decode_public_key_hex(
    hex_str: &str,
    curve: auths_crypto::CurveType,
) -> Result<DevicePublicKey, PublicKeyDecodeError> {
    let bytes =
        hex::decode(hex_str.trim()).map_err(|e| PublicKeyDecodeError::InvalidHex(e.to_string()))?;
    decode_public_key_bytes(&bytes, curve)
}

/// Decode raw public key bytes into a typed, curve-tagged `DevicePublicKey`
/// using an explicit curve tag.
///
/// Args:
/// * `bytes`: Raw public key bytes.
/// * `curve`: The curve type for the key.
///
/// Usage:
/// ```ignore
/// let pk = decode_public_key_bytes(&ffi_bytes[..len], CurveType::P256)?;
/// ```
pub fn decode_public_key_bytes(
    bytes: &[u8],
    curve: auths_crypto::CurveType,
) -> Result<DevicePublicKey, PublicKeyDecodeError> {
    DevicePublicKey::try_new(curve, bytes)
        .map_err(|e| PublicKeyDecodeError::Validation(e.to_string()))
}

/// Error returned by [`DevicePublicKey::verify`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SignatureVerifyError {
    /// Underlying signature check failed. Argument contains provider-specific detail.
    #[error("signature verification failed: {0}")]
    VerificationFailed(String),

    /// The target platform does not support the requested curve (e.g. WASM
    /// without the `native` feature bundled).
    #[error("{0}")]
    UnsupportedOnTarget(String),
}

impl From<Ed25519PublicKey> for DevicePublicKey {
    fn from(pk: Ed25519PublicKey) -> Self {
        Self {
            curve: auths_crypto::CurveType::Ed25519,
            bytes: pk.as_bytes().to_vec(),
        }
    }
}

impl Serialize for DevicePublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("DevicePublicKey", 2)?;
        st.serialize_field("curve", &self.curve.to_string())?;
        st.serialize_field("key", &hex::encode(&self.bytes))?;
        st.end()
    }
}

impl<'de> Deserialize<'de> for DevicePublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // Accept both formats:
        // - New: {"curve": "p256", "key": "hex..."}
        // - Legacy: "hex..." (bare string, infer curve from length)
        let value = serde_json::Value::deserialize(d)?;

        if let Some(s) = value.as_str() {
            // Legacy format: bare hex string
            if s.is_empty() {
                return Ok(Self::default());
            }
            let bytes = hex::decode(s)
                .map_err(|e| serde::de::Error::custom(format!("invalid hex: {e}")))?;
            let curve = match bytes.len() {
                32 => auths_crypto::CurveType::Ed25519,
                33 | 65 => auths_crypto::CurveType::P256,
                n => {
                    return Err(serde::de::Error::custom(format!(
                        "invalid device public key length: {n}"
                    )));
                }
            };
            return Self::try_new(curve, &bytes)
                .map_err(|e| serde::de::Error::custom(e.to_string()));
        }

        // New format: {"curve": "...", "key": "..."}
        let curve_str = value["curve"]
            .as_str()
            .ok_or_else(|| serde::de::Error::custom("missing 'curve' field"))?;
        let key_hex = value["key"]
            .as_str()
            .ok_or_else(|| serde::de::Error::custom("missing 'key' field"))?;

        let curve = match curve_str {
            "ed25519" => auths_crypto::CurveType::Ed25519,
            "p256" => auths_crypto::CurveType::P256,
            other => {
                return Err(serde::de::Error::custom(format!("unknown curve: {other}")));
            }
        };
        if key_hex.is_empty() {
            return Err(serde::de::Error::custom("empty key"));
        }
        let bytes = hex::decode(key_hex)
            .map_err(|e| serde::de::Error::custom(format!("invalid hex: {e}")))?;
        Self::try_new(curve, &bytes).map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

impl Default for DevicePublicKey {
    fn default() -> Self {
        Self {
            curve: auths_crypto::CurveType::Ed25519,
            bytes: vec![0u8; 32],
        }
    }
}

impl fmt::Display for DevicePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.curve, hex::encode(&self.bytes))
    }
}

// =============================================================================
// Signature algorithm enum (for configurable checkpoint verification)
// =============================================================================

/// Signature algorithm used by a transparency log for checkpoint signing.
///
/// Each log in a `TrustConfig` specifies which algorithm its checkpoints use.
/// The verifier dispatches on this when checking checkpoint signatures.
///
/// Usage:
/// ```ignore
/// match trust_root.signature_algorithm {
///     SignatureAlgorithm::Ed25519 => verify_ed25519(..),
///     SignatureAlgorithm::EcdsaP256 => verify_ecdsa_p256(..),
/// }
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureAlgorithm {
    /// Ed25519 (RFC 8032). Default for auths-native logs.
    #[default]
    Ed25519,
    /// ECDSA with NIST P-256 and SHA-256. Used by Rekor production shard.
    EcdsaP256,
}

impl fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ed25519 => f.write_str("ed25519"),
            Self::EcdsaP256 => f.write_str("ecdsa_p256"),
        }
    }
}

// =============================================================================
// ECDSA P-256 types (for Rekor checkpoint verification)
// =============================================================================

/// A DER-encoded ECDSA P-256 public key (PKIX SubjectPublicKeyInfo).
///
/// Stores the full DER encoding so `ring::signature::UnparsedPublicKey`
/// can consume it directly.
///
/// Usage:
/// ```ignore
/// let pk = EcdsaP256PublicKey::from_der(&der_bytes)?;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaP256PublicKey(Vec<u8>);

impl EcdsaP256PublicKey {
    /// Creates from DER-encoded PKIX SubjectPublicKeyInfo bytes.
    ///
    /// Performs minimal validation: checks the ASN.1 OID prefix for P-256
    /// (`06 08 2a 86 48 ce 3d 03 01 07`).
    pub fn from_der(der: &[u8]) -> Result<Self, EcdsaP256Error> {
        // PKIX P-256 key is typically 91 bytes (SEQUENCE { AlgorithmIdentifier, BIT STRING })
        // The AlgorithmIdentifier contains OID 1.2.840.10045.3.1.7 (P-256)
        const P256_OID: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
        if der.len() < 26 {
            return Err(EcdsaP256Error::InvalidKey(
                "DER too short for P-256 PKIX key".into(),
            ));
        }
        if !der.windows(P256_OID.len()).any(|w| w == P256_OID) {
            return Err(EcdsaP256Error::InvalidKey(
                "missing P-256 OID in PKIX key".into(),
            ));
        }
        Ok(Self(der.to_vec()))
    }

    /// Returns the raw DER bytes.
    pub fn as_der(&self) -> &[u8] {
        &self.0
    }

    /// Returns the public key as a raw uncompressed SEC1 point
    /// (`0x04 || X || Y`, 65 bytes).
    ///
    /// This is the form `ring`'s `ECDSA_P256_SHA256_ASN1` verifier consumes — it
    /// does NOT accept the DER SPKI returned by [`Self::as_der`]. For a
    /// well-formed P-256 SPKI the point is the trailing 65 bytes (the BIT STRING
    /// value, sans its `0x00` unused-bits prefix). Returns `None` for a
    /// compressed or malformed key.
    ///
    /// Usage:
    /// ```ignore
    /// let point = key.as_sec1_uncompressed().ok_or(/* malformed */)?;
    /// let verifier = UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, point);
    /// ```
    pub fn as_sec1_uncompressed(&self) -> Option<&[u8]> {
        let start = self.0.len().checked_sub(65)?;
        let point = &self.0[start..];
        (point[0] == 0x04).then_some(point)
    }
}

impl Serialize for EcdsaP256PublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use base64::Engine;
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for EcdsaP256PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use base64::Engine;
        let s = String::deserialize(d)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&s)
            .map_err(|e| serde::de::Error::custom(format!("invalid base64: {e}")))?;
        Self::from_der(&bytes).map_err(serde::de::Error::custom)
    }
}

/// A DER-encoded ECDSA P-256 signature.
///
/// ECDSA signatures are variable-length ASN.1 DER (typically 70-72 bytes).
///
/// Usage:
/// ```ignore
/// let sig = EcdsaP256Signature::from_der(&der_bytes)?;
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaP256Signature(Vec<u8>);

impl EcdsaP256Signature {
    /// Creates from DER-encoded signature bytes.
    pub fn from_der(der: &[u8]) -> Result<Self, EcdsaP256Error> {
        // Minimal check: ASN.1 SEQUENCE tag (0x30)
        if der.is_empty() || der[0] != 0x30 {
            return Err(EcdsaP256Error::InvalidSignature(
                "not an ASN.1 SEQUENCE".into(),
            ));
        }
        Ok(Self(der.to_vec()))
    }

    /// Returns the raw DER bytes.
    pub fn as_der(&self) -> &[u8] {
        &self.0
    }
}

impl Serialize for EcdsaP256Signature {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use base64::Engine;
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for EcdsaP256Signature {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use base64::Engine;
        let s = String::deserialize(d)?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&s)
            .map_err(|e| serde::de::Error::custom(format!("invalid base64: {e}")))?;
        Self::from_der(&bytes).map_err(serde::de::Error::custom)
    }
}

/// Errors from ECDSA P-256 operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum EcdsaP256Error {
    /// Invalid DER-encoded public key.
    #[error("invalid ECDSA P-256 key: {0}")]
    InvalidKey(String),
    /// Invalid DER-encoded signature.
    #[error("invalid ECDSA P-256 signature: {0}")]
    InvalidSignature(String),
}

/// An identity bundle for stateless verification in CI/CD environments.
///
/// Contains all the information needed to verify commit signatures without
/// requiring access to the identity repository or daemon.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct IdentityBundle {
    /// The DID of the identity (e.g., `"did:keri:..."`)
    pub identity_did: IdentityDID,
    /// The public key in hex format for signature verification.
    pub public_key_hex: PublicKeyHex,
    /// Curve of `public_key_hex`. Carried in-band so verifiers never infer
    /// curve from byte length. Defaults to P-256 when absent (older bundles
    /// shipped before this field existed).
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub curve: auths_crypto::CurveType,
    /// Chain of attestations linking the signing key to the identity
    pub attestation_chain: Vec<Attestation>,
    /// The identity's KEL events, oldest first (parsed at the deserialize
    /// boundary, not held as loose JSON). Carried so KEL-native commit
    /// verification stays stateless on CI runners with no identity store. Empty
    /// in bundles exported before this field existed. Wire form is unchanged — a
    /// JSON array of event objects.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kel: Vec<auths_keri::Event>,
    /// The CESR signature attachment (hex) for each `kel` event, in the same
    /// order. Lets a stateless verifier AUTHENTICATE the bundle's KEL — verify
    /// each event is signed by the controlling key-state — not just replay it
    /// structurally (RT-002). A bundle whose `kel_attachments` length differs
    /// from `kel`, or whose signatures don't verify, fails closed. Empty in
    /// pre-RT-002 bundles.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub kel_attachments: Vec<String>,
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
    /// DID of the issuing identity (can be `did:keri:` or `did:key:`).
    pub issuer: CanonicalDid,
    /// DID of the attested subject (device `did:key:` or identity `did:keri:`).
    pub subject: CanonicalDid,
    /// Device public key (32 bytes Ed25519 or 33 bytes P-256 compressed, hex-encoded in JSON).
    pub device_public_key: DevicePublicKey,
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

    /// Git commit SHA (for commit signing attestations).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_sha: Option<String>,

    /// Git commit message (for commit signing attestations).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_message: Option<String>,

    /// Git commit author (for commit signing attestations).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,

    /// OIDC binding information (issuer, subject, audience, expiration).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc_binding: Option<OidcBinding>,

    /// DID of the attestation that delegated authority (for chain tracking).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated_by: Option<CanonicalDid>,

    /// The type of entity that produced this signature (human, agent, workload).
    /// Included in the canonical JSON before signing — the signature covers this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_type: Option<SignerType>,

    /// Unsigned environment claim for gateway-level verification via `auths-env`.
    /// Excluded from `CanonicalAttestationData` — does not affect signatures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment_claim: Option<Value>,
}

/// OIDC token binding information for machine identity attestations.
///
/// Proves that the attestation was created by a CI/CD workload with a specific
/// OIDC token. Contains the issuer, subject, audience, and expiration so verifiers
/// can reconstruct the identity without needing the ephemeral private key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct OidcBinding {
    /// OIDC token issuer (e.g., "https://token.actions.githubusercontent.com").
    pub issuer: String,
    /// Token subject (unique workload identifier).
    pub subject: String,
    /// Expected audience.
    pub audience: String,
    /// Token expiration timestamp (Unix timestamp).
    pub token_exp: i64,
    /// CI/CD platform (e.g., "github", "gitlab", "circleci").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    /// JTI for replay detection (if available).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// Platform-normalized claims (e.g., repo, actor, run_id for GitHub).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub normalized_claims: Option<serde_json::Map<String, serde_json::Value>>,
}

/// The type of entity that produced a signature.
///
/// Duplicated here (also in `auths-policy`) because `auths-verifier` is a
/// standalone minimal-dependency crate that cannot depend on `auths-policy`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[non_exhaustive]
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
/// - Verification functions (`verify_with_keys`, `verify_chain`)
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
    pub issuer: &'a CanonicalDid,
    /// DID of the attested subject.
    pub subject: &'a CanonicalDid,
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

    /// DID of the delegating attestation (included in signed envelope).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegated_by: Option<&'a CanonicalDid>,
    /// Type of signer (included in signed envelope).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer_type: Option<&'a SignerType>,
    /// Git commit SHA for provenance binding (included in signed envelope).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit_sha: Option<&'a str>,
    /// OIDC workload binding (included in signed envelope when present, so a
    /// verifier can trust the claims it joins against an org policy).
    /// `skip_serializing_if` keeps canonical bytes for binding-less
    /// attestations byte-identical to the pre-binding shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oidc_binding: Option<&'a OidcBinding>,
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

    /// Returns the canonical subset of fields that signatures are computed over.
    ///
    /// Args:
    /// * `&self`: The attestation to extract canonical data from.
    ///
    /// Usage:
    /// ```ignore
    /// let canonical = attestation.canonical_data();
    /// let bytes = canonicalize_attestation_data(&canonical)?;
    /// ```
    pub fn canonical_data(&self) -> CanonicalAttestationData<'_> {
        CanonicalAttestationData {
            version: self.version,
            rid: &self.rid,
            issuer: &self.issuer,
            subject: &self.subject,
            device_public_key: self.device_public_key.as_bytes(),
            payload: &self.payload,
            timestamp: &self.timestamp,
            expires_at: &self.expires_at,
            revoked_at: &self.revoked_at,
            note: &self.note,
            delegated_by: self.delegated_by.as_ref(),
            signer_type: self.signer_type.as_ref(),
            commit_sha: self.commit_sha.as_deref(),
            oidc_binding: self.oidc_binding.as_ref(),
        }
    }

    /// Formats the attestation contents for debug or inspection purposes.
    pub fn to_debug_string(&self) -> String {
        format!(
            "RID: {}\nIssuer DID: {}\nSubject DID: {}\nDevice PK: {}\nIdentity Sig: {}\nDevice Sig: {}\nRevoked At: {:?}\nExpires: {:?}\nNote: {:?}",
            self.rid,
            self.issuer,
            self.subject, // CanonicalDid implements Display
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
    pub policy_id: PolicyId,

    /// Scope of operations this policy covers (optional)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<Capability>,

    /// Ceremony coordination endpoint (e.g., WebSocket URL for signing rounds)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ceremony_endpoint: Option<String>,
}

impl ThresholdPolicy {
    /// Create a new threshold policy
    pub fn new(threshold: u8, signers: Vec<String>, policy_id: impl Into<PolicyId>) -> Self {
        Self {
            threshold,
            signers,
            policy_id: policy_id.into(),
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

// =============================================================================
// CommitOid newtype (validated)
// =============================================================================

/// Error type for `CommitOid` construction.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CommitOidError {
    /// The string is empty.
    #[error("commit OID is empty")]
    Empty,
    /// The string length is not 40 (SHA-1) or 64 (SHA-256).
    #[error("expected 40 or 64 hex chars, got {0}")]
    InvalidLength(usize),
    /// The string contains non-hex characters.
    #[error("invalid hex character in commit OID")]
    InvalidHex,
}

/// A validated Git commit object identifier (SHA-1 or SHA-256 hex string).
///
/// Accepts exactly 40 lowercase hex characters (SHA-1) or 64 (SHA-256).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[repr(transparent)]
#[serde(try_from = "String")]
pub struct CommitOid(String);

impl CommitOid {
    /// Parses and validates a commit OID string.
    ///
    /// Args:
    /// * `raw`: A hex string that must be exactly 40 or 64 lowercase hex characters.
    ///
    /// Usage:
    /// ```ignore
    /// let oid = CommitOid::parse("a".repeat(40))?;
    /// ```
    pub fn parse(raw: &str) -> Result<Self, CommitOidError> {
        let s = raw.trim().to_lowercase();
        if s.is_empty() {
            return Err(CommitOidError::Empty);
        }
        if s.len() != 40 && s.len() != 64 {
            return Err(CommitOidError::InvalidLength(s.len()));
        }
        if !s.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(CommitOidError::InvalidHex);
        }
        Ok(Self(s))
    }

    /// Creates a `CommitOid` without validation.
    ///
    /// Only use at deserialization boundaries where the value was previously validated.
    pub fn new_unchecked(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Returns the inner string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes self and returns the inner `String`.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for CommitOid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for CommitOid {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CommitOid {
    type Error = CommitOidError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

impl TryFrom<&str> for CommitOid {
    type Error = CommitOidError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

impl FromStr for CommitOid {
    type Err = CommitOidError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl From<CommitOid> for String {
    fn from(oid: CommitOid) -> Self {
        oid.0
    }
}

impl<'de> Deserialize<'de> for CommitOid {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

// =============================================================================
// PublicKeyHex newtype (validated)
// =============================================================================

/// Error type for `PublicKeyHex` construction.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PublicKeyHexError {
    /// The hex string has the wrong length (not 64 or 66 chars).
    #[error("expected 64 (Ed25519) or 66 (P-256) hex chars, got {0} chars")]
    InvalidLength(usize),
    /// The string contains non-hex characters.
    #[error("invalid hex: {0}")]
    InvalidHex(String),
}

/// A validated hex-encoded public key (64 hex chars for Ed25519, 66 for P-256 compressed).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[repr(transparent)]
#[serde(try_from = "String")]
pub struct PublicKeyHex(String);

impl PublicKeyHex {
    /// Parses and validates a hex-encoded public key string.
    ///
    /// Args:
    /// * `raw`: A 64-character hex string encoding 32 bytes.
    ///
    /// Usage:
    /// ```ignore
    /// let pk = PublicKeyHex::parse("ab".repeat(32))?;
    /// ```
    pub fn parse(raw: &str) -> Result<Self, PublicKeyHexError> {
        let s = raw.trim().to_lowercase();
        let bytes = hex::decode(&s).map_err(|e| PublicKeyHexError::InvalidHex(e.to_string()))?;
        if bytes.len() != 32 && bytes.len() != 33 {
            return Err(PublicKeyHexError::InvalidLength(s.len()));
        }
        Ok(Self(s))
    }

    /// Creates a `PublicKeyHex` without validation.
    ///
    /// Only use at deserialization boundaries where the value was previously validated.
    pub fn new_unchecked(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Returns the inner string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes self and returns the inner `String`.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Display for PublicKeyHex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for PublicKeyHex {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for PublicKeyHex {
    type Error = PublicKeyHexError;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        Self::parse(&s)
    }
}

impl TryFrom<&str> for PublicKeyHex {
    type Error = PublicKeyHexError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

impl FromStr for PublicKeyHex {
    type Err = PublicKeyHexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl From<PublicKeyHex> for String {
    fn from(pk: PublicKeyHex) -> Self {
        pk.0
    }
}

impl<'de> Deserialize<'de> for PublicKeyHex {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

// =============================================================================
// PolicyId newtype (unvalidated)
// =============================================================================

/// An opaque policy identifier.
///
/// No validation — wraps any `String`. Use where policy IDs are passed around
/// without needing to inspect their content.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(transparent)]
pub struct PolicyId(String);

impl PolicyId {
    /// Creates a new PolicyId.
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Returns the inner string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for PolicyId {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PolicyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for PolicyId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for PolicyId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl PartialEq<str> for PolicyId {
    fn eq(&self, other: &str) -> bool {
        self.0 == other
    }
}

impl PartialEq<&str> for PolicyId {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::AttestationBuilder;

    // Tests for Attestation delegation field

    #[test]
    fn attestation_old_json_without_delegated_by_deserializes() {
        // Simulates an attestation JSON without the delegated_by field.
        let old_json = r#"{
            "version": 1,
            "rid": "test-rid",
            "issuer": "did:keri:Eissuer",
            "subject": "did:key:zSubject",
            "device_public_key": "0102030405060708091011121314151617181920212223242526272829303132",
            "identity_signature": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "device_signature": "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "revoked_at": null,
            "timestamp": null
        }"#;

        let att: Attestation = serde_json::from_str(old_json).unwrap();

        assert_eq!(att.delegated_by, None);
    }

    #[test]
    fn attestation_delegated_by_serializes_correctly() {
        let att = AttestationBuilder::default()
            .rid("test-rid")
            .issuer("did:keri:Eissuer")
            .subject("did:key:zSubject")
            .delegated_by(Some(CanonicalDid::new_unchecked("did:keri:Edelegator")))
            .build();

        let json = serde_json::to_string(&att).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed["delegated_by"], "did:keri:Edelegator");
    }

    #[test]
    fn attestation_omits_delegated_by_when_absent() {
        let att = AttestationBuilder::default()
            .rid("test-rid")
            .issuer("did:keri:Eissuer")
            .subject("did:key:zSubject")
            .build();

        let json = serde_json::to_string(&att).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(parsed.get("delegated_by").is_none());
    }

    #[test]
    fn attestation_delegated_by_roundtrips() {
        let original = AttestationBuilder::default()
            .rid("test-rid")
            .issuer("did:keri:Eissuer")
            .subject("did:key:zSubject")
            .delegated_by(Some(CanonicalDid::new_unchecked("did:keri:Eadmin")))
            .build();

        let json = serde_json::to_string(&original).unwrap();
        let deserialized: Attestation = serde_json::from_str(&json).unwrap();

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
            identity_did: IdentityDID::new_unchecked("did:keri:test123"),
            public_key_hex: PublicKeyHex::new_unchecked("aabbccdd"),
            curve: Default::default(),
            attestation_chain: vec![],
            kel: vec![],
            kel_attachments: vec![],
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
            "public_key_hex": "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            "attestation_chain": [],
            "bundle_timestamp": "2099-01-01T00:00:00Z",
            "max_valid_for_secs": 86400
        }"#;

        let bundle: IdentityBundle = serde_json::from_str(json).unwrap();

        assert_eq!(bundle.identity_did.as_str(), "did:keri:abc123");
        assert_eq!(
            bundle.public_key_hex.as_str(),
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        );
        assert!(bundle.attestation_chain.is_empty());
    }

    #[test]
    fn identity_bundle_roundtrips() {
        let attestation = AttestationBuilder::default()
            .rid("test-rid")
            .issuer("did:keri:Eissuer")
            .subject("did:key:zSubject")
            .build();

        let original = IdentityBundle {
            identity_did: IdentityDID::new_unchecked("did:keri:Eexample"),
            public_key_hex: PublicKeyHex::new_unchecked(
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            ),
            curve: Default::default(),
            attestation_chain: vec![attestation],
            kel: vec![],
            kel_attachments: vec![],
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

#[cfg(test)]
mod decode_public_key_tests {
    use super::*;

    #[test]
    fn hex_ed25519_32_bytes() {
        let hex = "00".repeat(32);
        let pk = decode_public_key_hex(&hex, auths_crypto::CurveType::Ed25519).unwrap();
        assert_eq!(pk.curve(), auths_crypto::CurveType::Ed25519);
        assert_eq!(pk.len(), 32);
    }

    #[test]
    fn hex_p256_33_bytes_compressed() {
        // Need a valid-ish compressed SEC1 for try_new to accept: starts with 0x02 or 0x03
        let mut bytes = [0u8; 33];
        bytes[0] = 0x02;
        let hex = hex::encode(bytes);
        let pk = decode_public_key_hex(&hex, auths_crypto::CurveType::P256).unwrap();
        assert_eq!(pk.curve(), auths_crypto::CurveType::P256);
        assert_eq!(pk.len(), 33);
    }

    #[test]
    fn bytes_p256_65_uncompressed() {
        let mut bytes = [0u8; 65];
        bytes[0] = 0x04;
        let pk = decode_public_key_bytes(&bytes, auths_crypto::CurveType::P256).unwrap();
        assert_eq!(pk.curve(), auths_crypto::CurveType::P256);
        assert_eq!(pk.len(), 65);
    }

    #[test]
    fn rejects_validation_error() {
        let err = decode_public_key_bytes(&[0u8; 50], auths_crypto::CurveType::P256).unwrap_err();
        assert!(matches!(err, PublicKeyDecodeError::Validation(_)));
    }

    #[test]
    fn rejects_malformed_hex() {
        let err = decode_public_key_hex("zz", auths_crypto::CurveType::P256).unwrap_err();
        assert!(matches!(err, PublicKeyDecodeError::InvalidHex(_)));
    }
}
