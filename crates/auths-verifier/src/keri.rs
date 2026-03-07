//! Stateless KERI KEL verification.
//!
//! This module provides verification of KERI event logs without requiring
//! Git or filesystem access. Events are provided as input, making it
//! suitable for WASM and FFI consumers.

use std::borrow::Borrow;
use std::fmt;

use auths_crypto::CryptoProvider;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize, Serializer};
use subtle::ConstantTimeEq;

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

// ── KERI Verification Errors ────────────────────────────────────────────────

/// Errors specific to KERI KEL verification.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
pub enum KeriVerifyError {
    /// The computed SAID does not match the SAID stored in the event.
    #[error("Invalid SAID: expected {expected}, got {actual}")]
    InvalidSaid {
        /// The SAID computed from the event content.
        expected: Said,
        /// The SAID found in the event field.
        actual: Said,
    },
    /// The `p` field of an event does not match the SAID of the preceding event.
    #[error("Broken chain at seq {sequence}: references {referenced}, previous was {actual}")]
    BrokenChain {
        /// Sequence number of the event with the broken link.
        sequence: u64,
        /// The SAID referenced by the `p` field.
        referenced: Said,
        /// The SAID of the actual preceding event.
        actual: Said,
    },
    /// Event sequence number does not follow the expected monotonic order.
    #[error("Invalid sequence: expected {expected}, got {actual}")]
    InvalidSequence {
        /// The expected sequence number.
        expected: u64,
        /// The sequence number found in the event.
        actual: u64,
    },
    /// The rotation key does not satisfy the pre-rotation commitment from the prior event.
    #[error("Pre-rotation commitment mismatch at sequence {sequence}")]
    CommitmentMismatch {
        /// Sequence number of the rotation event that failed commitment verification.
        sequence: u64,
    },
    /// Ed25519 signature verification failed.
    #[error("Signature verification failed at sequence {sequence}")]
    SignatureFailed {
        /// Sequence number of the event whose signature failed.
        sequence: u64,
    },
    /// The KEL's first event is not an inception (`icp`) event.
    #[error("First event must be inception")]
    NotInception,
    /// The KEL contains no events.
    #[error("Empty KEL")]
    EmptyKel,
    /// More than one inception event was found in the KEL.
    #[error("Multiple inception events")]
    MultipleInceptions,
    /// JSON serialization or deserialization failed.
    #[error("Serialization error: {0}")]
    Serialization(String),
    /// The key encoding prefix is unsupported or malformed.
    #[error("Invalid key encoding: {0}")]
    InvalidKey(String),
    /// The sequence number string cannot be parsed as a `u64`.
    #[error("Malformed sequence number: {raw:?}")]
    MalformedSequence {
        /// The raw sequence string that could not be parsed.
        raw: String,
    },
}

use auths_crypto::KeriPublicKey;

/// KERI event types for verification.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(tag = "t")]
pub enum KeriEvent {
    /// Inception event (`icp`) — creates the identity and establishes the first key.
    #[serde(rename = "icp")]
    Inception(IcpEvent),
    /// Rotation event (`rot`) — rotates to the pre-committed key.
    #[serde(rename = "rot")]
    Rotation(RotEvent),
    /// Interaction event (`ixn`) — anchors data without rotating keys.
    #[serde(rename = "ixn")]
    Interaction(IxnEvent),
}

impl Serialize for KeriEvent {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            KeriEvent::Inception(e) => e.serialize(serializer),
            KeriEvent::Rotation(e) => e.serialize(serializer),
            KeriEvent::Interaction(e) => e.serialize(serializer),
        }
    }
}

impl KeriEvent {
    /// Get the SAID of this event.
    pub fn said(&self) -> &Said {
        match self {
            KeriEvent::Inception(e) => &e.d,
            KeriEvent::Rotation(e) => &e.d,
            KeriEvent::Interaction(e) => &e.d,
        }
    }

    /// Get the signature of this event.
    pub fn signature(&self) -> &str {
        match self {
            KeriEvent::Inception(e) => &e.x,
            KeriEvent::Rotation(e) => &e.x,
            KeriEvent::Interaction(e) => &e.x,
        }
    }

    /// Get the sequence number of this event.
    pub fn sequence(&self) -> Result<u64, KeriVerifyError> {
        let s = match self {
            KeriEvent::Inception(e) => &e.s,
            KeriEvent::Rotation(e) => &e.s,
            KeriEvent::Interaction(e) => &e.s,
        };
        s.parse::<u64>()
            .map_err(|_| KeriVerifyError::MalformedSequence { raw: s.clone() })
    }
}

/// Inception event.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct IcpEvent {
    /// KERI version string (e.g. `"KERI10JSON"`).
    pub v: String,
    /// Self-Addressing Identifier (SAID) of this event.
    #[serde(default)]
    pub d: Said,
    /// KERI prefix — same as `d` for inception.
    pub i: Prefix,
    /// Sequence number (always `"0"` for inception).
    pub s: String,
    /// Signing key threshold.
    #[serde(default)]
    pub kt: String,
    /// Current signing keys (base64url-encoded with derivation prefix).
    pub k: Vec<String>,
    /// Next-key commitment threshold.
    #[serde(default)]
    pub nt: String,
    /// Next-key commitments (Blake3 hashes of the pre-rotation public keys).
    pub n: Vec<String>,
    /// Witness threshold.
    #[serde(default)]
    pub bt: String,
    /// Witness list (DIDs or URLs of witnesses).
    #[serde(default)]
    pub b: Vec<String>,
    /// Anchored seals (attached data digests).
    #[serde(default)]
    pub a: Vec<Seal>,
    /// Ed25519 signature over the canonical event body.
    #[serde(default)]
    pub x: String,
}

/// Spec field order: v, t, d, i, s, kt, k, nt, n, bt, b, a, x
impl Serialize for IcpEvent {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let field_count = 12 + (!self.d.is_empty() as usize) + (!self.x.is_empty() as usize);
        let mut map = serializer.serialize_map(Some(field_count))?;
        map.serialize_entry("v", &self.v)?;
        map.serialize_entry("t", "icp")?;
        if !self.d.is_empty() {
            map.serialize_entry("d", &self.d)?;
        }
        map.serialize_entry("i", &self.i)?;
        map.serialize_entry("s", &self.s)?;
        map.serialize_entry("kt", &self.kt)?;
        map.serialize_entry("k", &self.k)?;
        map.serialize_entry("nt", &self.nt)?;
        map.serialize_entry("n", &self.n)?;
        map.serialize_entry("bt", &self.bt)?;
        map.serialize_entry("b", &self.b)?;
        map.serialize_entry("a", &self.a)?;
        if !self.x.is_empty() {
            map.serialize_entry("x", &self.x)?;
        }
        map.end()
    }
}

/// Rotation event.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct RotEvent {
    /// KERI version string.
    pub v: String,
    /// SAID of this event.
    #[serde(default)]
    pub d: Said,
    /// KERI prefix of the identity being rotated.
    pub i: Prefix,
    /// Sequence number.
    pub s: String,
    /// SAID of the prior event (chain link).
    pub p: Said,
    /// Signing key threshold.
    #[serde(default)]
    pub kt: String,
    /// Current signing keys after rotation.
    pub k: Vec<String>,
    /// Next-key commitment threshold.
    #[serde(default)]
    pub nt: String,
    /// Next-key commitments for the subsequent rotation.
    pub n: Vec<String>,
    /// Witness threshold.
    #[serde(default)]
    pub bt: String,
    /// Witness list.
    #[serde(default)]
    pub b: Vec<String>,
    /// Anchored seals.
    #[serde(default)]
    pub a: Vec<Seal>,
    /// Ed25519 signature over the canonical event body.
    #[serde(default)]
    pub x: String,
}

/// Spec field order: v, t, d, i, s, p, kt, k, nt, n, bt, b, a, x
impl Serialize for RotEvent {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let field_count = 13 + (!self.d.is_empty() as usize) + (!self.x.is_empty() as usize);
        let mut map = serializer.serialize_map(Some(field_count))?;
        map.serialize_entry("v", &self.v)?;
        map.serialize_entry("t", "rot")?;
        if !self.d.is_empty() {
            map.serialize_entry("d", &self.d)?;
        }
        map.serialize_entry("i", &self.i)?;
        map.serialize_entry("s", &self.s)?;
        map.serialize_entry("p", &self.p)?;
        map.serialize_entry("kt", &self.kt)?;
        map.serialize_entry("k", &self.k)?;
        map.serialize_entry("nt", &self.nt)?;
        map.serialize_entry("n", &self.n)?;
        map.serialize_entry("bt", &self.bt)?;
        map.serialize_entry("b", &self.b)?;
        map.serialize_entry("a", &self.a)?;
        if !self.x.is_empty() {
            map.serialize_entry("x", &self.x)?;
        }
        map.end()
    }
}

/// Interaction event.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct IxnEvent {
    /// KERI version string.
    pub v: String,
    /// SAID of this event.
    #[serde(default)]
    pub d: Said,
    /// KERI prefix of the identity.
    pub i: Prefix,
    /// Sequence number.
    pub s: String,
    /// SAID of the prior event (chain link).
    pub p: Said,
    /// Anchored seals (e.g. attestation digests).
    pub a: Vec<Seal>,
    /// Ed25519 signature over the canonical event body.
    #[serde(default)]
    pub x: String,
}

/// Spec field order: v, t, d, i, s, p, a, x
impl Serialize for IxnEvent {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let field_count = 7 + (!self.d.is_empty() as usize) + (!self.x.is_empty() as usize);
        let mut map = serializer.serialize_map(Some(field_count))?;
        map.serialize_entry("v", &self.v)?;
        map.serialize_entry("t", "ixn")?;
        if !self.d.is_empty() {
            map.serialize_entry("d", &self.d)?;
        }
        map.serialize_entry("i", &self.i)?;
        map.serialize_entry("s", &self.s)?;
        map.serialize_entry("p", &self.p)?;
        map.serialize_entry("a", &self.a)?;
        if !self.x.is_empty() {
            map.serialize_entry("x", &self.x)?;
        }
        map.end()
    }
}

/// A seal anchors external data in a KERI event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Seal {
    /// Digest (SAID) of the anchored data.
    pub d: Said,
    /// Semantic type label (e.g. `"device-attestation"`).
    #[serde(rename = "type")]
    pub seal_type: String,
}

/// Result of KEL verification.
#[derive(Debug, Clone, Serialize)]
pub struct KeriKeyState {
    /// The KERI prefix
    pub prefix: Prefix,

    /// The current public key (raw bytes)
    #[serde(skip)]
    pub current_key: Vec<u8>,

    /// The current public key (encoded, e.g. "D..." base64url)
    pub current_key_encoded: String,

    /// The next-key commitment (if any)
    pub next_commitment: Option<String>,

    /// The current sequence number
    pub sequence: u64,

    /// Whether the identity is abandoned (no next commitment)
    pub is_abandoned: bool,

    /// The SAID of the last processed event
    pub last_event_said: Said,
}

/// Verify a KERI event log and return the resulting key state.
///
/// This is a stateless function that validates the cryptographic integrity
/// of a KEL without requiring filesystem access. Verifies SAID integrity,
/// chain linkage, sequence ordering, pre-rotation commitments, and Ed25519
/// signatures on every event.
///
/// # Arguments
/// * `events` - Ordered list of events (inception first)
/// * `provider` - Crypto provider for Ed25519 signature verification
///
/// # Returns
/// * `Ok(KeriKeyState)` - The current key state after replaying events
/// * `Err(KeriVerifyError)` - If validation fails
pub async fn verify_kel(
    events: &[KeriEvent],
    provider: &dyn CryptoProvider,
) -> Result<KeriKeyState, KeriVerifyError> {
    if events.is_empty() {
        return Err(KeriVerifyError::EmptyKel);
    }

    let KeriEvent::Inception(icp) = &events[0] else {
        return Err(KeriVerifyError::NotInception);
    };

    verify_event_said(&events[0])?;

    let icp_key = icp
        .k
        .first()
        .ok_or(KeriVerifyError::SignatureFailed { sequence: 0 })?;
    verify_event_signature(&events[0], icp_key, provider).await?;

    let current_key = decode_key(icp_key)?;
    let current_key_encoded = icp_key.clone();

    let mut state = KeriKeyState {
        prefix: icp.i.clone(),
        current_key,
        current_key_encoded,
        next_commitment: icp.n.first().cloned(),
        sequence: 0,
        is_abandoned: icp.n.is_empty(),
        last_event_said: icp.d.clone(),
    };

    for (idx, event) in events.iter().enumerate().skip(1) {
        let expected_seq = idx as u64;

        verify_event_said(event)?;

        match event {
            KeriEvent::Rotation(rot) => {
                let actual_seq = event.sequence()?;
                if actual_seq != expected_seq {
                    return Err(KeriVerifyError::InvalidSequence {
                        expected: expected_seq,
                        actual: actual_seq,
                    });
                }

                if rot.p != state.last_event_said {
                    return Err(KeriVerifyError::BrokenChain {
                        sequence: actual_seq,
                        referenced: rot.p.clone(),
                        actual: state.last_event_said.clone(),
                    });
                }

                if !rot.k.is_empty() {
                    verify_event_signature(event, &rot.k[0], provider).await?;

                    let new_key_bytes = decode_key(&rot.k[0])?;

                    if let Some(commitment) = &state.next_commitment
                        && !verify_commitment(&new_key_bytes, commitment)
                    {
                        return Err(KeriVerifyError::CommitmentMismatch {
                            sequence: actual_seq,
                        });
                    }

                    state.current_key = new_key_bytes;
                    state.current_key_encoded = rot.k[0].clone();
                }

                state.next_commitment = rot.n.first().cloned();
                state.is_abandoned = rot.n.is_empty();
                state.sequence = actual_seq;
                state.last_event_said = rot.d.clone();
            }
            KeriEvent::Interaction(ixn) => {
                let actual_seq = event.sequence()?;
                if actual_seq != expected_seq {
                    return Err(KeriVerifyError::InvalidSequence {
                        expected: expected_seq,
                        actual: actual_seq,
                    });
                }

                if ixn.p != state.last_event_said {
                    return Err(KeriVerifyError::BrokenChain {
                        sequence: actual_seq,
                        referenced: ixn.p.clone(),
                        actual: state.last_event_said.clone(),
                    });
                }

                verify_event_signature(event, &state.current_key_encoded, provider).await?;

                state.sequence = actual_seq;
                state.last_event_said = ixn.d.clone();
            }
            KeriEvent::Inception(_) => {
                return Err(KeriVerifyError::MultipleInceptions);
            }
        }
    }

    Ok(state)
}

/// Serialize event for signing/SAID computation (clears d, x, and for ICP also i).
///
/// This produces the canonical form over which both SAID and signatures are computed.
fn serialize_for_signing(event: &KeriEvent) -> Result<Vec<u8>, KeriVerifyError> {
    match event {
        KeriEvent::Inception(e) => {
            let mut copy = e.clone();
            copy.d = Said::default();
            copy.i = Prefix::default();
            copy.x = String::new();
            serde_json::to_vec(&KeriEvent::Inception(copy))
        }
        KeriEvent::Rotation(e) => {
            let mut copy = e.clone();
            copy.d = Said::default();
            copy.x = String::new();
            serde_json::to_vec(&KeriEvent::Rotation(copy))
        }
        KeriEvent::Interaction(e) => {
            let mut copy = e.clone();
            copy.d = Said::default();
            copy.x = String::new();
            serde_json::to_vec(&KeriEvent::Interaction(copy))
        }
    }
    .map_err(|e| KeriVerifyError::Serialization(e.to_string()))
}

/// Verify an event's SAID matches its content.
fn verify_event_said(event: &KeriEvent) -> Result<(), KeriVerifyError> {
    let json = serialize_for_signing(event)?;
    let computed = compute_said(&json);
    let said = event.said();

    if computed != *said {
        return Err(KeriVerifyError::InvalidSaid {
            expected: computed,
            actual: said.clone(),
        });
    }

    Ok(())
}

/// Verify an event's Ed25519 signature using the specified key.
async fn verify_event_signature(
    event: &KeriEvent,
    signing_key: &str,
    provider: &dyn CryptoProvider,
) -> Result<(), KeriVerifyError> {
    let sequence = event.sequence()?;

    let sig_str = event.signature();
    if sig_str.is_empty() {
        return Err(KeriVerifyError::SignatureFailed { sequence });
    }
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_str)
        .map_err(|_| KeriVerifyError::SignatureFailed { sequence })?;

    let key_bytes =
        decode_key(signing_key).map_err(|_| KeriVerifyError::SignatureFailed { sequence })?;

    let canonical = serialize_for_signing(event)?;

    provider
        .verify_ed25519(&key_bytes, &canonical, &sig_bytes)
        .await
        .map_err(|_| KeriVerifyError::SignatureFailed { sequence })?;

    Ok(())
}

/// Compute a KERI Self-Addressing Identifier (SAID) using Blake3.
// SYNC: must match auths-core/src/crypto/said.rs — tested by said_cross_validation
pub fn compute_said(data: &[u8]) -> Said {
    let hash = blake3::hash(data);
    Said::new_unchecked(format!("E{}", URL_SAFE_NO_PAD.encode(hash.as_bytes())))
}

/// Compute next-key commitment.
// SYNC: must match auths-core/src/crypto/said.rs — tested by said_cross_validation
fn compute_commitment(public_key: &[u8]) -> String {
    let hash = blake3::hash(public_key);
    format!("E{}", URL_SAFE_NO_PAD.encode(hash.as_bytes()))
}

// Defense-in-depth: both values are derived from public data, but constant-time
// comparison prevents timing side-channels on commitment verification.
fn verify_commitment(public_key: &[u8], commitment: &str) -> bool {
    let computed = compute_commitment(public_key);
    computed.as_bytes().ct_eq(commitment.as_bytes()).into()
}

/// Decode a KERI key (D-prefixed Base64url for Ed25519).
fn decode_key(key_str: &str) -> Result<Vec<u8>, KeriVerifyError> {
    KeriPublicKey::parse(key_str)
        .map(|k| k.into_bytes().to_vec())
        .map_err(|e| KeriVerifyError::InvalidKey(e.to_string()))
}

/// Check if a seal with given digest exists in any IXN event.
///
/// Returns the sequence number of the IXN event if found.
pub fn find_seal_in_kel(events: &[KeriEvent], digest: &str) -> Option<u64> {
    for event in events {
        if let KeriEvent::Interaction(ixn) = event {
            for seal in &ixn.a {
                if seal.d.as_str() == digest {
                    return ixn.s.parse::<u64>().ok();
                }
            }
        }
    }
    None
}

/// Parse events from JSON.
pub fn parse_kel_json(json: &str) -> Result<Vec<KeriEvent>, KeriVerifyError> {
    serde_json::from_str(json).map_err(|e| KeriVerifyError::Serialization(e.to_string()))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use auths_crypto::RingCryptoProvider;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn provider() -> RingCryptoProvider {
        RingCryptoProvider
    }

    fn finalize_icp(mut icp: IcpEvent) -> IcpEvent {
        icp.d = Said::default();
        icp.i = Prefix::default();
        icp.x = String::new();
        let json = serde_json::to_vec(&KeriEvent::Inception(icp.clone())).unwrap();
        let said = compute_said(&json);
        icp.i = Prefix::new_unchecked(said.as_str().to_string());
        icp.d = said;
        icp
    }

    // ── Signed helpers ──

    fn make_signed_icp(keypair: &Ed25519KeyPair, next_commitment: &str) -> IcpEvent {
        let key_encoded = format!("D{}", URL_SAFE_NO_PAD.encode(keypair.public_key().as_ref()));

        let mut icp = IcpEvent {
            v: "KERI10JSON".into(),
            d: Said::default(),
            i: Prefix::default(),
            s: "0".into(),
            kt: "1".into(),
            k: vec![key_encoded],
            nt: "1".into(),
            n: vec![next_commitment.to_string()],
            bt: "0".into(),
            b: vec![],
            a: vec![],
            x: String::new(),
        };

        // Finalize SAID
        icp = finalize_icp(icp);

        // Sign
        let canonical = serialize_for_signing(&KeriEvent::Inception(icp.clone())).unwrap();
        let sig = keypair.sign(&canonical);
        icp.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

        icp
    }

    fn make_signed_rot(
        prefix: &str,
        prev_said: &str,
        seq: u64,
        new_keypair: &Ed25519KeyPair,
        next_commitment: &str,
    ) -> RotEvent {
        let key_encoded = format!(
            "D{}",
            URL_SAFE_NO_PAD.encode(new_keypair.public_key().as_ref())
        );

        let mut rot = RotEvent {
            v: "KERI10JSON".into(),
            d: Said::default(),
            i: Prefix::new_unchecked(prefix.to_string()),
            s: seq.to_string(),
            p: Said::new_unchecked(prev_said.to_string()),
            kt: "1".into(),
            k: vec![key_encoded],
            nt: "1".into(),
            n: vec![next_commitment.to_string()],
            bt: "0".into(),
            b: vec![],
            a: vec![],
            x: String::new(),
        };

        // Compute SAID
        let json = serialize_for_signing(&KeriEvent::Rotation(rot.clone())).unwrap();
        rot.d = compute_said(&json);

        // Sign with the NEW key
        let canonical = serialize_for_signing(&KeriEvent::Rotation(rot.clone())).unwrap();
        let sig = new_keypair.sign(&canonical);
        rot.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

        rot
    }

    fn make_signed_ixn(
        prefix: &str,
        prev_said: &str,
        seq: u64,
        keypair: &Ed25519KeyPair,
        seals: Vec<Seal>,
    ) -> IxnEvent {
        let mut ixn = IxnEvent {
            v: "KERI10JSON".into(),
            d: Said::default(),
            i: Prefix::new_unchecked(prefix.to_string()),
            s: seq.to_string(),
            p: Said::new_unchecked(prev_said.to_string()),
            a: seals,
            x: String::new(),
        };

        // Compute SAID
        let json = serialize_for_signing(&KeriEvent::Interaction(ixn.clone())).unwrap();
        ixn.d = compute_said(&json);

        // Sign
        let canonical = serialize_for_signing(&KeriEvent::Interaction(ixn.clone())).unwrap();
        let sig = keypair.sign(&canonical);
        ixn.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

        ixn
    }

    fn generate_keypair() -> (Ed25519KeyPair, Vec<u8>) {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let pkcs8_bytes = pkcs8.as_ref().to_vec();
        let keypair = Ed25519KeyPair::from_pkcs8(&pkcs8_bytes).unwrap();
        (keypair, pkcs8_bytes)
    }

    // ── Structural tests (existing, updated for x field) ──

    #[tokio::test]
    async fn rejects_empty_kel() {
        let result = verify_kel(&[], &provider()).await;
        assert!(matches!(result, Err(KeriVerifyError::EmptyKel)));
    }

    #[tokio::test]
    async fn rejects_non_inception_first() {
        let ixn = KeriEvent::Interaction(IxnEvent {
            v: "KERI10JSON".into(),
            d: Said::new_unchecked("EIXN".into()),
            i: Prefix::new_unchecked("EPrefix".into()),
            s: "0".into(),
            p: Said::new_unchecked("EPrev".into()),
            a: vec![],
            x: String::new(),
        });

        let result = verify_kel(&[ixn], &provider()).await;
        assert!(matches!(result, Err(KeriVerifyError::NotInception)));
    }

    #[test]
    fn find_seal_locates_attestation_sync() {
        let (kp1, _) = generate_keypair();
        let (kp2, _) = generate_keypair();
        let next_commitment = compute_commitment(kp2.public_key().as_ref());

        let icp = make_signed_icp(&kp1, &next_commitment);

        // Create signed IXN with seal
        let ixn = make_signed_ixn(
            icp.i.as_str(),
            icp.d.as_str(),
            1,
            &kp1,
            vec![Seal {
                d: Said::new_unchecked("EAttDigest".into()),
                seal_type: "device-attestation".into(),
            }],
        );

        let events = vec![KeriEvent::Inception(icp), KeriEvent::Interaction(ixn)];

        let found = find_seal_in_kel(&events, "EAttDigest");
        assert_eq!(found, Some(1));

        let not_found = find_seal_in_kel(&events, "ENotExist");
        assert_eq!(not_found, None);
    }

    #[test]
    fn decode_key_works() {
        let key_bytes = [42u8; 32];
        let encoded = format!("D{}", URL_SAFE_NO_PAD.encode(key_bytes));

        let decoded = decode_key(&encoded).unwrap();
        assert_eq!(decoded, key_bytes);
    }

    #[test]
    fn decode_key_rejects_unknown_code() {
        let result = decode_key("Xsomething");
        assert!(matches!(result, Err(KeriVerifyError::InvalidKey(_))));
    }

    // ── Signed verification tests ──

    #[tokio::test]
    async fn verify_signed_inception() {
        let (kp1, _) = generate_keypair();
        let (kp2, _) = generate_keypair();
        let next_commitment = compute_commitment(kp2.public_key().as_ref());

        let icp = make_signed_icp(&kp1, &next_commitment);
        let events = vec![KeriEvent::Inception(icp.clone())];

        let state = verify_kel(&events, &provider()).await.unwrap();
        assert_eq!(state.prefix, icp.i);
        assert_eq!(state.current_key, kp1.public_key().as_ref());
        assert_eq!(state.sequence, 0);
        assert!(!state.is_abandoned);
    }

    #[tokio::test]
    async fn verify_icp_rot_ixn_signed() {
        let (kp1, _) = generate_keypair();
        let (kp2, _) = generate_keypair();
        let (kp3, _) = generate_keypair();

        let next1_commitment = compute_commitment(kp2.public_key().as_ref());
        let next2_commitment = compute_commitment(kp3.public_key().as_ref());

        let icp = make_signed_icp(&kp1, &next1_commitment);
        let rot = make_signed_rot(icp.i.as_str(), icp.d.as_str(), 1, &kp2, &next2_commitment);
        let ixn = make_signed_ixn(
            icp.i.as_str(),
            rot.d.as_str(),
            2,
            &kp2,
            vec![Seal {
                d: Said::new_unchecked("EAttest".into()),
                seal_type: "device-attestation".into(),
            }],
        );

        let events = vec![
            KeriEvent::Inception(icp.clone()),
            KeriEvent::Rotation(rot),
            KeriEvent::Interaction(ixn),
        ];

        let state = verify_kel(&events, &provider()).await.unwrap();
        assert_eq!(state.prefix, icp.i);
        assert_eq!(state.current_key, kp2.public_key().as_ref());
        assert_eq!(state.sequence, 2);
    }

    #[tokio::test]
    async fn rejects_forged_signature() {
        let (kp1, _) = generate_keypair();
        let (kp2, _) = generate_keypair();
        let next_commitment = compute_commitment(kp2.public_key().as_ref());

        let mut icp = make_signed_icp(&kp1, &next_commitment);
        icp.x = URL_SAFE_NO_PAD.encode([0u8; 64]);

        let events = vec![KeriEvent::Inception(icp)];
        let result = verify_kel(&events, &provider()).await;
        assert!(matches!(
            result,
            Err(KeriVerifyError::SignatureFailed { sequence: 0 })
        ));
    }

    #[tokio::test]
    async fn rejects_missing_signature() {
        let (kp1, _) = generate_keypair();
        let (kp2, _) = generate_keypair();
        let next_commitment = compute_commitment(kp2.public_key().as_ref());

        let mut icp = make_signed_icp(&kp1, &next_commitment);
        icp.x = String::new();

        let events = vec![KeriEvent::Inception(icp)];
        let result = verify_kel(&events, &provider()).await;
        assert!(matches!(
            result,
            Err(KeriVerifyError::SignatureFailed { sequence: 0 })
        ));
    }

    #[tokio::test]
    async fn rejects_wrong_key_signature() {
        let (kp1, _) = generate_keypair();
        let (kp_wrong, _) = generate_keypair();
        let (kp2, _) = generate_keypair();
        let next_commitment = compute_commitment(kp2.public_key().as_ref());

        let key_encoded = format!("D{}", URL_SAFE_NO_PAD.encode(kp1.public_key().as_ref()));
        let mut icp = IcpEvent {
            v: "KERI10JSON".into(),
            d: Said::default(),
            i: Prefix::default(),
            s: "0".into(),
            kt: "1".into(),
            k: vec![key_encoded],
            nt: "1".into(),
            n: vec![next_commitment],
            bt: "0".into(),
            b: vec![],
            a: vec![],
            x: String::new(),
        };
        icp = finalize_icp(icp);

        let canonical = serialize_for_signing(&KeriEvent::Inception(icp.clone())).unwrap();
        let sig = kp_wrong.sign(&canonical);
        icp.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

        let events = vec![KeriEvent::Inception(icp)];
        let result = verify_kel(&events, &provider()).await;
        assert!(matches!(
            result,
            Err(KeriVerifyError::SignatureFailed { sequence: 0 })
        ));
    }

    #[tokio::test]
    async fn rejects_rot_signed_with_old_key() {
        let (kp1, _) = generate_keypair();
        let (kp2, _) = generate_keypair();
        let (kp3, _) = generate_keypair();

        let next1_commitment = compute_commitment(kp2.public_key().as_ref());
        let next2_commitment = compute_commitment(kp3.public_key().as_ref());

        let icp = make_signed_icp(&kp1, &next1_commitment);

        let key2_encoded = format!("D{}", URL_SAFE_NO_PAD.encode(kp2.public_key().as_ref()));
        let mut rot = RotEvent {
            v: "KERI10JSON".into(),
            d: Said::default(),
            i: icp.i.clone(),
            s: "1".into(),
            p: icp.d.clone(),
            kt: "1".into(),
            k: vec![key2_encoded],
            nt: "1".into(),
            n: vec![next2_commitment],
            bt: "0".into(),
            b: vec![],
            a: vec![],
            x: String::new(),
        };

        let json = serialize_for_signing(&KeriEvent::Rotation(rot.clone())).unwrap();
        rot.d = compute_said(&json);

        let canonical = serialize_for_signing(&KeriEvent::Rotation(rot.clone())).unwrap();
        let sig = kp1.sign(&canonical);
        rot.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

        let events = vec![KeriEvent::Inception(icp), KeriEvent::Rotation(rot)];
        let result = verify_kel(&events, &provider()).await;
        assert!(matches!(
            result,
            Err(KeriVerifyError::SignatureFailed { sequence: 1 })
        ));
    }

    #[tokio::test]
    async fn rotation_updates_signing_key_for_ixn() {
        let (kp1, _) = generate_keypair();
        let (kp2, _) = generate_keypair();
        let (kp3, _) = generate_keypair();

        let next1_commitment = compute_commitment(kp2.public_key().as_ref());
        let next2_commitment = compute_commitment(kp3.public_key().as_ref());

        let icp = make_signed_icp(&kp1, &next1_commitment);
        let rot = make_signed_rot(icp.i.as_str(), icp.d.as_str(), 1, &kp2, &next2_commitment);
        let ixn = make_signed_ixn(icp.i.as_str(), rot.d.as_str(), 2, &kp1, vec![]);

        let events = vec![
            KeriEvent::Inception(icp),
            KeriEvent::Rotation(rot),
            KeriEvent::Interaction(ixn),
        ];
        let result = verify_kel(&events, &provider()).await;
        assert!(matches!(
            result,
            Err(KeriVerifyError::SignatureFailed { sequence: 2 })
        ));
    }

    #[tokio::test]
    async fn rejects_wrong_commitment() {
        let (kp1, _) = generate_keypair();
        let (kp2, _) = generate_keypair();
        let (kp_wrong, _) = generate_keypair();
        let (kp3, _) = generate_keypair();

        let next1_commitment = compute_commitment(kp2.public_key().as_ref());
        let next2_commitment = compute_commitment(kp3.public_key().as_ref());

        let icp = make_signed_icp(&kp1, &next1_commitment);
        let rot = make_signed_rot(
            icp.i.as_str(),
            icp.d.as_str(),
            1,
            &kp_wrong,
            &next2_commitment,
        );

        let events = vec![KeriEvent::Inception(icp), KeriEvent::Rotation(rot)];
        let result = verify_kel(&events, &provider()).await;
        assert!(matches!(
            result,
            Err(KeriVerifyError::CommitmentMismatch { sequence: 1 })
        ));
    }

    #[tokio::test]
    async fn rejects_broken_chain() {
        let (kp1, _) = generate_keypair();
        let (kp2, _) = generate_keypair();
        let next_commitment = compute_commitment(kp2.public_key().as_ref());

        let icp = make_signed_icp(&kp1, &next_commitment);

        let mut ixn = IxnEvent {
            v: "KERI10JSON".into(),
            d: Said::default(),
            i: icp.i.clone(),
            s: "1".into(),
            p: Said::new_unchecked("EWrongPrevious".into()),
            a: vec![],
            x: String::new(),
        };

        let json = serialize_for_signing(&KeriEvent::Interaction(ixn.clone())).unwrap();
        ixn.d = compute_said(&json);

        let canonical = serialize_for_signing(&KeriEvent::Interaction(ixn.clone())).unwrap();
        let sig = kp1.sign(&canonical);
        ixn.x = URL_SAFE_NO_PAD.encode(sig.as_ref());

        let events = vec![KeriEvent::Inception(icp), KeriEvent::Interaction(ixn)];
        let result = verify_kel(&events, &provider()).await;
        assert!(matches!(result, Err(KeriVerifyError::BrokenChain { .. })));
    }

    #[tokio::test]
    async fn verify_kel_with_rotation() {
        let (kp1, _) = generate_keypair();
        let (kp2, _) = generate_keypair();
        let (kp3, _) = generate_keypair();

        let next1_commitment = compute_commitment(kp2.public_key().as_ref());
        let next2_commitment = compute_commitment(kp3.public_key().as_ref());

        let icp = make_signed_icp(&kp1, &next1_commitment);
        let rot = make_signed_rot(icp.i.as_str(), icp.d.as_str(), 1, &kp2, &next2_commitment);

        let events = vec![KeriEvent::Inception(icp), KeriEvent::Rotation(rot)];

        let state = verify_kel(&events, &provider()).await.unwrap();
        assert_eq!(state.sequence, 1);
        assert_eq!(state.current_key, kp2.public_key().as_ref());
    }

    #[test]
    fn rejects_malformed_sequence_number() {
        // An event with a non-numeric sequence must be rejected, not coerced to 0
        let icp = IcpEvent {
            v: "KERI10JSON".into(),
            d: Said::default(),
            i: Prefix::default(),
            s: "not_a_number".to_string(),
            kt: "1".to_string(),
            k: vec!["DKey".to_string()],
            nt: "1".to_string(),
            n: vec!["ENext".to_string()],
            bt: "0".to_string(),
            b: vec![],
            a: vec![],
            x: String::new(),
        };

        let event = KeriEvent::Inception(icp);
        let result = event.sequence();
        assert!(
            matches!(result, Err(KeriVerifyError::MalformedSequence { .. })),
            "Expected MalformedSequence error, got: {:?}",
            result
        );
    }
}
