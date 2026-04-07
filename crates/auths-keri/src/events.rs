//! Canonical KERI event types: Inception (ICP), Rotation (ROT), Interaction (IXN).
//!
//! These types are the single authoritative definition of KERI events for the
//! entire workspace. All other crates import from here.

use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize, Serializer};
use std::fmt;

use crate::types::{Prefix, Said};

/// KERI protocol version prefix string.
pub const KERI_VERSION: &str = "KERI10JSON";

// ── KeriSequence ─────────────────────────────────────────────────────────────

/// A KERI sequence number, stored internally as u64 and serialized as a hex string.
///
/// Sequence numbers are spec-compliant hex strings: "0", "1", "a", "ff", etc.
///
/// Usage:
/// ```ignore
/// let seq = KeriSequence::new(10);
/// assert_eq!(seq.value(), 10);
/// assert_eq!(serde_json::to_string(&seq).unwrap(), "\"a\"");
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeriSequence(u64);

#[cfg(feature = "schema")]
impl schemars::JsonSchema for KeriSequence {
    fn schema_name() -> String {
        "KeriSequence".to_string()
    }

    fn json_schema(_gen: &mut schemars::r#gen::SchemaGenerator) -> schemars::schema::Schema {
        schemars::schema::SchemaObject {
            instance_type: Some(schemars::schema::InstanceType::String.into()),
            ..Default::default()
        }
        .into()
    }
}

impl KeriSequence {
    /// Create a new sequence number.
    pub fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the inner u64 value.
    pub fn value(self) -> u64 {
        self.0
    }
}

impl fmt::Display for KeriSequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

impl Serialize for KeriSequence {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format!("{:x}", self.0))
    }
}

impl<'de> Deserialize<'de> for KeriSequence {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let value = u64::from_str_radix(&s, 16)
            .map_err(|_| serde::de::Error::custom(format!("invalid hex sequence: {s:?}")))?;
        Ok(KeriSequence(value))
    }
}

// ── Seal ─────────────────────────────────────────────────────────────────────

/// Type of data anchored by a seal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum SealType {
    /// Device attestation seal
    DeviceAttestation,
    /// Revocation seal
    Revocation,
    /// Capability delegation seal
    Delegation,
    /// Identity provider binding seal
    IdpBinding,
}

impl fmt::Display for SealType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SealType::DeviceAttestation => write!(f, "device-attestation"),
            SealType::Revocation => write!(f, "revocation"),
            SealType::Delegation => write!(f, "delegation"),
            SealType::IdpBinding => write!(f, "idp-binding"),
        }
    }
}

/// A seal anchors external data in a KERI event.
///
/// Seals are included in the `a` (anchors) field of KERI events.
/// They contain a digest of the anchored data and a type indicator.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Seal {
    /// SAID (digest) of the anchored data
    pub d: Said,
    /// Type of anchored data
    #[serde(rename = "type")]
    pub seal_type: SealType,
}

impl Seal {
    /// Create a new seal with the given digest and type.
    ///
    /// Args:
    /// * `digest`: SAID of the anchored data.
    /// * `seal_type`: Type of anchored data.
    pub fn new(digest: impl Into<String>, seal_type: SealType) -> Self {
        Self {
            d: Said::new_unchecked(digest.into()),
            seal_type,
        }
    }

    /// Create a seal for a device attestation.
    ///
    /// Args:
    /// * `attestation_digest`: SAID of the attestation JSON.
    pub fn device_attestation(attestation_digest: impl Into<String>) -> Self {
        Self::new(attestation_digest, SealType::DeviceAttestation)
    }

    /// Create a seal for a revocation.
    pub fn revocation(revocation_digest: impl Into<String>) -> Self {
        Self::new(revocation_digest, SealType::Revocation)
    }

    /// Create a seal for capability delegation.
    pub fn delegation(delegation_digest: impl Into<String>) -> Self {
        Self::new(delegation_digest, SealType::Delegation)
    }

    /// Create a seal for an IdP binding.
    pub fn idp_binding(binding_digest: impl Into<String>) -> Self {
        Self::new(binding_digest, SealType::IdpBinding)
    }
}

// ── Event Types ───────────────────────────────────────────────────────────────

/// Inception event — creates a new KERI identity.
///
/// The inception event establishes the identifier prefix and commits
/// to the first rotation key via the `n` (next) field.
///
/// Note: The `t` (type) field is handled by the `Event` enum's serde tag.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct IcpEvent {
    /// Version string: "KERI10JSON"
    pub v: String,
    /// SAID (Self-Addressing Identifier) — Blake3 hash of event
    #[serde(default)]
    pub d: Said,
    /// Identifier prefix (same as `d` for inception)
    pub i: Prefix,
    /// Sequence number (always 0 for inception)
    pub s: KeriSequence,
    /// Key threshold: "1" for single-sig
    pub kt: String,
    /// Current public key(s), Base64url encoded with derivation code
    pub k: Vec<String>,
    /// Next key threshold: "1"
    pub nt: String,
    /// Next key commitment(s) — hash of next public key(s)
    pub n: Vec<String>,
    /// Witness threshold: "0" (no witnesses)
    pub bt: String,
    /// Witness list (empty)
    pub b: Vec<String>,
    /// Anchored seals
    #[serde(default)]
    pub a: Vec<Seal>,
    /// Event signature (Ed25519, base64url-no-pad)
    #[serde(default)]
    pub x: String,
}

/// Spec field order: v, t, d, i, s, kt, k, nt, n, bt, b, a, x
impl Serialize for IcpEvent {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let field_count = 10
            + (!self.d.is_empty() as usize)
            + (!self.a.is_empty() as usize)
            + (!self.x.is_empty() as usize);
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
        if !self.a.is_empty() {
            map.serialize_entry("a", &self.a)?;
        }
        if !self.x.is_empty() {
            map.serialize_entry("x", &self.x)?;
        }
        map.end()
    }
}

/// Rotation event — rotates to pre-committed key.
///
/// The new key must match the previous event's next-key commitment.
/// This provides cryptographic pre-rotation security.
///
/// Note: The `t` (type) field is handled by the `Event` enum's serde tag.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct RotEvent {
    /// Version string
    pub v: String,
    /// SAID of this event
    #[serde(default)]
    pub d: Said,
    /// Identifier prefix
    pub i: Prefix,
    /// Sequence number (increments with each event)
    pub s: KeriSequence,
    /// Previous event SAID (creates the hash chain)
    pub p: Said,
    /// Key threshold
    pub kt: String,
    /// New current key(s)
    pub k: Vec<String>,
    /// Next key threshold
    pub nt: String,
    /// New next key commitment(s)
    pub n: Vec<String>,
    /// Witness threshold
    pub bt: String,
    /// Witness list
    pub b: Vec<String>,
    /// Anchored seals
    #[serde(default)]
    pub a: Vec<Seal>,
    /// Event signature (Ed25519, base64url-no-pad)
    #[serde(default)]
    pub x: String,
}

/// Spec field order: v, t, d, i, s, p, kt, k, nt, n, bt, b, a, x
impl Serialize for RotEvent {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let field_count = 11
            + (!self.d.is_empty() as usize)
            + (!self.a.is_empty() as usize)
            + (!self.x.is_empty() as usize);
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
        if !self.a.is_empty() {
            map.serialize_entry("a", &self.a)?;
        }
        if !self.x.is_empty() {
            map.serialize_entry("x", &self.x)?;
        }
        map.end()
    }
}

/// Interaction event — anchors data without key rotation.
///
/// Used to anchor attestations, delegations, or other data
/// in the KEL without changing keys.
///
/// Note: The `t` (type) field is handled by the `Event` enum's serde tag.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct IxnEvent {
    /// Version string
    pub v: String,
    /// SAID of this event
    #[serde(default)]
    pub d: Said,
    /// Identifier prefix
    pub i: Prefix,
    /// Sequence number
    pub s: KeriSequence,
    /// Previous event SAID
    pub p: Said,
    /// Anchored seals (the main purpose of IXN events)
    pub a: Vec<Seal>,
    /// Event signature (Ed25519, base64url-no-pad)
    #[serde(default)]
    pub x: String,
}

/// Spec field order: v, t, d, i, s, p, a, x
impl Serialize for IxnEvent {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let field_count = 6 + (!self.d.is_empty() as usize) + (!self.x.is_empty() as usize);
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

/// Unified event enum for processing any KERI event type.
///
/// Uses serde's tagged enum feature to deserialize based on the `t` field.
///
/// Usage:
/// ```ignore
/// let event: Event = serde_json::from_str(json)?;
/// match event {
///     Event::Icp(icp) => { /* inception */ }
///     Event::Rot(rot) => { /* rotation */ }
///     Event::Ixn(ixn) => { /* interaction */ }
/// }
/// ```
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(tag = "t")]
pub enum Event {
    /// Inception event
    #[serde(rename = "icp")]
    Icp(IcpEvent),
    /// Rotation event
    #[serde(rename = "rot")]
    Rot(RotEvent),
    /// Interaction event
    #[serde(rename = "ixn")]
    Ixn(IxnEvent),
}

impl Serialize for Event {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Event::Icp(e) => e.serialize(serializer),
            Event::Rot(e) => e.serialize(serializer),
            Event::Ixn(e) => e.serialize(serializer),
        }
    }
}

impl Event {
    /// Get the SAID of this event.
    pub fn said(&self) -> &Said {
        match self {
            Event::Icp(e) => &e.d,
            Event::Rot(e) => &e.d,
            Event::Ixn(e) => &e.d,
        }
    }

    /// Get the signature of this event.
    pub fn signature(&self) -> &str {
        match self {
            Event::Icp(e) => &e.x,
            Event::Rot(e) => &e.x,
            Event::Ixn(e) => &e.x,
        }
    }

    /// Get the sequence number of this event.
    pub fn sequence(&self) -> KeriSequence {
        match self {
            Event::Icp(e) => e.s,
            Event::Rot(e) => e.s,
            Event::Ixn(e) => e.s,
        }
    }

    /// Get the identifier prefix.
    pub fn prefix(&self) -> &Prefix {
        match self {
            Event::Icp(e) => &e.i,
            Event::Rot(e) => &e.i,
            Event::Ixn(e) => &e.i,
        }
    }

    /// Get the previous event SAID (None for inception).
    pub fn previous(&self) -> Option<&Said> {
        match self {
            Event::Icp(_) => None,
            Event::Rot(e) => Some(&e.p),
            Event::Ixn(e) => Some(&e.p),
        }
    }

    /// Get the current keys (only applicable to ICP and ROT events).
    pub fn keys(&self) -> Option<&[String]> {
        match self {
            Event::Icp(e) => Some(&e.k),
            Event::Rot(e) => Some(&e.k),
            Event::Ixn(_) => None,
        }
    }

    /// Get the next key commitments (only applicable to ICP and ROT events).
    pub fn next_commitments(&self) -> Option<&[String]> {
        match self {
            Event::Icp(e) => Some(&e.n),
            Event::Rot(e) => Some(&e.n),
            Event::Ixn(_) => None,
        }
    }

    /// Get the anchored seals.
    pub fn anchors(&self) -> &[Seal] {
        match self {
            Event::Icp(e) => &e.a,
            Event::Rot(e) => &e.a,
            Event::Ixn(e) => &e.a,
        }
    }

    /// Check if this is an inception event.
    pub fn is_inception(&self) -> bool {
        matches!(self, Event::Icp(_))
    }

    /// Check if this is a rotation event.
    pub fn is_rotation(&self) -> bool {
        matches!(self, Event::Rot(_))
    }

    /// Check if this is an interaction event.
    pub fn is_interaction(&self) -> bool {
        matches!(self, Event::Ixn(_))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn keri_sequence_serializes_as_hex() {
        assert_eq!(
            serde_json::to_string(&KeriSequence::new(0)).unwrap(),
            "\"0\""
        );
        assert_eq!(
            serde_json::to_string(&KeriSequence::new(10)).unwrap(),
            "\"a\""
        );
        assert_eq!(
            serde_json::to_string(&KeriSequence::new(255)).unwrap(),
            "\"ff\""
        );
    }

    #[test]
    fn keri_sequence_deserializes_from_hex() {
        let s: KeriSequence = serde_json::from_str("\"0\"").unwrap();
        assert_eq!(s.value(), 0);
        let s: KeriSequence = serde_json::from_str("\"a\"").unwrap();
        assert_eq!(s.value(), 10);
        let s: KeriSequence = serde_json::from_str("\"ff\"").unwrap();
        assert_eq!(s.value(), 255);
    }

    #[test]
    fn keri_sequence_rejects_invalid_hex() {
        assert!(serde_json::from_str::<KeriSequence>("\"not_hex\"").is_err());
    }

    #[test]
    fn icp_event_omits_empty_d_a_x() {
        let icp = IcpEvent {
            v: KERI_VERSION.to_string(),
            d: Said::default(),
            i: Prefix::new_unchecked("ETest123".to_string()),
            s: KeriSequence::new(0),
            kt: "1".to_string(),
            k: vec!["DKey123".to_string()],
            nt: "1".to_string(),
            n: vec!["ENext456".to_string()],
            bt: "0".to_string(),
            b: vec![],
            a: vec![],
            x: String::new(),
        };
        let json = serde_json::to_string(&icp).unwrap();
        assert!(!json.contains("\"d\":"), "empty d must be omitted");
        assert!(!json.contains("\"a\":"), "empty a must be omitted");
        assert!(!json.contains("\"x\":"), "empty x must be omitted");
        assert!(json.contains("\"s\":\"0\""), "s must serialize as hex");
    }

    #[test]
    fn event_enum_deserializes_by_t_field() {
        let json = r#"{"v":"KERI10JSON","t":"icp","i":"E123","s":"0","kt":"1","k":["DKey"],"nt":"1","n":["ENext"],"bt":"0","b":[]}"#;
        let event: Event = serde_json::from_str(json).unwrap();
        assert!(event.is_inception());
        assert_eq!(event.sequence().value(), 0);
    }

    #[test]
    fn seal_serializes_with_kebab_case_type() {
        let seal = Seal::device_attestation("EDigest");
        let json = serde_json::to_string(&seal).unwrap();
        assert!(json.contains(r#""type":"device-attestation""#));
    }

    #[test]
    fn seal_roundtrips() {
        let original = Seal::device_attestation("ETest123");
        let json = serde_json::to_string(&original).unwrap();
        let parsed: Seal = serde_json::from_str(&json).unwrap();
        assert_eq!(original, parsed);
    }
}
