//! KERI event types: Inception (ICP), Rotation (ROT), Interaction (IXN).
//!
//! These events form the Key Event Log (KEL), a hash-chained sequence
//! that records all key lifecycle operations for a KERI identity.

use auths_core::witness::Receipt;
use serde::ser::SerializeMap;
use serde::{Deserialize, Serialize, Serializer};
use std::collections::HashSet;
use std::fmt;

use super::seal::Seal;
use super::types::{Prefix, Said};

/// A KERI sequence number, stored internally as u64 and serialized as a hex string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeriSequence(u64);

impl KeriSequence {
    pub fn new(value: u64) -> Self {
        Self(value)
    }

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

/// Receipts attached to a KEL event.
///
/// Receipts are witness acknowledgments that prove an event was observed.
/// They are stored separately from the event itself, linked by SAID.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EventReceipts {
    /// Event SAID these receipts are for
    pub event_said: Said,
    /// Collected receipts from witnesses
    pub receipts: Vec<Receipt>,
}

impl EventReceipts {
    /// Create a new EventReceipts collection, deduplicating by witness identifier.
    pub fn new(event_said: impl Into<String>, receipts: Vec<Receipt>) -> Self {
        let mut seen = HashSet::new();
        let deduped: Vec<Receipt> = receipts
            .into_iter()
            .filter(|r| seen.insert(r.i.clone()))
            .collect();
        Self {
            event_said: Said::new_unchecked(event_said.into()),
            receipts: deduped,
        }
    }

    /// Check if the unique receipt count meets the threshold without exceeding the witness set.
    ///
    /// Args:
    /// * `threshold`: Minimum number of unique witness receipts required.
    /// * `witness_count`: Size of the configured witness set. If unique receipts
    ///   exceed this, the result is `false` (indicates replay/duplication).
    pub fn meets_threshold(&self, threshold: usize, witness_count: usize) -> bool {
        let unique = self.unique_witness_count();
        if unique > witness_count {
            log::warn!(
                "Receipt count ({}) exceeds witness set size ({}) for event {} — possible replay",
                unique,
                witness_count,
                self.event_said,
            );
            return false;
        }
        unique >= threshold
    }

    /// Number of unique witnesses that provided receipts.
    pub fn unique_witness_count(&self) -> usize {
        let seen: HashSet<&str> = self.receipts.iter().map(|r| r.i.as_str()).collect();
        seen.len()
    }

    /// Get the number of receipts.
    pub fn count(&self) -> usize {
        self.receipts.len()
    }
}

/// Inception event - creates a new KERI identity.
///
/// The inception event establishes the identifier prefix and commits
/// to the first rotation key via the `n` (next) field.
///
/// Note: The `t` (type) field is handled by the `Event` enum's serde tag.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct IcpEvent {
    /// Version string: "KERI10JSON"
    pub v: String,
    /// SAID (Self-Addressing Identifier) - Blake3 hash of event
    #[serde(default)]
    pub d: Said,
    /// Identifier prefix (same as `d` for inception)
    pub i: Prefix,
    /// Sequence number
    pub s: KeriSequence,
    /// Key threshold: "1" for single-sig
    pub kt: String,
    /// Current public key(s), Base64url encoded with derivation code
    pub k: Vec<String>,
    /// Next key threshold: "1"
    pub nt: String,
    /// Next key commitment(s) - hash of next public key(s)
    pub n: Vec<String>,
    /// Witness threshold: "0" (no witnesses)
    pub bt: String,
    /// Witness list (empty)
    pub b: Vec<String>,
    /// Anchored seals
    #[serde(default)]
    pub a: Vec<Seal>,
    /// Event signature (Ed25519 over canonical event with empty d, i, and x fields)
    #[serde(default)]
    pub x: String,
}

/// Spec field order: v, t, d, i, s, kt, k, nt, n, bt, b, a, x
impl Serialize for IcpEvent {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let field_count = 12
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

/// Rotation event - rotates to pre-committed key.
///
/// The new key must match the previous event's next-key commitment.
/// This provides cryptographic pre-rotation security.
///
/// Note: The `t` (type) field is handled by the `Event` enum's serde tag.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
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
    /// Event signature (Ed25519 over canonical event with empty d and x fields)
    #[serde(default)]
    pub x: String,
}

/// Spec field order: v, t, d, i, s, p, kt, k, nt, n, bt, b, a, x
impl Serialize for RotEvent {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let field_count = 13
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

/// Interaction event - anchors data without key rotation.
///
/// Used to anchor attestations, delegations, or other data
/// in the KEL without changing keys.
///
/// Note: The `t` (type) field is handled by the `Event` enum's serde tag.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
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
    /// Event signature (Ed25519 over canonical event with empty d and x fields)
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

/// Unified event enum for processing any KERI event type.
///
/// Uses serde's tagged enum feature to deserialize based on the `t` field.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
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
    /// Get the SAID (Self-Addressing Identifier) of this event.
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
mod tests {
    use super::*;
    use crate::keri::KERI_VERSION;

    #[test]
    fn keri_sequence_serializes_as_hex() {
        let seq = KeriSequence::new(0);
        assert_eq!(serde_json::to_string(&seq).unwrap(), "\"0\"");

        let seq = KeriSequence::new(10);
        assert_eq!(serde_json::to_string(&seq).unwrap(), "\"a\"");

        let seq = KeriSequence::new(255);
        assert_eq!(serde_json::to_string(&seq).unwrap(), "\"ff\"");
    }

    #[test]
    fn keri_sequence_deserializes_from_hex() {
        let seq: KeriSequence = serde_json::from_str("\"0\"").unwrap();
        assert_eq!(seq.value(), 0);

        let seq: KeriSequence = serde_json::from_str("\"a\"").unwrap();
        assert_eq!(seq.value(), 10);

        let seq: KeriSequence = serde_json::from_str("\"ff\"").unwrap();
        assert_eq!(seq.value(), 255);
    }

    #[test]
    fn keri_sequence_rejects_invalid_hex() {
        let result = serde_json::from_str::<KeriSequence>("\"not_hex\"");
        assert!(result.is_err());
    }

    #[test]
    fn icp_event_serializes_correctly() {
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
        assert!(json.contains("\"v\":\"KERI10JSON\""));
        assert!(json.contains("\"k\":[\"DKey123\"]"));
        assert!(json.contains("\"s\":\"0\""));
        // Empty d, a, and x should be skipped
        assert!(!json.contains("\"d\":\"\""));
        assert!(!json.contains("\"a\":[]"));
        assert!(!json.contains("\"x\":\"\""));
    }

    #[test]
    fn rot_event_serializes_correctly() {
        let rot = RotEvent {
            v: KERI_VERSION.to_string(),
            d: Said::new_unchecked("ERotSaid".to_string()),
            i: Prefix::new_unchecked("EPrefix".to_string()),
            s: KeriSequence::new(1),
            p: Said::new_unchecked("EPrevSaid".to_string()),
            kt: "1".to_string(),
            k: vec!["DNewKey".to_string()],
            nt: "1".to_string(),
            n: vec!["ENextCommit".to_string()],
            bt: "0".to_string(),
            b: vec![],
            a: vec![],
            x: String::new(),
        };
        let json = serde_json::to_string(&rot).unwrap();
        assert!(json.contains("\"p\":\"EPrevSaid\""));
        assert!(json.contains("\"s\":\"1\""));
    }

    #[test]
    fn ixn_event_serializes_correctly() {
        let seal = Seal::device_attestation("EAttestDigest");
        let ixn = IxnEvent {
            v: KERI_VERSION.to_string(),
            d: Said::new_unchecked("EIxnSaid".to_string()),
            i: Prefix::new_unchecked("EPrefix".to_string()),
            s: KeriSequence::new(2),
            p: Said::new_unchecked("EPrevSaid".to_string()),
            a: vec![seal],
            x: String::new(),
        };
        let json = serde_json::to_string(&ixn).unwrap();
        assert!(json.contains("\"a\":["));
        assert!(json.contains("device-attestation"));
    }

    #[test]
    fn event_enum_deserializes_icp_by_type() {
        let json = r#"{"v":"KERI10JSON","t":"icp","i":"E123","s":"0","kt":"1","k":["DKey"],"nt":"1","n":["ENext"],"bt":"0","b":[]}"#;
        let event: Event = serde_json::from_str(json).unwrap();
        assert!(event.is_inception());
        assert_eq!(event.prefix(), "E123");
        assert_eq!(event.sequence().value(), 0);
        assert!(event.previous().is_none());
    }

    #[test]
    fn event_enum_deserializes_rot_by_type() {
        let json = r#"{"v":"KERI10JSON","t":"rot","d":"ENew","i":"E123","s":"1","p":"EPrev","kt":"1","k":["DKey"],"nt":"1","n":["ENext"],"bt":"0","b":[]}"#;
        let event: Event = serde_json::from_str(json).unwrap();
        assert!(event.is_rotation());
        assert_eq!(event.sequence().value(), 1);
        assert_eq!(event.previous().map(|s| s.as_str()), Some("EPrev"));
    }

    #[test]
    fn event_enum_deserializes_ixn_by_type() {
        let json =
            r#"{"v":"KERI10JSON","t":"ixn","d":"EIxn","i":"E123","s":"2","p":"EPrev","a":[]}"#;
        let event: Event = serde_json::from_str(json).unwrap();
        assert!(event.is_interaction());
        assert_eq!(event.sequence().value(), 2);
        assert!(event.keys().is_none());
    }

    #[test]
    fn event_keys_and_next_accessors() {
        let icp = Event::Icp(IcpEvent {
            v: KERI_VERSION.to_string(),
            d: Said::default(),
            i: Prefix::new_unchecked("ETest".to_string()),
            s: KeriSequence::new(0),
            kt: "1".to_string(),
            k: vec!["DKey1".to_string(), "DKey2".to_string()],
            nt: "1".to_string(),
            n: vec!["ENext1".to_string()],
            bt: "0".to_string(),
            b: vec![],
            a: vec![],
            x: String::new(),
        });

        assert_eq!(
            icp.keys(),
            Some(&["DKey1".to_string(), "DKey2".to_string()][..])
        );
        assert_eq!(icp.next_commitments(), Some(&["ENext1".to_string()][..]));
    }

    #[test]
    fn event_anchors_accessor() {
        let seal = Seal::device_attestation("EDigest");
        let ixn = Event::Ixn(IxnEvent {
            v: KERI_VERSION.to_string(),
            d: Said::default(),
            i: Prefix::new_unchecked("ETest".to_string()),
            s: KeriSequence::new(1),
            p: Said::new_unchecked("EPrev".to_string()),
            a: vec![seal.clone()],
            x: String::new(),
        });

        assert_eq!(ixn.anchors().len(), 1);
        assert_eq!(ixn.anchors()[0].d, "EDigest");
    }

    #[test]
    fn icp_event_roundtrips() {
        let icp = IcpEvent {
            v: KERI_VERSION.to_string(),
            d: Said::new_unchecked("ESaid".to_string()),
            i: Prefix::new_unchecked("ESaid".to_string()),
            s: KeriSequence::new(0),
            kt: "1".to_string(),
            k: vec!["DKey".to_string()],
            nt: "1".to_string(),
            n: vec!["ENext".to_string()],
            bt: "0".to_string(),
            b: vec![],
            a: vec![Seal::device_attestation("EAttest")],
            x: String::new(),
        };

        let json = serde_json::to_string(&icp).unwrap();
        let parsed: IcpEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(icp, parsed);
    }

    fn make_receipt(witness_id: &str) -> Receipt {
        Receipt {
            v: "KERI10JSON000000_".into(),
            t: "rct".into(),
            d: Said::new_unchecked("EReceipt".into()),
            i: witness_id.into(),
            s: 0,
            a: Said::new_unchecked("EEvent".into()),
            sig: vec![0; 64],
        }
    }

    #[test]
    fn event_receipts_deduplicates_by_witness_id() {
        let receipts = EventReceipts::new(
            "ESAID",
            vec![
                make_receipt("did:key:w1"),
                make_receipt("did:key:w1"),
                make_receipt("did:key:w2"),
            ],
        );
        assert_eq!(receipts.count(), 2);
        assert_eq!(receipts.unique_witness_count(), 2);
    }

    #[test]
    fn meets_threshold_rejects_excess_receipts() {
        let receipts = EventReceipts::new(
            "ESAID",
            vec![
                make_receipt("did:key:w1"),
                make_receipt("did:key:w2"),
                make_receipt("did:key:w3"),
            ],
        );
        // 3 unique receipts but witness_count is 2 — anomalous
        assert!(!receipts.meets_threshold(1, 2));
    }

    #[test]
    fn meets_threshold_normal_operation() {
        let receipts = EventReceipts::new(
            "ESAID",
            vec![make_receipt("did:key:w1"), make_receipt("did:key:w2")],
        );
        assert!(receipts.meets_threshold(2, 3));
        assert!(!receipts.meets_threshold(3, 3));
    }
}
