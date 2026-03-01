//! KERI event types: Inception (ICP), Rotation (ROT), Interaction (IXN).
//!
//! These events form the Key Event Log (KEL), a hash-chained sequence
//! that records all key lifecycle operations for a KERI identity.

use auths_core::witness::Receipt;
use serde::{Deserialize, Serialize};

use super::seal::Seal;
use super::types::{Prefix, Said};

/// Error when parsing a sequence number from a KERI event's `s` field.
#[derive(Debug, Clone, thiserror::Error, PartialEq, Eq)]
#[error("Malformed sequence number: {raw:?}")]
pub struct SequenceParseError {
    /// The raw string that failed to parse as u64.
    pub raw: String,
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
    /// Create a new EventReceipts collection.
    pub fn new(event_said: impl Into<String>, receipts: Vec<Receipt>) -> Self {
        Self {
            event_said: Said::new_unchecked(event_said.into()),
            receipts,
        }
    }

    /// Check if the receipts meet a threshold.
    pub fn meets_threshold(&self, threshold: usize) -> bool {
        self.receipts.len() >= threshold
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IcpEvent {
    /// Version string: "KERI10JSON"
    pub v: String,
    /// SAID (Self-Addressing Identifier) - Blake3 hash of event
    #[serde(default, skip_serializing_if = "Said::is_empty")]
    pub d: Said,
    /// Identifier prefix (same as `d` for inception)
    pub i: Prefix,
    /// Sequence number: "0" for inception
    pub s: String,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub a: Vec<Seal>,
    /// Event signature (Ed25519 over canonical event with empty d, i, and x fields)
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub x: String,
}

/// Rotation event - rotates to pre-committed key.
///
/// The new key must match the previous event's next-key commitment.
/// This provides cryptographic pre-rotation security.
///
/// Note: The `t` (type) field is handled by the `Event` enum's serde tag.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RotEvent {
    /// Version string
    pub v: String,
    /// SAID of this event
    #[serde(default, skip_serializing_if = "Said::is_empty")]
    pub d: Said,
    /// Identifier prefix
    pub i: Prefix,
    /// Sequence number (increments with each event)
    pub s: String,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub a: Vec<Seal>,
    /// Event signature (Ed25519 over canonical event with empty d and x fields)
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub x: String,
}

/// Interaction event - anchors data without key rotation.
///
/// Used to anchor attestations, delegations, or other data
/// in the KEL without changing keys.
///
/// Note: The `t` (type) field is handled by the `Event` enum's serde tag.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IxnEvent {
    /// Version string
    pub v: String,
    /// SAID of this event
    #[serde(default, skip_serializing_if = "Said::is_empty")]
    pub d: Said,
    /// Identifier prefix
    pub i: Prefix,
    /// Sequence number
    pub s: String,
    /// Previous event SAID
    pub p: Said,
    /// Anchored seals (the main purpose of IXN events)
    pub a: Vec<Seal>,
    /// Event signature (Ed25519 over canonical event with empty d and x fields)
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub x: String,
}

/// Unified event enum for processing any KERI event type.
///
/// Uses serde's tagged enum feature to deserialize based on the `t` field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    pub fn sequence(&self) -> Result<u64, SequenceParseError> {
        let s = match self {
            Event::Icp(e) => &e.s,
            Event::Rot(e) => &e.s,
            Event::Ixn(e) => &e.s,
        };
        s.parse::<u64>()
            .map_err(|_| SequenceParseError { raw: s.clone() })
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
    fn icp_event_serializes_correctly() {
        let icp = IcpEvent {
            v: KERI_VERSION.to_string(),
            d: Said::default(),
            i: Prefix::new_unchecked("ETest123".to_string()),
            s: "0".to_string(),
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
            s: "1".to_string(),
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
            s: "2".to_string(),
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
        assert_eq!(event.sequence().unwrap(), 0);
        assert!(event.previous().is_none());
    }

    #[test]
    fn event_enum_deserializes_rot_by_type() {
        let json = r#"{"v":"KERI10JSON","t":"rot","d":"ENew","i":"E123","s":"1","p":"EPrev","kt":"1","k":["DKey"],"nt":"1","n":["ENext"],"bt":"0","b":[]}"#;
        let event: Event = serde_json::from_str(json).unwrap();
        assert!(event.is_rotation());
        assert_eq!(event.sequence().unwrap(), 1);
        assert_eq!(event.previous().map(|s| s.as_str()), Some("EPrev"));
    }

    #[test]
    fn event_enum_deserializes_ixn_by_type() {
        let json =
            r#"{"v":"KERI10JSON","t":"ixn","d":"EIxn","i":"E123","s":"2","p":"EPrev","a":[]}"#;
        let event: Event = serde_json::from_str(json).unwrap();
        assert!(event.is_interaction());
        assert_eq!(event.sequence().unwrap(), 2);
        assert!(event.keys().is_none());
    }

    #[test]
    fn event_keys_and_next_accessors() {
        let icp = Event::Icp(IcpEvent {
            v: KERI_VERSION.to_string(),
            d: Said::default(),
            i: Prefix::new_unchecked("ETest".to_string()),
            s: "0".to_string(),
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
            s: "1".to_string(),
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
            s: "0".to_string(),
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

    #[test]
    fn rejects_malformed_sequence_number() {
        let event = Event::Icp(IcpEvent {
            v: KERI_VERSION.to_string(),
            d: Said::default(),
            i: Prefix::new_unchecked("ETest".to_string()),
            s: "not_a_number".to_string(),
            kt: "1".to_string(),
            k: vec!["DKey".to_string()],
            nt: "1".to_string(),
            n: vec!["ENext".to_string()],
            bt: "0".to_string(),
            b: vec![],
            a: vec![],
            x: String::new(),
        });

        let result = event.sequence();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.raw, "not_a_number");
    }
}
