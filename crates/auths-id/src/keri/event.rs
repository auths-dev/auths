//! KERI event types: Inception (ICP), Rotation (ROT), Interaction (IXN).
//!
//! These events form the Key Event Log (KEL), a hash-chained sequence
//! that records all key lifecycle operations for a KERI identity.
//!
//! The canonical type definitions live in `auths-keri`. This module
//! re-exports them and adds `EventReceipts`, which requires `auths-core`.

pub use auths_keri::{
    CesrKey, ConfigTrait, Event, IcpEvent, IxnEvent, KERI_VERSION_PREFIX, KeriSequence, RotEvent,
    Threshold, VersionString,
};

use auths_core::witness::Receipt;
use std::collections::HashSet;

use super::types::Said;

/// Receipts attached to a KEL event.
///
/// Receipts are witness acknowledgments that prove an event was observed.
/// They are stored separately from the event itself, linked by SAID.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct EventReceipts {
    /// Event SAID these receipts are for
    pub event_said: Said,
    /// Collected receipts from witnesses
    pub receipts: Vec<Receipt>,
}

impl EventReceipts {
    /// Create a new EventReceipts collection, deduplicating by witness identifier.
    ///
    /// Args:
    /// * `event_said`: SAID of the event these receipts are for.
    /// * `receipts`: Receipts from witnesses.
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
    /// * `witness_count`: Size of the configured witness set.
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

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::keri::{Prefix, Seal};

    fn make_receipt(witness_id: &str) -> Receipt {
        Receipt {
            v: VersionString::placeholder(),
            t: "rct".into(),
            d: Said::new_unchecked("EReceipt".into()),
            i: Prefix::new_unchecked(witness_id.into()),
            s: KeriSequence::new(0),
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

    #[test]
    fn keri_version_constant_is_correct() {
        assert_eq!(KERI_VERSION_PREFIX, "KERI10JSON");
    }

    #[test]
    fn icp_event_is_reexported_and_works() {
        let icp = IcpEvent {
            v: VersionString::placeholder(),
            d: Said::default(),
            i: crate::keri::Prefix::new_unchecked("ETest123".to_string()),
            s: KeriSequence::new(0),
            kt: Threshold::Simple(1),
            k: vec![CesrKey::new_unchecked("DKey123".to_string())],
            nt: Threshold::Simple(1),
            n: vec![Said::new_unchecked("ENext456".to_string())],
            bt: Threshold::Simple(0),
            b: vec![],
            c: vec![],
            a: vec![Seal::digest("EAttest")],
            x: String::new(),
        };
        let json = serde_json::to_string(&icp).unwrap();
        assert!(json.contains("\"s\":\"0\""));
        assert!(json.contains("\"a\":"));
    }
}
