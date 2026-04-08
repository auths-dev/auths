//! Duplicity detection for KERI witness infrastructure.
//!
//! This module implements the "first-seen-always-seen" policy that is central
//! to KERI's duplicity detection mechanism. When a witness observes an event
//! for the first time, it records the event's SAID. Any subsequent event with
//! the same (prefix, sequence) but different SAID indicates duplicity.
//!
//! # First-Seen-Always-Seen Policy
//!
//! The policy is simple but powerful:
//!
//! 1. First time seeing (prefix, seq) → record the SAID
//! 2. Same (prefix, seq) with same SAID → OK (idempotent)
//! 3. Same (prefix, seq) with different SAID → **DUPLICITY**
//!
//! This works because KERI sequence numbers are monotonic and each sequence
//! number should map to exactly one event SAID.

use std::collections::HashMap;

use auths_keri::{Prefix, Said};

use super::error::{DuplicityEvidence, WitnessReport};
use super::receipt::Receipt;

/// Duplicity detector implementing first-seen-always-seen policy.
///
/// This detector maintains an in-memory map of (prefix, seq) → SAID.
/// It can detect when a controller presents different events with the
/// same sequence number to different witnesses (split-view attack).
///
/// # Thread Safety
///
/// This type is NOT thread-safe. For concurrent use, wrap in a `Mutex`
/// or `RwLock`.
///
/// # Example
///
/// ```rust
/// use auths_core::witness::DuplicityDetector;
/// use auths_keri::{Prefix, Said};
///
/// let mut detector = DuplicityDetector::new();
/// let prefix = Prefix::new_unchecked("EPrefix".into());
/// let said_a = Said::new_unchecked("ESAID_A".into());
/// let said_b = Said::new_unchecked("ESAID_B".into());
///
/// // First event at seq 0
/// assert!(detector.check_event(&prefix, 0, &said_a).is_none());
///
/// // Same event again (idempotent)
/// assert!(detector.check_event(&prefix, 0, &said_a).is_none());
///
/// // Different event at same seq → DUPLICITY!
/// let evidence = detector.check_event(&prefix, 0, &said_b);
/// assert!(evidence.is_some());
/// ```
#[derive(Debug, Clone, Default)]
pub struct DuplicityDetector {
    /// Map of (prefix, seq) → first-seen SAID
    first_seen: HashMap<(String, u64), String>,
}

impl DuplicityDetector {
    /// Create a new empty detector.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a detector with pre-populated state.
    ///
    /// This is useful for restoring state from persistent storage.
    pub fn with_state(first_seen: HashMap<(String, u64), String>) -> Self {
        Self { first_seen }
    }

    /// Check an event for duplicity.
    ///
    /// Implements the first-seen-always-seen policy:
    /// - First time: records SAID, returns None
    /// - Same SAID: returns None (idempotent)
    /// - Different SAID: returns Some(evidence)
    ///
    /// # Arguments
    ///
    /// * `prefix` - The KERI prefix of the identity
    /// * `seq` - The sequence number of the event
    /// * `said` - The SAID (Self-Addressing IDentifier) of the event
    ///
    /// # Returns
    ///
    /// * `None` - No duplicity detected
    /// * `Some(evidence)` - Duplicity detected with evidence
    pub fn check_event(
        &mut self,
        prefix: &Prefix,
        seq: u64,
        said: &Said,
    ) -> Option<DuplicityEvidence> {
        let key = (prefix.as_str().to_string(), seq);

        match self.first_seen.get(&key) {
            None => {
                // First time seeing this (prefix, seq)
                self.first_seen.insert(key, said.as_str().to_string());
                None
            }
            Some(existing_said) => {
                if existing_said == said.as_str() {
                    // Same event (idempotent)
                    None
                } else {
                    // DUPLICITY: different SAID for same (prefix, seq)
                    Some(DuplicityEvidence {
                        prefix: prefix.clone(),
                        sequence: seq,
                        event_a_said: Said::new_unchecked(existing_said.clone()),
                        event_b_said: said.clone(),
                        witness_reports: vec![],
                    })
                }
            }
        }
    }

    /// Check if a specific (prefix, seq) has been seen.
    pub fn has_seen(&self, prefix: &Prefix, seq: u64) -> bool {
        self.first_seen
            .contains_key(&(prefix.as_str().to_string(), seq))
    }

    /// Get the SAID for a (prefix, seq) if seen.
    pub fn get_said(&self, prefix: &Prefix, seq: u64) -> Option<Said> {
        self.first_seen
            .get(&(prefix.as_str().to_string(), seq))
            .map(|s| Said::new_unchecked(s.clone()))
    }

    /// Verify that a set of receipts are consistent (same event SAID).
    ///
    /// This checks that all receipts are for the same event. If receipts
    /// have different `d` (event SAID) fields, this indicates duplicity.
    ///
    /// # Arguments
    ///
    /// * `receipts` - The receipts to verify
    ///
    /// # Returns
    ///
    /// * `Ok(())` - All receipts are consistent
    /// * `Err(evidence)` - Inconsistent receipts indicate duplicity
    pub fn verify_receipts(&self, receipts: &[Receipt]) -> Result<(), DuplicityEvidence> {
        if receipts.is_empty() {
            return Ok(());
        }

        let first = &receipts[0];
        let expected_said = &first.d;

        for receipt in receipts.iter().skip(1) {
            if receipt.d != *expected_said {
                // Different receipts claim different SAIDs
                return Err(DuplicityEvidence {
                    prefix: Prefix::default(),
                    sequence: first.s.value(),
                    event_a_said: expected_said.clone(),
                    event_b_said: receipt.d.clone(),
                    witness_reports: receipts
                        .iter()
                        .map(|r| WitnessReport {
                            witness_id: r.i.as_str().to_string(),
                            observed_said: r.d.clone(),
                            observed_at: None,
                        })
                        .collect(),
                });
            }
        }

        Ok(())
    }

    /// Get the current state for persistence.
    pub fn state(&self) -> &HashMap<(String, u64), String> {
        &self.first_seen
    }

    /// Clear all recorded state.
    pub fn clear(&mut self) {
        self.first_seen.clear();
    }

    /// Get the number of events tracked.
    pub fn len(&self) -> usize {
        self.first_seen.len()
    }

    /// Check if the detector is empty.
    pub fn is_empty(&self) -> bool {
        self.first_seen.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix(s: &str) -> Prefix {
        Prefix::new_unchecked(s.into())
    }

    fn said(s: &str) -> Said {
        Said::new_unchecked(s.into())
    }

    #[test]
    fn first_seen_records_said() {
        let mut detector = DuplicityDetector::new();
        let p = prefix("EPrefix");

        // First event
        let result = detector.check_event(&p, 0, &said("ESAID_A"));
        assert!(result.is_none());

        // Verify it was recorded
        assert!(detector.has_seen(&p, 0));
        assert_eq!(detector.get_said(&p, 0), Some(said("ESAID_A")));
    }

    #[test]
    fn same_said_is_idempotent() {
        let mut detector = DuplicityDetector::new();
        let p = prefix("EPrefix");

        // First event
        detector.check_event(&p, 0, &said("ESAID_A"));

        // Same event again
        let result = detector.check_event(&p, 0, &said("ESAID_A"));
        assert!(result.is_none());
    }

    #[test]
    fn different_said_is_duplicity() {
        let mut detector = DuplicityDetector::new();
        let p = prefix("EPrefix");

        // First event
        detector.check_event(&p, 0, &said("ESAID_A"));

        // Different SAID at same seq
        let result = detector.check_event(&p, 0, &said("ESAID_B"));
        assert!(result.is_some());

        let evidence = result.unwrap();
        assert_eq!(evidence.prefix, "EPrefix");
        assert_eq!(evidence.sequence, 0);
        assert_eq!(evidence.event_a_said, "ESAID_A");
        assert_eq!(evidence.event_b_said, "ESAID_B");
    }

    #[test]
    fn different_seq_is_ok() {
        let mut detector = DuplicityDetector::new();
        let p = prefix("EPrefix");

        // Events at different sequences
        assert!(detector.check_event(&p, 0, &said("ESAID_A")).is_none());
        assert!(detector.check_event(&p, 1, &said("ESAID_B")).is_none());
        assert!(detector.check_event(&p, 2, &said("ESAID_C")).is_none());
    }

    #[test]
    fn different_prefix_is_ok() {
        let mut detector = DuplicityDetector::new();

        // Same seq but different prefixes
        assert!(
            detector
                .check_event(&prefix("EPrefix1"), 0, &said("ESAID_A"))
                .is_none()
        );
        assert!(
            detector
                .check_event(&prefix("EPrefix2"), 0, &said("ESAID_B"))
                .is_none()
        );
    }

    #[test]
    fn verify_receipts_consistent() {
        use auths_keri::{KeriSequence, VersionString};
        let detector = DuplicityDetector::new();

        let receipts = vec![
            Receipt {
                v: VersionString::placeholder(),
                t: "rct".into(),
                d: Said::new_unchecked("EEVENT_SAID".into()),
                i: Prefix::new_unchecked("W1".into()),
                s: KeriSequence::new(5),
            },
            Receipt {
                v: VersionString::placeholder(),
                t: "rct".into(),
                d: Said::new_unchecked("EEVENT_SAID".into()),
                i: Prefix::new_unchecked("W2".into()),
                s: KeriSequence::new(5),
            },
        ];

        assert!(detector.verify_receipts(&receipts).is_ok());
    }

    #[test]
    fn verify_receipts_inconsistent() {
        use auths_keri::{KeriSequence, VersionString};
        let detector = DuplicityDetector::new();

        let receipts = vec![
            Receipt {
                v: VersionString::placeholder(),
                t: "rct".into(),
                d: Said::new_unchecked("ESAID_A".into()),
                i: Prefix::new_unchecked("W1".into()),
                s: KeriSequence::new(5),
            },
            Receipt {
                v: VersionString::placeholder(),
                t: "rct".into(),
                d: Said::new_unchecked("ESAID_B".into()),
                i: Prefix::new_unchecked("W2".into()),
                s: KeriSequence::new(5),
            },
        ];

        let result = detector.verify_receipts(&receipts);
        assert!(result.is_err());

        let evidence = result.unwrap_err();
        assert_eq!(evidence.event_a_said, "ESAID_A");
        assert_eq!(evidence.event_b_said, "ESAID_B");
        assert_eq!(evidence.witness_reports.len(), 2);
    }

    #[test]
    fn verify_receipts_empty() {
        let detector = DuplicityDetector::new();
        assert!(detector.verify_receipts(&[]).is_ok());
    }

    #[test]
    fn with_state_restores() {
        let mut state = HashMap::new();
        state.insert(("EPrefix".to_string(), 0), "ESAID_A".to_string());
        state.insert(("EPrefix".to_string(), 1), "ESAID_B".to_string());

        let detector = DuplicityDetector::with_state(state);
        let p = prefix("EPrefix");

        assert!(detector.has_seen(&p, 0));
        assert!(detector.has_seen(&p, 1));
        assert!(!detector.has_seen(&p, 2));
    }

    #[test]
    fn len_and_is_empty() {
        let mut detector = DuplicityDetector::new();
        assert!(detector.is_empty());
        assert_eq!(detector.len(), 0);

        detector.check_event(&prefix("E1"), 0, &said("ES1"));
        detector.check_event(&prefix("E2"), 0, &said("ES2"));

        assert!(!detector.is_empty());
        assert_eq!(detector.len(), 2);

        detector.clear();
        assert!(detector.is_empty());
    }
}
