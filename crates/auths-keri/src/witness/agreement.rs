//! KAWA (KERI Algorithm for Witness Agreement).
//!
//! Tracks receipt collection per event and determines when an event
//! has sufficient witness agreement to be accepted.
//!
//! The spec rule: controller designates N witnesses and threshold M.
//! An event is accepted when M-of-N witnesses provide valid receipts.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;

use crate::types::{Prefix, Said, Threshold};

/// Status of an event in the witness agreement process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgreementStatus {
    /// Waiting for more receipts.
    Pending {
        /// How many receipts have been collected so far.
        collected: usize,
    },
    /// Sufficient receipts collected — event accepted.
    Accepted,
}

/// Tracks witness agreement for pending events.
///
/// Events are submitted and then receipts are collected. Once the backer
/// threshold is met, the event is marked as accepted.
///
/// Usage:
/// ```
/// use auths_keri::witness::agreement::WitnessAgreement;
/// use auths_keri::{Prefix, Said, Threshold};
///
/// let agreement = WitnessAgreement::new(1000);
/// let prefix = Prefix::new_unchecked("ETest".into());
/// let said = Said::new_unchecked("ESAID".into());
/// let bt = Threshold::Simple(2);
/// let backers = [
///     Prefix::new_unchecked("witness1".into()),
///     Prefix::new_unchecked("witness2".into()),
///     Prefix::new_unchecked("witness3".into()),
/// ];
///
/// agreement.submit_event(&prefix, 0, &said, &bt, &backers);
/// agreement.add_receipt(&prefix, 0, &said, "witness1");
/// agreement.add_receipt(&prefix, 0, &said, "witness2");
/// assert!(agreement.is_accepted(&prefix, 0, &said));
/// ```
pub struct WitnessAgreement {
    state: Mutex<AgreementState>,
}

struct AgreementState {
    /// Pending events: (prefix, sn, said) → set of witness IDs that have receipted
    pending: HashMap<(String, u64, String), PendingEvent>,
    /// FIFO eviction queue
    eviction_order: VecDeque<(String, u64, String)>,
    /// Maximum number of pending events (FIFO eviction)
    max_pending: usize,
    /// Accepted events: (prefix, sn, said) → true
    accepted: HashSet<(String, u64, String)>,
}

struct PendingEvent {
    /// Designated backer AIDs in `b[]` order; the index is the backer position.
    witness_list: Vec<String>,
    /// Backer AIDs that have receipted (deduplicated).
    received: HashSet<String>,
    /// Typed backer threshold, evaluated over the receipted backers' indices.
    threshold: Threshold,
}

impl PendingEvent {
    /// Whether the receipted backers satisfy the typed threshold over `b[]`.
    ///
    /// Each receipted backer AID is mapped to its position in `b[]`; the typed
    /// [`Threshold`] then decides over those indices. A receipt whose AID is not
    /// a designated backer contributes no index and cannot count toward quorum.
    fn is_satisfied(&self) -> bool {
        let indices: Vec<u32> = self
            .received
            .iter()
            .filter_map(|aid| self.witness_list.iter().position(|w| w == aid))
            .map(|pos| pos as u32)
            .collect();
        self.threshold
            .is_satisfied(&indices, self.witness_list.len())
    }
}

impl WitnessAgreement {
    /// Create a new witness agreement tracker with the given max pending queue size.
    pub fn new(max_pending: usize) -> Self {
        Self {
            state: Mutex::new(AgreementState {
                pending: HashMap::new(),
                eviction_order: VecDeque::new(),
                max_pending,
                accepted: HashSet::new(),
            }),
        }
    }

    /// Submit an event for witness agreement tracking.
    ///
    /// Args:
    /// * `prefix` - Identity prefix.
    /// * `sn` - Sequence number.
    /// * `said` - Event SAID.
    /// * `bt` - Typed backer threshold (simple or weighted).
    /// * `witnesses` - Designated backer AIDs in `b[]` order. A receipt counts
    ///   toward quorum only when its witness AID appears here; its position is
    ///   the index the typed threshold is evaluated over.
    pub fn submit_event(
        &self,
        prefix: &Prefix,
        sn: u64,
        said: &Said,
        bt: &Threshold,
        witnesses: &[Prefix],
    ) {
        let key = (prefix.as_str().to_string(), sn, said.as_str().to_string());
        let pending = PendingEvent {
            witness_list: witnesses.iter().map(|w| w.as_str().to_string()).collect(),
            received: HashSet::new(),
            threshold: bt.clone(),
        };

        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());

        // Already accepted?
        if state.accepted.contains(&key) {
            return;
        }

        // A threshold already satisfied by zero receipts (e.g. a 0-of-n backer
        // threshold) is accepted immediately.
        if pending.is_satisfied() {
            state.accepted.insert(key);
            return;
        }

        // FIFO eviction if at capacity
        while state.pending.len() >= state.max_pending {
            if let Some(evicted) = state.eviction_order.pop_front() {
                state.pending.remove(&evicted);
            } else {
                break;
            }
        }

        if !state.pending.contains_key(&key) {
            state.eviction_order.push_back(key.clone());
            state.pending.insert(key, pending);
        }
    }

    /// Add a witness receipt for an event.
    ///
    /// Returns the agreement status after adding the receipt.
    pub fn add_receipt(
        &self,
        prefix: &Prefix,
        sn: u64,
        said: &Said,
        witness_id: &str,
    ) -> AgreementStatus {
        let key = (prefix.as_str().to_string(), sn, said.as_str().to_string());

        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());

        if state.accepted.contains(&key) {
            return AgreementStatus::Accepted;
        }

        if let Some(pending) = state.pending.get_mut(&key) {
            pending.received.insert(witness_id.to_string());
            let satisfied = pending.is_satisfied();
            let collected = pending.received.len();
            if satisfied {
                state.pending.remove(&key);
                state.accepted.insert(key);
                return AgreementStatus::Accepted;
            }
            AgreementStatus::Pending { collected }
        } else {
            AgreementStatus::Pending { collected: 0 }
        }
    }

    /// Check if an event has been accepted (sufficient witness agreement).
    pub fn is_accepted(&self, prefix: &Prefix, sn: u64, said: &Said) -> bool {
        let key = (prefix.as_str().to_string(), sn, said.as_str().to_string());
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.accepted.contains(&key)
    }

    /// Get the current status of an event.
    pub fn status(&self, prefix: &Prefix, sn: u64, said: &Said) -> AgreementStatus {
        let key = (prefix.as_str().to_string(), sn, said.as_str().to_string());
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.accepted.contains(&key) {
            AgreementStatus::Accepted
        } else if let Some(pending) = state.pending.get(&key) {
            AgreementStatus::Pending {
                collected: pending.received.len(),
            }
        } else {
            AgreementStatus::Pending { collected: 0 }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// Designated backers `witness1..witnessN`, in `b[]` order.
    fn backers(n: usize) -> Vec<Prefix> {
        (1..=n)
            .map(|i| Prefix::new_unchecked(format!("witness{i}")))
            .collect()
    }

    #[test]
    fn event_accepted_after_threshold_receipts() {
        let agreement = WitnessAgreement::new(100);
        let prefix = Prefix::new_unchecked("ETest".into());
        let said = Said::new_unchecked("ESAID".into());
        let bt = Threshold::Simple(2);

        agreement.submit_event(&prefix, 0, &said, &bt, &backers(3));

        let s1 = agreement.add_receipt(&prefix, 0, &said, "witness1");
        assert_eq!(s1, AgreementStatus::Pending { collected: 1 });

        let s2 = agreement.add_receipt(&prefix, 0, &said, "witness2");
        assert_eq!(s2, AgreementStatus::Accepted);

        assert!(agreement.is_accepted(&prefix, 0, &said));
    }

    #[test]
    fn event_stays_pending_with_insufficient_receipts() {
        let agreement = WitnessAgreement::new(100);
        let prefix = Prefix::new_unchecked("ETest".into());
        let said = Said::new_unchecked("ESAID".into());
        let bt = Threshold::Simple(3);

        agreement.submit_event(&prefix, 0, &said, &bt, &backers(5));
        agreement.add_receipt(&prefix, 0, &said, "witness1");
        agreement.add_receipt(&prefix, 0, &said, "witness2");

        assert!(!agreement.is_accepted(&prefix, 0, &said));
    }

    #[test]
    fn zero_threshold_immediately_accepted() {
        let agreement = WitnessAgreement::new(100);
        let prefix = Prefix::new_unchecked("ETest".into());
        let said = Said::new_unchecked("ESAID".into());
        let bt = Threshold::Simple(0);

        agreement.submit_event(&prefix, 0, &said, &bt, &backers(0));
        assert!(agreement.is_accepted(&prefix, 0, &said));
    }

    #[test]
    fn duplicate_receipt_from_same_witness_not_double_counted() {
        let agreement = WitnessAgreement::new(100);
        let prefix = Prefix::new_unchecked("ETest".into());
        let said = Said::new_unchecked("ESAID".into());
        let bt = Threshold::Simple(2);

        agreement.submit_event(&prefix, 0, &said, &bt, &backers(3));
        agreement.add_receipt(&prefix, 0, &said, "witness1");
        agreement.add_receipt(&prefix, 0, &said, "witness1"); // duplicate

        assert!(!agreement.is_accepted(&prefix, 0, &said));
    }

    #[test]
    fn fifo_eviction_at_capacity() {
        let agreement = WitnessAgreement::new(2);
        let prefix = Prefix::new_unchecked("ETest".into());
        let bt = Threshold::Simple(2);

        // Submit 3 events with capacity 2
        for i in 0..3 {
            let said = Said::new_unchecked(format!("ESAID{i}"));
            agreement.submit_event(&prefix, i as u64, &said, &bt, &backers(3));
        }

        // First event should have been evicted
        let said0 = Said::new_unchecked("ESAID0".into());
        let status = agreement.status(&prefix, 0, &said0);
        assert_eq!(status, AgreementStatus::Pending { collected: 0 });
    }

    #[test]
    fn weighted_bt_requires_quorum() {
        // F-31: a weighted bt must be honored, not collapsed to a counter.
        // `[[1/2, 1/2, 1/2]]` over 3 backers needs any two (1/2 + 1/2 = 1).
        // Under the old `simple_value().unwrap_or(0)` collapse the threshold
        // became 0 and the event was accepted immediately with zero receipts.
        use crate::types::Fraction;
        let half = || Fraction {
            numerator: 1,
            denominator: 2,
        };
        let bt = Threshold::Weighted(vec![vec![half(), half(), half()]]);

        let agreement = WitnessAgreement::new(100);
        let prefix = Prefix::new_unchecked("ETest".into());
        let said = Said::new_unchecked("ESAID".into());

        agreement.submit_event(&prefix, 0, &said, &bt, &backers(3));
        assert!(
            !agreement.is_accepted(&prefix, 0, &said),
            "zero receipts must not satisfy a weighted bt"
        );

        // One receipt: 1/2 < 1 -> still pending.
        agreement.add_receipt(&prefix, 0, &said, "witness1");
        assert!(!agreement.is_accepted(&prefix, 0, &said));

        // Second receipt: 1/2 + 1/2 = 1 -> quorum reached.
        agreement.add_receipt(&prefix, 0, &said, "witness2");
        assert!(agreement.is_accepted(&prefix, 0, &said));
    }
}
