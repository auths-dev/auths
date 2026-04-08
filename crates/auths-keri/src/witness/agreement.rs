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
///
/// agreement.submit_event(&prefix, 0, &said, &bt, 3);
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
    witnesses: HashSet<String>,
    threshold: u64,
    #[allow(dead_code)]
    witness_count: usize,
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
    /// * `bt` - Backer threshold (simple only for now).
    /// * `witness_count` - Total number of designated witnesses.
    pub fn submit_event(
        &self,
        prefix: &Prefix,
        sn: u64,
        said: &Said,
        bt: &Threshold,
        witness_count: usize,
    ) {
        let key = (prefix.as_str().to_string(), sn, said.as_str().to_string());
        let threshold = bt.simple_value().unwrap_or(0);

        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());

        // Already accepted?
        if state.accepted.contains(&key) {
            return;
        }

        // Zero threshold = immediately accepted
        if threshold == 0 {
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
            state.pending.insert(
                key,
                PendingEvent {
                    witnesses: HashSet::new(),
                    threshold,
                    witness_count,
                },
            );
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
            pending.witnesses.insert(witness_id.to_string());
            if pending.witnesses.len() as u64 >= pending.threshold {
                state.pending.remove(&key);
                state.accepted.insert(key);
                return AgreementStatus::Accepted;
            }
            AgreementStatus::Pending {
                collected: pending.witnesses.len(),
            }
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
                collected: pending.witnesses.len(),
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

    #[test]
    fn event_accepted_after_threshold_receipts() {
        let agreement = WitnessAgreement::new(100);
        let prefix = Prefix::new_unchecked("ETest".into());
        let said = Said::new_unchecked("ESAID".into());
        let bt = Threshold::Simple(2);

        agreement.submit_event(&prefix, 0, &said, &bt, 3);

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

        agreement.submit_event(&prefix, 0, &said, &bt, 5);
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

        agreement.submit_event(&prefix, 0, &said, &bt, 0);
        assert!(agreement.is_accepted(&prefix, 0, &said));
    }

    #[test]
    fn duplicate_receipt_from_same_witness_not_double_counted() {
        let agreement = WitnessAgreement::new(100);
        let prefix = Prefix::new_unchecked("ETest".into());
        let said = Said::new_unchecked("ESAID".into());
        let bt = Threshold::Simple(2);

        agreement.submit_event(&prefix, 0, &said, &bt, 3);
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
            agreement.submit_event(&prefix, i as u64, &said, &bt, 3);
        }

        // First event should have been evicted
        let said0 = Said::new_unchecked("ESAID0".into());
        let status = agreement.status(&prefix, 0, &said0);
        assert_eq!(status, AgreementStatus::Pending { collected: 0 });
    }
}
