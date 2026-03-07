//! Error types for witness operations.
//!
//! This module defines the error types used by the async witness infrastructure,
//! including duplicity evidence for split-view detection.

use auths_verifier::keri::{Prefix, Said};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Evidence of duplicity (split-view attack) detected by witnesses.
///
/// When a controller presents different events with the same (prefix, seq)
/// to different witnesses, this evidence captures the conflicting SAIDs.
///
/// # Fields
///
/// - `prefix`: The KERI prefix of the identity
/// - `sequence`: The sequence number where duplicity was detected
/// - `event_a_said`: SAID of the first event seen
/// - `event_b_said`: SAID of the conflicting event
/// - `witness_reports`: Reports from witnesses that observed the conflict
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DuplicityEvidence {
    /// The KERI prefix of the identity
    pub prefix: Prefix,
    /// The sequence number where duplicity was detected
    pub sequence: u64,
    /// SAID of the first event seen (the "canonical" one)
    pub event_a_said: Said,
    /// SAID of the conflicting event
    pub event_b_said: Said,
    /// Reports from individual witnesses
    pub witness_reports: Vec<WitnessReport>,
}

impl fmt::Display for DuplicityEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Duplicity detected for {} at seq {}: {} vs {}",
            self.prefix, self.sequence, self.event_a_said, self.event_b_said
        )
    }
}

/// A report from a single witness about what it observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessReport {
    /// The witness identifier (DID)
    pub witness_id: String,
    /// The SAID this witness observed for the (prefix, seq)
    pub observed_said: Said,
    /// When this observation was made (ISO 8601)
    pub observed_at: Option<String>,
}

/// Errors that can occur during witness operations.
///
/// These errors cover the full range of failure modes for async witness
/// interactions, from network issues to security violations.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WitnessError {
    /// Network error communicating with witness.
    #[error("network error: {0}")]
    Network(String),

    /// Duplicity detected - the controller presented different events.
    ///
    /// This is a **security violation** indicating a potential split-view attack.
    #[error("duplicity detected: {0}")]
    Duplicity(DuplicityEvidence),

    /// The witness rejected the event.
    ///
    /// This can happen if the event is malformed, the witness doesn't track
    /// this identity, or the event fails validation.
    #[error("event rejected: {reason}")]
    Rejected {
        /// Human-readable reason for rejection
        reason: String,
    },

    /// Operation timed out.
    #[error("timeout after {0}ms")]
    Timeout(u64),

    /// Invalid receipt signature.
    #[error("invalid receipt signature from witness {witness_id}")]
    InvalidSignature {
        /// The witness that provided the invalid signature
        witness_id: String,
    },

    /// Insufficient receipts to meet threshold.
    #[error("insufficient receipts: got {got}, need {required}")]
    InsufficientReceipts {
        /// Number of receipts received
        got: usize,
        /// Number of receipts required
        required: usize,
    },

    /// Receipt is for wrong event.
    #[error("receipt SAID mismatch: expected {expected}, got {got}")]
    SaidMismatch {
        /// Expected event SAID
        expected: Said,
        /// Actual SAID in receipt
        got: Said,
    },

    /// Storage error.
    #[error("storage error: {0}")]
    Storage(String),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicity_evidence_display() {
        let evidence = DuplicityEvidence {
            prefix: Prefix::new_unchecked("EPrefix123".into()),
            sequence: 5,
            event_a_said: Said::new_unchecked("ESAID_A".into()),
            event_b_said: Said::new_unchecked("ESAID_B".into()),
            witness_reports: vec![],
        };
        let display = format!("{}", evidence);
        assert!(display.contains("EPrefix123"));
        assert!(display.contains("5"));
        assert!(display.contains("ESAID_A"));
        assert!(display.contains("ESAID_B"));
    }

    #[test]
    fn witness_error_variants() {
        let network_err = WitnessError::Network("connection refused".into());
        assert!(format!("{}", network_err).contains("network error"));

        let timeout_err = WitnessError::Timeout(5000);
        assert!(format!("{}", timeout_err).contains("5000ms"));

        let rejected_err = WitnessError::Rejected {
            reason: "invalid format".into(),
        };
        assert!(format!("{}", rejected_err).contains("invalid format"));
    }

    #[test]
    fn duplicity_evidence_serialization() {
        let evidence = DuplicityEvidence {
            prefix: Prefix::new_unchecked("EPrefix123".into()),
            sequence: 5,
            event_a_said: Said::new_unchecked("ESAID_A".into()),
            event_b_said: Said::new_unchecked("ESAID_B".into()),
            witness_reports: vec![WitnessReport {
                witness_id: "did:key:witness1".into(),
                observed_said: Said::new_unchecked("ESAID_A".into()),
                observed_at: Some("2024-01-01T00:00:00Z".into()),
            }],
        };

        let json = serde_json::to_string(&evidence).unwrap();
        let parsed: DuplicityEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(evidence, parsed);
    }
}
