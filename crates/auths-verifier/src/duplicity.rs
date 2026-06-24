//! Detect diverging rotation events on a shared identity KEL.
//!
//! With a `kt=1` controller set and no witnesses, two controllers can each
//! sign a valid `rot` at the same sequence number independently. Both
//! rotations are cryptographically valid — there is no single source of
//! truth that orders them. Verifiers treat the KEL as duplicitous and
//! surface the conflict; the user resolves it out-of-band (typically by
//! running `auths device remove` on whichever side they trust).
//!
//! This module is read-only: it inspects a replay stream and reports
//! whether divergence is present. It never mutates state or rejects
//! otherwise-valid signatures. Callers decide policy (fail-open with a
//! warning, fail-closed, etc.) — the structured report is the contract.

use std::collections::HashMap;

use crate::types::IdentityDID;

/// A descriptor of one event as seen in a local replay stream.
///
/// Two events collide if they share `prefix` + `seq` but differ in
/// `said`. Same-SAID collisions are replicas of the same event and
/// never indicate duplicity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KelEventRef<'a> {
    /// The shared-KEL prefix (`did:keri:E…`) the event belongs to.
    pub prefix: &'a str,
    /// The event sequence number.
    pub seq: u64,
    /// The event's self-addressing identifier (the `d` field).
    pub said: &'a str,
}

/// Output of [`detect_duplicity`].
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum DuplicityReport {
    /// No conflicting events seen.
    Clean,
    /// Two or more events at the same `seq` have different SAIDs.
    Diverging {
        /// The shared-KEL prefix the conflict is on.
        shared_kel_prefix: IdentityDID,
        /// The sequence number where divergence starts.
        seq: u64,
        /// The conflicting event SAIDs, in the order they were observed.
        event_saids: Vec<String>,
    },
}

impl DuplicityReport {
    /// `true` when the report represents an actual divergence.
    pub fn is_diverging(&self) -> bool {
        matches!(self, DuplicityReport::Diverging { .. })
    }
}

/// Scan `events` for same-prefix same-seq events with differing SAIDs.
///
/// Returns the first divergence found (lowest `seq`). Callers that need
/// all divergences can filter the input and call repeatedly; for the
/// Stage-1 UX path — single warning banner — first-wins is enough.
///
/// Args:
/// * `events`: Events to scan. Can be any subset / order; duplicates of
///   the same SAID (i.e., replicas) are tolerated.
///
/// Usage:
/// ```
/// use auths_verifier::duplicity::{KelEventRef, detect_duplicity, DuplicityReport};
///
/// let events = vec![
///     KelEventRef { prefix: "did:keri:EShared", seq: 1, said: "Ea" },
///     KelEventRef { prefix: "did:keri:EShared", seq: 2, said: "Eb" },
///     KelEventRef { prefix: "did:keri:EShared", seq: 2, said: "Ec" },
/// ];
/// match detect_duplicity(&events) {
///     DuplicityReport::Diverging { seq, .. } => assert_eq!(seq, 2),
///     _ => panic!("expected divergence"),
/// }
/// ```
pub fn detect_duplicity(events: &[KelEventRef<'_>]) -> DuplicityReport {
    // Group observed SAIDs by (prefix, seq) while preserving first-seen
    // order so the report deterministically returns SAIDs in the order
    // they appeared in the input.
    let mut seen: HashMap<(String, u64), Vec<String>> = HashMap::new();
    let mut first_conflict: Option<(String, u64)> = None;

    for ev in events {
        let key = (ev.prefix.to_string(), ev.seq);
        let saids = seen.entry(key.clone()).or_default();
        if !saids.iter().any(|s| s == ev.said) {
            saids.push(ev.said.to_string());
            if saids.len() >= 2 && first_conflict.is_none() {
                first_conflict = Some(key);
            }
        }
    }

    if let Some((prefix, seq)) = first_conflict {
        let saids = seen.remove(&(prefix.clone(), seq)).unwrap_or_default();
        let shared_kel_prefix = {
            #[allow(clippy::disallowed_methods)]
            IdentityDID::new_unchecked(prefix)
        };
        return DuplicityReport::Diverging {
            shared_kel_prefix,
            seq,
            event_saids: saids,
        };
    }

    DuplicityReport::Clean
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev<'a>(prefix: &'a str, seq: u64, said: &'a str) -> KelEventRef<'a> {
        KelEventRef { prefix, seq, said }
    }

    #[test]
    fn empty_is_clean() {
        assert_eq!(detect_duplicity(&[]), DuplicityReport::Clean);
    }

    #[test]
    fn single_event_is_clean() {
        let events = vec![ev("did:keri:E1", 0, "EaaaA")];
        assert_eq!(detect_duplicity(&events), DuplicityReport::Clean);
    }

    #[test]
    fn sequential_rots_are_clean() {
        // Different seq values are not duplicity — that's a normal chain.
        let events = vec![
            ev("did:keri:E1", 0, "EincpA"),
            ev("did:keri:E1", 1, "ErotA"),
            ev("did:keri:E1", 2, "ErotB"),
        ];
        assert_eq!(detect_duplicity(&events), DuplicityReport::Clean);
    }

    #[test]
    fn identical_said_at_same_seq_is_clean() {
        // Replicated event (same SAID seen twice — e.g., network redelivery)
        // must not trigger duplicity.
        let events = vec![ev("did:keri:E1", 2, "Erot"), ev("did:keri:E1", 2, "Erot")];
        assert_eq!(detect_duplicity(&events), DuplicityReport::Clean);
    }

    #[test]
    fn two_different_saids_at_same_seq_is_diverging() {
        let events = vec![
            ev("did:keri:E1", 0, "Eincp"),
            ev("did:keri:E1", 2, "ErotA"),
            ev("did:keri:E1", 2, "ErotB"),
        ];
        match detect_duplicity(&events) {
            DuplicityReport::Diverging {
                shared_kel_prefix,
                seq,
                event_saids,
            } => {
                assert_eq!(shared_kel_prefix.as_str(), "did:keri:E1");
                assert_eq!(seq, 2);
                assert_eq!(event_saids, vec!["ErotA".to_string(), "ErotB".to_string()]);
            }
            DuplicityReport::Clean => panic!("expected Diverging"),
        }
    }

    #[test]
    fn three_way_fork_reports_all_saids() {
        let events = vec![
            ev("did:keri:E1", 2, "ErotA"),
            ev("did:keri:E1", 2, "ErotB"),
            ev("did:keri:E1", 2, "ErotC"),
        ];
        match detect_duplicity(&events) {
            DuplicityReport::Diverging { event_saids, .. } => {
                assert_eq!(event_saids.len(), 3);
            }
            _ => panic!("expected three-way divergence"),
        }
    }

    #[test]
    fn icp_only_stream_is_clean() {
        let events = vec![ev("did:keri:E1", 0, "Eincp")];
        assert_eq!(detect_duplicity(&events), DuplicityReport::Clean);
    }

    #[test]
    fn concurrent_rotation_is_detected_or_prevented() {
        // The documented kt=1 accepted risk: with a single-signer shared KEL, two
        // controllers can each author a rotation at the same sequence, forking the KEL.
        // Authoring does not prevent it, so it must be surfaced — detect_duplicity flags
        // the two competing heads rather than silently accepting both as valid.
        let events = vec![
            ev("did:keri:EShared", 0, "Eicp"),
            ev("did:keri:EShared", 1, "Erot1"),
            ev("did:keri:EShared", 2, "ErotControllerA"),
            ev("did:keri:EShared", 2, "ErotControllerB"),
        ];
        match detect_duplicity(&events) {
            DuplicityReport::Diverging {
                shared_kel_prefix,
                seq,
                event_saids,
            } => {
                assert_eq!(shared_kel_prefix.as_str(), "did:keri:EShared");
                assert_eq!(seq, 2, "divergence is at the concurrent rotation");
                assert_eq!(event_saids.len(), 2);
            }
            DuplicityReport::Clean => {
                panic!("concurrent rotations at the same sequence must be flagged, not accepted")
            }
        }
    }

    #[test]
    fn diverging_report_is_diverging() {
        let report = DuplicityReport::Diverging {
            #[allow(clippy::disallowed_methods)]
            shared_kel_prefix: IdentityDID::new_unchecked("did:keri:E1".to_string()),
            seq: 2,
            event_saids: vec!["Ea".into(), "Eb".into()],
        };
        assert!(report.is_diverging());
        assert!(!DuplicityReport::Clean.is_diverging());
    }
}
