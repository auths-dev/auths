//! rct cross-read equivocation monitor — a SAMPLING tripwire, not a guarantee.
//!
//! The monitor cross-reads pinned operators at the same sequence and flags
//! same-seq/different-SAID forks. It compares **content** (the SAID each operator
//! first saw at a sequence, via the W.1.2 `/said/{seq}` endpoint), never head
//! *numbers* — two operators can report the identical `latest_seq` while hiding a
//! fork. Detection is explicitly **sampled**: a targeted partition that forks to a
//! victim while showing the monitor a consistent history evades it. The
//! non-repudiable guarantee is the W.3 gossip layer.
//!
//! Liveness falls out for free: polling each operator records reachability, so an
//! operator being *down* is surfaced as a distinct signal from equivocation.

use auths_infra_http::HttpAsyncWitnessClient;
use auths_keri::Prefix;
use auths_keri::Said;
use auths_keri::witness::{DuplicityEvidence, WitnessError, WitnessReport};
use chrono::{DateTime, Utc};

/// One operator's observation at a sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperatorObservation {
    /// The operator reported this SAID at the sequence.
    Said(Said),
    /// The operator is reachable but has not seen this sequence — a gap, not a
    /// fork. Treating a gap as divergence would be a false positive.
    Gap,
    /// The operator could not be reached (a liveness signal, not equivocation).
    Unreachable,
}

/// One operator's reading at a sequence.
#[derive(Debug, Clone)]
pub struct OperatorReading {
    /// The operator's pinned AID.
    pub aid: Prefix,
    /// What it reported at the sequence.
    pub observation: OperatorObservation,
}

/// Per-operator liveness recorded by the polling loop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorLiveness {
    /// The operator's pinned AID.
    pub aid: Prefix,
    /// Whether the operator answered this round.
    pub reachable: bool,
    /// When it last answered successfully (injected clock).
    pub last_success: Option<DateTime<Utc>>,
    /// Observed round-trip latency in milliseconds, if reachable.
    pub latency_ms: Option<u64>,
}

/// The verdict from cross-reading operators at a single sequence.
#[derive(Debug, Clone, Default)]
pub struct CrossReadVerdict {
    /// The sequence checked.
    pub sequence: u128,
    /// Same-seq/different-SAID forks — typed evidence naming the disagreeing
    /// operators.
    pub conflicts: Vec<DuplicityEvidence>,
    /// Operators reachable but missing this sequence (incomplete view).
    pub incomplete: Vec<Prefix>,
    /// Unreachable operators (a liveness signal, distinct from equivocation).
    pub down: Vec<Prefix>,
    /// The SAID the reporting operators unanimously agree on, if any.
    pub agreed_said: Option<Said>,
}

impl CrossReadVerdict {
    /// The honest detection-strength label for any surface showing this verdict.
    pub const DETECTION_LABEL: &'static str = "sampled, not yet non-repudiable";

    /// Whether a fork was flagged this round.
    pub fn has_conflict(&self) -> bool {
        !self.conflicts.is_empty()
    }
}

/// Cross-read operators at one sequence and classify the result.
///
/// Compares the SAID each operator reports (content), never head numbers. Pure
/// and deterministic.
///
/// Args:
/// * `prefix`: The identity whose sequence is being cross-read.
/// * `sequence`: The sequence number checked across operators.
/// * `readings`: Each operator's observation at the sequence.
/// * `now`: Injected timestamp for the evidence reports.
///
/// Usage:
/// ```ignore
/// let verdict = cross_read_verdict(&prefix, seq, &readings, now);
/// if verdict.has_conflict() { /* alert: sampled fork */ }
/// ```
pub fn cross_read_verdict(
    prefix: &Prefix,
    sequence: u128,
    readings: &[OperatorReading],
    now: DateTime<Utc>,
) -> CrossReadVerdict {
    let mut verdict = CrossReadVerdict {
        sequence,
        ..Default::default()
    };

    let mut reporters: Vec<(Prefix, Said)> = Vec::new();
    for reading in readings {
        match &reading.observation {
            OperatorObservation::Said(said) => reporters.push((reading.aid.clone(), said.clone())),
            OperatorObservation::Gap => verdict.incomplete.push(reading.aid.clone()),
            OperatorObservation::Unreachable => verdict.down.push(reading.aid.clone()),
        }
    }

    let Some((canonical_aid, canonical_said)) = reporters.first().cloned() else {
        return verdict;
    };
    verdict.agreed_said = Some(canonical_said.clone());

    let stamp = now.to_rfc3339();
    for (aid, said) in reporters.iter().skip(1) {
        if *said != canonical_said {
            verdict.agreed_said = None;
            verdict.conflicts.push(DuplicityEvidence {
                prefix: prefix.clone(),
                sequence,
                event_a_said: canonical_said.clone(),
                event_b_said: said.clone(),
                witness_reports: vec![
                    WitnessReport {
                        witness_id: canonical_aid.as_str().to_string(),
                        observed_said: canonical_said.clone(),
                        observed_at: Some(stamp.clone()),
                    },
                    WitnessReport {
                        witness_id: aid.as_str().to_string(),
                        observed_said: said.clone(),
                        observed_at: Some(stamp.clone()),
                    },
                ],
            });
        }
    }

    verdict
}

/// Whether shedding the `down` operators drops the reachable set below `threshold`.
///
/// A `true` result is an at-risk-quorum warning the monitor must surface — never
/// silently ignore.
///
/// Args:
/// * `total`: Total pinned operators.
/// * `down`: How many are unreachable this round.
/// * `threshold`: The quorum threshold (`k` of `n`).
///
/// Usage:
/// ```ignore
/// if quorum_at_risk(operators.len(), verdict.down.len(), threshold) { warn(); }
/// ```
pub fn quorum_at_risk(total: usize, down: usize, threshold: usize) -> bool {
    total.saturating_sub(down) < threshold
}

/// Map a `said_at_seq` client result to an [`OperatorObservation`].
fn classify_observation(result: &Result<Option<Said>, WitnessError>) -> OperatorObservation {
    match result {
        Ok(Some(said)) => OperatorObservation::Said(said.clone()),
        Ok(None) => OperatorObservation::Gap,
        Err(_) => OperatorObservation::Unreachable,
    }
}

/// Poll every operator's first-seen SAID at `sequence` and produce the cross-read
/// verdict plus per-operator liveness.
///
/// One round of the monitor loop; the caller chooses `sequence` (typically from a
/// prior `/head` read) and repeats on its own cadence.
///
/// Args:
/// * `prefix`: The identity to cross-read.
/// * `sequence`: The sequence to compare across operators.
/// * `operators`: Pinned `(aid, client)` pairs.
/// * `now`: Injected timestamp for liveness/evidence.
///
/// Usage:
/// ```ignore
/// let (verdict, liveness) = monitor_round(&prefix, seq, &operators, now).await;
/// ```
pub async fn monitor_round(
    prefix: &Prefix,
    sequence: u64,
    operators: &[(Prefix, HttpAsyncWitnessClient)],
    now: DateTime<Utc>,
) -> (CrossReadVerdict, Vec<OperatorLiveness>) {
    let mut readings = Vec::with_capacity(operators.len());
    let mut liveness = Vec::with_capacity(operators.len());

    for (aid, client) in operators {
        let started = std::time::Instant::now();
        let result = client.said_at_seq(prefix, sequence).await;
        let latency_ms = started.elapsed().as_millis() as u64;

        let observation = classify_observation(&result);
        let reachable = !matches!(observation, OperatorObservation::Unreachable);
        liveness.push(OperatorLiveness {
            aid: aid.clone(),
            reachable,
            last_success: reachable.then_some(now),
            latency_ms: reachable.then_some(latency_ms),
        });
        readings.push(OperatorReading {
            aid: aid.clone(),
            observation,
        });
    }

    (
        cross_read_verdict(prefix, sequence as u128, &readings, now),
        liveness,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix() -> Prefix {
        Prefix::new_unchecked("EIdentity000000000000000000000000000000000000".to_string())
    }

    fn aid(n: u8) -> Prefix {
        Prefix::new_unchecked(format!("BWitness{n:0>36}"))
    }

    fn said(s: &str) -> Said {
        Said::new_unchecked(s.to_string())
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-06-08T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn reading(n: u8, obs: OperatorObservation) -> OperatorReading {
        OperatorReading {
            aid: aid(n),
            observation: obs,
        }
    }

    #[test]
    fn same_seq_same_said_no_flag() {
        let readings = vec![
            reading(1, OperatorObservation::Said(said("EEventA"))),
            reading(2, OperatorObservation::Said(said("EEventA"))),
        ];
        let verdict = cross_read_verdict(&prefix(), 5, &readings, now());
        assert!(!verdict.has_conflict());
        assert_eq!(verdict.agreed_said, Some(said("EEventA")));
    }

    #[test]
    fn same_seq_different_said_is_flagged_naming_witnesses() {
        let readings = vec![
            reading(1, OperatorObservation::Said(said("EEventA"))),
            reading(2, OperatorObservation::Said(said("EEventB"))),
        ];
        let verdict = cross_read_verdict(&prefix(), 5, &readings, now());
        assert!(verdict.has_conflict());
        let evidence = &verdict.conflicts[0];
        assert_eq!(evidence.sequence, 5);
        // Names both disagreeing operators.
        let named: Vec<&str> = evidence
            .witness_reports
            .iter()
            .map(|r| r.witness_id.as_str())
            .collect();
        assert!(named.contains(&aid(1).as_str()));
        assert!(named.contains(&aid(2).as_str()));
        assert_eq!(verdict.agreed_said, None);
    }

    #[test]
    fn head_numbers_equal_but_saids_differ_still_flagged() {
        // Both operators are at the SAME sequence (so a head-number comparison
        // would see equality) yet report different SAIDs — content comparison
        // catches the fork the head-number trap would miss.
        let readings = vec![
            reading(1, OperatorObservation::Said(said("EHonest"))),
            reading(2, OperatorObservation::Said(said("EForked"))),
        ];
        let verdict = cross_read_verdict(&prefix(), 9, &readings, now());
        assert!(verdict.has_conflict());
    }

    #[test]
    fn one_has_seq_other_gap_is_incomplete_not_duplicity() {
        let readings = vec![
            reading(1, OperatorObservation::Said(said("EEventA"))),
            reading(2, OperatorObservation::Gap),
        ];
        let verdict = cross_read_verdict(&prefix(), 5, &readings, now());
        assert!(!verdict.has_conflict());
        assert_eq!(verdict.incomplete, vec![aid(2)]);
    }

    #[test]
    fn unreachable_is_down_distinct_from_equivocation() {
        let readings = vec![
            reading(1, OperatorObservation::Said(said("EEventA"))),
            reading(2, OperatorObservation::Unreachable),
        ];
        let verdict = cross_read_verdict(&prefix(), 5, &readings, now());
        assert!(!verdict.has_conflict());
        assert_eq!(verdict.down, vec![aid(2)]);
        // 3 pinned, 1 down, threshold 3 → quorum at risk.
        assert!(quorum_at_risk(3, 1, 3));
        assert!(!quorum_at_risk(3, 1, 2));
    }

    #[test]
    fn detection_label_is_sampled() {
        assert!(CrossReadVerdict::DETECTION_LABEL.contains("sampled"));
        assert!(CrossReadVerdict::DETECTION_LABEL.contains("not yet non-repudiable"));
    }

    #[test]
    fn classify_maps_client_results() {
        assert_eq!(
            classify_observation(&Ok(Some(said("E1")))),
            OperatorObservation::Said(said("E1"))
        );
        assert_eq!(classify_observation(&Ok(None)), OperatorObservation::Gap);
        assert_eq!(
            classify_observation(&Err(WitnessError::Timeout(5000))),
            OperatorObservation::Unreachable
        );
    }
}
