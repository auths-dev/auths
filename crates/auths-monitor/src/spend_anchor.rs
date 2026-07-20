//! Spend-anchor watching — duplicity detection and withholding-gap alerts.
//!
//! This mirrors the checkpoint-equivocation scan (`evidence::detect_cross_operator_equivocation`)
//! for spend anchors: pull observed anchors from peer logs, find `(seed_id,
//! index)` collisions with differing heads, and emit the `DuplicityProof`. The
//! proof itself is *constructed by `auths-anchor`*, not here — the watcher's job
//! is detection and publication (D1–D3), not protocol. The proof is a portable
//! JSON artifact any channel can carry; nothing about verifying it requires
//! contacting the witness that emitted it.

use auths_anchor::{Anchor, DuplicityProof};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// An anchor observed on some witness's log, tagged with where it was seen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedAnchor {
    /// The witness log the anchor was observed on.
    pub source: String,
    /// The observed anchor.
    pub anchor: Anchor,
}

/// A withholding-gap alert: the latest anchor for a watched seed is older than
/// the configured tolerance (`now − τ_latest > threshold`, FR-7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithholdingGap {
    /// The watched seed, lowercase-hex.
    pub seed_id: String,
    /// Seconds since the latest observed anchor.
    pub gap_seconds: i64,
    /// The configured tolerance in seconds.
    pub threshold_seconds: i64,
}

/// Scan observed anchors for a same-party fork at one `(seed_id, index)`.
///
/// Returns the first duplicity proof found, constructed by `auths-anchor`. Two
/// observations conflict when they share a seed and index but differ in head
/// and were signed by the same party key; anything else (a re-observation, a
/// different index) is not a fork.
///
/// Args:
/// * `observations`: anchors gathered from peer logs.
///
/// Usage:
/// ```ignore
/// if let Some(proof) = detect_spend_anchor_duplicity(&observed) {
///     publish(proof); // portable, offline-verifiable artifact
/// }
/// ```
pub fn detect_spend_anchor_duplicity(observations: &[ObservedAnchor]) -> Option<DuplicityProof> {
    for (i, a) in observations.iter().enumerate() {
        for b in &observations[i + 1..] {
            if a.anchor.seed_id == b.anchor.seed_id
                && a.anchor.index == b.anchor.index
                && a.anchor.head != b.anchor.head
                && let Ok(proof) = DuplicityProof::new(&a.anchor, &b.anchor)
            {
                return Some(proof);
            }
        }
    }
    None
}

/// Pull each watched seed's latest co-signed anchor from every watched
/// witness. Unreachable witnesses and unknown seeds are skipped (a watcher
/// tolerates partial visibility); whatever was observed feeds the duplicity
/// scan and the gap alerts.
///
/// Args:
/// * `client`: the shared HTTP client.
/// * `witnesses`: witness base URLs.
/// * `seeds`: watched seeds, lowercase-hex.
///
/// Usage:
/// ```ignore
/// let observed = fetch_observed_anchors(&client, &witnesses, &seeds).await;
/// if let Some(proof) = detect_spend_anchor_duplicity(&observed) { publish(proof); }
/// ```
pub async fn fetch_observed_anchors(
    client: &reqwest::Client,
    witnesses: &[String],
    seeds: &[String],
) -> Vec<ObservedAnchor> {
    #[derive(serde::Deserialize)]
    struct LatestBody {
        anchor: Anchor,
    }
    let mut observed = Vec::new();
    for witness in witnesses {
        for seed in seeds {
            let url = format!("{}/v1/anchor/{seed}", witness.trim_end_matches('/'));
            let response = client
                .get(&url)
                .timeout(std::time::Duration::from_secs(10))
                .send()
                .await;
            match response {
                Ok(resp) if resp.status().is_success() => match resp.json::<LatestBody>().await {
                    Ok(body) => observed.push(ObservedAnchor {
                        source: witness.clone(),
                        anchor: body.anchor,
                    }),
                    Err(e) => {
                        tracing::warn!(witness = %witness, seed = %seed, error = %e, "bad anchor body")
                    }
                },
                Ok(resp) if resp.status() == reqwest::StatusCode::NOT_FOUND => {}
                Ok(resp) => {
                    tracing::warn!(witness = %witness, seed = %seed, status = %resp.status(), "anchor read refused")
                }
                Err(e) => {
                    tracing::warn!(witness = %witness, seed = %seed, error = %e, "witness unreachable")
                }
            }
        }
    }
    observed
}

/// Raise a withholding-gap alert when the newest anchor for a seed is stale.
///
/// Args:
/// * `seed_id`: the watched seed, lowercase-hex.
/// * `latest_anchor_at`: timestamp of the newest observed anchor for the seed.
/// * `now`: the current instant.
/// * `threshold_seconds`: the tolerated silence in seconds.
pub fn withholding_gap(
    seed_id: &str,
    latest_anchor_at: DateTime<Utc>,
    now: DateTime<Utc>,
    threshold_seconds: i64,
) -> Option<WithholdingGap> {
    let gap_seconds = (now - latest_anchor_at).num_seconds();
    (gap_seconds > threshold_seconds).then(|| WithholdingGap {
        seed_id: seed_id.to_string(),
        gap_seconds,
        threshold_seconds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_anchor::{CurveType, Head, PartySignature, SeedId, WitnessSetRef};
    use ed25519_dalek::{Signer, SigningKey};

    fn signed(index: u64, head: [u8; 32]) -> Anchor {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let mut anchor = Anchor {
            seed_id: SeedId::derive("root", "agent", "seal"),
            index,
            head: Head::from_bytes(head),
            cumulative: index as u128,
            timestamp: chrono::TimeZone::timestamp_opt(&Utc, 1_700_000_000, 0).unwrap(),
            witness_set: WitnessSetRef {
                said: "EWit".into(),
                threshold: 1,
            },
            sig_party: PartySignature {
                curve: CurveType::Ed25519,
                public_key: sk.verifying_key().as_bytes().to_vec(),
                signature: Vec::new(),
            },
        };
        let msg = anchor.party_signing_bytes().unwrap();
        anchor.sig_party.signature = sk.sign(&msg).to_bytes().to_vec();
        anchor
    }

    fn observed(source: &str, anchor: Anchor) -> ObservedAnchor {
        ObservedAnchor {
            source: source.into(),
            anchor,
        }
    }

    #[test]
    fn detects_a_cross_log_fork() {
        let obs = vec![
            observed("w0", signed(5, [1u8; 32])),
            observed("w1", signed(5, [2u8; 32])),
        ];
        let proof = detect_spend_anchor_duplicity(&obs).expect("fork");
        proof.verify().unwrap();
    }

    #[test]
    fn ignores_matching_reobservations() {
        let obs = vec![
            observed("w0", signed(5, [1u8; 32])),
            observed("w1", signed(5, [1u8; 32])),
        ];
        assert!(detect_spend_anchor_duplicity(&obs).is_none());
    }

    #[test]
    fn gap_fires_past_threshold() {
        let now = chrono::TimeZone::timestamp_opt(&Utc, 1_700_010_000, 0).unwrap();
        let old = chrono::TimeZone::timestamp_opt(&Utc, 1_700_000_000, 0).unwrap();
        assert!(withholding_gap("ab", old, now, 3600).is_some());
        assert!(withholding_gap("ab", now, now, 3600).is_none());
    }

    #[test]
    fn gap_and_duplicity_produce_pushable_events() {
        let now = chrono::TimeZone::timestamp_opt(&Utc, 1_700_010_000, 0).unwrap();
        let old = chrono::TimeZone::timestamp_opt(&Utc, 1_700_000_000, 0).unwrap();
        let gap = withholding_gap("abc123", old, now, 3600).expect("gap past threshold");
        let gap_body = serde_json::json!({ "kind": "withholding", "event": gap });
        assert_eq!(gap_body["kind"], "withholding");
        assert_eq!(gap_body["event"]["seed_id"], "abc123");
        assert!(gap_body["event"]["gap_seconds"].as_i64().unwrap() > 3600);

        let obs = vec![
            observed("w0", signed(5, [1u8; 32])),
            observed("w1", signed(5, [2u8; 32])),
        ];
        let proof = detect_spend_anchor_duplicity(&obs).expect("fork");
        let proof_body = serde_json::json!({ "kind": "duplicity", "event": proof });
        assert_eq!(proof_body["kind"], "duplicity");
        let embedded: DuplicityProof = serde_json::from_value(proof_body["event"].clone()).unwrap();
        embedded.verify().unwrap();
    }
}
