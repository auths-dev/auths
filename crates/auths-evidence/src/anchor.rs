//! Anchor construction and verification — the head witness that turns absence
//! claims ("no other settled call", "no revocation") into checkable facts (§2.2).
//!
//! The composite head commits every source the verdicts' absence-facts depend on:
//! the spend-log binding head, both KEL digests, and the revocation surface — so
//! a bundle cannot claim `authorized` while silently omitting a same-instant
//! revocation that moves no KEL tip.
//!
//! Tier honesty: the treasury tier's committer signs `{fleet, count, cumulative}`
//! over the SPEND surface; the KEL/revocation components of the composite head
//! ride inside the bundle under first-seen semantics unless a witness tier also
//! covers them. The bundle always states its tier, so a verdict is never read as
//! stronger than its evidence.

use auths_mcp_core::{SPEND_LOG_GENESIS, TreasuryCheckpoint, verify_checkpoint_trail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::EvidenceError;
use crate::types::{AnchorRef, AnchorTier, RevocationFact, TreasuryCheck};

/// The by-value proof a treasury-tier anchor carries: the raw `checkpoints.jsonl`
/// lines plus the pinned committer key, so an air-gapped verifier re-checks the
/// trail with no further context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreasuryAnchorProof {
    /// The raw signed checkpoint lines, in order.
    pub checkpoints: Vec<String>,
    /// The pinned committer public key (compressed P-256, hex).
    pub public_key_hex: String,
    /// The scope the cumulative-equality check assumes. `"single-delegation"`
    /// means the fleet is exactly this one agent, so the checkpointed cumulative
    /// must equal the re-derived settled total of this one log. A multi-delegation
    /// fleet needs the fleet-wide sum and is not yet expressible here.
    pub scope: String,
}

/// The single-delegation scope marker.
pub const TREASURY_SCOPE_SINGLE: &str = "single-delegation";

fn hex_sha256(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Digest of a serialized KEL (canonical JSON over the whole event array) — the
/// KEL component of the composite head. Deterministic on both the build and the
/// offline-verify side because both hold the same embedded events.
///
/// Args:
/// * `events`: the KEL events as serialized JSON values, in order.
///
/// Usage:
/// ```ignore
/// let digest = kel_digest(&proof.agent_kel)?;
/// ```
pub fn kel_digest(events: &[serde_json::Value]) -> Result<String, EvidenceError> {
    let canon =
        json_canon::to_string(&events).map_err(|e| EvidenceError::Canonical(e.to_string()))?;
    Ok(hex_sha256(canon.as_bytes()))
}

/// The composite head H — a commitment over every source the verdicts' absence
/// facts depend on (§2.2(c)). Recomputable from a bundle's embedded proof alone.
///
/// Args:
/// * `spend_binding`: the spend-log binding head (`bindingₙ`, or the genesis sentinel).
/// * `agent_kel_digest` / `delegator_kel_digest`: [`kel_digest`] of each embedded KEL.
/// * `revocation`: the revocation surface as resolved at build time.
///
/// Usage:
/// ```ignore
/// let head = composite_head(&binding, &agent_digest, &root_digest, &revocation)?;
/// ```
pub fn composite_head(
    spend_binding: &str,
    agent_kel_digest: &str,
    delegator_kel_digest: &str,
    revocation: &Option<RevocationFact>,
) -> Result<String, EvidenceError> {
    let body = serde_json::json!({
        "v": "anchor-head/v1",
        "spendLogBinding": spend_binding,
        "agentKel": agent_kel_digest,
        "delegatorKel": delegator_kel_digest,
        "revocation": revocation,
    });
    let canon =
        json_canon::to_string(&body).map_err(|e| EvidenceError::Canonical(e.to_string()))?;
    Ok(hex_sha256(canon.as_bytes()))
}

/// Build a first-seen anchor — the documented bare default posture. `ts` is the
/// build observation instant; nobody else committed this head.
pub fn first_seen_anchor(head: String, kel_seq: u64, ts: DateTime<Utc>) -> AnchorRef {
    AnchorRef {
        tier: AnchorTier::FirstSeen,
        head,
        kel_seq,
        committer: None,
        proof: None,
        ts,
    }
}

/// Build a treasury-tier anchor from a verified checkpoint trail. The caller has
/// already verified the trail (via [`check_trail`]) and asserts the
/// single-delegation scope; `ts` is the FINAL checkpoint's own committed instant.
pub fn treasury_anchor(
    head: String,
    kel_seq: u64,
    trail_lines: Vec<String>,
    public_key_hex: String,
    last: &TreasuryCheckpoint,
) -> Result<AnchorRef, EvidenceError> {
    let proof = TreasuryAnchorProof {
        checkpoints: trail_lines,
        public_key_hex: public_key_hex.clone(),
        scope: TREASURY_SCOPE_SINGLE.to_string(),
    };
    let proof =
        serde_json::to_value(&proof).map_err(|e| EvidenceError::Canonical(e.to_string()))?;
    Ok(AnchorRef {
        tier: AnchorTier::Treasury,
        head,
        kel_seq,
        committer: Some(public_key_hex),
        proof: Some(proof),
        ts: last.at,
    })
}

/// The by-value proof a witness-tier anchor carries: the finalized anchor
/// itself (≥ t cosignatures + per-witness inclusion proofs), offline-checkable
/// exactly like a treasury proof (I-VERIFY-1). The tier ladder becomes real:
/// `treasury < witness < onchain`.
pub type WitnessAnchorProof = auths_anchor::FinalizedAnchor;

/// Build a witness-tier anchor from a finalized (t-of-N co-signed) anchor.
///
/// The caller has already collected ≥ t cosignatures; [`verify_anchor`]
/// re-checks them offline. The committer is the KEL-anchored witness-set SAID
/// the finalized anchor commits to, and `ts` is the anchor's own instant.
///
/// Args:
/// * `head`: the composite head this anchor covers.
/// * `kel_seq`: the KEL sequence at the anchored instant.
/// * `finalized`: the finalized anchor, carried by value.
///
/// Usage:
/// ```ignore
/// let anchor = witness_anchor(head, kel_seq, finalized)?;
/// ```
pub fn witness_anchor(
    head: String,
    kel_seq: u64,
    finalized: WitnessAnchorProof,
) -> Result<AnchorRef, EvidenceError> {
    let committer = finalized.anchor.witness_set.said.clone();
    let ts = finalized.anchor.timestamp;
    let proof =
        serde_json::to_value(&finalized).map_err(|e| EvidenceError::Canonical(e.to_string()))?;
    Ok(AnchorRef {
        tier: AnchorTier::Witness,
        head,
        kel_seq,
        committer: Some(committer),
        proof: Some(proof),
        ts,
    })
}

/// Verify a treasury checkpoint trail: one stable signer (pinned when supplied),
/// every signature valid under P-256, count + cumulative monotonic. Returns the
/// final checkpoint.
///
/// Args:
/// * `lines`: the raw `checkpoints.jsonl` lines.
/// * `expect_pubkey_hex`: the pinned committer key; `None` accepts the trail's own
///   (first-seen on the committer — weaker, stated by the caller's tier).
///
/// Usage:
/// ```ignore
/// let last = check_trail(&lines, Some(&pinned_hex))?;
/// ```
pub fn check_trail(
    lines: &[String],
    expect_pubkey_hex: Option<&str>,
) -> Result<TreasuryCheckpoint, EvidenceError> {
    verify_checkpoint_trail(lines, expect_pubkey_hex, |pk, msg, sig| {
        auths_crypto::typed_verify(auths_crypto::CurveType::P256, pk, msg, sig).is_ok()
    })
    .map_err(|e| EvidenceError::Treasury(e.to_string()))
}

/// The result of verifying an anchor against re-derived facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorCheck {
    /// The anchor verifies for its tier.
    Valid,
    /// The anchor does not verify; the reason is a stable code + detail.
    Invalid {
        /// A stable failure code (`anchor-unverifiable`, `stale-anchor`, …).
        code: &'static str,
        /// Human-readable detail.
        detail: String,
    },
}

/// Verify an anchor's tier-specific proof against the re-derived settled total.
///
/// * `treasury`: re-check the embedded trail against the pinned committer, then —
///   under single-delegation scope — require the final checkpointed cumulative to
///   equal `rederived_settled_cents` (a stale or forged trail fails here).
/// * `first-seen`: nothing to verify; the tier IS the statement that nobody committed.
/// * `witness`: re-check the embedded finalized anchor offline (≥ t cosignatures,
///   all in the declared set, inclusion proofs), then require its cumulative to
///   equal `rederived_settled_cents` and its instant to match `anchor.ts`.
/// * `onchain`: not yet wired — fail closed.
///
/// Args:
/// * `anchor`: the anchor to verify.
/// * `rederived_settled_cents`: the settled total re-derived from the embedded log.
///
/// Usage:
/// ```ignore
/// if let AnchorCheck::Invalid { code, .. } = verify_anchor(&anchor, settled) { deny(code) }
/// ```
pub fn verify_anchor(anchor: &AnchorRef, rederived_settled_cents: u64) -> AnchorCheck {
    match anchor.tier {
        AnchorTier::FirstSeen => AnchorCheck::Valid,
        AnchorTier::Treasury => {
            let Some(proof) = &anchor.proof else {
                return AnchorCheck::Invalid {
                    code: "anchor-unverifiable",
                    detail: "treasury anchor carries no proof".to_string(),
                };
            };
            let proof: TreasuryAnchorProof = match serde_json::from_value(proof.clone()) {
                Ok(p) => p,
                Err(e) => {
                    return AnchorCheck::Invalid {
                        code: "anchor-unverifiable",
                        detail: format!("treasury proof malformed: {e}"),
                    };
                }
            };
            let pinned = anchor.committer.as_deref().unwrap_or(&proof.public_key_hex);
            let last = match check_trail(&proof.checkpoints, Some(pinned)) {
                Ok(last) => last,
                Err(e) => {
                    return AnchorCheck::Invalid {
                        code: "anchor-unverifiable",
                        detail: e.to_string(),
                    };
                }
            };
            if proof.scope == TREASURY_SCOPE_SINGLE
                && last.cumulative_cents.get() != rederived_settled_cents
            {
                return AnchorCheck::Invalid {
                    code: "head-mismatch",
                    detail: format!(
                        "checkpointed cumulative {}c != re-derived settled {}c",
                        last.cumulative_cents.get(),
                        rederived_settled_cents
                    ),
                };
            }
            if last.at != anchor.ts {
                return AnchorCheck::Invalid {
                    code: "anchor-unverifiable",
                    detail: "anchor ts does not match the final checkpoint".to_string(),
                };
            }
            AnchorCheck::Valid
        }
        AnchorTier::Witness => {
            let Some(proof) = &anchor.proof else {
                return AnchorCheck::Invalid {
                    code: "anchor-unverifiable",
                    detail: "witness anchor carries no proof".to_string(),
                };
            };
            let finalized: WitnessAnchorProof = match serde_json::from_value(proof.clone()) {
                Ok(f) => f,
                Err(e) => {
                    return AnchorCheck::Invalid {
                        code: "anchor-unverifiable",
                        detail: format!("witness proof malformed: {e}"),
                    };
                }
            };
            if let Err(e) = auths_anchor::verify_finalized(&finalized) {
                return AnchorCheck::Invalid {
                    code: "anchor-unverifiable",
                    detail: e.to_string(),
                };
            }
            if finalized.anchor.cumulative != u128::from(rederived_settled_cents) {
                return AnchorCheck::Invalid {
                    code: "head-mismatch",
                    detail: format!(
                        "anchored cumulative {}c != re-derived settled {}c",
                        finalized.anchor.cumulative, rederived_settled_cents
                    ),
                };
            }
            if finalized.anchor.timestamp != anchor.ts {
                return AnchorCheck::Invalid {
                    code: "anchor-unverifiable",
                    detail: "anchor ts does not match the finalized anchor".to_string(),
                };
            }
            AnchorCheck::Valid
        }
        AnchorTier::Onchain => AnchorCheck::Invalid {
            code: "anchor-unverifiable",
            detail: "on-chain anchor tier not yet supported by this verifier".to_string(),
        },
    }
}

/// The AWN witness-tier freshness of a bundle whose head is this anchor.
///
/// A bundle self-reports `fresh` only when it carries a finalized quorum anchor
/// (witness tier); otherwise it is `unanchored` — freshness unknown, never
/// silently "fresh". The `stale` label is not a bundle's to assign about itself;
/// it arises when a relying party compares this bundle against a store's *newer*
/// finalized anchor (call [`auths_anchor::freshness`] with both indices).
///
/// Args:
/// * `anchor`: the bundle's as-of anchor.
pub fn anchor_freshness_of(anchor: &AnchorRef) -> auths_anchor::Freshness {
    if anchor.tier == AnchorTier::Witness
        && let Some(proof) = &anchor.proof
        && let Ok(finalized) = serde_json::from_value::<WitnessAnchorProof>(proof.clone())
    {
        let index = finalized.anchor.index;
        return auths_anchor::freshness(Some(index), Some(index));
    }
    auths_anchor::Freshness::Unanchored
}

/// Convert a verified trail's final checkpoint into the typed `audit/v1` field.
pub fn treasury_check_of(last: &TreasuryCheckpoint) -> TreasuryCheck {
    TreasuryCheck {
        fleet: last.fleet.clone(),
        count: last.count,
        cumulative_cents: last.cumulative_cents.get(),
        at: last.at,
    }
}

/// The spend-log binding head of an embedded log: the last record's commit
/// binding, or the genesis sentinel for an empty log.
pub fn spend_binding_head(records: &[auths_mcp_core::SpendLogRecord]) -> String {
    records
        .last()
        .map(|record| auths_mcp_core::call_commit_binding(&record.call_commit))
        .unwrap_or_else(|| SPEND_LOG_GENESIS.to_string())
}
