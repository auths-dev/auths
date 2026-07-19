//! The `ReversalRail` port + adapters (plan RC-E3.5.4): the evidence core emits
//! the determination; a pluggable rail EXECUTES it or, when it can't, RECORDS a
//! claim. Auths never custodies — an executing adapter calls the rail's own API.
//!
//! Shipped adapters: [`EscrowReleaseRail`] (the clean path — a held escrow slice)
//! and [`ClaimOnlyRail`] (final rails: the determination becomes a proven debt).
//! Stripe / x402 refund adapters are rail-credential-gated and land with their
//! rail integrations, not here.

use std::path::PathBuf;

use auths_evidence::{RailHint, ReversalDetermination, reversal_signing_bytes};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::escrow::{EscrowRecord, RulingOutcome, evaluate_rule_track};

/// Errors a rail adapter can surface.
#[derive(Debug, Error)]
pub enum RailError {
    /// The adapter cannot execute this determination.
    #[error("reversal rail refused: {0}")]
    Refused(String),
    /// Adapter I/O failed.
    #[error("reversal rail I/O: {0}")]
    Io(String),
}

/// What a rail did with a determination.
#[derive(Debug, Clone, serde::Serialize)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub enum RailOutcome {
    /// The reversal executed on the rail.
    Executed {
        /// The rail-native execution reference.
        reference: String,
    },
    /// The rail cannot move the funds; the determination is recorded as a proven
    /// claim owed, collectible by escrow, reputation, or legal enforcement.
    ClaimRecorded {
        /// The recorded claim's content-addressed reference.
        claim_ref: String,
    },
}

/// The port: execute a determination or record it as a claim.
pub trait ReversalRail {
    /// The adapter's stable name.
    fn name(&self) -> &'static str;

    /// Execute the determination, or record the claim.
    fn execute(&self, det: &ReversalDetermination) -> Result<RailOutcome, RailError>;
}

/// The claim-only adapter: content-address the determination into a claims
/// directory. For final/irreversible rails the determination is a PROVEN DEBT,
/// not a clawback (RC-E3.5.7a).
pub struct ClaimOnlyRail {
    /// Where recorded claims persist.
    pub claims_dir: PathBuf,
}

impl ReversalRail for ClaimOnlyRail {
    fn name(&self) -> &'static str {
        "claim-only"
    }

    fn execute(&self, det: &ReversalDetermination) -> Result<RailOutcome, RailError> {
        let bytes = reversal_signing_bytes(det).map_err(|e| RailError::Io(e.to_string()))?;
        let digest = Sha256::digest(&bytes);
        let mut claim_ref = String::with_capacity(16);
        for byte in digest.iter().take(8) {
            use std::fmt::Write as _;
            let _ = write!(claim_ref, "{byte:02x}");
        }
        std::fs::create_dir_all(&self.claims_dir).map_err(|e| RailError::Io(e.to_string()))?;
        let path = self.claims_dir.join(format!("claim-{claim_ref}.json"));
        let json = serde_json::to_vec_pretty(det).map_err(|e| RailError::Io(e.to_string()))?;
        std::fs::write(&path, json).map_err(|e| RailError::Io(e.to_string()))?;
        Ok(RailOutcome::ClaimRecorded { claim_ref })
    }
}

/// The escrow adapter — the clean path (RC-E3.5.5): a reversal against a HELD
/// escrow slice. In reserved mode this adapter moves nothing itself (S2 — only a
/// buyer release settles); what it does is bind the determination to the record's
/// rule track: a refund the rule track already grants is EXECUTED (the unspent
/// reservation was never the seller's — closing returns it); anything else is
/// recorded as a claim against the deal.
pub struct EscrowReleaseRail {
    /// The verified escrow record the determination cites.
    pub record: EscrowRecord,
    /// The milestone the reversal concerns.
    pub milestone: usize,
    /// Where claims land when the rule track does not already grant the refund.
    pub claims_dir: PathBuf,
}

impl ReversalRail for EscrowReleaseRail {
    fn name(&self) -> &'static str {
        "escrow.release"
    }

    fn execute(&self, det: &ReversalDetermination) -> Result<RailOutcome, RailError> {
        if det.rail_hint != RailHint::EscrowRelease {
            return Err(RailError::Refused(format!(
                "determination hints {:?}, not escrow.release",
                det.rail_hint
            )));
        }
        let eval = evaluate_rule_track(&self.record, self.milestone)
            .map_err(|e| RailError::Refused(e.to_string()))?;
        match eval.outcome {
            RulingOutcome::Refund => Ok(RailOutcome::Executed {
                reference: format!(
                    "escrow:{}:milestone:{}:refund-by-rule",
                    self.record.id, self.milestone
                ),
            }),
            other => {
                // The slice is not refundable by rule — record the claim; the
                // subjective track (arbiter) or the buyer's release resolves it.
                let claim = ClaimOnlyRail {
                    claims_dir: self.claims_dir.clone(),
                }
                .execute(det)?;
                let RailOutcome::ClaimRecorded { claim_ref } = claim else {
                    return Err(RailError::Io("claim adapter returned execution".to_string()));
                };
                Ok(RailOutcome::ClaimRecorded {
                    claim_ref: format!("{claim_ref} (rule track: {other:?})"),
                })
            }
        }
    }
}

/// Pick the adapter a determination's hint names. Stripe/x402 refund adapters are
/// rail-credential-gated and not shipped here — their hints record claims.
pub fn rail_for(
    det: &ReversalDetermination,
    escrow: Option<(EscrowRecord, usize)>,
    claims_dir: PathBuf,
) -> Box<dyn ReversalRail> {
    match (det.rail_hint, escrow) {
        (RailHint::EscrowRelease, Some((record, milestone))) => Box::new(EscrowReleaseRail {
            record,
            milestone,
            claims_dir,
        }),
        _ => Box::new(ClaimOnlyRail { claims_dir }),
    }
}
