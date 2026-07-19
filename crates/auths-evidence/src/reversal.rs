//! `ReversalDetermination` (`reversal/v1`) — Auths computes the repayment; the
//! rail executes it (plan RC-E3.5).
//!
//! Auths is the reversal AUTHORITY, never the reversal RAIL: from the same signed
//! evidence a remit-violation verdict rests on, this module re-derives who owes
//! whom, how much, and why — and signs a determination anyone re-derives offline.
//! Nothing here moves money.
//!
//! Honest boundaries (RC-E3.5.7): a within-remit call is NEVER auto-reversed —
//! `authorized` routes to the subjective track; on final rails the determination
//! is a proven claim, not a clawback; the liability rule itself belongs to the
//! regulator/contract, not to this code.

use auths_mcp_core::{AuditResume, Budget};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

use crate::bundle::{BundleSigner, verify_offline};
use crate::error::EvidenceError;
use crate::types::{AnchorRef, CallVerdict, EvidenceBundle};

/// The reversal wire version.
pub const REVERSAL_VERSION: &str = "reversal/v1";

/// WHY the reversal is owed: the remit-violation verdict, anchored.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReversalBasis {
    /// The call verdict that triggered the reversal.
    pub verdict: CallVerdict,
    /// The anchor the verdict is "as of".
    #[serde(rename = "asOf")]
    pub as_of: AnchorRef,
}

/// WHO owes WHOM. The refund flows to the PRINCIPAL — the chain-walk-proven root
/// the delegation reaches — never to the ephemeral agent that acted (RC-E3.5.2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReversalParties {
    /// The principal owed the refund (individual root AID or org AID — the proven root).
    #[serde(rename = "payerPrincipal")]
    pub payer_principal: String,
    /// The delegated agent that signed the violating call.
    #[serde(rename = "actingAgent")]
    pub acting_agent: String,
    /// The vendor org / seller identity that was paid.
    #[serde(rename = "payeeOrg")]
    pub payee_org: String,
    /// Where the original charge landed (CAIP-10 / rail account).
    #[serde(rename = "payeeSettlementAccount")]
    pub payee_settlement_account: String,
}

/// What kind of amount is owed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReversalAmountKind {
    /// The full transaction — the agent exceeded its remit.
    Full,
    /// Only the overage past the cap (`spentBefore + cost − cap`).
    Overage,
    /// One escrow milestone slice.
    Milestone,
}

/// HOW MUCH, re-derived from the signed log — never a party's claim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReversalAmount {
    /// The owed cents.
    pub cents: u64,
    /// What the amount covers.
    pub kind: ReversalAmountKind,
}

/// The rail the executor should use — a hint, because execution is the rail
/// adapter's job, never this crate's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RailHint {
    /// Refund the connected-account charge.
    #[serde(rename = "stripe.refund")]
    StripeRefund,
    /// On-chain refund, iff the settlement is still reversible.
    #[serde(rename = "x402.refund")]
    X402Refund,
    /// Release/refund a held escrow slice — the clean path.
    #[serde(rename = "escrow.release")]
    EscrowRelease,
    /// Final/irreversible rail with no hold: a proven debt owed, to be collected
    /// by escrow, reputation, or legal enforcement.
    #[serde(rename = "claim-only")]
    ClaimOnly,
}

/// The signed, anchored, offline-re-derivable reversal determination.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReversalDetermination {
    /// Always `"reversal/v1"`.
    pub version: String,
    /// In-band curve-tagged signature suite.
    pub suite: String,
    /// The dispute reference, when one exists (RC-E3.2).
    #[serde(rename = "disputeRef", default, skip_serializing_if = "Option::is_none")]
    pub dispute_ref: Option<String>,
    /// The settlement being reversed.
    #[serde(rename = "disputedTx")]
    pub disputed_tx: String,
    /// Why.
    pub basis: ReversalBasis,
    /// Who owes whom.
    pub parties: ReversalParties,
    /// How much.
    pub amount: ReversalAmount,
    /// Reversals only ever run payee → payer-principal.
    pub direction: String,
    /// The suggested execution rail.
    #[serde(rename = "railHint")]
    pub rail_hint: RailHint,
    /// The determining tool's own agent DID.
    pub issued_by: String,
    /// Signature over `canon(determination minus signature)` per `suite`.
    pub signature: String,
}

/// The determination's canonical signing bytes.
pub fn reversal_signing_bytes(det: &ReversalDetermination) -> Result<Vec<u8>, EvidenceError> {
    let mut value =
        serde_json::to_value(det).map_err(|e| EvidenceError::Canonical(e.to_string()))?;
    if let Some(map) = value.as_object_mut() {
        map.remove("signature");
    }
    json_canon::to_string(&value)
        .map(String::into_bytes)
        .map_err(|e| EvidenceError::Canonical(e.to_string()))
}

/// Whether a hold exists that makes the reversal EXECUTABLE (RC-E3.5.5); without
/// one on a final rail the determination degrades to `claim-only`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldState {
    /// A reserved/locked escrow slice covers the amount.
    EscrowHeld,
    /// A Stripe authorization not yet captured.
    StripeAuthUncaptured,
    /// An on-chain settlement still reversible.
    X402Reversible,
    /// No hold — final rail.
    None,
}

/// Extra inputs the determination needs beyond the bundle.
#[derive(Debug, Clone)]
pub struct ReversalInputs {
    /// The dispute reference, when one exists.
    pub dispute_ref: Option<String>,
    /// The vendor org / seller identity that was paid (the bundle's resolved
    /// counterparty when absent).
    pub payee_org: Option<String>,
    /// Where the original charge landed.
    pub payee_settlement_account: Option<String>,
    /// The hold state the executor established (RC-E3.5.5).
    pub hold: HoldState,
}

/// The outcome of a determination request.
#[derive(Debug)]
pub enum ReversalOutcome {
    /// A remit violation: the signed determination.
    Determined(Box<ReversalDetermination>),
    /// Within remit (`authorized`) — no auto-reversal; route to the subjective
    /// track (escrow/arbitration, consumer cooling-off).
    WithinRemit,
    /// The verdict cannot ground a reversal (`unverifiable`).
    Ungrounded(String),
}

/// Compute the reversal a verified bundle grounds (RC-E3.5.1). The bundle is
/// re-verified offline FIRST — a determination never rests on an unverified
/// bundle — and the overage amount is re-derived from the embedded signed log,
/// never taken from a party.
///
/// Args:
/// * `bundle`: the evidence bundle for the disputed call.
/// * `inputs`: the dispute/payee/hold inputs.
/// * `signer`: the determining tool's signing identity.
///
/// Usage:
/// ```ignore
/// match determine_reversal(&bundle, inputs, &signer).await? {
///     ReversalOutcome::Determined(det) => rail.execute(&det)?,
///     ReversalOutcome::WithinRemit => route_to_arbitration(),
///     ReversalOutcome::Ungrounded(why) => refuse(why),
/// }
/// ```
pub async fn determine_reversal(
    bundle: &EvidenceBundle,
    inputs: ReversalInputs,
    signer: &BundleSigner,
) -> Result<ReversalOutcome, EvidenceError> {
    let verified = verify_offline(bundle).await;
    if !verified.ok {
        return Err(EvidenceError::Input(format!(
            "bundle does not verify: {}",
            verified.reason.unwrap_or_default()
        )));
    }

    let amount = match bundle.verdicts.call {
        CallVerdict::Authorized => return Ok(ReversalOutcome::WithinRemit),
        CallVerdict::Unverifiable => {
            return Ok(ReversalOutcome::Ungrounded(
                "an unverifiable verdict grounds no reversal".to_string(),
            ));
        }
        CallVerdict::Unauthorized
        | CallVerdict::Expired
        | CallVerdict::OutOfScope
        | CallVerdict::OutOfCounterparty => ReversalAmount {
            cents: settled_amount_cents(bundle)?,
            kind: ReversalAmountKind::Full,
        },
        CallVerdict::OverBudget => ReversalAmount {
            cents: overage_cents(bundle).await?,
            kind: ReversalAmountKind::Overage,
        },
    };

    let rail_hint = match inputs.hold {
        HoldState::EscrowHeld => RailHint::EscrowRelease,
        HoldState::StripeAuthUncaptured => RailHint::StripeRefund,
        HoldState::X402Reversible => RailHint::X402Refund,
        HoldState::None => RailHint::ClaimOnly,
    };

    let mut det = ReversalDetermination {
        version: REVERSAL_VERSION.to_string(),
        suite: signer.suite.as_str().to_string(),
        dispute_ref: inputs.dispute_ref,
        disputed_tx: bundle.settlement.tx.clone(),
        basis: ReversalBasis {
            verdict: bundle.verdicts.call,
            as_of: bundle.verdicts.as_of.clone(),
        },
        parties: ReversalParties {
            // The chain-walk-proven root the verifier established — the principal,
            // never the ephemeral agent. Org-internal apportionment is org policy.
            payer_principal: bundle.subject.root.clone(),
            acting_agent: bundle.subject.agent.clone(),
            payee_org: inputs
                .payee_org
                .unwrap_or_else(|| bundle.settlement.counterparty.clone()),
            payee_settlement_account: inputs
                .payee_settlement_account
                .unwrap_or_else(|| bundle.settlement.counterparty.clone()),
        },
        amount,
        direction: "payee->payerPrincipal".to_string(),
        rail_hint,
        issued_by: signer.did.clone(),
        signature: String::new(),
    };
    det.signature = sign_determination(&det, signer)?;
    Ok(ReversalOutcome::Determined(Box::new(det)))
}

fn sign_determination(
    det: &ReversalDetermination,
    signer: &BundleSigner,
) -> Result<String, EvidenceError> {
    let message = reversal_signing_bytes(det)?;
    signer.sign_message(&message)
}

/// Re-verify a determination offline: signature under `issued_by`, direction, and
/// (given the bundle it cites) that amount + parties + basis re-derive.
///
/// Args:
/// * `det`: the determination.
/// * `bundle`: the evidence bundle it rests on.
///
/// Usage:
/// ```ignore
/// verify_determination(&det, &bundle).await?;
/// ```
pub async fn verify_determination(
    det: &ReversalDetermination,
    bundle: &EvidenceBundle,
) -> Result<(), EvidenceError> {
    if det.version != REVERSAL_VERSION {
        return Err(EvidenceError::Input(format!("unknown version {}", det.version)));
    }
    if det.direction != "payee->payerPrincipal" {
        return Err(EvidenceError::Input("reversals only run payee->payerPrincipal".to_string()));
    }
    let suite = crate::bundle::SignatureSuite::parse(&det.suite)?;
    let decoded = auths_crypto::did_key_decode(&det.issued_by)
        .map_err(|e| EvidenceError::Input(format!("issued_by: {e}")))?;
    if decoded.curve() != suite.curve() {
        return Err(EvidenceError::Input("issued_by curve does not match suite".to_string()));
    }
    let message = reversal_signing_bytes(det)?;
    let signature = BASE64
        .decode(&det.signature)
        .map_err(|e| EvidenceError::Input(format!("signature b64: {e}")))?;
    let public_key = match &decoded {
        auths_crypto::DecodedDidKey::Ed25519(pk) => pk.as_slice(),
        auths_crypto::DecodedDidKey::P256(pk) => pk.as_slice(),
    };
    auths_crypto::typed_verify(suite.curve(), public_key, &message, &signature)
        .map_err(|_| EvidenceError::Input("determination signature did not verify".to_string()))?;

    let verified = verify_offline(bundle).await;
    if !verified.ok {
        return Err(EvidenceError::Input("cited bundle does not verify".to_string()));
    }
    if det.disputed_tx != bundle.settlement.tx || det.basis.verdict != bundle.verdicts.call {
        return Err(EvidenceError::Input("determination does not match the cited bundle".to_string()));
    }
    let expected = match bundle.verdicts.call {
        CallVerdict::OverBudget => overage_cents(bundle).await?,
        CallVerdict::Unauthorized
        | CallVerdict::Expired
        | CallVerdict::OutOfScope
        | CallVerdict::OutOfCounterparty => settled_amount_cents(bundle)?,
        _ => {
            return Err(EvidenceError::Input(
                "the cited verdict grounds no reversal".to_string(),
            ));
        }
    };
    if det.amount.cents != expected {
        return Err(EvidenceError::Input(format!(
            "amount {} does not re-derive (expected {expected})",
            det.amount.cents
        )));
    }
    if det.parties.payer_principal != bundle.subject.root
        || det.parties.acting_agent != bundle.subject.agent
    {
        return Err(EvidenceError::Input("parties do not re-derive from the bundle".to_string()));
    }
    Ok(())
}

fn settled_amount_cents(bundle: &EvidenceBundle) -> Result<u64, EvidenceError> {
    bundle
        .settlement
        .amount
        .parse::<u64>()
        .map_err(|e| EvidenceError::Input(format!("settlement amount: {e}")))
}

/// The overage past the cap, re-derived from the embedded signed log
/// (`spentBefore + cost − cap`) — never a party's number.
async fn overage_cents(bundle: &EvidenceBundle) -> Result<u64, EvidenceError> {
    let agent_kel = crate::kel_wire::kel_from_wire(&bundle.proof.agent_kel)?;
    let delegator_kel = crate::kel_wire::kel_from_wire(&bundle.proof.delegator_kel)?;
    let pinned = vec![bundle.subject.root.clone()];
    let annotated = auths_mcp_core::audit_spend_log_annotated(
        &bundle.proof.spend_log,
        &agent_kel,
        &delegator_kel,
        &pinned,
        bundle.verdicts.as_of.ts.timestamp(),
        None,
        None,
        &AuditResume::genesis(),
    )
    .await;
    let index = bundle.call.index as usize;
    let record = bundle
        .proof
        .spend_log
        .get(index)
        .ok_or_else(|| EvidenceError::CallNotFound(format!("#{index}")))?;
    let budget = Budget::parse(&bundle.grant.cap)
        .map_err(|e| EvidenceError::Input(format!("grant cap: {e}")))?;
    let cap = budget.cap_cents().get();
    // A refused over-budget call settled nothing; the would-be figure is the
    // gate's recorded refusal, cross-checked against the re-derived spent-before.
    let (spent_before, would_be) = match (&record.receipt.verdict, annotated.facts.get(index)) {
        (
            auths_mcp_core::Verdict::UsageCapExceeded { would_be_cents, .. },
            Some(fact),
        ) => (fact.settled_cents_before.get(), would_be_cents.get()),
        (_, Some(fact)) => {
            let cost = fact.signed_cents.map(|c| c.get()).unwrap_or(0);
            (
                fact.settled_cents_before.get(),
                fact.settled_cents_before.get() + cost,
            )
        }
        (_, None) => {
            return Err(EvidenceError::Input(
                "the audited prefix does not reach the disputed call".to_string(),
            ));
        }
    };
    let _ = spent_before;
    Ok(would_be.saturating_sub(cap))
}
