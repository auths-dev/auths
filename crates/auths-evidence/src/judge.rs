//! `judge_call` / `judge_log` — total functions over proven facts (§2.4).
//!
//! No cryptography happens here: every chain-of-custody fact arrives already
//! re-derived by the one audit walk. The judges only order and compare — the
//! "report is the only API" rule with no exceptions.
//!
//! Two rules the arithmetic encodes:
//! * **D1** — the gate's recorded, chained verdict is the ground truth; the budget
//!   arithmetic RE-CHECKS it. Divergence returns `unverifiable` (a flagged
//!   reconciliation), never a silent override of what the gate recorded.
//! * **D2** — `spent_before` is the re-derived CROSS-RAIL settled counter (the
//!   walk's own running total), never a raw single-rail sum.

use auths_mcp_core::{AuditVerdict, Budget, RecordFact, SpendLogRecord, Verdict};

use crate::error::EvidenceError;
use crate::types::{
    AnchorRef, BundleGrant, CallVerdict, LogVerdict, PolicyDecision, RevocationFact,
};

/// A read-only view of a resolved chain — constructible from a live
/// [`crate::resolve_chain::ResolvedChain`] or from a bundle's embedded proof, so
/// the build-time judge and the offline re-check run the identical function over
/// identical facts.
#[derive(Debug)]
pub struct ChainView<'a> {
    /// The grant the verdicts judge against.
    pub grant: &'a BundleGrant,
    /// The spend-log records, in order.
    pub records: &'a [SpendLogRecord],
    /// Per-record re-derived facts from the audit walk.
    pub facts: &'a [RecordFact],
    /// The whole-log audit verdict.
    pub audit_verdict: &'a AuditVerdict,
    /// The anchor the verdicts are "as of".
    pub anchor: &'a AnchorRef,
    /// The revocation surface as resolved at build time.
    pub revocation: Option<&'a RevocationFact>,
}

/// Judge one identified call — first failure wins; each check presumes the ones
/// above it (§2.4).
///
/// Args:
/// * `view`: the proven facts.
/// * `index`: the call's index in the log.
/// * `counterparty`: the resolved counterparty the settlement paid.
///
/// Usage:
/// ```ignore
/// let verdict = judge_call(&view, call_index, &settlement.counterparty);
/// ```
pub fn judge_call(view: &ChainView<'_>, index: usize, counterparty: &str) -> CallVerdict {
    // A chain whose integrity broke (tampered proof, dropped record, cost or
    // budget mismatch) cannot establish completeness for ANY call.
    match view.audit_verdict {
        AuditVerdict::Consistent(_) => {}
        AuditVerdict::Revoked { at } => {
            // The walk stopped at the revocation: calls at/after it are signed
            // under a dead delegation. Calls before it are judged over the
            // verified prefix below.
            if index >= *at {
                return CallVerdict::Unauthorized;
            }
        }
        _ => return CallVerdict::Unverifiable,
    }

    let Some(record) = view.records.get(index) else {
        return CallVerdict::Unverifiable;
    };
    let Some(fact) = view.facts.get(index) else {
        return CallVerdict::Unverifiable;
    };

    // A revocation recorded at or before the anchor instant kills the delegation
    // for every covered call — including a TEL revocation that moves no KEL tip.
    if let Some(revocation) = view.revocation
        && revocation.ts.is_none_or(|ts| ts <= view.anchor.ts)
    {
        return CallVerdict::Unauthorized;
    }

    // The verifier's own re-derived per-call verdict, first.
    match &fact.rederived_verdict {
        Verdict::ProofUnauthentic { .. } | Verdict::Revoked => return CallVerdict::Unauthorized,
        Verdict::AgentExpired => return CallVerdict::Expired,
        Verdict::OutsideAgentScope { .. } => return CallVerdict::OutOfScope,
        Verdict::Stale => return CallVerdict::Unverifiable,
        Verdict::Allowed
        | Verdict::UsageCapExceeded { .. }
        | Verdict::MeteredAmountRequired { .. }
        | Verdict::UsageCounterRolledBack { .. } => {}
    }

    // Grant validity window, on the call's own judged instant.
    let at = record.receipt.at;
    if at < view.grant.issued_at || at > view.grant.expires_at {
        return CallVerdict::Expired;
    }

    // The counterparty remit — the single adapter implementation (§2.4).
    if view.grant.counterparty_policy.decide(counterparty) == PolicyDecision::Deny {
        return CallVerdict::OutOfCounterparty;
    }

    judge_budget(view, record, fact)
}

/// The budget leg: re-check the gate's RECORDED decision against the re-derived
/// settled arithmetic (D1/D2). Agreement lets the recorded verdict stand;
/// divergence is `unverifiable` — evidence of gate misbehavior or a bug, surfaced
/// rather than papered over.
fn judge_budget(view: &ChainView<'_>, record: &SpendLogRecord, fact: &RecordFact) -> CallVerdict {
    let Ok(budget) = Budget::parse(&view.grant.cap) else {
        return CallVerdict::Unverifiable;
    };
    let cap_cents = budget.cap_cents().get();
    let spent_before = fact.settled_cents_before.get();
    let cost = fact.signed_cents.map(|c| c.get()).unwrap_or(0);
    let rederived_over = spent_before + cost > cap_cents;

    match &record.receipt.verdict {
        Verdict::Allowed | Verdict::AgentExpired => {
            if rederived_over {
                // The gate granted what the settled-only re-derivation refuses —
                // possibly in-flight reserves the log cannot see. Flag, never override.
                CallVerdict::Unverifiable
            } else {
                CallVerdict::Authorized
            }
        }
        Verdict::UsageCapExceeded {
            cap_cents: recorded_cap,
            would_be_cents,
        } => {
            // A refused call settled nothing, so the re-check works over the
            // gate's own recorded numbers plus the re-derived spent-before.
            let recorded_over = would_be_cents.get() > recorded_cap.get();
            if recorded_over && recorded_cap.get() == cap_cents {
                CallVerdict::OverBudget
            } else {
                CallVerdict::Unverifiable
            }
        }
        // Refusals the offline arithmetic cannot re-derive (a counter rollback, a
        // missing metered amount) — surfaced as unverifiable, never guessed.
        Verdict::MeteredAmountRequired { .. } | Verdict::UsageCounterRolledBack { .. } => {
            CallVerdict::Unverifiable
        }
        // The gate never records these as a CALL verdict; a log that claims one is
        // internally inconsistent.
        Verdict::OutsideAgentScope { .. }
        | Verdict::Revoked
        | Verdict::ProofUnauthentic { .. }
        | Verdict::Stale => CallVerdict::Unverifiable,
    }
}

/// Judge the whole log — the auditor's answer, surfaced from the one audit walk,
/// never recomputed here.
pub fn judge_log(audit_verdict: &AuditVerdict) -> LogVerdict {
    match audit_verdict {
        AuditVerdict::Consistent(_) => LogVerdict::Consistent,
        _ => LogVerdict::Inconsistent,
    }
}

/// Locate the identified call a payment reference names: a rail settlement
/// reference (`charge_ref`), a signed-call proof SHA, or an explicit `#<index>`.
///
/// Args:
/// * `records`: the resolved log.
/// * `payment_ref`: the reference the caller holds.
///
/// Usage:
/// ```ignore
/// let index = locate_call(&chain.records, "0xtxhash…")?;
/// ```
pub fn locate_call(records: &[SpendLogRecord], payment_ref: &str) -> Result<usize, EvidenceError> {
    if let Some(index) = payment_ref.strip_prefix('#')
        && let Ok(index) = index.parse::<usize>()
    {
        return if index < records.len() {
            Ok(index)
        } else {
            Err(EvidenceError::CallNotFound(payment_ref.to_string()))
        };
    }
    records
        .iter()
        .position(|record| {
            record.receipt.charge_ref.as_deref() == Some(payment_ref)
                || record.receipt.proof_ref == payment_ref
        })
        .ok_or_else(|| EvidenceError::CallNotFound(payment_ref.to_string()))
}
