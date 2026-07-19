//! Dispute-evidence assembly (plan RC-E3.1) — the retainer-grade bundle.
//!
//! Everything a human arbiter/auditor/chargeback desk needs in ONE signed
//! artifact: the authorization chain, the escrow record when the deal used one
//! (by value — never read out of anyone's identity registry), a minimized
//! compliance cross-link, a human-readable render, and the build-time online
//! freshness stamp (design D4). Stateless — every input is passed in or pinned.

use auths_evidence::{
    BuildOpts, BundleSigner, CallVerdict, ChainInput, EvidenceBundle, EvidenceError,
    OnlineFreshness, ResolvedChain, build_bundle, judge_call, locate_call, resolve_chain,
};
use chrono::{DateTime, Utc};

use crate::escrow::{EscrowRecord, evaluate_rule_track};

/// The optional inputs a dispute bundle can carry beyond the chain itself.
#[derive(Debug, Clone, Default)]
pub struct DisputeInputs {
    /// The escrow record, by value, when the deal used one.
    pub escrow_record: Option<serde_json::Value>,
    /// The pinned escrow-anchor committer key, when the caller pins one.
    pub escrow_anchor_key_hex: Option<String>,
    /// A minimized compliance cross-link `{ ref, passed }` — never a full
    /// screening payload (security S3).
    pub compliance: Option<serde_json::Value>,
    /// The consumer's freshness policy: the oldest acceptable head age, in
    /// seconds, for the online re-check to still stamp `contradicted: false`.
    pub head_max_age_secs: Option<u64>,
}

/// Verify an escrow record that arrived by value and reduce it to the minimized
/// summary that travels in a portable bundle (S3): ids, heads, per-milestone
/// states and rule-track outcomes — never party payloads.
///
/// Args:
/// * `raw`: the record as received.
/// * `pinned_anchor_key_hex`: the anchor committer pin, when the caller holds one.
///
/// Usage:
/// ```ignore
/// let summary = verify_escrow_record(&raw, None)?;
/// ```
pub fn verify_escrow_record(
    raw: &serde_json::Value,
    pinned_anchor_key_hex: Option<&str>,
) -> Result<serde_json::Value, EvidenceError> {
    let record = EscrowRecord::verify_value(raw, pinned_anchor_key_hex)
        .map_err(|e| EvidenceError::Input(format!("escrow record: {e}")))?;
    let milestone_count = match record.open_terms() {
        Ok(crate::escrow::EscrowEventBody::Open { milestones, .. }) => milestones.len(),
        _ => 0,
    };
    let mut milestones = Vec::with_capacity(milestone_count);
    for index in 0..milestone_count {
        let state = record.milestone_state(index);
        let rule = evaluate_rule_track(&record, index)
            .map(|eval| serde_json::json!({ "outcome": eval.outcome, "proof": eval.proof }))
            .unwrap_or(serde_json::Value::Null);
        milestones.push(serde_json::json!({
            "index": index,
            "state": state,
            "rule": rule,
        }));
    }
    Ok(serde_json::json!({
        "id": record.id,
        "head": record.head(),
        "events": record.events.len(),
        "anchors": record.anchors.len(),
        "milestones": milestones,
    }))
}

/// Reduce a compliance cross-link to the minimized form that may travel (S3):
/// only a reference and a pass/fail — the full screening result never enters a
/// portable, re-shareable bundle.
pub fn minimize_compliance(raw: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "ref": raw.get("ref").cloned().unwrap_or(serde_json::Value::Null),
        "passed": raw.get("passed").cloned().unwrap_or(serde_json::Value::Null),
    })
}

/// The human render — built over HASHED fields only, never re-expanding them (S3).
pub fn render_human(
    chain: &ResolvedChain,
    call_index: usize,
    escrow: Option<&serde_json::Value>,
) -> String {
    let record = chain.records.get(call_index);
    let tool = record.map(|r| r.receipt.tool.as_str()).unwrap_or("?");
    let args_hash = record
        .map(|r| r.receipt.action_hash.as_str())
        .unwrap_or("?");
    let at = record
        .map(|r| r.receipt.at.to_rfc3339())
        .unwrap_or_else(|| "?".to_string());
    let mut out = format!(
        "DISPUTE EVIDENCE\n\
         Subject: agent {} under root {}\n\
         Call #{call_index}: tool `{tool}` (args hash {args_hash}) at {at}\n\
         Log: {} records re-derived; verdict {}\n\
         Anchor: tier {:?}, head {}…, as of {}\n",
        chain.agent,
        chain.root,
        chain.records.len(),
        chain.audit.code,
        chain.anchor.tier,
        &chain.anchor.head[..16.min(chain.anchor.head.len())],
        chain.anchor.ts.to_rfc3339(),
    );
    if let Some(escrow) = escrow {
        out.push_str(&format!(
            "Escrow: record {} ({} events, {} anchors)\n",
            escrow.get("id").and_then(|v| v.as_str()).unwrap_or("?"),
            escrow.get("events").and_then(|v| v.as_u64()).unwrap_or(0),
            escrow.get("anchors").and_then(|v| v.as_u64()).unwrap_or(0),
        ));
    }
    out.push_str(
        "Verification: re-check offline with `receipt_verify` or POST /v1/verify — \
         the bundle is self-contained; trust neither the producer nor this render.\n",
    );
    out
}

/// The build-time online freshness re-check (design D4): re-resolve the chain
/// fresh and report whether a later head contradicts the judged verdict. The
/// offline verdict stays "as of H"; this stamp tells the human consumer when we
/// last confirmed no later head contradicts it.
///
/// Args:
/// * `input`: the same chain input the bundle was resolved from.
/// * `call_index`: the identified call.
/// * `counterparty`: the resolved counterparty.
/// * `stated`: the verdict the bundle states.
/// * `now`: the re-check instant.
///
/// Usage:
/// ```ignore
/// let freshness = online_freshness_recheck(input, index, &cp, verdict, Utc::now()).await;
/// ```
pub async fn online_freshness_recheck(
    input: ChainInput,
    call_index: usize,
    counterparty: &str,
    stated: CallVerdict,
    now: DateTime<Utc>,
) -> OnlineFreshness {
    let contradicted = match resolve_chain(input, now).await {
        Ok(fresh) => {
            let view = auths_evidence::ChainView {
                grant: &fresh.grant,
                records: &fresh.records,
                facts: &fresh.facts,
                audit_verdict: &fresh.audit.verdict,
                anchor: &fresh.anchor,
                revocation: fresh.revocation.as_ref(),
            };
            judge_call(&view, call_index, counterparty) != stated
        }
        // An unreachable registry proves nothing either way — report contradicted
        // so the human treats the stamp as failed, never as a freshness pass.
        Err(_) => true,
    };
    OnlineFreshness {
        checked_at: now,
        contradicted,
    }
}

/// Assemble the retainer-grade dispute bundle: resolve, locate, judge, attach the
/// verified escrow summary + minimized compliance + human render, stamp
/// freshness, sign. The same function serves the MCP tool and `POST /v1/bundles`.
///
/// Args:
/// * `input`: the chain input.
/// * `payment_ref`: the disputed payment reference.
/// * `network` / `counterparty`: settlement resolution inputs.
/// * `inputs`: the optional dispute sections.
/// * `signer`: the tool's signing identity.
/// * `now`: the injected clock.
///
/// Usage:
/// ```ignore
/// let bundle = dispute_evidence(input, "0xtx…", net, cp, inputs, &signer, Utc::now()).await?;
/// ```
#[allow(clippy::too_many_arguments)]
pub async fn dispute_evidence(
    input: ChainInput,
    payment_ref: &str,
    network: String,
    counterparty: String,
    inputs: DisputeInputs,
    signer: &BundleSigner,
    now: DateTime<Utc>,
) -> Result<EvidenceBundle, EvidenceError> {
    let chain = resolve_chain(input.clone(), now).await?;
    let call_index = locate_call(&chain.records, payment_ref)?;

    let escrow = match &inputs.escrow_record {
        Some(raw) => Some(verify_escrow_record(
            raw,
            inputs.escrow_anchor_key_hex.as_deref(),
        )?),
        None => None,
    };
    let compliance = inputs.compliance.as_ref().map(minimize_compliance);
    let rendered = render_human(&chain, call_index, escrow.as_ref());

    // Provisional judge to know the stated verdict for the freshness comparison.
    let view = auths_evidence::ChainView {
        grant: &chain.grant,
        records: &chain.records,
        facts: &chain.facts,
        audit_verdict: &chain.audit.verdict,
        anchor: &chain.anchor,
        revocation: chain.revocation.as_ref(),
    };
    let stated = judge_call(&view, call_index, &counterparty);
    let mut freshness =
        online_freshness_recheck(input, call_index, &counterparty, stated, now).await;
    if let Some(max_age) = inputs.head_max_age_secs {
        let age = (now - chain.anchor.ts).num_seconds();
        if age < 0 || age as u64 > max_age {
            freshness.contradicted = true;
        }
    }

    build_bundle(
        &chain,
        call_index,
        BuildOpts {
            network,
            counterparty,
            online_freshness: Some(freshness),
            escrow,
            compliance,
            rendered: Some(rendered),
            allow_first_seen_fallback: true,
        },
        signer,
    )
}
