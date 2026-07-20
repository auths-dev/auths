//! Threat-model rows that are pure judge arithmetic (rows 6, 16,
//! 17, 20, 21 + the revocation/expiry legs): total functions over proven facts,
//! exercised over synthetic facts — no crypto here by design, the walk already
//! proved them.

use auths_evidence::{
    AnchorRef, BudgetBasis, BundleGrant, CallVerdict, ChainView, CounterpartyPolicy,
    CounterpartyPolicyKind, PolicyDecision, RevocationFact, judge_call,
};
use auths_mcp_core::{AuditVerdict, Cents, Receipt, RecordFact, SpendLogRecord, ToolCall, Verdict};
use chrono::{Duration, TimeZone, Utc};

fn t0() -> chrono::DateTime<Utc> {
    Utc.timestamp_opt(1_760_000_000, 0).unwrap()
}

fn grant(policy: CounterpartyPolicy) -> BundleGrant {
    BundleGrant {
        scope: vec!["paid.call".to_string()],
        cap: "$5".to_string(),
        currency: "USD".to_string(),
        issued_at: t0() - Duration::hours(1),
        expires_at: t0() + Duration::hours(24),
        budget_basis: BudgetBasis::CrossRail,
        counterparty_policy: policy,
    }
}

fn anchor() -> AnchorRef {
    auths_evidence::anchor::first_seen_anchor("head".to_string(), 1, t0())
}

/// Mint a `Consistent` audit verdict through serde — the typed proof's
/// constructor is deliberately private to production code.
fn consistent(calls: usize, settled: u64) -> AuditVerdict {
    serde_json::from_value(serde_json::json!({
        "verdict": "consistent", "calls": calls, "settled_cents": settled,
    }))
    .unwrap()
}

fn record(verdict: Verdict, cumulative: u64) -> SpendLogRecord {
    let call = ToolCall {
        tool: "paid_call".to_string(),
        args: serde_json::json!({ "q": "x" }),
        cost_cents: Cents::ZERO,
    };
    SpendLogRecord {
        call_commit: b"synthetic".to_vec(),
        receipt: Receipt::for_call(
            "did:keri:Eagent",
            "did:keri:Eroot",
            &call,
            "proofsha",
            verdict,
            Some("x402"),
            Some("0xtx"),
            Cents::ZERO,
            Cents::new(cumulative),
            t0(),
        ),
        settlement: auths_mcp_core::Settlement::Unmetered,
    }
}

fn fact(index: usize, verdict: Verdict, before: u64, signed: Option<u64>) -> RecordFact {
    RecordFact {
        index,
        rederived_verdict: verdict,
        binding: format!("binding-{index}"),
        settled_cents_before: Cents::new(before),
        signed_cents: signed.map(Cents::new),
        counterparty: None,
    }
}

struct Fixture {
    grant: BundleGrant,
    records: Vec<SpendLogRecord>,
    facts: Vec<RecordFact>,
    audit: AuditVerdict,
    anchor: AnchorRef,
    revocation: Option<RevocationFact>,
}

impl Fixture {
    fn view(&self) -> ChainView<'_> {
        ChainView {
            grant: &self.grant,
            records: &self.records,
            facts: &self.facts,
            audit_verdict: &self.audit,
            anchor: &self.anchor,
            revocation: self.revocation.as_ref(),
        }
    }
}

fn clean_fixture() -> Fixture {
    Fixture {
        grant: grant(CounterpartyPolicy::allow_all()),
        records: vec![record(Verdict::Allowed, 100)],
        facts: vec![fact(0, Verdict::Allowed, 0, Some(100))],
        audit: consistent(1, 100),
        anchor: anchor(),
        revocation: None,
    }
}

#[test]
fn clean_call_is_authorized() {
    let fx = clean_fixture();
    assert_eq!(
        judge_call(&fx.view(), 0, "0xseller"),
        CallVerdict::Authorized
    );
}

/// Row 6 — a call the gate refused over-cap, whose recorded numbers re-derive:
/// `over-budget`, in agreement with the recorded verdict (D1).
#[test]
fn over_budget_when_gate_refusal_rederives() {
    let mut fx = clean_fixture();
    fx.records = vec![record(
        Verdict::UsageCapExceeded {
            cap_cents: Cents::new(500),
            would_be_cents: Cents::new(600),
        },
        400,
    )];
    fx.facts = vec![fact(0, Verdict::Allowed, 400, None)];
    assert_eq!(
        judge_call(&fx.view(), 0, "0xseller"),
        CallVerdict::OverBudget
    );
}

/// Row 16 (D1) — the gate recorded `granted` but the settled-only re-derivation
/// says over-cap: `unverifiable`, the flagged reconciliation — the recorded
/// verdict is NEVER silently overridden.
#[test]
fn gate_vs_rederivation_mismatch_is_unverifiable() {
    let mut fx = clean_fixture();
    fx.records = vec![record(Verdict::Allowed, 600)];
    fx.facts = vec![fact(0, Verdict::Allowed, 450, Some(150))]; // 450+150 = 600 > $5 cap
    fx.audit = consistent(1, 600);
    assert_eq!(
        judge_call(&fx.view(), 0, "0xseller"),
        CallVerdict::Unverifiable
    );
}

/// Row 17 (D2) — the budget check runs over the CROSS-RAIL settled counter the
/// walk re-derived (`settled_cents_before` sums every rail), so a cap crossing
/// hidden by a per-rail view is still refused. Two rails: 300c on stripe before
/// this 250c x402 call under a $5 cap → over.
#[test]
fn cross_rail_spend_counts_against_one_cap() {
    let mut fx = clean_fixture();
    fx.records = vec![
        record(Verdict::Allowed, 300),
        record(
            Verdict::UsageCapExceeded {
                cap_cents: Cents::new(500),
                would_be_cents: Cents::new(550),
            },
            300,
        ),
    ];
    fx.facts = vec![
        fact(0, Verdict::Allowed, 0, Some(300)),
        // The walk's cross-rail counter carries the stripe spend into this
        // x402 call's spent-before — no per-rail silo exists to hide behind.
        fact(1, Verdict::Allowed, 300, None),
    ];
    fx.audit = consistent(2, 300);
    assert_eq!(
        judge_call(&fx.view(), 1, "0xseller"),
        CallVerdict::OverBudget
    );
}

/// Row 20 — injection redirect under `AllowList`: in-scope, under cap, but the
/// resolved counterparty is not on the grant's list → `out-of-counterparty`.
#[test]
fn allow_list_denies_off_list_counterparty() {
    let mut fx = clean_fixture();
    fx.grant = grant(CounterpartyPolicy {
        kind: CounterpartyPolicyKind::AllowList,
        allow: Some(vec!["0xseller".to_string()]),
        predicate_ref: None,
    });
    assert_eq!(
        judge_call(&fx.view(), 0, "0xseller"),
        CallVerdict::Authorized
    );
    assert_eq!(
        judge_call(&fx.view(), 0, "0xattacker"),
        CallVerdict::OutOfCounterparty
    );
}

/// Row 21 — policy downgrade: the policy is SIGNED INTO THE GRANT; there is no
/// runtime adapter input to swap. The single decide() implementation reads only
/// the grant, so an off-list call re-derives `out-of-counterparty` no matter
/// what an operator's gateway config claims.
#[test]
fn policy_lives_in_the_grant_not_the_operator() {
    let signed_policy = CounterpartyPolicy {
        kind: CounterpartyPolicyKind::AllowList,
        allow: Some(vec!["0xseller".to_string()]),
        predicate_ref: None,
    };
    // The operator's "runtime" policy object is a different value entirely —
    // and judge_call has no parameter that could carry it.
    let operator_policy = CounterpartyPolicy::allow_all();
    assert_eq!(operator_policy.decide("0xattacker"), PolicyDecision::Allow);

    let mut fx = clean_fixture();
    fx.grant = grant(signed_policy);
    assert_eq!(
        judge_call(&fx.view(), 0, "0xattacker"),
        CallVerdict::OutOfCounterparty
    );
}

/// An allow-list with no list fails closed; a predicate without its adapter
/// fails closed.
#[test]
fn partial_policies_fail_closed() {
    let empty = CounterpartyPolicy {
        kind: CounterpartyPolicyKind::AllowList,
        allow: None,
        predicate_ref: None,
    };
    assert_eq!(empty.decide("anyone"), PolicyDecision::Deny);
    let predicate = CounterpartyPolicy {
        kind: CounterpartyPolicyKind::Predicate,
        allow: None,
        predicate_ref: Some("reputation>=0.9".to_string()),
    };
    assert_eq!(predicate.decide("anyone"), PolicyDecision::Deny);
}

/// Row 8b (unit leg) — a TEL/attestation revocation recorded at or before the
/// anchor instant kills the delegation for every covered call, even though it
/// moved no KEL tip.
#[test]
fn tel_revocation_before_anchor_is_unauthorized() {
    let mut fx = clean_fixture();
    fx.revocation = Some(RevocationFact {
        source: "tel".to_string(),
        seq: None,
        ts: Some(t0() - Duration::minutes(5)),
    });
    assert_eq!(
        judge_call(&fx.view(), 0, "0xseller"),
        CallVerdict::Unauthorized
    );
}

/// Row 8 (unit leg) — a revocation recorded AFTER the anchor instant does not
/// reach back: the verdict is authorized as-of H (the online re-check flags it).
#[test]
fn revocation_after_anchor_leaves_as_of_verdict() {
    let mut fx = clean_fixture();
    fx.revocation = Some(RevocationFact {
        source: "tel".to_string(),
        seq: None,
        ts: Some(t0() + Duration::minutes(5)),
    });
    assert_eq!(
        judge_call(&fx.view(), 0, "0xseller"),
        CallVerdict::Authorized
    );
}

/// A call outside the grant window is expired.
#[test]
fn out_of_window_call_is_expired() {
    let mut fx = clean_fixture();
    fx.grant.expires_at = t0() - Duration::minutes(1);
    assert_eq!(judge_call(&fx.view(), 0, "0xseller"), CallVerdict::Expired);
}

/// A broken walk (tampered proof) grounds nothing — every call is unverifiable.
#[test]
fn tampered_walk_grounds_no_call() {
    let mut fx = clean_fixture();
    fx.audit = AuditVerdict::TamperedProof {
        at: 0,
        proof_ref: "deadbeef".to_string(),
    };
    assert_eq!(
        judge_call(&fx.view(), 0, "0xseller"),
        CallVerdict::Unverifiable
    );
}

/// Row 7 (unit leg) — the walk stopped at an in-KEL revocation: calls at/after
/// it are unauthorized.
#[test]
fn revoked_walk_kills_covered_calls() {
    let mut fx = clean_fixture();
    fx.audit = AuditVerdict::Revoked { at: 0 };
    fx.facts = vec![];
    assert_eq!(
        judge_call(&fx.view(), 0, "0xseller"),
        CallVerdict::Unauthorized
    );
}
