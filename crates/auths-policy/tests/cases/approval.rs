use auths_policy::types::{CanonicalCapability, CanonicalDid};
use auths_policy::{
    ApprovalAttestation, ApprovalScope, EvalContext, Expr, ReasonCode, compile,
    compute_request_hash, enforce, evaluate_strict, evaluate3,
};
use chrono::{Duration, Utc};
use std::cell::RefCell;

fn did(s: &str) -> CanonicalDid {
    CanonicalDid::parse(s).unwrap()
}

fn cap(s: &str) -> CanonicalCapability {
    CanonicalCapability::parse(s).unwrap()
}

fn base_ctx() -> EvalContext {
    EvalContext::new(Utc::now(), did("did:keri:issuer"), did("did:keri:subject"))
}

fn approval_gate_expr(cap_name: &str, approver: &str) -> Expr {
    Expr::ApprovalGate {
        inner: Box::new(Expr::HasCapability(cap_name.into())),
        approvers: vec![approver.into()],
        ttl_seconds: 300,
        scope: Some("identity".into()),
    }
}

fn make_approval(
    approver: &str,
    request_hash: auths_verifier::Hash256,
    expires_in: i64,
) -> ApprovalAttestation {
    ApprovalAttestation {
        jti: "test-jti-001".into(),
        approver_did: did(approver),
        request_hash,
        expires_at: Utc::now() + Duration::seconds(expires_in),
        approved_capabilities: vec![],
    }
}

// ── Core ApprovalGate behavior ────────────────────────────────────────

#[test]
fn approval_gate_no_approval_submitted() {
    let policy = compile(&approval_gate_expr("deploy:prod", "did:keri:human")).unwrap();
    let ctx = base_ctx().capability(cap("deploy:prod"));
    let decision = evaluate3(&policy, &ctx);
    assert!(decision.is_approval_required());
    assert_eq!(decision.reason, ReasonCode::ApprovalRequired);
}

#[test]
fn approval_gate_valid_approval_submitted() {
    let approver = "did:keri:human";
    let policy = compile(&approval_gate_expr("deploy:prod", approver)).unwrap();
    let ctx = base_ctx().capability(cap("deploy:prod"));
    let hash = compute_request_hash(&ctx, ApprovalScope::Identity);
    let approval = make_approval(approver, hash, 300);
    let ctx = ctx.approval(approval);

    let decision = evaluate3(&policy, &ctx);
    assert!(decision.is_allowed());
    assert_eq!(decision.reason, ReasonCode::ApprovalGranted);
}

#[test]
fn approval_gate_expired_approval() {
    let approver = "did:keri:human";
    let policy = compile(&approval_gate_expr("deploy:prod", approver)).unwrap();
    let ctx = base_ctx().capability(cap("deploy:prod"));
    let hash = compute_request_hash(&ctx, ApprovalScope::Identity);
    let approval = make_approval(approver, hash, -60); // already expired
    let ctx = ctx.approval(approval);

    let decision = evaluate3(&policy, &ctx);
    assert!(decision.is_approval_required());
}

#[test]
fn approval_gate_wrong_approver() {
    let policy = compile(&approval_gate_expr("deploy:prod", "did:keri:human")).unwrap();
    let ctx = base_ctx().capability(cap("deploy:prod"));
    let hash = compute_request_hash(&ctx, ApprovalScope::Identity);
    let approval = make_approval("did:keri:unauthorized", hash, 300);
    let ctx = ctx.approval(approval);

    let decision = evaluate3(&policy, &ctx);
    assert!(decision.is_approval_required());
}

#[test]
fn approval_gate_request_hash_mismatch() {
    let approver = "did:keri:human";
    let policy = compile(&approval_gate_expr("deploy:prod", approver)).unwrap();
    let ctx = base_ctx().capability(cap("deploy:prod"));
    let wrong_hash = auths_verifier::Hash256::new([0xFFu8; 32]);
    let approval = make_approval(approver, wrong_hash, 300);
    let ctx = ctx.approval(approval);

    let decision = evaluate3(&policy, &ctx);
    assert!(decision.is_approval_required());
}

#[test]
fn approval_gate_inner_deny() {
    let policy = compile(&approval_gate_expr("deploy:prod", "did:keri:human")).unwrap();
    // Agent does NOT have the required capability
    let ctx = base_ctx();
    let decision = evaluate3(&policy, &ctx);
    assert!(decision.is_denied());
}

#[test]
fn approval_gate_inner_indeterminate() {
    // Inner expression: RepoIs("org/repo") — no repo in context → Indeterminate
    let expr = Expr::ApprovalGate {
        inner: Box::new(Expr::RepoIs("org/repo".into())),
        approvers: vec!["did:keri:human".into()],
        ttl_seconds: 300,
        scope: Some("identity".into()),
    };
    let policy = compile(&expr).unwrap();
    let ctx = base_ctx(); // no repo set
    let decision = evaluate3(&policy, &ctx);
    assert!(decision.is_indeterminate());
}

// ── Combinator interaction tests ──────────────────────────────────────

#[test]
fn and_with_approval_gate_no_approval() {
    // And(HasCapability("read"), ApprovalGate(HasCapability("write")))
    let expr = Expr::And(vec![
        Expr::HasCapability("read".into()),
        approval_gate_expr("write", "did:keri:human"),
    ]);
    let policy = compile(&expr).unwrap();
    let ctx = base_ctx().capability(cap("read")).capability(cap("write"));
    let decision = evaluate3(&policy, &ctx);
    // RequiresApproval dominates Allow in And
    assert!(decision.is_approval_required());
}

#[test]
fn or_with_approval_gate_admin_allows() {
    // Or(ApprovalGate(HasCapability("deploy")), HasCapability("admin"))
    let expr = Expr::Or(vec![
        approval_gate_expr("deploy", "did:keri:human"),
        Expr::HasCapability("admin".into()),
    ]);
    let policy = compile(&expr).unwrap();
    let ctx = base_ctx()
        .capability(cap("deploy"))
        .capability(cap("admin"));
    let decision = evaluate3(&policy, &ctx);
    // Allow dominates RequiresApproval in Or
    assert!(decision.is_allowed());
}

#[test]
fn or_with_approval_gate_deploy_only() {
    // Or(ApprovalGate(HasCapability("deploy")), HasCapability("admin"))
    let expr = Expr::Or(vec![
        approval_gate_expr("deploy", "did:keri:human"),
        Expr::HasCapability("admin".into()),
    ]);
    let policy = compile(&expr).unwrap();
    let ctx = base_ctx().capability(cap("deploy"));
    let decision = evaluate3(&policy, &ctx);
    // RequiresApproval dominates Deny in Or
    assert!(decision.is_approval_required());
}

#[test]
fn not_requires_approval_passthrough() {
    // Not wrapping an inner expr that returns RequiresApproval
    // We can't directly Not(ApprovalGate) (compile-time rejection),
    // but we can And(ApprovalGate, True) inside a Not to get RequiresApproval propagated through Not's inner.
    // Actually, Not only wraps a single expression. We need something that returns RequiresApproval
    // without being an ApprovalGate directly.
    // The simplest way: And(True, ApprovalGate(...)) returns RequiresApproval.
    // Then Not(And(True, ApprovalGate(...)))
    let inner = Expr::And(vec![
        Expr::True,
        approval_gate_expr("deploy", "did:keri:human"),
    ]);
    let expr = Expr::Not(Box::new(inner));
    let policy = compile(&expr).unwrap();
    let ctx = base_ctx().capability(cap("deploy"));
    let decision = evaluate3(&policy, &ctx);
    // RequiresApproval passes through Not (like Indeterminate)
    assert!(decision.is_approval_required());
}

// ── Compile-time validation tests ─────────────────────────────────────

#[test]
fn not_approval_gate_compile_rejection() {
    let expr = Expr::Not(Box::new(Expr::ApprovalGate {
        inner: Box::new(Expr::HasCapability("deploy".into())),
        approvers: vec!["did:keri:human".into()],
        ttl_seconds: 300,
        scope: None,
    }));
    let errors = compile(&expr).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| e.message.contains("Not cannot wrap an ApprovalGate"))
    );
}

// ── Scope tests ───────────────────────────────────────────────────────

#[test]
fn identity_scope_valid_across_different_repos() {
    let approver = "did:keri:human";
    let now = Utc::now();

    let ctx_a = EvalContext::new(now, did("did:keri:issuer"), did("did:keri:subject"))
        .capability(cap("deploy:prod"))
        .repo("org/repo-a");
    let hash = compute_request_hash(&ctx_a, ApprovalScope::Identity);
    let approval = make_approval(approver, hash, 300);

    // Evaluate with different repo
    let ctx_b = EvalContext::new(now, did("did:keri:issuer"), did("did:keri:subject"))
        .capability(cap("deploy:prod"))
        .repo("org/repo-b")
        .approval(approval);

    let policy = compile(&approval_gate_expr("deploy:prod", approver)).unwrap();
    let decision = evaluate3(&policy, &ctx_b);
    // Identity scope ignores repo — approval is valid
    assert!(decision.is_allowed());
}

#[test]
fn scoped_scope_invalid_for_different_repo() {
    let approver = "did:keri:human";
    let now = Utc::now();
    let expr = Expr::ApprovalGate {
        inner: Box::new(Expr::HasCapability("deploy:prod".into())),
        approvers: vec![approver.into()],
        ttl_seconds: 300,
        scope: Some("scoped".into()),
    };
    let policy = compile(&expr).unwrap();

    let ctx_a = EvalContext::new(now, did("did:keri:issuer"), did("did:keri:subject"))
        .capability(cap("deploy:prod"))
        .repo("org/repo-a");
    let hash = compute_request_hash(&ctx_a, ApprovalScope::Scoped);
    let approval = make_approval(approver, hash, 300);

    // Evaluate with different repo
    let ctx_b = EvalContext::new(now, did("did:keri:issuer"), did("did:keri:subject"))
        .capability(cap("deploy:prod"))
        .repo("org/repo-b")
        .approval(approval);

    let decision = evaluate3(&policy, &ctx_b);
    // Scoped includes repo — hash mismatch
    assert!(decision.is_approval_required());
}

// ── evaluate_strict and enforce tests ─────────────────────────────────

#[test]
fn evaluate_strict_propagates_requires_approval() {
    let policy = compile(&approval_gate_expr("deploy:prod", "did:keri:human")).unwrap();
    let ctx = base_ctx().capability(cap("deploy:prod"));
    let decision = evaluate_strict(&policy, &ctx);
    // RequiresApproval is NOT collapsed to Deny
    assert!(decision.is_approval_required());
}

#[test]
fn enforce_requires_approval_same_no_divergence() {
    let primary = compile(&approval_gate_expr("deploy:prod", "did:keri:human")).unwrap();
    let shadow = compile(&approval_gate_expr("deploy:prod", "did:keri:human")).unwrap();
    let ctx = base_ctx().capability(cap("deploy:prod"));

    let called = RefCell::new(false);
    let decision = enforce(&primary, Some(&shadow), &ctx, |_| {
        *called.borrow_mut() = true;
    });
    assert!(decision.is_approval_required());
    assert!(!*called.borrow());
}

#[test]
fn enforce_requires_approval_vs_allow_divergence() {
    let primary = compile(&approval_gate_expr("deploy:prod", "did:keri:human")).unwrap();
    let shadow = compile(&Expr::True).unwrap();
    let ctx = base_ctx().capability(cap("deploy:prod"));

    let diverged = RefCell::new(false);
    let decision = enforce(&primary, Some(&shadow), &ctx, |_| {
        *diverged.borrow_mut() = true;
    });
    assert!(decision.is_approval_required());
    assert!(*diverged.borrow());
}

#[test]
fn enforce_requires_approval_vs_deny_divergence() {
    let primary = compile(&approval_gate_expr("deploy:prod", "did:keri:human")).unwrap();
    let shadow = compile(&Expr::False).unwrap();
    let ctx = base_ctx().capability(cap("deploy:prod"));

    let diverged = RefCell::new(false);
    let decision = enforce(&primary, Some(&shadow), &ctx, |_| {
        *diverged.borrow_mut() = true;
    });
    assert!(decision.is_approval_required());
    assert!(*diverged.borrow());
}

#[test]
fn enforce_allow_vs_requires_approval_divergence() {
    let primary = compile(&Expr::True).unwrap();
    let shadow = compile(&approval_gate_expr("deploy:prod", "did:keri:human")).unwrap();
    let ctx = base_ctx().capability(cap("deploy:prod"));

    let diverged = RefCell::new(false);
    let decision = enforce(&primary, Some(&shadow), &ctx, |_| {
        *diverged.borrow_mut() = true;
    });
    assert!(decision.is_allowed());
    assert!(*diverged.borrow());
}

// ── Serialization ─────────────────────────────────────────────────────

#[test]
fn approval_gate_serde_roundtrip() {
    let expr = Expr::ApprovalGate {
        inner: Box::new(Expr::HasCapability("deploy:prod".into())),
        approvers: vec!["did:keri:human1".into(), "did:keri:human2".into()],
        ttl_seconds: 600,
        scope: Some("scoped".into()),
    };
    let json = serde_json::to_string(&expr).unwrap();
    let parsed: Expr = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, expr);
}

#[test]
fn compute_request_hash_deterministic() {
    let now = Utc::now();
    let ctx = EvalContext::new(now, did("did:keri:issuer"), did("did:keri:subject"))
        .capability(cap("deploy:prod"));
    let hash1 = compute_request_hash(&ctx, ApprovalScope::Identity);
    let hash2 = compute_request_hash(&ctx, ApprovalScope::Identity);
    assert_eq!(hash1, hash2);
}
