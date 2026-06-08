//! Audit event emission convenience for SDK operations.

use crate::context::AuthsContext;

/// Emit a structured audit event through the SDK context's event sink.
///
/// Args:
/// * `ctx`: The runtime context providing the event sink.
/// * `actor_did`: The DID of the acting principal.
/// * `action`: The action being performed (e.g. `"sign:commit"`, `"mcp:deploy"`).
/// * `status`: The outcome (e.g. `"Success"`, `"Denied"`).
///
/// Usage:
/// ```ignore
/// emit_audit(&ctx, &agent_did, "sign:commit", "Success");
/// ```
pub fn emit_audit(ctx: &AuthsContext, actor_did: &str, action: &str, status: &str) {
    let now = ctx.clock.now().timestamp();
    let event = auths_telemetry::build_audit_event(actor_did, action, status, now);
    let payload = serde_json::to_string(&event).unwrap_or_default();
    ctx.event_sink.emit(&payload);
}

/// Emit an audit event for a policy-enforcement decision (E1 A5).
///
/// Records every enforcement decision — allow **and** deny — so denials are
/// observable and traceability is measurable. The status carries the typed outcome,
/// reason code, and the policy hash (audit pinning). Called by the enforcement
/// callers (commit + request paths); the policy gate itself stays side-effect-free.
///
/// Args:
/// * `ctx`: The runtime context providing the event sink + clock.
/// * `surface`: The enforcement surface (e.g. `"commit"`, `"request"`).
/// * `subject_did`: The principal the decision was made about.
/// * `decision`: The typed policy decision.
///
/// Usage:
/// ```ignore
/// emit_policy_decision(&ctx, "commit", &signer_did, &decision);
/// ```
pub fn emit_policy_decision(
    ctx: &AuthsContext,
    surface: &str,
    subject_did: &str,
    decision: &auths_id::policy::Decision,
) {
    let hash = decision
        .policy_hash
        .map(hex::encode)
        .unwrap_or_else(|| "none".to_string());
    let status = format!("{}:{} policy={}", decision.outcome, decision.reason, hash);
    emit_audit(ctx, subject_did, &format!("policy:{surface}"), &status);
}
