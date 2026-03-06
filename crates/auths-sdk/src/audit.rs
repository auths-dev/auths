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
