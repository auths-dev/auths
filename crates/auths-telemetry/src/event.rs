use schemars::JsonSchema;
use serde::Serialize;

/// Represents a standardized security event for SIEM ingestion.
///
/// Args:
/// * `timestamp` - Unix epoch seconds when the event was recorded.
/// * `actor_did` - The KERI decentralized identifier initiating the action.
/// * `action` - The specific capability or operation attempted.
/// * `status` - The resolution of the event (e.g., "Success", "Denied").
/// * `trace_id` - Optional W3C traceparent-compatible trace identifier.
///
/// Usage:
/// ```rust
/// use auths_telemetry::build_audit_event;
/// let event = build_audit_event("did:keri:abc...", "assume_role", "Denied", 0);
/// ```
#[derive(Serialize, JsonSchema)]
pub struct AuditEvent<'a> {
    pub timestamp: i64,
    pub actor_did: &'a str,
    pub action: &'a str,
    pub status: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
}

/// Constructs a standardized audit event for security tracking.
///
/// Args:
/// * `actor_did` - The identifier of the actor.
/// * `action` - The capability being exercised.
/// * `status` - The policy evaluation outcome.
/// * `timestamp` - Unix epoch seconds for this event (caller supplies).
///
/// Usage:
/// ```rust
/// use auths_telemetry::build_audit_event;
/// let event = build_audit_event("did:keri:abc...", "session_verification", "Success", 0);
/// ```
pub fn build_audit_event<'a>(
    actor_did: &'a str,
    action: &'a str,
    status: &'a str,
    timestamp: i64,
) -> AuditEvent<'a> {
    AuditEvent {
        timestamp,
        actor_did,
        action,
        status,
        trace_id: None,
    }
}
