use thiserror::Error;

/// Domain errors for Auths Agent Guard execution and spend verification.
#[derive(Debug, Error, PartialEq)]
pub enum AgentGuardError {
    /// Budget exceeded error variant (in integer cents)
    #[error(
        "Budget exceeded: requested {requested_cents} cents, remaining {remaining_cents} cents"
    )]
    BudgetExceeded {
        /// Requested cost in cents
        requested_cents: u64,
        /// Remaining allocated budget in cents
        remaining_cents: u64,
    },

    /// Capability scope denied variant
    #[error("Capability scope denied: required '{required_scope}', granted '{granted_scope}'")]
    ScopeDenied {
        /// Scope required by the tool call
        required_scope: String,
        /// Scope granted to the agent
        granted_scope: String,
    },

    /// Capability expired variant
    #[error("Agent capability guard expired at {expired_at}")]
    CapabilityExpired {
        /// Expiration timestamp
        expired_at: chrono::DateTime<chrono::Utc>,
    },

    /// Capsec capability violation variant
    #[error("Capsec error: {0}")]
    CapsecViolation(String),
}
