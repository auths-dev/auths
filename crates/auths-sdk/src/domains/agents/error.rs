use auths_core::error::AuthsErrorInfo;
use auths_verifier::IdentityDID;
use thiserror::Error;

/// Errors from agent operations (provisioning, authorization, revocation).
///
/// Usage:
/// ```ignore
/// match provision_result {
///     Err(AgentError::DelegationViolation(_)) => { /* delegation constraints not met */ }
///     Err(e) => return Err(e.into()),
///     Ok(response) => { /* agent provisioned successfully */ }
/// }
/// ```
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AgentError {
    /// The agent was not found in the registry.
    #[error("agent not found: {agent_did}")]
    AgentNotFound {
        /// The DID of the agent that was not found.
        agent_did: IdentityDID,
    },

    /// The agent has been revoked.
    #[error("agent is revoked: {agent_did}")]
    AgentRevoked {
        /// The DID of the revoked agent.
        agent_did: IdentityDID,
    },

    /// The agent's session has expired.
    #[error("agent has expired: {agent_did}")]
    AgentExpired {
        /// The DID of the expired agent.
        agent_did: IdentityDID,
    },

    /// The agent lacks the required capability.
    #[error("capability not granted: {capability}")]
    CapabilityNotGranted {
        /// The capability that was not granted.
        capability: String,
    },

    /// A delegation constraint was violated (parent TTL, depth limit, capability subset).
    #[error("delegation constraint violated: {0}")]
    DelegationViolation(#[source] super::delegation::DelegationError),

    /// A persistence operation failed.
    #[error("persistence error: {0}")]
    PersistenceError(String),
}

impl AuthsErrorInfo for AgentError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::AgentNotFound { .. } => "AUTHS-E6001",
            Self::AgentRevoked { .. } => "AUTHS-E6002",
            Self::AgentExpired { .. } => "AUTHS-E6003",
            Self::CapabilityNotGranted { .. } => "AUTHS-E6004",
            Self::DelegationViolation(_) => "AUTHS-E6005",
            Self::PersistenceError(_) => "AUTHS-E6006",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::AgentNotFound { .. } => {
                Some("Agent not found in registry; ensure it has been provisioned")
            }
            Self::AgentRevoked { .. } => {
                Some("This agent has been revoked and cannot perform operations")
            }
            Self::AgentExpired { .. } => {
                Some("Agent session has expired; provision a new agent to continue")
            }
            Self::CapabilityNotGranted { .. } => {
                Some("Agent does not have the required capability for this operation")
            }
            Self::DelegationViolation(_) => {
                Some("Delegation constraints violated; check parent agent TTL and depth limit")
            }
            Self::PersistenceError(_) => {
                Some("Failed to persist agent state; check Redis connection and storage")
            }
        }
    }
}
