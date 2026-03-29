use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Agent session status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentStatus {
    /// Session is currently active
    Active,
    /// Session has been revoked
    Revoked,
}

/// Agent session stored in registry
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AgentSession {
    /// Unique session identifier
    pub session_id: Uuid,
    /// Agent DID (unique identity)
    pub agent_did: String,
    /// Human-readable agent name
    pub agent_name: String,
    /// Parent delegator DID (optional)
    pub delegator_did: Option<String>,
    /// Granted capabilities
    pub capabilities: Vec<String>,
    /// Session status
    pub status: AgentStatus,
    /// When session was created
    pub created_at: DateTime<Utc>,
    /// When session expires
    pub expires_at: DateTime<Utc>,
    /// Delegation depth in the tree
    pub delegation_depth: u32,
    /// Max delegation depth this agent can create
    pub max_delegation_depth: u32,
}

impl AgentSession {
    /// Check if session is expired
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        now > self.expires_at
    }

    /// Check if session is active (not revoked and not expired)
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        self.status == AgentStatus::Active && !self.is_expired(now)
    }
}

/// Request to provision a new agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionRequest {
    /// Who is delegating (empty for root provision)
    pub delegator_did: String,
    /// Human-readable name for the agent
    pub agent_name: String,
    /// Capabilities granted to this agent
    pub capabilities: Vec<String>,
    /// How long agent should live (seconds)
    pub ttl_seconds: u64,
    /// Maximum delegation depth this agent can create (0 = cannot delegate)
    pub max_delegation_depth: Option<u32>,
    /// Base64-encoded Ed25519 signature over canonicalized request body
    pub signature: String,
    /// When request was signed (for clock skew tolerance)
    pub timestamp: DateTime<Utc>,
}

/// Response from provisioning a new agent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionResponse {
    /// Unique session ID for audit
    pub session_id: Uuid,
    /// Agent's DID (cryptographic identity)
    pub agent_did: String,
    /// Optional bearer token (convenience only, not required for auth)
    pub bearer_token: Option<String>,
    /// Signed attestation proof
    pub attestation: String,
    /// When agent expires
    pub expires_at: DateTime<Utc>,
}

/// Request to authorize an operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizeRequest {
    /// Agent's DID performing the operation
    pub agent_did: String,
    /// Capability being requested
    pub capability: String,
    /// Base64-encoded Ed25519 signature over canonicalized request body
    pub signature: String,
    /// When request was signed (for clock skew tolerance)
    pub timestamp: DateTime<Utc>,
}

/// Response to authorization request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizeResponse {
    /// Whether the agent is authorized
    pub authorized: bool,
    /// Message explaining the decision
    pub message: String,
    /// Matched capabilities (if authorized)
    pub matched_capabilities: Vec<String>,
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // INVARIANT: test fixtures call Utc::now() and Uuid::new_v4()
mod tests {
    use super::*;

    #[test]
    fn test_session_expiry() {
        let now = Utc::now();
        let session = AgentSession {
            session_id: Uuid::new_v4(),
            agent_did: "did:keri:test".to_string(),
            agent_name: "test-agent".to_string(),
            delegator_did: None,
            capabilities: vec!["read".to_string()],
            status: AgentStatus::Active,
            created_at: now,
            expires_at: now - chrono::Duration::seconds(1),
            delegation_depth: 0,
            max_delegation_depth: 0,
        };

        assert!(session.is_expired(now));
        assert!(!session.is_active(now));
    }
}
