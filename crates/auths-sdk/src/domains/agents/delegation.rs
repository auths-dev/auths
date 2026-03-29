use super::types::{AgentSession, ProvisionRequest};
use chrono::{DateTime, Utc};

/// Error type for delegation validation
#[derive(Debug, Clone)]
pub enum DelegationError {
    /// Child capability not in parent's capability set
    CapabilityNotGranted(String),
    /// Child TTL exceeds parent remaining TTL
    TtlExceedsParent(String),
    /// Delegation depth limit reached
    DepthLimitExceeded,
}

impl std::fmt::Display for DelegationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DelegationError::CapabilityNotGranted(msg) => write!(f, "{}", msg),
            DelegationError::TtlExceedsParent(msg) => write!(f, "{}", msg),
            DelegationError::DepthLimitExceeded => write!(f, "Delegation depth limit exceeded"),
        }
    }
}

impl std::error::Error for DelegationError {}

/// Validates delegation constraints before provisioning a child agent
///
/// Checks:
/// - Capability subset: child can only have capabilities parent has
/// - TTL limit: child TTL ≤ parent remaining TTL
/// - Depth limit: parent delegation_depth < parent max_delegation_depth
pub fn validate_delegation_constraints(
    parent_session: &AgentSession,
    provision_req: &ProvisionRequest,
    now: DateTime<Utc>,
) -> Result<(), DelegationError> {
    // Check capability subset
    for cap in &provision_req.capabilities {
        if !parent_session.capabilities.contains(cap) {
            return Err(DelegationError::CapabilityNotGranted(format!(
                "Parent does not have capability: {}",
                cap
            )));
        }
    }

    // Check TTL limit: child TTL ≤ parent remaining TTL
    let parent_remaining = (parent_session.expires_at - now).num_seconds() as u64;
    if provision_req.ttl_seconds > parent_remaining {
        return Err(DelegationError::TtlExceedsParent(format!(
            "TTL {} exceeds parent remaining TTL {}",
            provision_req.ttl_seconds, parent_remaining
        )));
    }

    // Check depth limit: parent's current depth < parent's max_delegation_depth
    if parent_session.delegation_depth >= parent_session.max_delegation_depth {
        return Err(DelegationError::DepthLimitExceeded);
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // INVARIANT: test fixtures call Utc::now() and Uuid::new_v4()
mod tests {
    use super::*;
    use crate::domains::agents::types::AgentStatus;
    use uuid::Uuid;

    #[test]
    fn test_capability_subset_valid() {
        let now = Utc::now();
        let parent = AgentSession {
            session_id: Uuid::new_v4(),
            agent_did: "did:keri:parent".to_string(),
            agent_name: "parent".to_string(),
            delegator_did: None,
            capabilities: vec!["read".to_string(), "write".to_string()],
            status: AgentStatus::Active,
            created_at: now,
            expires_at: now + chrono::Duration::hours(1),
            delegation_depth: 0,
            max_delegation_depth: 2,
        };

        let req = ProvisionRequest {
            delegator_did: "did:keri:parent".to_string(),
            agent_name: "child".to_string(),
            capabilities: vec!["read".to_string()],
            ttl_seconds: 3600,
            max_delegation_depth: Some(0),
            signature: "sig".to_string(),
            timestamp: now,
        };

        assert!(validate_delegation_constraints(&parent, &req, now).is_ok());
    }

    #[test]
    fn test_capability_subset_invalid() {
        let now = Utc::now();
        let parent = AgentSession {
            session_id: Uuid::new_v4(),
            agent_did: "did:keri:parent".to_string(),
            agent_name: "parent".to_string(),
            delegator_did: None,
            capabilities: vec!["read".to_string()],
            status: AgentStatus::Active,
            created_at: now,
            expires_at: now + chrono::Duration::hours(1),
            delegation_depth: 0,
            max_delegation_depth: 2,
        };

        let req = ProvisionRequest {
            delegator_did: "did:keri:parent".to_string(),
            agent_name: "child".to_string(),
            capabilities: vec!["admin".to_string()],
            ttl_seconds: 3600,
            max_delegation_depth: Some(0),
            signature: "sig".to_string(),
            timestamp: now,
        };

        assert!(validate_delegation_constraints(&parent, &req, now).is_err());
    }

    #[test]
    fn test_ttl_limit() {
        let now = Utc::now();
        let parent = AgentSession {
            session_id: Uuid::new_v4(),
            agent_did: "did:keri:parent".to_string(),
            agent_name: "parent".to_string(),
            delegator_did: None,
            capabilities: vec!["read".to_string()],
            status: AgentStatus::Active,
            created_at: now,
            expires_at: now + chrono::Duration::hours(1),
            delegation_depth: 0,
            max_delegation_depth: 2,
        };

        let req = ProvisionRequest {
            delegator_did: "did:keri:parent".to_string(),
            agent_name: "child".to_string(),
            capabilities: vec!["read".to_string()],
            ttl_seconds: 7200,
            max_delegation_depth: Some(0),
            signature: "sig".to_string(),
            timestamp: now,
        };

        assert!(validate_delegation_constraints(&parent, &req, now).is_err());
    }

    #[test]
    fn test_depth_limit() {
        let now = Utc::now();
        let parent = AgentSession {
            session_id: Uuid::new_v4(),
            agent_did: "did:keri:parent".to_string(),
            agent_name: "parent".to_string(),
            delegator_did: None,
            capabilities: vec!["read".to_string()],
            status: AgentStatus::Active,
            created_at: now,
            expires_at: now + chrono::Duration::hours(1),
            delegation_depth: 2,
            max_delegation_depth: 2,
        };

        let req = ProvisionRequest {
            delegator_did: "did:keri:parent".to_string(),
            agent_name: "child".to_string(),
            capabilities: vec!["read".to_string()],
            ttl_seconds: 3600,
            max_delegation_depth: Some(0),
            signature: "sig".to_string(),
            timestamp: now,
        };

        assert!(validate_delegation_constraints(&parent, &req, now).is_err());
    }
}
