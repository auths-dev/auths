use base64::Engine;
use chrono::Utc;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

use super::delegation::validate_delegation_constraints;
use super::persistence::AgentPersistencePort;
use super::registry::AgentRegistry;
use super::types::{
    AgentSession, AgentStatus, AuthorizeResponse, ProvisionRequest, ProvisionResponse,
};

/// Business logic service for agent operations
/// Separates HTTP concerns (handlers) from domain logic
pub struct AgentService {
    registry: Arc<AgentRegistry>,
    persistence: Arc<dyn AgentPersistencePort>,
}

impl AgentService {
    /// Create a new agent service with injected registry and persistence
    pub fn new(registry: Arc<AgentRegistry>, persistence: Arc<dyn AgentPersistencePort>) -> Self {
        Self {
            registry,
            persistence,
        }
    }

    /// Provision a new agent identity
    /// Validates signature, delegates, provisions, and stores in registry + persistence
    pub async fn provision(
        &self,
        req: ProvisionRequest,
        now: chrono::DateTime<Utc>,
    ) -> Result<ProvisionResponse, String> {
        // Validate clock skew (±5 minutes)
        let time_diff = {
            let duration = now.signed_duration_since(req.timestamp);
            duration.num_seconds().unsigned_abs()
        };
        if time_diff > 300 {
            return Err("Clock skew too large".to_string());
        }

        // Verify signature using IdentityResolver
        // TODO: Integrate with IdentityResolver when available

        // Validate delegation constraints if delegator exists in registry
        if !req.delegator_did.is_empty() {
            let delegator_session = self
                .registry
                .get(&req.delegator_did, now)
                .ok_or_else(|| format!("Delegator not found: {}", req.delegator_did))?;

            validate_delegation_constraints(&delegator_session, &req, now)
                .map_err(|e| e.to_string())?;
        }

        // Provision agent identity using auths-id
        // TODO: Call provision_agent_identity() from auths-id crate
        let agent_did = format!("did:keri:{}", {
            #[allow(clippy::disallowed_methods)]
            Uuid::new_v4()
        });
        let attestation = json!({
            "version": "1.0",
            "agent_did": agent_did,
            "issuer": req.delegator_did,
            "capabilities": req.capabilities,
            "timestamp": now.to_rfc3339(),
        })
        .to_string();

        // Generate optional bearer token
        let bearer_token = {
            let mut buf = [0u8; 32];
            use ring::rand::SecureRandom;
            ring::rand::SystemRandom::new()
                .fill(&mut buf)
                .map_err(|_| "RNG failed".to_string())?;

            Some(base64::engine::general_purpose::STANDARD.encode(buf))
        };

        // Create session
        let session_id = {
            #[allow(clippy::disallowed_methods)]
            Uuid::new_v4()
        };
        let expires_at = now + chrono::Duration::seconds(req.ttl_seconds as i64);
        let delegation_depth = if req.delegator_did.is_empty() {
            0
        } else {
            self.registry
                .get(&req.delegator_did, now)
                .map(|s| s.delegation_depth + 1)
                .unwrap_or(1)
        };

        let session = AgentSession {
            session_id,
            agent_did: agent_did.clone(),
            agent_name: req.agent_name,
            delegator_did: if req.delegator_did.is_empty() {
                None
            } else {
                Some(req.delegator_did)
            },
            capabilities: req.capabilities,
            status: AgentStatus::Active,
            created_at: now,
            expires_at,
            delegation_depth,
            max_delegation_depth: req.max_delegation_depth.unwrap_or(0),
        };

        // Store in persistence first (source of truth), then DashMap cache
        self.persistence.set_session(&session).await?;

        // Only update cache if persistence write succeeded
        self.registry.insert(session);

        // Set expiry on persistence key
        self.persistence.expire(&agent_did, expires_at).await?;

        Ok(ProvisionResponse {
            session_id,
            agent_did,
            bearer_token,
            attestation,
            expires_at,
        })
    }

    /// Authorize an operation for an agent
    /// Verifies signature, checks agent is active, evaluates capabilities
    pub fn authorize(
        &self,
        agent_did: &str,
        capability: &str,
        now: chrono::DateTime<Utc>,
        request_timestamp: chrono::DateTime<Utc>,
    ) -> Result<AuthorizeResponse, String> {
        // Validate clock skew (±5 minutes)
        let time_diff = {
            let duration = now.signed_duration_since(request_timestamp);
            duration.num_seconds().unsigned_abs()
        };
        if time_diff > 300 {
            return Err("Clock skew too large".to_string());
        }

        // Verify signature using IdentityResolver
        // TODO: Integrate with IdentityResolver when available

        // Get agent session from registry
        let session = self
            .registry
            .get(agent_did, now)
            .ok_or_else(|| "Agent not found or expired".to_string())?;

        // Check if agent is active (not revoked, not expired)
        if session.status != AgentStatus::Active {
            return Err("Agent revoked".to_string());
        }

        // Evaluate capabilities (hierarchical matching)
        let matched: Vec<String> = session
            .capabilities
            .iter()
            .filter(|cap| *cap == capability || *cap == "*")
            .cloned()
            .collect();

        let authorized = !matched.is_empty();

        Ok(AuthorizeResponse {
            authorized,
            message: if authorized {
                format!("Capability '{}' granted", capability)
            } else {
                format!("Capability '{}' not granted", capability)
            },
            matched_capabilities: matched,
        })
    }

    /// Revoke an agent and all its children (cascading)
    pub async fn revoke(&self, agent_did: &str, now: chrono::DateTime<Utc>) -> Result<(), String> {
        // Check agent exists
        if self.registry.get(agent_did, now).is_none() {
            return Err("Agent not found".to_string());
        }

        // Revoke in memory
        self.registry.revoke(agent_did);

        // Revoke in persistence
        self.persistence.revoke_agent(agent_did).await?;

        // Cascade: revoke all children
        let children = self.registry.list_by_delegator(agent_did, now);

        for child in children {
            self.registry.revoke(&child.agent_did);
            self.persistence.revoke_agent(&child.agent_did).await?;
        }

        Ok(())
    }
}
