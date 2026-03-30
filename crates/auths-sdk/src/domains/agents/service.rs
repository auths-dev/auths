use auths_verifier::{Capability, IdentityDID};
use chrono::{DateTime, Duration, Utc};
use std::sync::Arc;
use uuid::Uuid;

use super::{
    AgentError, AgentPersistencePort, AgentRegistry,
    delegation::validate_delegation_constraints,
    types::{AgentSession, AgentStatus, AuthorizeResponse, ProvisionRequest, ProvisionResponse},
};

/// Orchestrates agent provisioning, authorization, and revocation.
///
/// Holds references to the in-memory registry and persistent storage backend.
/// All methods are thread-safe due to interior mutability in AgentRegistry and Arc<dyn Port>.
pub struct AgentService {
    registry: Arc<AgentRegistry>,
    persistence: Arc<dyn AgentPersistencePort>,
}

impl AgentService {
    /// Create a new agent service.
    ///
    /// Args:
    /// * `registry` — In-memory cache for active agent sessions.
    /// * `persistence` — Redis-backed persistence layer.
    pub fn new(registry: Arc<AgentRegistry>, persistence: Arc<dyn AgentPersistencePort>) -> Self {
        Self {
            registry,
            persistence,
        }
    }

    /// Provision a new agent.
    ///
    /// Validates delegation constraints (if delegating), creates a session in both
    /// registry and persistence, and returns provisioning response.
    ///
    /// The agent DID is created server-side via KERI identity initialization
    /// at the HTTP handler boundary.
    ///
    /// Args:
    /// * `req` — Provisioning request with delegator, capabilities, TTL, etc.
    /// * `session_id` — Pre-generated UUID (from HTTP handler boundary).
    /// * `agent_did` — KERI identity created by handler via initialize_registry_identity.
    /// * `now` — Current time for expiry calculations.
    ///
    /// Usage:
    /// ```ignore
    /// let session_id = Uuid::new_v4();
    /// let (agent_did, _) = initialize_registry_identity(...)?;  // Handler creates identity
    /// let response = service.provision(req, session_id, agent_did, Utc::now()).await?;
    /// ```
    pub async fn provision(
        &self,
        req: ProvisionRequest,
        session_id: Uuid,
        agent_did: IdentityDID,
        now: DateTime<Utc>,
    ) -> Result<ProvisionResponse, AgentError> {
        let expires_at = now + Duration::seconds(req.ttl_seconds as i64);

        // If delegating from an agent (not root), validate constraints
        let delegation_depth = if let Some(delegator_did) = &req.delegator_did {
            let parent_session =
                self.registry
                    .get(delegator_did, now)
                    .ok_or_else(|| AgentError::AgentNotFound {
                        agent_did: delegator_did.clone(),
                    })?;

            validate_delegation_constraints(&parent_session, &req, now)
                .map_err(AgentError::DelegationViolation)?;

            parent_session.delegation_depth + 1
        } else {
            0 // Root agent
        };

        let session = AgentSession {
            session_id,
            agent_did: agent_did.clone(),
            agent_name: req.agent_name.clone(),
            delegator_did: req.delegator_did.clone(),
            capabilities: req.capabilities.clone(),
            status: AgentStatus::Active,
            created_at: now,
            expires_at,
            delegation_depth,
            max_delegation_depth: req.max_delegation_depth.unwrap_or(3),
        };

        // Persist to Redis
        self.persistence
            .set_session(&session)
            .await
            .map_err(AgentError::PersistenceError)?;

        // Set expiry in Redis
        self.persistence
            .expire(&agent_did, expires_at)
            .await
            .map_err(AgentError::PersistenceError)?;

        // Cache in registry
        self.registry.insert(session);

        Ok(ProvisionResponse {
            session_id,
            agent_did,
            bearer_token: None,         // TODO: Generate JWT bearer token
            attestation: String::new(), // TODO: Generate signed attestation
            expires_at,
        })
    }

    /// Check if an agent is authorized to use a capability.
    ///
    /// Validates that the agent exists, is active, and has the requested capability.
    ///
    /// Args:
    /// * `agent_did` — The agent DID to authorize.
    /// * `capability` — The capability being requested.
    /// * `now` — Current time for expiry checks.
    ///
    /// Usage:
    /// ```ignore
    /// let resp = service.authorize(&agent_did, "sign:commit", Utc::now())?;
    /// ```
    pub fn authorize(
        &self,
        agent_did: &IdentityDID,
        capability: &str,
        now: DateTime<Utc>,
    ) -> Result<AuthorizeResponse, AgentError> {
        // Get raw session without filtering to distinguish NotFound vs Revoked vs Expired
        let session =
            self.registry
                .get_raw(agent_did)
                .ok_or_else(|| AgentError::AgentNotFound {
                    agent_did: agent_did.clone(),
                })?;

        // Check revocation first (revoked agents should error with 401, not NotFound)
        if session.status == AgentStatus::Revoked {
            return Err(AgentError::AgentRevoked {
                agent_did: agent_did.clone(),
            });
        }

        // Then check expiry
        if session.is_expired(now) {
            return Err(AgentError::AgentExpired {
                agent_did: agent_did.clone(),
            });
        }

        let requested_capability =
            Capability::parse(capability).map_err(|_| AgentError::CapabilityNotGranted {
                capability: capability.to_string(),
            })?;

        if !session.capabilities.contains(&requested_capability) {
            return Err(AgentError::CapabilityNotGranted {
                capability: capability.to_string(),
            });
        }

        Ok(AuthorizeResponse {
            authorized: true,
            message: "Agent authorized".to_string(),
            matched_capabilities: vec![requested_capability],
        })
    }

    /// Revoke an agent and all its delegated children (cascading).
    ///
    /// Marks the agent as revoked in both registry and persistence, then
    /// recursively revokes all child agents delegated from this agent.
    ///
    /// Args:
    /// * `agent_did` — The agent DID to revoke.
    /// * `now` — Current time for enumerating active children.
    ///
    /// Usage:
    /// ```ignore
    /// service.revoke(&agent_did, Utc::now()).await?;
    /// ```
    pub async fn revoke(
        &self,
        agent_did: &IdentityDID,
        now: DateTime<Utc>,
    ) -> Result<(), AgentError> {
        // Revoke in registry (in-memory)
        self.registry.revoke(agent_did);

        // Revoke in persistence (Redis)
        self.persistence
            .revoke_agent(agent_did)
            .await
            .map_err(AgentError::PersistenceError)?;

        // Find and revoke all children (delegated by this agent)
        let children = self.registry.list_by_delegator(agent_did, now);
        for child in children {
            // Collect child DIDs and revoke them sequentially to avoid recursive async
            let child_did = child.agent_did.clone();
            Box::pin(self.revoke(&child_did, now)).await?;
        }

        Ok(())
    }
}
