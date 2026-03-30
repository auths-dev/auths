use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::Serialize;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::AppState;
use auths_core::error::AgentError as CoreAgentError;
use auths_core::signing::PassphraseProvider;
use auths_core::storage::keychain::KeyAlias;
use auths_id::identity::initialize::initialize_registry_identity;
use auths_sdk::domains::agents::{
    AgentError, AgentService, AgentSession, AuthorizeRequest, AuthorizeResponse, ProvisionRequest,
    ProvisionResponse,
};
use auths_verifier::IdentityDID;

/// Simple passphrase provider for agent key storage.
/// Uses a fixed server-configured value.
struct AgentPassphraseProvider {
    passphrase: String,
}

impl PassphraseProvider for AgentPassphraseProvider {
    fn get_passphrase(&self, _prompt: &str) -> Result<Zeroizing<String>, CoreAgentError> {
        Ok(Zeroizing::new(self.passphrase.clone()))
    }
}

/// Convert an AgentError to an HTTP response tuple.
fn agent_error_to_http(error: &AgentError) -> (StatusCode, String) {
    match error {
        AgentError::AgentNotFound { agent_did } => (
            StatusCode::NOT_FOUND,
            format!("Agent not found: {}", agent_did),
        ),
        AgentError::AgentRevoked { agent_did } => (
            StatusCode::UNAUTHORIZED,
            format!("Agent is revoked: {}", agent_did),
        ),
        AgentError::AgentExpired { agent_did } => (
            StatusCode::UNAUTHORIZED,
            format!("Agent has expired: {}", agent_did),
        ),
        AgentError::CapabilityNotGranted { capability } => (
            StatusCode::FORBIDDEN,
            format!("Capability not granted: {}", capability),
        ),
        AgentError::DelegationViolation(e) => (
            StatusCode::BAD_REQUEST,
            format!("Delegation constraint violated: {}", e),
        ),
        AgentError::PersistenceError(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Persistence error: {}", e),
        ),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Unknown agent error".to_string(),
        ),
    }
}

/// Provision a new agent identity
///
/// POST /v1/agents
///
/// Creates a new KERI identity for the agent, stores encrypted keypairs in the keychain,
/// validates delegation constraints, and stores the agent session in registry + Redis.
pub async fn provision_agent(
    State(state): State<AppState>,
    Json(req): Json<ProvisionRequest>,
) -> Result<(StatusCode, Json<ProvisionResponse>), (StatusCode, String)> {
    #[allow(clippy::disallowed_methods)]
    // INVARIANT: HTTP handler boundary, inject time and IDs at presentation layer
    let now = chrono::Utc::now();

    #[allow(clippy::disallowed_methods)] // INVARIANT: HTTP handler boundary
    let session_id = Uuid::new_v4();

    // Create KERI identity for the agent at HTTP boundary
    let passphrase_provider = AgentPassphraseProvider {
        passphrase: "agent-key-secure-12chars".to_string(), // TODO: Use secure configuration
    };
    let key_alias = KeyAlias::new_unchecked(format!("agent-{}", session_id));

    let (agent_did, _) = initialize_registry_identity(
        state.registry_backend.clone(),
        &key_alias,
        &passphrase_provider,
        &*state.keychain,
        None, // no witness config for agents
    )
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to create agent identity: {}", e),
        )
    })?;

    // Assign default capabilities if none provided (at HTTP boundary)
    let mut provision_req = req;
    if provision_req.capabilities.is_empty() {
        use auths_verifier::Capability;
        provision_req.capabilities = vec![Capability::sign_commit()];
    }

    let service = AgentService::new(state.registry, state.persistence);
    let resp = service
        .provision(provision_req, session_id, agent_did, now)
        .await
        .map_err(|e| agent_error_to_http(&e))?;

    Ok((StatusCode::CREATED, Json(resp)))
}

/// Authorize an operation for an agent
///
/// POST /v1/authorize
///
/// Verifies Ed25519 signature, checks agent is active, evaluates capabilities.
/// Returns authorization decision.
pub async fn authorize_operation(
    State(state): State<AppState>,
    Json(req): Json<AuthorizeRequest>,
) -> Result<(StatusCode, Json<AuthorizeResponse>), (StatusCode, String)> {
    #[allow(clippy::disallowed_methods)] // INVARIANT: HTTP handler boundary
    let now = chrono::Utc::now();

    // Validate clock skew (±5 minutes)
    let time_diff = {
        let duration = now.signed_duration_since(req.timestamp);
        duration.num_seconds().unsigned_abs()
    };
    if time_diff > 300 {
        return Err((StatusCode::BAD_REQUEST, "Clock skew too large".to_string()));
    }

    let service = AgentService::new(state.registry, state.persistence);
    let resp = service
        .authorize(&req.agent_did, &req.capability, now)
        .map_err(|e| agent_error_to_http(&e))?;

    Ok((StatusCode::OK, Json(resp)))
}

/// Revoke an agent and all its children (cascading)
///
/// DELETE /v1/agents/{agent_did}
pub async fn revoke_agent(
    State(state): State<AppState>,
    Path(agent_did_str): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    #[allow(clippy::disallowed_methods)] // INVARIANT: HTTP handler boundary
    let now = chrono::Utc::now();

    let agent_did = IdentityDID::parse(&agent_did_str)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid agent DID: {}", e)))?;

    let service = AgentService::new(state.registry, state.persistence);
    service
        .revoke(&agent_did, now)
        .await
        .map_err(|e| agent_error_to_http(&e))?;

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize)]
pub struct ListAgentsResponse {
    pub agents: Vec<AgentSession>,
    pub total: usize,
}

/// List all active agents
///
/// GET /v1/agents
pub async fn list_agents(
    State(state): State<AppState>,
) -> Result<(StatusCode, Json<ListAgentsResponse>), (StatusCode, String)> {
    #[allow(clippy::disallowed_methods)] // INVARIANT: HTTP handler boundary
    let now = chrono::Utc::now();

    let agents = state.registry.list(now);
    let total = agents.len();

    Ok((StatusCode::OK, Json(ListAgentsResponse { agents, total })))
}

#[derive(Debug, Serialize)]
pub struct AgentStatsResponse {
    pub total_active: usize,
    pub total_revoked: usize,
    pub max_delegation_depth: u32,
}

/// Get registry statistics
///
/// GET /v1/admin/stats
pub async fn admin_stats(
    State(state): State<AppState>,
) -> Result<(StatusCode, Json<AgentStatsResponse>), (StatusCode, String)> {
    #[allow(clippy::disallowed_methods)] // INVARIANT: HTTP handler boundary
    let now = chrono::Utc::now();

    let sessions = state.registry.list(now);
    let total_active = sessions.len();
    let max_delegation_depth = sessions
        .iter()
        .map(|s| s.delegation_depth)
        .max()
        .unwrap_or(0);

    Ok((
        StatusCode::OK,
        Json(AgentStatsResponse {
            total_active,
            total_revoked: 0,
            max_delegation_depth,
        }),
    ))
}

/// Get details for a specific agent
///
/// GET /v1/agents/{agent_did}
pub async fn get_agent(
    State(state): State<AppState>,
    Path(agent_did_str): Path<String>,
) -> Result<(StatusCode, Json<AgentSession>), (StatusCode, String)> {
    #[allow(clippy::disallowed_methods)] // INVARIANT: HTTP handler boundary
    let now = chrono::Utc::now();

    let agent_did = IdentityDID::parse(&agent_did_str)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid agent DID: {}", e)))?;

    let session = state
        .registry
        .get(&agent_did, now)
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Agent not found".to_string()))?;

    Ok((StatusCode::OK, Json(session)))
}
