use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::Serialize;

use crate::AppState;
use auths_sdk::domains::agents::{
    AgentService, AgentSession, AuthorizeRequest, AuthorizeResponse, ProvisionRequest,
    ProvisionResponse,
};

/// Provision a new agent identity
///
/// POST /v1/agents
///
/// Request is signed with delegator's private key. Handler verifies signature,
/// validates delegation constraints, provisions agent identity, and stores in registry + Redis.
pub async fn provision_agent(
    State(state): State<AppState>,
    Json(req): Json<ProvisionRequest>,
) -> Result<(StatusCode, Json<ProvisionResponse>), (StatusCode, String)> {
    #[allow(clippy::disallowed_methods)]
    // INVARIANT: HTTP handler boundary, inject time at presentation layer
    let now = chrono::Utc::now();

    let service = AgentService::new(state.registry, state.persistence);
    let resp = service
        .provision(req, now)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

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

    let service = AgentService::new(state.registry, state.persistence);
    let resp = service
        .authorize(&req.agent_did, &req.capability, now, req.timestamp)
        .map_err(|e| {
            let error_msg = e.to_string();
            // Clock skew is a request validation error (400)
            // Authorization failures are authorization errors (401)
            let status = if error_msg.contains("Clock skew") {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::UNAUTHORIZED
            };
            (status, error_msg)
        })?;

    Ok((StatusCode::OK, Json(resp)))
}

/// Revoke an agent and all its children (cascading)
///
/// DELETE /v1/agents/{agent_did}
pub async fn revoke_agent(
    State(state): State<AppState>,
    Path(agent_did): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    #[allow(clippy::disallowed_methods)] // INVARIANT: HTTP handler boundary
    let now = chrono::Utc::now();

    let service = AgentService::new(state.registry, state.persistence);
    service
        .revoke(&agent_did, now)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;

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
    Path(agent_did): Path<String>,
) -> Result<(StatusCode, Json<AgentSession>), (StatusCode, String)> {
    #[allow(clippy::disallowed_methods)] // INVARIANT: HTTP handler boundary
    let now = chrono::Utc::now();

    let session = state
        .registry
        .get(&agent_did, now)
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Agent not found".to_string()))?;

    Ok((StatusCode::OK, Json(session)))
}
