//! Axum route handlers.

use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::StatusCode,
    middleware,
    routing::{get, post},
};
use serde::Serialize;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::config::McpServerConfig;
use crate::error::McpServerError;
use crate::middleware::jwt_auth_middleware;
use crate::state::McpServerState;
use crate::tools::{
    DeployRequest, ReadFileRequest, ToolResponse, WriteFileRequest, execute_deploy,
    execute_read_file, execute_write_file,
};
use crate::types::VerifiedAgent;

/// Build the application router.
///
/// Args:
/// * `state`: The shared MCP server state.
/// * `config`: The server configuration.
pub fn router(state: McpServerState, config: &McpServerConfig) -> Router {
    let protected_routes = Router::new()
        .route("/mcp/tools/{tool_name}", post(handle_tool_call))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            jwt_auth_middleware,
        ));

    let public_routes = Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource_metadata),
        )
        .route("/mcp/tools", get(list_tools))
        .route("/health", get(health));

    let app = public_routes
        .merge(protected_routes)
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    if config.enable_cors {
        app.layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
    } else {
        app
    }
}

/// `POST /mcp/tools/{tool_name}`
async fn handle_tool_call(
    State(state): State<McpServerState>,
    Extension(agent): Extension<VerifiedAgent>,
    Path(tool_name): Path<String>,
    body: axum::body::Bytes,
) -> Result<Json<ToolResponse>, McpServerError> {
    let required_cap = state
        .auth()
        .tool_capabilities()
        .get(&tool_name)
        .ok_or_else(|| McpServerError::UnknownTool(tool_name.clone()))?;

    if !agent.capabilities.contains(&required_cap.to_string()) {
        return Err(McpServerError::InsufficientCapabilities {
            tool: tool_name,
            required: required_cap.to_string(),
            granted: agent.capabilities,
        });
    }

    tracing::info!(
        agent_did = %agent.did,
        tool = %tool_name,
        "auths.mcp.tool_call.authorized"
    );

    let response = match tool_name.as_str() {
        "read_file" => {
            let request: ReadFileRequest = serde_json::from_slice(&body)
                .map_err(|e| McpServerError::ToolError(format!("invalid request body: {e}")))?;
            execute_read_file(request)?
        }
        "write_file" => {
            let request: WriteFileRequest = serde_json::from_slice(&body)
                .map_err(|e| McpServerError::ToolError(format!("invalid request body: {e}")))?;
            execute_write_file(request)?
        }
        "deploy" => {
            let request: DeployRequest = serde_json::from_slice(&body)
                .map_err(|e| McpServerError::ToolError(format!("invalid request body: {e}")))?;
            execute_deploy(request)?
        }
        _ => {
            return Err(McpServerError::UnknownTool(tool_name));
        }
    };

    Ok(Json(response))
}

/// OAuth Protected Resource Metadata.
#[derive(Serialize)]
struct ProtectedResourceMetadata {
    resource: String,
    authorization_servers: Vec<String>,
    scopes_supported: Vec<String>,
}

/// `GET /.well-known/oauth-protected-resource`
async fn protected_resource_metadata(
    State(state): State<McpServerState>,
) -> Json<ProtectedResourceMetadata> {
    let config = state.config();
    let scopes: Vec<String> = config.tool_capabilities.values().cloned().collect();

    Json(ProtectedResourceMetadata {
        resource: format!("http://{}", config.bind_addr),
        authorization_servers: vec![config.expected_issuer.clone()],
        scopes_supported: scopes,
    })
}

/// Tool listing response.
#[derive(Serialize)]
struct ToolInfo {
    name: String,
    required_capability: String,
}

/// `GET /mcp/tools`
async fn list_tools(State(state): State<McpServerState>) -> Json<Vec<ToolInfo>> {
    let tools: Vec<ToolInfo> = state
        .auth()
        .tool_capabilities()
        .iter()
        .map(|(name, cap)| ToolInfo {
            name: name.clone(),
            required_capability: cap.clone(),
        })
        .collect();

    Json(tools)
}

/// Health check response.
#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
}

/// `GET /health`
async fn health() -> (StatusCode, Json<HealthResponse>) {
    (
        StatusCode::OK,
        Json(HealthResponse {
            status: "ok".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }),
    )
}
