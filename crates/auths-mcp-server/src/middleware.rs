//! Axum middleware for JWT authentication and tool authorization.

use axum::{
    extract::{Request, State},
    http::HeaderMap,
    middleware::Next,
    response::Response,
};

use crate::error::McpServerError;
use crate::state::McpServerState;
use crate::types::VerifiedAgent;

/// Extracts the Bearer token from the Authorization header.
pub fn extract_bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
}

/// Axum middleware that validates the JWT and inserts claims into request extensions.
///
/// Args:
/// * `state`: The shared MCP server state containing the AuthsToolAuth instance.
/// * `headers`: Request headers (for Authorization extraction).
/// * `request`: The incoming request.
/// * `next`: The next middleware/handler in the chain.
///
/// Usage:
/// ```ignore
/// let app = Router::new()
///     .route("/mcp/tools/:tool", post(handle_tool))
///     .route_layer(middleware::from_fn_with_state(state.clone(), jwt_auth_middleware));
/// ```
pub async fn jwt_auth_middleware(
    State(state): State<McpServerState>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, McpServerError> {
    let token = match extract_bearer_token(&headers) {
        Some(t) => t,
        None => {
            emit_auth_failure("mcp:auth");
            return Err(McpServerError::Unauthorized(
                "missing Authorization header".to_string(),
            ));
        }
    };

    let claims = match state.auth().validate_jwt(token).await {
        Ok(c) => c,
        Err(e) => {
            emit_auth_failure("mcp:auth");
            return Err(e);
        }
    };

    let agent = VerifiedAgent {
        did: claims.sub,
        keri_prefix: claims.keri_prefix,
        capabilities: claims.capabilities,
    };

    request.extensions_mut().insert(agent);
    Ok(next.run(request).await)
}

fn emit_auth_failure(action: &str) {
    let now = chrono::Utc::now().timestamp();
    let event = auths_telemetry::build_audit_event("unknown", action, "Denied", now);
    auths_telemetry::emit_telemetry(&event);
}
