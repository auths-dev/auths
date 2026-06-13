//! Axum authentication middleware: Bearer JWTs and KERI `Auths-Presentation`s.

use axum::{
    extract::{Request, State},
    http::HeaderMap,
    middleware::Next,
    response::Response,
};

use auths_rp::{AUTHS_PRESENTATION_SCHEME, parse_presentation_header};

use crate::error::McpServerError;
use crate::state::McpServerState;
use crate::types::VerifiedAgent;

/// Axum middleware that authenticates the request and inserts a [`VerifiedAgent`]
/// into request extensions.
///
/// Dispatches on the `Authorization` scheme:
/// * `Bearer <jwt>` — validated against the OIDC bridge's JWKS (an issuer in the path).
/// * `Auths-Presentation <token>` — verified offline against the KERI registry (no
///   issuer in the path); requires the state to be built with
///   [`McpServerState::with_keri_presentation`].
///
/// Per-tool capability gating happens in the route handler, identically for both schemes.
///
/// Usage:
/// ```ignore
/// let app = Router::new()
///     .route("/mcp/tools/:tool", post(handle_tool))
///     .route_layer(middleware::from_fn_with_state(state.clone(), auth_middleware));
/// ```
pub async fn auth_middleware(
    State(state): State<McpServerState>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, McpServerError> {
    let Some(header) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    else {
        emit_auth_failure("mcp:auth");
        return Err(McpServerError::Unauthorized(
            "missing Authorization header".to_string(),
        ));
    };

    let authenticated = if let Some(token) = header.strip_prefix("Bearer ") {
        authenticate_jwt(&state, token).await
    } else if header.starts_with(AUTHS_PRESENTATION_SCHEME) {
        authenticate_presentation_header(&state, header).await
    } else {
        Err(McpServerError::Unauthorized(
            "unsupported authorization scheme (expected 'Bearer' or 'Auths-Presentation')"
                .to_string(),
        ))
    };

    let agent = match authenticated {
        Ok(agent) => agent,
        Err(e) => {
            emit_auth_failure("mcp:auth");
            return Err(e);
        }
    };

    request.extensions_mut().insert(agent);
    Ok(next.run(request).await)
}

/// Validate a Bearer JWT into a [`VerifiedAgent`].
async fn authenticate_jwt(
    state: &McpServerState,
    token: &str,
) -> Result<VerifiedAgent, McpServerError> {
    let claims = state.auth().validate_jwt(token).await?;
    Ok(VerifiedAgent {
        did: claims.sub,
        keri_prefix: claims.keri_prefix,
        capabilities: claims.capabilities,
    })
}

/// Verify an `Auths-Presentation` header into a [`VerifiedAgent`] (no issuer in the path).
async fn authenticate_presentation_header(
    state: &McpServerState,
    header: &str,
) -> Result<VerifiedAgent, McpServerError> {
    let Some(keri) = state.keri() else {
        return Err(McpServerError::Unauthorized(
            "Auths-Presentation authentication is not enabled on this server".to_string(),
        ));
    };
    // Parse only the wire shape here; never log the header (nonce/signature).
    let wire = parse_presentation_header(header)
        .map_err(|e| McpServerError::Unauthorized(format!("malformed presentation: {e}")))?;
    keri.authenticate(wire, chrono::Utc::now()).await
}

fn emit_auth_failure(action: &str) {
    let now = chrono::Utc::now().timestamp();
    let event = auths_telemetry::build_audit_event("unknown", action, "Denied", now);
    auths_telemetry::emit_telemetry(&event);
}
