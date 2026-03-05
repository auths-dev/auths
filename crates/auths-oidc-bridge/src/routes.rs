//! Axum route handlers.

use axum::{
    Json, Router,
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use serde::Serialize;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::config::BridgeConfig;
use crate::error::BridgeError;
use crate::state::BridgeState;
use crate::token::{ExchangeRequest, TokenResponse};

/// Build the application router.
pub fn router(state: BridgeState, config: &BridgeConfig) -> Router {
    let mut app = Router::new()
        .route("/.well-known/openid-configuration", get(openid_config))
        .route("/.well-known/jwks.json", get(jwks))
        .route("/token", post(token_exchange))
        .route("/health", get(health));

    if config.admin_token.is_some() {
        app = app
            .route("/admin/rotate-key", post(rotate_key))
            .route("/admin/drop-previous-key", post(drop_previous_key));
    }

    let app = app.with_state(state).layer(TraceLayer::new_for_http());

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

/// OIDC Discovery document.
#[derive(Serialize)]
struct OpenIdConfiguration {
    issuer: String,
    jwks_uri: String,
    token_endpoint: String,
    response_types_supported: Vec<String>,
    subject_types_supported: Vec<String>,
    id_token_signing_alg_values_supported: Vec<String>,
    claims_supported: Vec<String>,
}

/// `GET /.well-known/openid-configuration`
async fn openid_config(State(state): State<BridgeState>) -> Json<OpenIdConfiguration> {
    let issuer_url = &state.config().issuer_url;
    Json(OpenIdConfiguration {
        issuer: issuer_url.clone(),
        jwks_uri: format!("{issuer_url}/.well-known/jwks.json"),
        token_endpoint: format!("{issuer_url}/token"),
        response_types_supported: vec!["id_token".to_string()],
        subject_types_supported: vec!["public".to_string()],
        id_token_signing_alg_values_supported: vec!["RS256".to_string()],
        claims_supported: vec![
            "iss".to_string(),
            "sub".to_string(),
            "aud".to_string(),
            "exp".to_string(),
            "iat".to_string(),
            "jti".to_string(),
            "keri_prefix".to_string(),
            "capabilities".to_string(),
            "witness_quorum".to_string(),
            "github_actor".to_string(),
            "github_repository".to_string(),
        ],
    })
}

/// `GET /.well-known/jwks.json`
async fn jwks(State(state): State<BridgeState>) -> Json<crate::jwks::Jwks> {
    let km = state.key_manager().read().await;
    Json(km.jwks())
}

/// `POST /token`
async fn token_exchange(
    State(state): State<BridgeState>,
    Json(request): Json<ExchangeRequest>,
) -> Result<Json<TokenResponse>, BridgeError> {
    // Rate limit check (before expensive chain verification)
    if let Some(rate_limiter) = state.rate_limiter()
        && let Some(first_att) = request.attestation_chain.first()
    {
        let prefix = crate::token::extract_keri_prefix(first_att.issuer.as_ref());
        rate_limiter.check(&prefix)?;
    }

    // GitHub OIDC cross-reference (composable pre-step, separate from issuer)
    #[cfg(feature = "github-oidc")]
    let github_cross_ref = {
        match (&request.github_oidc_token, &request.github_actor) {
            (Some(gh_token), Some(expected_actor)) => {
                let jwks_client = state.github_jwks().ok_or_else(|| {
                    BridgeError::InvalidRequest(
                        "GitHub OIDC cross-reference not configured on this bridge".to_string(),
                    )
                })?;

                match crate::cross_reference::verify_github_cross_reference(
                    gh_token,
                    expected_actor,
                    jwks_client,
                )
                .await
                {
                    Ok(result) => {
                        tracing::info!(
                            actor = result.actor,
                            repository = result.repository,
                            "auths.exchange.github_cross_reference.success"
                        );
                        Some(result)
                    }
                    Err(e) => {
                        tracing::warn!(
                            error_code = %e,
                            "auths.exchange.github_cross_reference.failure"
                        );
                        return Err(e);
                    }
                }
            }
            (Some(_), None) => {
                return Err(BridgeError::InvalidRequest(
                    "github_actor is required when github_oidc_token is provided".to_string(),
                ));
            }
            _ => {
                tracing::info!("auths.exchange.keri_only");
                None
            }
        }
    };

    let issuer = state.issuer().read().await;
    let response = issuer
        .exchange(
            &request,
            #[cfg(feature = "oidc-policy")]
            state.workload_policy(),
            #[cfg(feature = "github-oidc")]
            github_cross_ref.as_ref(),
        )
        .await?;

    Ok(Json(response))
}

/// Verify the admin Bearer token from request headers.
fn verify_admin_token(headers: &HeaderMap, config: &BridgeConfig) -> Result<(), BridgeError> {
    let expected = config
        .admin_token
        .as_deref()
        .ok_or_else(|| BridgeError::Internal("admin endpoint not configured".into()))?;

    let provided = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "));

    match provided {
        Some(token) if token == expected => Ok(()),
        _ => Err(BridgeError::Unauthorized("invalid admin token".into())),
    }
}

/// `POST /admin/rotate-key`
async fn rotate_key(
    State(state): State<BridgeState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<crate::jwks::Jwks>, BridgeError> {
    verify_admin_token(&headers, state.config())?;
    let jwks = state.rotate_key(&body).await?;
    Ok(Json(jwks))
}

/// `POST /admin/drop-previous-key`
async fn drop_previous_key(
    State(state): State<BridgeState>,
    headers: HeaderMap,
) -> Result<Json<crate::jwks::Jwks>, BridgeError> {
    verify_admin_token(&headers, state.config())?;
    let jwks = state.drop_previous_key().await;
    Ok(Json(jwks))
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
