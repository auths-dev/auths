//! POST /auth/init — create a new auth challenge session.

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::AuthServerState;
use crate::domain::{AuthChallenge, AuthSession, SessionStatus};
use crate::error::{AuthApiError, AuthApiResult};

#[derive(Debug, Deserialize)]
pub struct InitRequest {
    /// The origin domain. Defaults to the server's own domain if omitted.
    #[serde(default)]
    pub domain: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct InitResponse {
    pub id: Uuid,
    pub challenge: String,
    pub domain: String,
    pub expires_at: String,
}

#[allow(clippy::disallowed_methods)]
pub async fn init_auth(
    State(state): State<AuthServerState>,
    Json(request): Json<InitRequest>,
) -> AuthApiResult<Json<InitResponse>> {
    let domain = request.domain.unwrap_or_else(|| "localhost".to_string());
    let now = state.app_service().clock().now();
    let ttl = chrono::Duration::seconds(state.config().challenge_ttl_secs as i64);
    let expires_at = now + ttl;

    // Generate 32 random bytes as hex nonce
    let mut nonce_bytes = [0u8; 32];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut nonce_bytes)
        .map_err(|_| AuthApiError::Internal("failed to generate nonce".to_string()))?;
    let nonce = hex::encode(nonce_bytes);

    let id = Uuid::new_v4();

    let challenge = AuthChallenge {
        id,
        nonce: nonce.clone(),
        domain: domain.clone(),
        created_at: now,
        expires_at,
    };

    let session = AuthSession {
        challenge,
        status: SessionStatus::Pending,
    };

    state
        .app_service()
        .sessions()
        .create(session)
        .await
        .map_err(|e| AuthApiError::Internal(e.to_string()))?;

    Ok(Json(InitResponse {
        id,
        challenge: nonce,
        domain,
        expires_at: expires_at.to_rfc3339(),
    }))
}
