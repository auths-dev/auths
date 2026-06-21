//! POST /auth/verify — verify a signed challenge from the mobile app.

use axum::{Json, extract::State};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::AuthServerState;
use crate::domain::app_service::VerifyCommand;
use crate::error::AuthApiResult;

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    /// Session ID from the QR code.
    pub id: Uuid,
    /// The user's DID, e.g. "did:keri:EPREFIX".
    pub did: String,
    /// Hex-encoded Ed25519 signature of the canonical challenge payload.
    pub signature: String,
    /// Hex-encoded 32-byte Ed25519 public key.
    pub public_key: String,
}

#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub verified: bool,
    pub token: String,
    pub did: String,
    pub expires_at: String,
}

/// Axum handler — parses the request and delegates to `AuthAppService`.
pub async fn verify_auth(
    State(state): State<AuthServerState>,
    Json(request): Json<VerifyRequest>,
) -> AuthApiResult<Json<VerifyResponse>> {
    let result = state
        .app_service()
        .verify_challenge(VerifyCommand {
            session_id: request.id,
            did: request.did,
            signature: request.signature,
            public_key: request.public_key,
        })
        .await?;

    Ok(Json(VerifyResponse {
        verified: true,
        token: result.session_id.to_string(),
        did: result.did,
        expires_at: result.expires_at.to_rfc3339(),
    }))
}
