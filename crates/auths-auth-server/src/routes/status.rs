//! GET /auth/status/:id — poll the status of an auth session.

use axum::{
    Json,
    extract::{Path, State},
};
use serde::Serialize;
use uuid::Uuid;

use crate::AuthServerState;
use crate::error::AuthApiResult;

#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub id: Uuid,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did: Option<String>,
    pub expires_at: String,
}

/// Axum handler — delegates status lookup to `AuthAppService`.
pub async fn auth_status(
    State(state): State<AuthServerState>,
    Path(id): Path<Uuid>,
) -> AuthApiResult<Json<StatusResponse>> {
    let view = state.app_service().get_session_status(&id).await?;

    Ok(Json(StatusResponse {
        id: view.id,
        status: view.status,
        did: view.did,
        expires_at: view.expires_at.to_rfc3339(),
    }))
}
