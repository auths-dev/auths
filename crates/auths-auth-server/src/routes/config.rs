//! GET /config — return server configuration to mobile clients.

use axum::{Json, extract::State};
use serde::Serialize;

use crate::AuthServerState;
use crate::config::ResolverMode;

#[derive(Debug, Serialize)]
pub struct ConfigResponse {
    pub registry_url: String,
}

pub async fn get_config(State(state): State<AuthServerState>) -> Json<ConfigResponse> {
    let registry_url = match &state.config().resolver_mode {
        ResolverMode::RegistryHttp { url } => url.clone(),
        ResolverMode::LocalGit { repo_path } => {
            format!("local:{}", repo_path.display())
        }
    };
    Json(ConfigResponse { registry_url })
}
