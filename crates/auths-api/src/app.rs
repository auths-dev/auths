use axum::Router;
use std::sync::Arc;

use crate::domains::agents::routes as agent_routes;
use crate::persistence::AgentPersistence;
use auths_core::storage::keychain::KeyStorage;
use auths_id::storage::registry::RegistryBackend;
use auths_sdk::domains::agents::AgentRegistry;

/// Application state shared across all handlers
#[derive(Clone)]
pub struct AppState {
    pub registry: Arc<AgentRegistry>,
    pub persistence: Arc<AgentPersistence>,
    pub registry_backend: Arc<dyn RegistryBackend + Send + Sync>,
    pub keychain: Arc<dyn KeyStorage + Send + Sync>,
}

/// Build the complete API router
/// Composes routes from all domains
pub fn build_router(state: AppState) -> Router {
    Router::new().nest("/v1", agent_routes::routes(state.clone()))
    // Future domains will be nested here:
    // .nest("/v1", developer_routes(state.clone()))
    // .nest("/v1", organization_routes(state.clone()))
    // .nest("/v1", verification_routes(state.clone()))
}
