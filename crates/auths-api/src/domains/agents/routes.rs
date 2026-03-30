use axum::{
    Router,
    routing::{delete, get, post},
};

use super::handlers::{
    admin_stats, authorize_operation, get_agent, list_agents, provision_agent, revoke_agent,
};
use crate::AppState;

/// Build agent domain routes
/// All routes are under /v1/ prefix (applied at router composition level)
pub fn routes(state: AppState) -> Router {
    Router::new()
        .route("/agents", post(provision_agent))
        .route("/agents", get(list_agents))
        .route("/agents/{agent_did}", get(get_agent))
        .route("/agents/{agent_did}", delete(revoke_agent))
        .route("/authorize", post(authorize_operation))
        .route("/admin/stats", get(admin_stats))
        .with_state(state)
}
