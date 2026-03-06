//! Axum router for the SCIM 2.0 API.

use axum::routing::{delete, get, patch, post, put};
use axum::Router;

use crate::handlers::{discovery, users};
use crate::state::ScimServerState;

/// Build the SCIM API router.
///
/// Args:
/// * `state`: Shared server state.
///
/// Usage:
/// ```ignore
/// let app = router(state);
/// let listener = tokio::net::TcpListener::bind("0.0.0.0:3301").await?;
/// axum::serve(listener, app).await?;
/// ```
pub fn router(state: ScimServerState) -> Router {
    Router::new()
        // Discovery endpoints (no auth required)
        .route("/", get(discovery::api_root))
        .route(
            "/ServiceProviderConfig",
            get(discovery::service_provider_config),
        )
        .route("/ResourceTypes", get(discovery::resource_types))
        // User CRUD endpoints (auth required via AuthenticatedTenant extractor)
        .route("/Users", post(users::create_user))
        .route("/Users", get(users::list_users))
        .route("/Users/{id}", get(users::get_user))
        .route("/Users/{id}", put(users::replace_user))
        .route("/Users/{id}", patch(users::update_user))
        .route("/Users/{id}", delete(users::delete_user))
        .with_state(state)
}
