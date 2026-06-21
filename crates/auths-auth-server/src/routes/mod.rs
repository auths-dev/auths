//! API route handlers for the auth server.

pub mod config;
pub mod init;
pub mod register;
pub mod status;
pub mod verify;

use axum::{
    Router,
    routing::{get, post},
};
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;

use crate::AuthServerState;

/// Build the API router.
pub fn router(state: AuthServerState) -> Router {
    let static_dir = state.config().static_dir.clone();

    let api_routes = Router::new()
        .route("/auth/init", post(init::init_auth))
        .route("/auth/verify", post(verify::verify_auth))
        .route("/auth/status/{id}", get(status::auth_status))
        .route("/connect/register", post(register::register_client))
        .route("/config", get(config::get_config))
        .with_state(state);

    // Serve static files (mock bank UI) at the root
    let static_service = ServeDir::new(static_dir);

    Router::new()
        .merge(api_routes)
        .fallback_service(static_service)
        .layer(TraceLayer::new_for_http())
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any),
        )
}
