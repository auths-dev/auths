use axum::routing::get;
use axum::Router;

/// Application state shared across handlers.
///
/// Empty until a domain is mounted — the legacy bearer-token agent state
/// (registry + Redis persistence) was removed in Epic E.
#[derive(Clone, Default)]
pub struct AppState {}

/// Build the API router.
///
/// Currently exposes only a `/health` probe. The legacy `/v1/agents` routes were
/// removed in Epic E (the agent surface is the SDK/CLI); future domains mount here.
///
/// Args:
/// * `_state`: Shared application state (unused until a stateful domain is mounted).
///
/// Usage:
/// ```
/// use auths_api::app::{AppState, build_router};
/// let _router = build_router(AppState::default());
/// ```
pub fn build_router(_state: AppState) -> Router {
    Router::new().route("/health", get(health))
}

/// Liveness probe.
async fn health() -> &'static str {
    "ok"
}
