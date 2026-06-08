//! SCIM 2.0 provisioning server for Auths.
//!
//! A library [`router`] mountable both standalone (via the `auths-scim-server`
//! binary) and nested inside `auths-api`'s control plane. This crate is the thin
//! HTTP presentation boundary for SCIM: it serves discovery, authenticates the
//! per-tenant channel, and maps domain errors to the RFC 7644 error envelope.
//!
//! KERI/registry is the source of truth — there is **no** authoritative database
//! here. The archived server's Postgres + fake-DID path is deliberately not
//! reproduced; provisioning writes through real identity-lifecycle workflows
//! (wired in the Joiner/Leaver tasks).
//!
//! This module ships the skeleton: read-only discovery endpoints, bearer-token
//! tenant auth, and error mapping. `/Users` is present and auth-gated but returns
//! an empty list until lifecycle wiring lands.

mod auth;
mod discovery;
mod error;
mod state;

pub use auth::AuthenticatedTenant;
pub use error::ScimServerError;
pub use state::{ScimServerState, TenantConfig};

use axum::Router;
use axum::routing::get;

/// Build the SCIM 2.0 router.
///
/// Mounts the read-only discovery endpoints and the auth-gated `/Users` route
/// under `/scim/v2`. Discovery is unauthenticated (as IdPs expect); `/Users`
/// extracts [`AuthenticatedTenant`] and fails closed (401) without a valid
/// bearer token. The returned router has its state applied, so it composes into
/// a parent `axum::Router` with `.merge()` / `.nest()` (e.g. `auths-api`).
///
/// Args:
/// * `state`: Shared server state (tenant config + hashed channel tokens).
///
/// Usage:
/// ```ignore
/// let app = router(state);
/// axum::serve(listener, app).await?;
/// ```
pub fn router(state: ScimServerState) -> Router {
    Router::new()
        .route(
            "/scim/v2/ServiceProviderConfig",
            get(discovery::service_provider_config),
        )
        .route("/scim/v2/ResourceTypes", get(discovery::resource_types))
        .route("/scim/v2/Schemas", get(discovery::schemas))
        .route("/scim/v2/Users", get(discovery::list_users))
        .route("/health", get(health))
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn test_state() -> ScimServerState {
        ScimServerState::new(vec![TenantConfig::new("acme", "EAbc123", "scim_secret")])
    }

    async fn body_string(resp: axum::response::Response) -> String {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn service_provider_config_is_unauthenticated_and_ok() {
        let resp = router(test_state())
            .oneshot(
                Request::builder()
                    .uri("/scim/v2/ServiceProviderConfig")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_string(resp).await.contains("patch"));
    }

    #[tokio::test]
    async fn resource_types_lists_user() {
        let resp = router(test_state())
            .oneshot(
                Request::builder()
                    .uri("/scim/v2/ResourceTypes")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp).await;
        assert!(body.contains("\"Resources\""));
        assert!(body.contains("/Users"));
    }

    #[tokio::test]
    async fn users_requires_bearer_token() {
        let resp = router(test_state())
            .oneshot(
                Request::builder()
                    .uri("/scim/v2/Users")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        // RFC 7644 error envelope.
        assert!(
            body_string(resp)
                .await
                .contains("scim:api:messages:2.0:Error")
        );
    }

    #[tokio::test]
    async fn users_with_valid_token_returns_empty_list() {
        let resp = router(test_state())
            .oneshot(
                Request::builder()
                    .uri("/scim/v2/Users")
                    .header(header::AUTHORIZATION, "Bearer scim_secret")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_string(resp).await.contains("\"totalResults\":0"));
    }

    #[tokio::test]
    async fn users_rejects_wrong_token() {
        let resp = router(test_state())
            .oneshot(
                Request::builder()
                    .uri("/scim/v2/Users")
                    .header(header::AUTHORIZATION, "Bearer wrong")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn router_nests_into_a_parent_router() {
        // Demonstrates mountability inside auths-api's control plane: the scim
        // router (state already applied) merges into a parent Router<()>.
        let parent = Router::new().merge(router(test_state()));
        let resp = parent
            .oneshot(
                Request::builder()
                    .uri("/scim/v2/ServiceProviderConfig")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
