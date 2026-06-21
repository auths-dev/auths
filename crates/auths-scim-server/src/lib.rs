//! SCIM 2.0 provisioning server for Auths.
//!
//! A library [`router`] mountable both standalone (via the `auths-scim-server`
//! binary) and nested inside `auths-api`'s control plane. This crate is the thin
//! HTTP presentation boundary for SCIM: it serves discovery, authenticates the
//! per-tenant channel, maps the request to identity-lifecycle calls through the
//! [`Provisioner`] port, and renders the RFC 7644 error envelope.
//!
//! KERI/registry is the source of truth — there is **no** authoritative database
//! here. The archived server's Postgres + fake-DID path is deliberately not
//! reproduced; the Joiner provisions a real delegated identity via `add_member`
//! (see [`SdkProvisioner`]), idempotent on `(tenant, externalId)`.

mod auth;
mod discovery;
mod error;
mod lifecycle;
mod provisioner;
mod serve;
mod state;
mod users;

pub use auth::AuthenticatedTenant;
pub use error::ScimServerError;
pub use provisioner::{
    ProvisionError, ProvisionedMember, Provisioner, RevokeOutcome, SdkProvisioner,
};
pub use serve::{ServeConfig, TenantBootstrap, build_provisioner, run};
pub use state::{ScimServerState, TenantConfig};

use axum::Router;
use axum::routing::{get, post};

/// Build the SCIM 2.0 router.
///
/// Mounts the read-only discovery endpoints and the auth-gated `/Users`
/// collection (list/create), item (`GET`/`PATCH`/`DELETE` on `/Users/{id}`), and
/// the explicit hard-revoke control endpoint (`POST /Users/{id}/revoke`) under
/// `/scim/v2`. PATCH/DELETE are reversible soft-disables; revoke is the
/// irreversible cryptographic off-boarding. Discovery is unauthenticated (as IdPs
/// expect); every `/Users` route extracts [`AuthenticatedTenant`] and fails closed
/// (401) without a valid bearer token. The returned router has its state applied,
/// so it composes into a parent `axum::Router` with `.merge()` / `.nest()` (e.g.
/// `auths-api`).
///
/// Args:
/// * `state`: Shared server state (tenants, hashed channel tokens, provisioner).
///
/// Usage:
/// ```ignore
/// let state = ScimServerState::new(tenants, Arc::new(SdkProvisioner::new(ctx)));
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
        .route(
            "/scim/v2/Users",
            get(users::list_users).post(users::create_user),
        )
        .route(
            "/scim/v2/Users/{id}",
            get(users::get_user)
                .put(users::put_user)
                .patch(lifecycle::patch_user)
                .delete(lifecycle::delete_user),
        )
        .route("/scim/v2/Users/{id}/revoke", post(lifecycle::revoke_user))
        .route("/health", get(health))
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::provisioner::fake::FakeProvisioner;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    const ORG: &str = "EAbc123";

    /// State wired to a fake provisioner that knows `ORG`. Returns the provisioner
    /// handle too, so tests can assert how many delegations actually happened.
    fn state_with_fake(known_org: &str) -> (ScimServerState, Arc<FakeProvisioner>) {
        let provisioner = Arc::new(FakeProvisioner::new(&[known_org]));
        // Capability allowlisting is deny-by-default (B.1 / RT-006). These CRUD
        // tests exercise provisioning behavior, not the allowlist (which is unit-
        // tested in `auths-scim`), and they use arbitrary capabilities, so the
        // harness opts into allow-all. A restrictive-allowlist deny is covered by
        // `joiner_with_disallowed_capability_is_denied` below.
        let tenant = TenantConfig::new("acme", ORG, "scim_secret")
            .with_base_url("https://scim.test/scim/v2")
            .with_allow_all(true);
        let state = ScimServerState::new(
            vec![tenant],
            Arc::clone(&provisioner) as Arc<dyn Provisioner>,
        );
        (state, provisioner)
    }

    fn test_state() -> ScimServerState {
        state_with_fake(ORG).0
    }

    fn user_body(user_name: &str, external_id: &str) -> String {
        format!(
            r#"{{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"{user_name}","externalId":"{external_id}","urn:ietf:params:scim:schemas:extension:auths:2.0:Agent":{{"capabilities":["sign:commit"]}}}}"#
        )
    }

    fn post_users(body: String) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/scim/v2/Users")
            .header(header::AUTHORIZATION, "Bearer scim_secret")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap()
    }

    fn get_authed(uri: &str) -> Request<Body> {
        Request::builder()
            .uri(uri)
            .header(header::AUTHORIZATION, "Bearer scim_secret")
            .body(Body::empty())
            .unwrap()
    }

    fn patch_req(id: &str, body: String) -> Request<Body> {
        Request::builder()
            .method("PATCH")
            .uri(format!("/scim/v2/Users/{id}"))
            .header(header::AUTHORIZATION, "Bearer scim_secret")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body))
            .unwrap()
    }

    fn delete_req(id: &str) -> Request<Body> {
        Request::builder()
            .method("DELETE")
            .uri(format!("/scim/v2/Users/{id}"))
            .header(header::AUTHORIZATION, "Bearer scim_secret")
            .body(Body::empty())
            .unwrap()
    }

    fn revoke_req(id: &str) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(format!("/scim/v2/Users/{id}/revoke"))
            .header(header::AUTHORIZATION, "Bearer scim_secret")
            .body(Body::empty())
            .unwrap()
    }

    /// A single-op PATCH body (`replace path = value`).
    fn patch_op(path: &str, value: serde_json::Value) -> String {
        format!(
            r#"{{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{{"op":"replace","path":"{path}","value":{value}}}]}}"#
        )
    }

    /// Create a user via the Joiner and return its resource id.
    async fn create_user_id(app: &Router, name: &str, external_id: &str) -> String {
        let resp = app
            .clone()
            .oneshot(post_users(user_body(name, external_id)))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        json_value(resp).await["id"].as_str().unwrap().to_string()
    }

    const AGENT_EXT: &str = "urn:ietf:params:scim:schemas:extension:auths:2.0:Agent";

    async fn body_string(resp: axum::response::Response) -> String {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    async fn json_value(resp: axum::response::Response) -> serde_json::Value {
        serde_json::from_str(&body_string(resp).await).unwrap()
    }

    // ── Discovery / auth skeleton (unchanged behaviour) ──

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
        assert!(
            body_string(resp)
                .await
                .contains("scim:api:messages:2.0:Error")
        );
    }

    #[tokio::test]
    async fn empty_tenant_lists_zero_users() {
        let resp = router(test_state())
            .oneshot(get_authed("/scim/v2/Users"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(body_string(resp).await.contains("\"totalResults\":0"));
    }

    #[tokio::test]
    async fn router_nests_into_a_parent_router() {
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

    // ── Joiner ──

    #[tokio::test]
    async fn joiner_creates_delegated_identity_with_typed_did() {
        let resp = router(test_state())
            .oneshot(post_users(user_body("deploy-bot", "okta-1")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let v = json_value(resp).await;
        assert_eq!(v["userName"], "deploy-bot");
        let did = v["urn:ietf:params:scim:schemas:extension:auths:2.0:Agent"]["identityDid"]
            .as_str()
            .expect("response carries the delegated DID");
        assert!(
            did.starts_with("did:keri:"),
            "real delegated did:keri, not a fake DID"
        );
        assert!(!v["id"].as_str().unwrap().is_empty());
    }

    #[tokio::test]
    async fn joiner_with_disallowed_capability_is_denied() {
        // B.1 / RT-006: a tenant with a restrictive allowlist denies a capability
        // outside it (deny-by-default at the server boundary, not just the mapper).
        let provisioner = Arc::new(FakeProvisioner::new(&[ORG]));
        let tenant = TenantConfig::new("acme", ORG, "scim_secret")
            .with_base_url("https://scim.test/scim/v2")
            .with_allowed_capabilities(vec![
                auths_verifier::Capability::parse("deploy:staging").unwrap(),
            ]);
        let state = ScimServerState::new(
            vec![tenant],
            Arc::clone(&provisioner) as Arc<dyn Provisioner>,
        );
        // `user_body` requests "sign:commit", which is NOT in the allowlist.
        let resp = router(state)
            .oneshot(post_users(user_body("deploy-bot", "okta-1")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn joiner_is_idempotent_on_external_id() {
        let (state, provisioner) = state_with_fake(ORG);
        let app = router(state);

        let first = app
            .clone()
            .oneshot(post_users(user_body("deploy-bot", "okta-1")))
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::CREATED);
        let first_id = json_value(first).await["id"].as_str().unwrap().to_string();

        // Re-POST the SAME externalId (an IdP retry) → existing resource, no new delegation.
        let second = app
            .oneshot(post_users(user_body("deploy-bot", "okta-1")))
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::OK);
        let second_id = json_value(second).await["id"].as_str().unwrap().to_string();

        assert_eq!(
            first_id, second_id,
            "same externalId resolves to the same resource"
        );
        assert_eq!(
            provisioner.provision_calls(),
            1,
            "two POSTs with the same externalId must issue exactly ONE KEL delegation"
        );
    }

    #[tokio::test]
    async fn unknown_org_tenant_returns_4xx_not_500() {
        // Tenant points at an org the provisioner does not know about.
        let provisioner = Arc::new(FakeProvisioner::new(&["ESomeOtherOrg"]));
        // allow-all so the capability check passes and we reach the org-resolution
        // path this test targets (see `state_with_fake`).
        let tenant = TenantConfig::new("acme", "EMissingOrg", "scim_secret").with_allow_all(true);
        let state = ScimServerState::new(vec![tenant], provisioner);
        let resp = router(state)
            .oneshot(post_users(user_body("deploy-bot", "okta-1")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(
            body_string(resp).await.contains("not provisioned"),
            "unprovisioned org → typed 4xx envelope, not a 500"
        );
    }

    // ── List: filter + pagination ──

    #[tokio::test]
    async fn list_filters_by_username_and_external_id() {
        let app = router(test_state());
        for (name, ext) in [("alice", "okta-a"), ("bob", "okta-b")] {
            app.clone()
                .oneshot(post_users(user_body(name, ext)))
                .await
                .unwrap();
        }

        let resp = app
            .clone()
            .oneshot(get_authed(
                "/scim/v2/Users?filter=userName%20eq%20%22alice%22",
            ))
            .await
            .unwrap();
        let v = json_value(resp).await;
        assert_eq!(v["totalResults"], 1);
        assert_eq!(v["Resources"][0]["userName"], "alice");

        let resp = app
            .oneshot(get_authed(
                "/scim/v2/Users?filter=externalId%20eq%20%22okta-b%22",
            ))
            .await
            .unwrap();
        let v = json_value(resp).await;
        assert_eq!(v["totalResults"], 1);
        assert_eq!(v["Resources"][0]["userName"], "bob");
    }

    #[tokio::test]
    async fn list_paginates_with_start_index_and_count() {
        let app = router(test_state());
        for (name, ext) in [("a", "x1"), ("b", "x2"), ("c", "x3")] {
            app.clone()
                .oneshot(post_users(user_body(name, ext)))
                .await
                .unwrap();
        }

        // startIndex is 1-based; count caps the page.
        let resp = app
            .oneshot(get_authed("/scim/v2/Users?startIndex=2&count=1"))
            .await
            .unwrap();
        let v = json_value(resp).await;
        assert_eq!(v["totalResults"], 3, "totalResults reflects the full set");
        assert_eq!(v["startIndex"], 2);
        assert_eq!(v["itemsPerPage"], 1);
        assert_eq!(v["Resources"].as_array().unwrap().len(), 1);
    }

    // ── Get by id ──

    #[tokio::test]
    async fn get_user_by_id_then_404_for_unknown() {
        let app = router(test_state());
        let created = app
            .clone()
            .oneshot(post_users(user_body("deploy-bot", "okta-1")))
            .await
            .unwrap();
        let id = json_value(created).await["id"]
            .as_str()
            .unwrap()
            .to_string();

        let resp = app
            .clone()
            .oneshot(get_authed(&format!("/scim/v2/Users/{id}")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(json_value(resp).await["id"], id);

        let resp = app
            .oneshot(get_authed("/scim/v2/Users/does-not-exist"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert!(
            body_string(resp)
                .await
                .contains("scim:api:messages:2.0:Error")
        );
    }

    // ── Leaver / lifecycle: soft-disable, hard-revoke, delete, atomic PATCH ──

    #[tokio::test]
    async fn patch_active_false_is_soft_disable_not_revoke() {
        let (state, provisioner) = state_with_fake(ORG);
        let app = router(state);
        let id = create_user_id(&app, "deploy-bot", "okta-1").await;

        let resp = app
            .clone()
            .oneshot(patch_req(&id, patch_op("active", serde_json::json!(false))))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = json_value(resp).await;
        assert_eq!(v["active"], false);
        assert_eq!(
            v[AGENT_EXT]["revoked"], false,
            "soft-disable must NOT claim the identity is revoked"
        );
        assert_eq!(
            provisioner.revoke_calls(),
            0,
            "deprovision is not revocation — no KEL off-boarding on active:false"
        );
    }

    #[tokio::test]
    async fn patch_get_shows_disabled_but_not_offboarded() {
        let app = router(test_state());
        let id = create_user_id(&app, "deploy-bot", "okta-1").await;
        app.clone()
            .oneshot(patch_req(&id, patch_op("active", serde_json::json!(false))))
            .await
            .unwrap();

        let v = json_value(
            app.oneshot(get_authed(&format!("/scim/v2/Users/{id}")))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(v["active"], false);
        assert_eq!(v[AGENT_EXT]["revoked"], false);
    }

    #[tokio::test]
    async fn patch_reactivates_soft_disabled_member() {
        let app = router(test_state());
        let id = create_user_id(&app, "deploy-bot", "okta-1").await;

        app.clone()
            .oneshot(patch_req(&id, patch_op("active", serde_json::json!(false))))
            .await
            .unwrap();
        let resp = app
            .oneshot(patch_req(&id, patch_op("active", serde_json::json!(true))))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(json_value(resp).await["active"], true);
    }

    #[tokio::test]
    async fn hard_revoke_emits_offboarding_and_is_idempotent() {
        let (state, provisioner) = state_with_fake(ORG);
        let app = router(state);
        let id = create_user_id(&app, "deploy-bot", "okta-1").await;

        let resp = app.clone().oneshot(revoke_req(&id)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = json_value(resp).await;
        assert_eq!(v["revoked"], true);
        assert_eq!(v["offboarding_recorded"], true);
        assert_eq!(provisioner.revoke_calls(), 1);

        // Repeat → no duplicate off-boarding record, still success.
        let resp = app.clone().oneshot(revoke_req(&id)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = json_value(resp).await;
        assert_eq!(v["revoked"], true);
        assert_eq!(
            v["offboarding_recorded"], false,
            "a repeat hard-revoke must not anchor a duplicate record"
        );

        // GET reflects the honest revoked state.
        let v = json_value(
            app.oneshot(get_authed(&format!("/scim/v2/Users/{id}")))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(v["active"], false);
        assert_eq!(v[AGENT_EXT]["revoked"], true);
    }

    #[tokio::test]
    async fn reactivation_after_hard_revoke_is_rejected() {
        let app = router(test_state());
        let id = create_user_id(&app, "deploy-bot", "okta-1").await;
        app.clone().oneshot(revoke_req(&id)).await.unwrap();

        let resp = app
            .oneshot(patch_req(&id, patch_op("active", serde_json::json!(true))))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(
            body_string(resp).await.contains("re-onboard"),
            "reactivation after hard-revoke must fail with a clear re-onboard error"
        );
    }

    #[tokio::test]
    async fn delete_is_soft_leaver_idempotent_not_revoke() {
        let (state, provisioner) = state_with_fake(ORG);
        let app = router(state);
        let id = create_user_id(&app, "deploy-bot", "okta-1").await;

        let resp = app.clone().oneshot(delete_req(&id)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // Now hidden → 404.
        let resp = app
            .clone()
            .oneshot(get_authed(&format!("/scim/v2/Users/{id}")))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        // DELETE again → still 204 (idempotent).
        let resp = app.clone().oneshot(delete_req(&id)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        assert_eq!(
            provisioner.revoke_calls(),
            0,
            "DELETE is a soft leaver — it must not cryptographically revoke"
        );
    }

    #[tokio::test]
    async fn multi_op_patch_is_atomic_rollback() {
        let app = router(test_state());
        let id = create_user_id(&app, "deploy-bot", "okta-1").await;

        // Op 1 (active:false) is valid; op 2 (mutate immutable `id`) must fail and
        // roll the whole PATCH back.
        let body = r#"{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"active","value":false},{"op":"replace","path":"id","value":"hijack"}]}"#;
        let resp = app
            .clone()
            .oneshot(patch_req(&id, body.to_string()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // The failed op 1 left no trace: still active.
        let v = json_value(
            app.oneshot(get_authed(&format!("/scim/v2/Users/{id}")))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(v["active"], true, "a failing op must roll the PATCH back");
    }

    #[tokio::test]
    async fn patch_remove_no_target_is_400_no_target() {
        let app = router(test_state());
        // user_body sets no displayName → removing it has no target.
        let id = create_user_id(&app, "deploy-bot", "okta-1").await;

        let body = r#"{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"remove","path":"displayName"}]}"#;
        let resp = app.oneshot(patch_req(&id, body.to_string())).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(body_string(resp).await.contains("noTarget"));
    }

    #[tokio::test]
    async fn concurrent_patch_cannot_split_state() {
        let app = router(test_state());
        let id = create_user_id(&app, "deploy-bot", "okta-1").await;

        let caps_a = r#"{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"capabilities","value":["only-a"]}]}"#;
        let caps_b = r#"{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"capabilities","value":["one-b","two-b"]}]}"#;

        let (r1, r2) = tokio::join!(
            app.clone().oneshot(patch_req(&id, caps_a.to_string())),
            app.clone().oneshot(patch_req(&id, caps_b.to_string())),
        );
        assert_eq!(r1.unwrap().status(), StatusCode::OK);
        assert_eq!(r2.unwrap().status(), StatusCode::OK);

        // Final state is exactly one writer's value — never a torn merge.
        let v = json_value(
            app.oneshot(get_authed(&format!("/scim/v2/Users/{id}")))
                .await
                .unwrap(),
        )
        .await;
        let caps = v[AGENT_EXT]["capabilities"].as_array().unwrap();
        let is_a = caps.len() == 1 && caps[0] == "only-a";
        let is_b = caps.len() == 2 && caps[0] == "one-b" && caps[1] == "two-b";
        assert!(is_a || is_b, "split state: capabilities = {caps:?}");
    }
}
