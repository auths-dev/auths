//! Control-plane HTTP surface: a thin Axum layer over the SDK agent workflows.
//!
//! Single-host, org-operated (the service holds the org signing key + passphrase and
//! issues for its own org — `OQ-custody`). Mutating routes are gated behind a
//! **single-use presentation** (`rp_auth`), the same primitive the agents it issues
//! authenticate with: the thing handing out leashes is itself on a leash.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::middleware::from_fn_with_state;
use axum::routing::{get, post};
use axum::Router;

use auths_core::storage::keychain::KeyAlias;
use auths_rp::{Audience, ChallengeStore};
use auths_sdk::context::AuthsContext;
use auths_verifier::Capability;

use crate::control_plane::{
    batch_revoke_agents, issue_agent, list_agents, list_fleet, revoke_agent,
};
use crate::error::ApiError;
use crate::rp_auth::{
    challenge_handler, rp_auth_middleware, ChallengeMintState, KeriPresentationVerifier,
    RpAuthState,
};

/// Outcome of an idempotency-key lookup.
pub(crate) enum IdempotencyHit {
    /// First time this key is seen — proceed and store the result.
    Miss,
    /// The key was seen with the same request — return the stored response verbatim.
    Replay(String),
    /// The key was reused with a different request body (409).
    Conflict,
}

/// Shared control-plane state. Holds the org's signing context (single-host custody),
/// the challenge store shared with the mint route + verifier, and a best-effort
/// in-memory idempotency cache.
#[derive(Clone)]
pub struct AppState {
    /// The org's signing context (registry + key storage + passphrase).
    pub ctx: Arc<AuthsContext>,
    /// Keychain alias of the org's (delegator) signing key.
    pub org_alias: KeyAlias,
    /// The bare KEL prefix of the org this server serves.
    pub org_prefix: String,
    /// Single-use challenge store (shared with the mint route + verifier).
    pub challenges: Arc<dyn ChallengeStore>,
    /// This relying party's canonical audience.
    pub audience: Audience,
    /// Best-effort, in-memory idempotency cache: key → (body fingerprint, response JSON).
    /// Non-durable across restarts (documented; a durable store is a follow-up).
    idempotency: Arc<Mutex<HashMap<String, (u64, String)>>>,
}

impl AppState {
    /// Build control-plane state for a single org.
    ///
    /// Args:
    /// * `ctx`: The org's signing context.
    /// * `org_alias`: Keychain alias of the org signing key.
    /// * `org_prefix`: The bare KEL prefix of the org.
    /// * `challenges`: The shared single-use challenge store.
    /// * `audience`: This RP's canonical audience.
    pub fn new(
        ctx: Arc<AuthsContext>,
        org_alias: KeyAlias,
        org_prefix: String,
        challenges: Arc<dyn ChallengeStore>,
        audience: Audience,
    ) -> Self {
        Self {
            ctx,
            org_alias,
            org_prefix,
            challenges,
            audience,
            idempotency: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Reject a path `{org}` that does not match the org this server serves (404).
    pub(crate) fn ensure_org(&self, org: &str) -> Result<(), ApiError> {
        let bare = org.strip_prefix("did:keri:").unwrap_or(org);
        if bare == self.org_prefix {
            Ok(())
        } else {
            Err(ApiError::NotFound(format!(
                "this control plane does not serve org '{org}'"
            )))
        }
    }

    /// Look up an idempotency key against a request fingerprint.
    pub(crate) fn idempotency_lookup(&self, key: &str, fingerprint: u64) -> IdempotencyHit {
        #[allow(clippy::expect_used)]
        // INVARIANT: a poisoned mutex means another thread panicked (unrecoverable).
        let map = self.idempotency.lock().expect("idempotency mutex poisoned");
        match map.get(key) {
            Some((fp, json)) if *fp == fingerprint => IdempotencyHit::Replay(json.clone()),
            Some(_) => IdempotencyHit::Conflict,
            None => IdempotencyHit::Miss,
        }
    }

    /// Store an idempotency key → (fingerprint, response JSON).
    pub(crate) fn idempotency_store(&self, key: String, fingerprint: u64, response_json: String) {
        #[allow(clippy::expect_used)]
        // INVARIANT: a poisoned mutex means another thread panicked (unrecoverable).
        let mut map = self.idempotency.lock().expect("idempotency mutex poisoned");
        map.insert(key, (fingerprint, response_json));
    }
}

/// Build the control-plane API router.
///
/// Public: `/health`, `GET /v1/auth/challenge` (mint a single-use nonce). Protected
/// (require a valid single-use presentation carrying `manage_members`):
/// `POST/GET /v1/org/{org}/agents`, `POST /v1/org/{org}/agents/{id}/revoke`.
///
/// Args:
/// * `state`: The control-plane state.
///
/// Usage:
/// ```ignore
/// let app = build_router(AppState::new(ctx, alias, prefix, challenges, audience));
/// ```
pub fn build_router(state: AppState) -> Router {
    let verifier = Arc::new(KeriPresentationVerifier::new(
        state.ctx.clone(),
        state.org_alias.clone(),
        state.challenges.clone(),
        state.audience.clone(),
    ));
    // The control plane is on a leash: a caller must present a credential carrying
    // `manage_members` (single-use challenge path), not a bearer token.
    let auth = RpAuthState::new(verifier).require(Capability::manage_members());
    let mint = ChallengeMintState::new(state.challenges.clone(), state.audience.clone());

    let protected = Router::new()
        .route("/v1/org/{org}/agents", post(issue_agent).get(list_agents))
        .route("/v1/org/{org}/fleet", get(list_fleet))
        .route("/v1/org/{org}/agents/{id}/revoke", post(revoke_agent))
        .route(
            "/v1/org/{org}/agents/revoke-batch",
            post(batch_revoke_agents),
        )
        .route_layer(from_fn_with_state(auth, rp_auth_middleware))
        .with_state(state);

    Router::new()
        .route("/health", get(health))
        .merge(
            Router::new()
                .route("/v1/auth/challenge", get(challenge_handler))
                .with_state(mint),
        )
        .merge(protected)
}

/// Liveness probe.
async fn health() -> &'static str {
    "ok"
}
