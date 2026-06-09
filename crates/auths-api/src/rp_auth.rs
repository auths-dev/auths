//! Relying-party presentation authentication for Axum — the reference drop-in (fn-153.9).
//!
//! Turns an `Authorization: Auths-Presentation <token>` header into a verified
//! [`VerifiedPrincipal`] inserted into request extensions, reachable by a handler ONLY
//! through the [`AuthedPrincipal`] extractor (private field) — an unauthenticated path
//! has no way to obtain a principal. The crypto step is injected via
//! [`PresentationVerifier`] so the production KERI path and tests share one middleware.
//!
//! Status mapping uses the shipped `http_status()`: wire/parse → 400, authn failure
//! (revoked/expired/replayed/wrong-audience/unresolved) → 401, insufficient capability
//! → 403, challenge store full → 503. The nonce and signature are never logged.

// HTTP boundary: this module samples the wall clock (`Utc::now()`) as the injected
// verification/mint time at the request edge — per the CLAUDE.md "CLI/API call Utc::now()
// at the presentation boundary" rule (the SDK/verifier stay clock-injected below it).
#![allow(clippy::disallowed_methods)]

use std::future::Future;
use std::sync::Arc;

use axum::extract::{FromRequestParts, Request, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{request::Parts, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Json, Response};
use chrono::{DateTime, Utc};
use serde::Serialize;

use auths_core::storage::keychain::KeyAlias;
use auths_rp::{
    parse_presentation_header, Audience, ChallengeError, ChallengeStore, VerifiedPrincipal,
    WirePresentation,
};
use auths_sdk::context::AuthsContext;
use auths_sdk::domains::credentials::{authenticate_presentation, PresentationAuthError};
use auths_verifier::Capability;

/// The injectable verification step: turn a parsed wire presentation into a verified
/// principal, consuming its single-use challenge along the way.
///
/// The production impl ([`KeriPresentationVerifier`]) calls the shipped
/// `authenticate_presentation` (consume challenge → resolve issuer/subject/delegator
/// KELs → verify offline). Tests substitute a fake that exercises the same
/// [`ChallengeStore`] so replay protection is covered without a live registry.
pub trait PresentationVerifier: Send + Sync + 'static {
    /// Verify `wire` as of `now`, consuming its single-use challenge.
    ///
    /// Args:
    /// * `wire`: The untrusted wire presentation parsed from the header.
    /// * `now`: Verification time (injected at the HTTP boundary).
    ///
    /// Usage:
    /// ```ignore
    /// let principal = verifier.verify(wire, Utc::now()).await?;
    /// ```
    fn verify(
        &self,
        wire: WirePresentation,
        now: DateTime<Utc>,
    ) -> impl Future<Output = Result<VerifiedPrincipal, PresentationAuthError>> + Send;
}

/// Production verifier: KERI presentation authentication over an Auths registry context.
pub struct KeriPresentationVerifier {
    ctx: Arc<AuthsContext>,
    issuer_alias: KeyAlias,
    challenges: Arc<dyn ChallengeStore>,
    audience: Audience,
}

impl KeriPresentationVerifier {
    /// Build a verifier bound to one relying-party audience.
    ///
    /// Args:
    /// * `ctx`: The Auths registry context the verifier resolves KELs/TEL from.
    /// * `issuer_alias`: The local key alias identifying the credential issuer.
    /// * `challenges`: The single-use challenge store (shared with the mint route).
    /// * `audience`: This relying party's canonical audience (the trust source, never the header).
    ///
    /// Usage:
    /// ```ignore
    /// let v = KeriPresentationVerifier::new(ctx, alias, challenges, audience);
    /// ```
    pub fn new(
        ctx: Arc<AuthsContext>,
        issuer_alias: KeyAlias,
        challenges: Arc<dyn ChallengeStore>,
        audience: Audience,
    ) -> Self {
        Self {
            ctx,
            issuer_alias,
            challenges,
            audience,
        }
    }
}

impl PresentationVerifier for KeriPresentationVerifier {
    async fn verify(
        &self,
        wire: WirePresentation,
        now: DateTime<Utc>,
    ) -> Result<VerifiedPrincipal, PresentationAuthError> {
        authenticate_presentation(
            &self.ctx,
            &self.issuer_alias,
            &*self.challenges,
            &self.audience,
            wire,
            now,
        )
        .await
    }
}

/// Shared state for [`rp_auth_middleware`]: the verifier plus an optional capability the
/// guarded routes require (missing → 403).
pub struct RpAuthState<V: PresentationVerifier> {
    verifier: Arc<V>,
    required: Option<Capability>,
}

impl<V: PresentationVerifier> RpAuthState<V> {
    /// State that authenticates but enforces no capability.
    pub fn new(verifier: Arc<V>) -> Self {
        Self {
            verifier,
            required: None,
        }
    }

    /// Require `cap` on the guarded routes — a principal lacking it is rejected 403.
    pub fn require(mut self, cap: Capability) -> Self {
        self.required = Some(cap);
        self
    }
}

// Manual `Clone`: only the `Arc<V>` is cloned, so `V` itself need not be `Clone`.
impl<V: PresentationVerifier> Clone for RpAuthState<V> {
    fn clone(&self) -> Self {
        Self {
            verifier: Arc::clone(&self.verifier),
            required: self.required.clone(),
        }
    }
}

/// A verified principal carried in request extensions, constructible ONLY here (private
/// field) so a handler can obtain it solely via the [`AuthedPrincipal`] extractor — an
/// unauthenticated path can never fabricate or read one.
#[derive(Debug, Clone)]
pub struct AuthedPrincipal(VerifiedPrincipal);

impl AuthedPrincipal {
    /// Borrow the verified principal.
    pub fn principal(&self) -> &VerifiedPrincipal {
        &self.0
    }

    /// Consume into the verified principal.
    pub fn into_principal(self) -> VerifiedPrincipal {
        self.0
    }
}

impl<S: Send + Sync> FromRequestParts<S> for AuthedPrincipal {
    type Rejection = Response;

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let found = parts.extensions.get::<AuthedPrincipal>().cloned();
        async move { found.ok_or_else(|| deny(StatusCode::UNAUTHORIZED, "authentication required")) }
    }
}

/// Axum middleware: authenticate the `Auths-Presentation` header, enforce the optional
/// required capability, and insert the [`AuthedPrincipal`] into request extensions.
///
/// Wire with `from_fn_with_state`:
/// ```ignore
/// let protected = Router::new()
///     .route("/deploy", post(handler))
///     .route_layer(from_fn_with_state(state.clone(), rp_auth_middleware));
/// ```
pub async fn rp_auth_middleware<V: PresentationVerifier>(
    State(state): State<RpAuthState<V>>,
    mut request: Request,
    next: Next,
) -> Response {
    let Some(raw) = request.headers().get(AUTHORIZATION) else {
        return deny(StatusCode::UNAUTHORIZED, "authentication required");
    };
    let Ok(header) = raw.to_str() else {
        return deny(StatusCode::BAD_REQUEST, "malformed authorization header");
    };
    // Parse only the wire shape here; never log the header (nonce/signature).
    let wire = match parse_presentation_header(header) {
        Ok(wire) => wire,
        Err(_) => return deny(StatusCode::BAD_REQUEST, "malformed presentation"),
    };

    let principal = match state.verifier.verify(wire, Utc::now()).await {
        Ok(principal) => principal,
        Err(err) => return deny_status(err.http_status(), "presentation rejected"),
    };

    // Nested (not a let-chain): this crate is edition 2021.
    if let Some(cap) = &state.required {
        if principal.authorize(cap).is_err() {
            return deny(StatusCode::FORBIDDEN, "insufficient capability");
        }
    }

    request.extensions_mut().insert(AuthedPrincipal(principal));
    next.run(request).await
}

/// Shared state for the [`challenge_handler`] mint route.
#[derive(Clone)]
pub struct ChallengeMintState {
    challenges: Arc<dyn ChallengeStore>,
    audience: Audience,
}

impl ChallengeMintState {
    /// Build mint state over the (shared) challenge store and this RP's audience.
    pub fn new(challenges: Arc<dyn ChallengeStore>, audience: Audience) -> Self {
        Self {
            challenges,
            audience,
        }
    }
}

/// The `/v1/auth/challenge` response: a fresh single-use nonce and its expiry.
#[derive(Debug, Serialize)]
pub struct ChallengeResponse {
    /// base64url-encoded single-use nonce the client signs over.
    pub nonce: String,
    /// RFC-3339 instant after which the challenge is no longer live.
    pub not_after: DateTime<Utc>,
}

/// `GET /v1/auth/challenge` — mint a fresh CSPRNG nonce bound to this RP's audience.
///
/// The store is bounded; at capacity it returns 503 rather than evicting a live nonce.
pub async fn challenge_handler(State(state): State<ChallengeMintState>) -> Response {
    match state.challenges.issue(&state.audience, Utc::now()) {
        Ok(issued) => Json(ChallengeResponse {
            nonce: issued.nonce.to_b64url(),
            not_after: issued.not_after,
        })
        .into_response(),
        Err(ChallengeError::StoreFull) => {
            deny(StatusCode::SERVICE_UNAVAILABLE, "challenge store full")
        }
        Err(_) => deny(StatusCode::INTERNAL_SERVER_ERROR, "challenge mint failed"),
    }
}

/// A minimal JSON error response — carries only a generic reason (never the nonce/signature).
fn deny(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

/// Map a verdict `http_status()` integer to a response, defaulting to 401 on an
/// out-of-range code.
fn deny_status(status: u16, message: &str) -> Response {
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::UNAUTHORIZED);
    deny(status, message)
}
