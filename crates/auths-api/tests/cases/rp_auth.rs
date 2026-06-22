//! fn-153.9 — Axum relying-party middleware + extractor (HTTP-level tests).
//!
//! The crypto path is faked, but the single-use `ChallengeStore` is REAL, so replay and
//! audience-binding are genuinely exercised; the actual presentation/KEL verification is
//! covered by `auths-sdk` `authenticate` + `auths-verifier` `presentation` tests. These
//! tests pin the middleware's HTTP contract: header parsing, verdict→status mapping, the
//! extractor's authenticated-only access, the capability gate, and the challenge mint.

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header::AUTHORIZATION, Request, StatusCode};
use axum::middleware::from_fn_with_state;
use axum::routing::get;
use axum::Router;
use chrono::{DateTime, Utc};
use tower::ServiceExt;

use auths_api::rp_auth::{
    challenge_handler, rp_auth_middleware, AuthedPrincipal, ChallengeMintState,
    PresentationVerifier, RpAuthState,
};
use auths_rp::{
    Audience, ChallengeStore, Denied, InMemoryChallengeStore, Nonce, VerifiedPrincipal,
    WireBinding, WirePresentation,
};
use auths_sdk::domains::credentials::PresentationAuthError;
use auths_verifier::{CanonicalDid, Capability, IdentityDID, PresentationVerdict};

const AUDIENCE: &str = "api.example.com";

/// What the fake verifier returns once the (real) challenge has been consumed.
enum FakeOutcome {
    Grant(VerifiedPrincipal),
    DenyExpired,
}

/// A verifier that runs the REAL challenge consume (replay/audience are real), then applies
/// a configured crypto outcome — so the middleware can be tested without a live registry.
struct FakeVerifier {
    challenges: Arc<InMemoryChallengeStore>,
    outcome: FakeOutcome,
}

impl PresentationVerifier for FakeVerifier {
    async fn verify(
        &self,
        wire: WirePresentation,
        now: DateTime<Utc>,
    ) -> Result<VerifiedPrincipal, PresentationAuthError> {
        let audience = Audience::parse(&wire.audience).map_err(PresentationAuthError::Wire)?;
        let nonce = match &wire.binding {
            WireBinding::Challenge { nonce } | WireBinding::Ttl { nonce, .. } => {
                Nonce::parse_b64url(nonce).map_err(PresentationAuthError::Wire)?
            }
        };
        self.challenges
            .consume(&audience, &nonce, now)
            .map_err(PresentationAuthError::Challenge)?;
        match &self.outcome {
            FakeOutcome::Grant(principal) => Ok(principal.clone()),
            FakeOutcome::DenyExpired => Err(PresentationAuthError::Denied(Denied::Expired)),
        }
    }
}

/// A verified principal holding `caps`, built through the real `from_verdict`.
fn principal(caps: &[&str]) -> VerifiedPrincipal {
    let verdict = PresentationVerdict::Valid {
        issuer: IdentityDID::parse("did:keri:Eissuer").expect("issuer"),
        subject: CanonicalDid::parse("did:keri:Eagent").expect("subject"),
        caps: caps
            .iter()
            .map(|c| Capability::parse(c).expect("cap"))
            .collect(),
        role: None,
        expires_at: None,
        freshness: auths_verifier::Freshness::Unknown,
    };
    VerifiedPrincipal::from_verdict(verdict).expect("verdict -> principal")
}

/// Handler reachable only behind the middleware; echoes the authenticated subject.
async fn protected(principal: AuthedPrincipal) -> String {
    principal.principal().subject().as_str().to_string()
}

/// A protected `/p` router guarding the handler with the RP middleware.
fn protected_app(state: RpAuthState<FakeVerifier>) -> Router {
    Router::new()
        .route("/p", get(protected))
        .route_layer(from_fn_with_state(state, rp_auth_middleware))
}

/// Issue a real challenge from `store` and build a wire presentation carrying its nonce,
/// bound to `bind_audience` (use a different audience than issued to test the mismatch).
fn header_for(store: &InMemoryChallengeStore, issue_audience: &str, bind_audience: &str) -> String {
    let audience = Audience::parse(issue_audience).expect("audience");
    let issued = store.issue(&audience, Utc::now()).expect("issue challenge");
    let wire = WirePresentation {
        credential_said: "ECred".into(),
        audience: bind_audience.into(),
        binding: WireBinding::Challenge {
            nonce: issued.nonce.to_b64url(),
        },
        signature_b64: "AAAA".into(),
    };
    format!("Auths-Presentation {}", wire.to_token().expect("token"))
}

async fn get_with_auth(app: Router, header: Option<&str>) -> (StatusCode, String) {
    let mut builder = Request::builder().uri("/p");
    if let Some(h) = header {
        builder = builder.header(AUTHORIZATION, h);
    }
    let response = app
        .oneshot(builder.body(Body::empty()).expect("request"))
        .await
        .expect("response");
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    (status, String::from_utf8(bytes.to_vec()).expect("utf8"))
}

#[tokio::test]
async fn valid_presentation_authenticates_and_exposes_subject() {
    let store = Arc::new(InMemoryChallengeStore::new(16));
    let header = header_for(&store, AUDIENCE, AUDIENCE);
    let state = RpAuthState::new(Arc::new(FakeVerifier {
        challenges: Arc::clone(&store),
        outcome: FakeOutcome::Grant(principal(&["deploy"])),
    }));

    let (status, body) = get_with_auth(protected_app(state), Some(&header)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "did:keri:Eagent");
}

#[tokio::test]
async fn replayed_presentation_is_rejected() {
    let store = Arc::new(InMemoryChallengeStore::new(16));
    let header = header_for(&store, AUDIENCE, AUDIENCE);
    let make_app = || {
        protected_app(RpAuthState::new(Arc::new(FakeVerifier {
            challenges: Arc::clone(&store),
            outcome: FakeOutcome::Grant(principal(&["deploy"])),
        })))
    };

    let (first, _) = get_with_auth(make_app(), Some(&header)).await;
    assert_eq!(first, StatusCode::OK, "first use succeeds");
    let (second, _) = get_with_auth(make_app(), Some(&header)).await;
    assert_eq!(
        second,
        StatusCode::UNAUTHORIZED,
        "the single-use nonce was already consumed"
    );
}

#[tokio::test]
async fn presentation_bound_to_other_audience_is_rejected() {
    let store = Arc::new(InMemoryChallengeStore::new(16));
    // Challenge issued for the real audience, but the presentation claims a different one →
    // there is no live challenge under (other-audience, nonce).
    let header = header_for(&store, AUDIENCE, "evil.example.com");
    let state = RpAuthState::new(Arc::new(FakeVerifier {
        challenges: Arc::clone(&store),
        outcome: FakeOutcome::Grant(principal(&["deploy"])),
    }));

    let (status, _) = get_with_auth(protected_app(state), Some(&header)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn expired_credential_maps_to_401() {
    let store = Arc::new(InMemoryChallengeStore::new(16));
    let header = header_for(&store, AUDIENCE, AUDIENCE);
    let state = RpAuthState::new(Arc::new(FakeVerifier {
        challenges: Arc::clone(&store),
        outcome: FakeOutcome::DenyExpired,
    }));

    let (status, _) = get_with_auth(protected_app(state), Some(&header)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn missing_capability_maps_to_403() {
    let store = Arc::new(InMemoryChallengeStore::new(16));
    let header = header_for(&store, AUDIENCE, AUDIENCE);
    // Principal holds no capabilities, but the route requires `deploy`.
    let state = RpAuthState::new(Arc::new(FakeVerifier {
        challenges: Arc::clone(&store),
        outcome: FakeOutcome::Grant(principal(&[])),
    }))
    .require(Capability::parse("deploy").expect("cap"));

    let (status, _) = get_with_auth(protected_app(state), Some(&header)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn missing_header_is_unauthorized_and_handler_unreached() {
    let store = Arc::new(InMemoryChallengeStore::new(16));
    let state = RpAuthState::new(Arc::new(FakeVerifier {
        challenges: store,
        outcome: FakeOutcome::Grant(principal(&["deploy"])),
    }));

    let (status, body) = get_with_auth(protected_app(state), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_ne!(body, "did:keri:Eagent", "handler must not run");
}

#[tokio::test]
async fn challenge_mint_returns_nonce_and_full_store_is_503() {
    // A live store mints a fresh nonce.
    let store: Arc<dyn ChallengeStore> = Arc::new(InMemoryChallengeStore::new(4));
    let app = Router::new()
        .route("/v1/auth/challenge", get(challenge_handler))
        .with_state(ChallengeMintState::new(
            Arc::clone(&store),
            Audience::parse(AUDIENCE).expect("audience"),
        ));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/auth/challenge")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::OK);

    // A store at capacity fails closed with 503 rather than evicting a live nonce.
    let full: Arc<dyn ChallengeStore> = Arc::new(InMemoryChallengeStore::new(0));
    let app = Router::new()
        .route("/v1/auth/challenge", get(challenge_handler))
        .with_state(ChallengeMintState::new(
            full,
            Audience::parse(AUDIENCE).expect("audience"),
        ));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/auth/challenge")
                .body(Body::empty())
                .expect("request"),
        )
        .await
        .expect("response");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
}
