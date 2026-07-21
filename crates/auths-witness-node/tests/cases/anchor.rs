//! The anchor role's HTTP surface, driven through the real router.
//!
//! These exercise the readiness gate and the honest-vs-operator error split at
//! the transport boundary: an unsynced registry is a distinct "operator, sync
//! your registry" signal (503), an unknown submitter is the stranger's concern
//! (422) with no libgit2 string leaked, and a malformed `{seed}` reads as one
//! named 400 rather than the internal hex-decoder phrasing.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use auths_anchor::{Anchor, CurveType, Head, PartySignature, SeedId, WitnessSetRef};
use auths_sdk::storage::{GitRegistryBackend, RegistryConfig};
use auths_transparency::{FsTileStore, LogOrigin, LogSigningKey, LogWriter};
use auths_witness_node::anchor_role::{AppState, anchor_router};
use auths_witness_node::registry::{PartyResolveError, registry_ready};
use auths_witness_node::{AnchorService, FileSigner, SqliteAnchorStore};
use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use tower::ServiceExt;

const SIXTY_FOUR_HEX_ZEROS: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

fn signed_anchor(index: u64, head: [u8; 32]) -> Anchor {
    let sk = SigningKey::from_bytes(&[9u8; 32]);
    let mut anchor = Anchor {
        seed_id: SeedId::derive("did:keri:root", "did:keri:agent", "ESeal"),
        index,
        head: Head::from_bytes(head),
        cumulative: index as u128 * 100,
        timestamp: chrono::TimeZone::timestamp_opt(&Utc, 1_700_000_000 + index as i64, 0).unwrap(),
        witness_set: WitnessSetRef {
            said: "EWitSet".into(),
            threshold: 1,
        },
        sig_party: PartySignature {
            curve: CurveType::Ed25519,
            public_key: sk.verifying_key().as_bytes().to_vec(),
            signature: Vec::new(),
        },
    };
    let message = anchor.party_signing_bytes().unwrap();
    anchor.sig_party.signature = sk.sign(&message).to_bytes().to_vec();
    anchor
}

/// Build the anchor role's state against a given registry path, with a fresh
/// durable store and log under `data_dir`.
fn state_for(registry: PathBuf, data_dir: &Path) -> Arc<AppState> {
    let seed = [1u8; 32];
    let store = SqliteAnchorStore::open(&data_dir.join("anchors.db")).unwrap();
    let log = LogWriter::new(
        FsTileStore::new(data_dir.join("log")),
        LogSigningKey::from_seed(seed).unwrap(),
        LogOrigin::new("awn/test-w1").unwrap(),
    );
    let signer = FileSigner::from_seed("test-w1", seed);
    Arc::new(AppState::new(
        AnchorService::new(signer, store, log),
        registry,
        data_dir.join("duplicity"),
        "test-w1".to_string(),
        vec!["anchor".to_string()],
    ))
}

/// A registry directory that resolves as synced (initialized git repo, no
/// identities in it yet).
fn synced_registry(dir: &Path) -> PathBuf {
    let backend = GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(dir));
    backend.init_if_needed().unwrap();
    dir.to_path_buf()
}

async fn send(app: Router, method: &str, uri: &str, body: Option<String>) -> (StatusCode, String) {
    let builder = Request::builder().method(method).uri(uri);
    let request = match body {
        Some(json) => builder
            .header("content-type", "application/json")
            .body(Body::from(json))
            .unwrap(),
        None => builder.body(Body::empty()).unwrap(),
    };
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

fn submit_body() -> String {
    serde_json::json!({
        "anchor": signed_anchor(1, [1u8; 32]),
        "party": { "root": "did:keri:ERoot", "agent": "did:keri:EAgentAbsent" },
    })
    .to_string()
}

#[test]
fn no_registry_is_not_ready() {
    let empty = tempfile::tempdir().unwrap();
    assert!(matches!(
        registry_ready(empty.path()),
        Err(PartyResolveError::RegistryUnavailable)
    ));

    let synced = tempfile::tempdir().unwrap();
    synced_registry(synced.path());
    assert!(
        registry_ready(synced.path()).is_ok(),
        "an initialized registry must read as ready"
    );
}

#[tokio::test]
async fn unsynced_registry_returns_503_not_422() {
    let data = tempfile::tempdir().unwrap();
    let empty_registry = tempfile::tempdir().unwrap();
    let state = state_for(empty_registry.path().to_path_buf(), data.path());

    let (status, body) = send(
        anchor_router(state, false),
        "POST",
        "/v1/anchor",
        Some(submit_body()),
    )
    .await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        body.contains("no openable registry"),
        "operator-facing 503 body was: {body}"
    );
}

#[tokio::test]
async fn unknown_identity_is_422_not_503_and_hides_registry_prefix() {
    let data = tempfile::tempdir().unwrap();
    let registry = tempfile::tempdir().unwrap();
    let state = state_for(synced_registry(registry.path()), data.path());

    let (status, body) = send(
        anchor_router(state, false),
        "POST",
        "/v1/anchor",
        Some(submit_body()),
    )
    .await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        body.contains("not in this witness's registry"),
        "stranger-facing 422 body was: {body}"
    );
    assert!(
        !body.contains("registry:") && !body.contains("/registry"),
        "the libgit2 string / prefix leaked into: {body}"
    );
}

#[tokio::test]
async fn non_hex_seed_is_named_400() {
    let data = tempfile::tempdir().unwrap();
    let registry = tempfile::tempdir().unwrap();
    let state = state_for(synced_registry(registry.path()), data.path());

    let (status, body) = send(
        anchor_router(state, false),
        "GET",
        "/v1/anchor/nonexistent-seed-abc123",
        None,
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body.contains("seed must be a 64-character hex seed_id"),
        "named 400 body was: {body}"
    );
    assert!(
        !body.contains("Odd number of digits"),
        "the hex-decoder phrasing leaked into: {body}"
    );
}

#[tokio::test]
async fn valid_hex_unknown_seed_is_404() {
    let data = tempfile::tempdir().unwrap();
    let registry = tempfile::tempdir().unwrap();
    let state = state_for(synced_registry(registry.path()), data.path());

    let (status, body) = send(
        anchor_router(state, false),
        "GET",
        &format!("/v1/anchor/{SIXTY_FOUR_HEX_ZEROS}"),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        body.contains("no anchor for this seed"),
        "unknown-seed 404 body was: {body}"
    );
}
