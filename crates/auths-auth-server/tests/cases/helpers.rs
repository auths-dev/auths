use axum::body::Body;
use http_body_util::BodyExt;
use ring::signature::{Ed25519KeyPair, KeyPair};

pub(super) async fn body_json(body: Body) -> serde_json::Value {
    let bytes = body.collect().await.unwrap().to_bytes();
    serde_json::from_slice(&bytes).unwrap()
}

/// Creates a deterministic Ed25519 keypair from a 32-byte seed.
// Used by the integration tests that are temporarily disabled pending a rewrite (see
// `tests/cases/mod.rs`); kept here so they can be re-enabled without restoring the helper.
#[allow(dead_code)]
pub(super) fn create_test_keypair(seed: &[u8; 32]) -> (Ed25519KeyPair, [u8; 32]) {
    let keypair = Ed25519KeyPair::from_seed_unchecked(seed).unwrap();
    let public_key: [u8; 32] = keypair.public_key().as_ref().try_into().unwrap();
    (keypair, public_key)
}
