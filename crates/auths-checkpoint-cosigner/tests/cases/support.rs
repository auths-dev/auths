//! Shared fixtures for checkpoint-cosigner integration tests.

use auths_checkpoint_cosigner::{WitnessConfig, WitnessState, build_router};
use auths_transparency::{
    Checkpoint, CosignRequest, CosignResponse, LogOrigin, MerkleHash, SignedCheckpoint,
    compute_root, hash_children, hash_leaf,
};
use auths_verifier::{Ed25519PublicKey, Ed25519Signature};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::DateTime;
use http_body_util::BodyExt;
use ring::signature::KeyPair;
use tempfile::TempDir;
use tower::ServiceExt;

pub const WITNESS_NAME: &str = "it-witness";

pub fn test_config() -> (WitnessConfig, TempDir) {
    let dir = TempDir::new().unwrap();
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let config = WitnessConfig {
        signing_key_hex: hex::encode(pkcs8.as_ref()),
        witness_name: WITNESS_NAME.into(),
        checkpoint_path: dir.path().join("last_checkpoint.json"),
        bind_addr: "127.0.0.1:0".into(),
    };
    (config, dir)
}

pub fn make_checkpoint(size: u64, root: [u8; 32]) -> SignedCheckpoint {
    make_checkpoint_with_root(size, MerkleHash::from_bytes(root))
}

pub fn make_checkpoint_with_root(size: u64, root: MerkleHash) -> SignedCheckpoint {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let kp = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

    let checkpoint = Checkpoint {
        origin: LogOrigin::new("test.dev/log").unwrap(),
        size,
        root,
        timestamp: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
    };

    let body = checkpoint.to_note_body();
    let sig = kp.sign(body.as_bytes());
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(sig.as_ref());

    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(kp.public_key().as_ref());

    SignedCheckpoint {
        checkpoint,
        log_signature: Ed25519Signature::from_bytes(sig_arr),
        log_public_key: Ed25519PublicKey::from_bytes(pk_arr),
        witnesses: vec![],
        ecdsa_checkpoint_signature: None,
        ecdsa_checkpoint_key: None,
    }
}

pub fn tofu_request(checkpoint: SignedCheckpoint) -> CosignRequest {
    CosignRequest {
        old_size: 0,
        consistency_proof: None,
        signed_checkpoint: checkpoint,
    }
}

/// Real RFC 6962 fixture: a 2-leaf tree grown to 4 leaves.
///
/// Returns `(old_root, new_root, proof_hashes)` such that
/// `verify_consistency(2, 4, &proof_hashes, &old_root, &new_root)` succeeds.
pub fn merkle_growth_fixture() -> (MerkleHash, MerkleHash, Vec<MerkleHash>) {
    let leaves: Vec<MerkleHash> = (0u8..4).map(|i| hash_leaf(&[i])).collect();
    let old_root = compute_root(&leaves[..2]);
    let new_root = compute_root(&leaves);
    let right_subtree = hash_children(&leaves[2], &leaves[3]);
    (old_root, new_root, vec![right_subtree])
}

pub async fn post_checkpoint(
    state: WitnessState,
    request: &CosignRequest,
) -> (StatusCode, Vec<u8>) {
    post_json(state, serde_json::to_vec(request).unwrap()).await
}

pub async fn post_json(state: WitnessState, body: Vec<u8>) -> (StatusCode, Vec<u8>) {
    let app = build_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/add-checkpoint")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, bytes)
}

pub fn parse_cosign_response(body: &[u8]) -> CosignResponse {
    serde_json::from_slice(body).unwrap()
}
