//! /add-checkpoint cosigning behaviour: happy path, cosignature validity,
//! consistency-proof enforcement, equivocation/rollback rejection, and
//! malformed-input handling.

use auths_transparency::{
    ConsistencyProof, CosignRequest, MerkleHash, SignedCheckpoint, cosignature_signed_message,
};
use auths_witness_node::cosign_role::{WitnessState, build_router};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::Utc;
use tower::ServiceExt;

use super::support::{
    WITNESS_NAME, make_checkpoint, make_checkpoint_with_root, merkle_growth_fixture,
    parse_cosign_response, post_checkpoint, post_json, test_config, tofu_request,
};

fn fresh_state() -> (
    WitnessState,
    auths_witness_node::cosign_role::WitnessConfig,
    tempfile::TempDir,
) {
    let (config, dir) = test_config();
    let state = WitnessState::new(&config).unwrap();
    (state, config, dir)
}

fn verify_cosignature(checkpoint: &SignedCheckpoint, body: &[u8]) {
    let cosig = parse_cosign_response(body).cosignature;
    let note_body = checkpoint.checkpoint.to_note_body();
    let msg = cosignature_signed_message(&note_body, cosig.timestamp.timestamp() as u64);
    let vk = ring::signature::UnparsedPublicKey::new(
        &ring::signature::ED25519,
        cosig.witness_public_key.as_bytes(),
    );
    vk.verify(&msg, cosig.signature.as_bytes())
        .expect("witness cosignature must verify against its own public key");
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tofu_checkpoint_returns_verifiable_cosignature() {
    let (state, _config, _dir) = fresh_state();
    let cp = make_checkpoint(10, [0xaa; 32]);

    let (status, body) = post_checkpoint(state, &tofu_request(cp.clone())).await;
    assert_eq!(status, StatusCode::OK);
    verify_cosignature(&cp, &body);
}

#[tokio::test]
async fn cosignature_carries_configured_witness_name() {
    let (state, _config, _dir) = fresh_state();
    let cp = make_checkpoint(10, [0xaa; 32]);

    let (_, body) = post_checkpoint(state, &tofu_request(cp)).await;
    let cosig = parse_cosign_response(&body).cosignature;
    assert_eq!(cosig.witness_name, WITNESS_NAME);
}

#[tokio::test]
async fn cosignature_pubkey_matches_configured_signing_key() {
    use ring::signature::KeyPair;

    let (state, config, _dir) = fresh_state();
    let key_bytes = hex::decode(&config.signing_key_hex).unwrap();
    let kp = ring::signature::Ed25519KeyPair::from_pkcs8(&key_bytes).unwrap();

    let (_, body) = post_checkpoint(state, &tofu_request(make_checkpoint(10, [0xaa; 32]))).await;
    let cosig = parse_cosign_response(&body).cosignature;
    assert_eq!(
        cosig.witness_public_key.as_bytes(),
        kp.public_key().as_ref()
    );
}

#[tokio::test]
async fn cosignature_timestamp_is_current() {
    let (state, _config, _dir) = fresh_state();

    let before = Utc::now().timestamp();
    let (_, body) = post_checkpoint(state, &tofu_request(make_checkpoint(10, [0xaa; 32]))).await;
    let after = Utc::now().timestamp();

    let ts = parse_cosign_response(&body)
        .cosignature
        .timestamp
        .timestamp();
    assert!(
        ts >= before && ts <= after,
        "timestamp {ts} outside [{before}, {after}]"
    );
}

#[tokio::test]
async fn resubmitting_identical_checkpoint_returns_fresh_cosignature() {
    let (state, _config, _dir) = fresh_state();
    let cp = make_checkpoint(10, [0xaa; 32]);

    let (status, _) = post_checkpoint(state.clone(), &tofu_request(cp.clone())).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = post_checkpoint(state, &tofu_request(cp.clone())).await;
    assert_eq!(status, StatusCode::OK);
    verify_cosignature(&cp, &body);
}

// ---------------------------------------------------------------------------
// Consistency-proof enforcement on growth
// ---------------------------------------------------------------------------

#[tokio::test]
async fn growth_with_valid_consistency_proof_accepted() {
    let (state, _config, _dir) = fresh_state();
    let (old_root, new_root, hashes) = merkle_growth_fixture();

    let (status, _) = post_checkpoint(
        state.clone(),
        &tofu_request(make_checkpoint_with_root(2, old_root)),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let new_cp = make_checkpoint_with_root(4, new_root);
    let request = CosignRequest {
        old_size: 2,
        consistency_proof: Some(ConsistencyProof {
            old_size: 2,
            new_size: 4,
            old_root,
            new_root,
            hashes,
        }),
        signed_checkpoint: new_cp.clone(),
    };

    let (status, body) = post_checkpoint(state, &request).await;
    assert_eq!(status, StatusCode::OK);
    verify_cosignature(&new_cp, &body);
}

#[tokio::test]
async fn accepted_growth_advances_state_and_blocks_rollback() {
    let (state, _config, _dir) = fresh_state();
    let (old_root, new_root, hashes) = merkle_growth_fixture();

    post_checkpoint(
        state.clone(),
        &tofu_request(make_checkpoint_with_root(2, old_root)),
    )
    .await;

    let request = CosignRequest {
        old_size: 2,
        consistency_proof: Some(ConsistencyProof {
            old_size: 2,
            new_size: 4,
            old_root,
            new_root,
            hashes,
        }),
        signed_checkpoint: make_checkpoint_with_root(4, new_root),
    };
    let (status, _) = post_checkpoint(state.clone(), &request).await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = post_checkpoint(state, &tofu_request(make_checkpoint(3, [0xdd; 32]))).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn growth_proof_with_mismatched_sizes_rejected() {
    let (state, _config, _dir) = fresh_state();
    let (old_root, new_root, hashes) = merkle_growth_fixture();

    post_checkpoint(
        state.clone(),
        &tofu_request(make_checkpoint_with_root(2, old_root)),
    )
    .await;

    let request = CosignRequest {
        old_size: 2,
        consistency_proof: Some(ConsistencyProof {
            old_size: 3,
            new_size: 4,
            old_root,
            new_root,
            hashes,
        }),
        signed_checkpoint: make_checkpoint_with_root(4, new_root),
    };
    let (status, _) = post_checkpoint(state, &request).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn growth_proof_with_mismatched_roots_rejected() {
    let (state, _config, _dir) = fresh_state();
    let (old_root, new_root, hashes) = merkle_growth_fixture();

    post_checkpoint(
        state.clone(),
        &tofu_request(make_checkpoint_with_root(2, old_root)),
    )
    .await;

    let request = CosignRequest {
        old_size: 2,
        consistency_proof: Some(ConsistencyProof {
            old_size: 2,
            new_size: 4,
            old_root: MerkleHash::from_bytes([0x99; 32]),
            new_root,
            hashes,
        }),
        signed_checkpoint: make_checkpoint_with_root(4, new_root),
    };
    let (status, _) = post_checkpoint(state, &request).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn growth_proof_with_bogus_hashes_rejected() {
    let (state, _config, _dir) = fresh_state();
    let (old_root, new_root, _) = merkle_growth_fixture();

    post_checkpoint(
        state.clone(),
        &tofu_request(make_checkpoint_with_root(2, old_root)),
    )
    .await;

    let request = CosignRequest {
        old_size: 2,
        consistency_proof: Some(ConsistencyProof {
            old_size: 2,
            new_size: 4,
            old_root,
            new_root,
            hashes: vec![MerkleHash::from_bytes([0x99; 32])],
        }),
        signed_checkpoint: make_checkpoint_with_root(4, new_root),
    };
    let (status, _) = post_checkpoint(state, &request).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn growth_proof_with_empty_hashes_rejected() {
    let (state, _config, _dir) = fresh_state();
    let (old_root, new_root, _) = merkle_growth_fixture();

    post_checkpoint(
        state.clone(),
        &tofu_request(make_checkpoint_with_root(2, old_root)),
    )
    .await;

    let request = CosignRequest {
        old_size: 2,
        consistency_proof: Some(ConsistencyProof {
            old_size: 2,
            new_size: 4,
            old_root,
            new_root,
            hashes: vec![],
        }),
        signed_checkpoint: make_checkpoint_with_root(4, new_root),
    };
    let (status, _) = post_checkpoint(state, &request).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

// ---------------------------------------------------------------------------
// Tampered / equivocating checkpoints
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tampered_root_at_same_size_rejected_as_equivocation() {
    let (state, _config, _dir) = fresh_state();

    let (status, _) = post_checkpoint(
        state.clone(),
        &tofu_request(make_checkpoint(10, [0xaa; 32])),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = post_checkpoint(state, &tofu_request(make_checkpoint(10, [0xbb; 32]))).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn rejected_equivocation_preserves_original_state() {
    let (state, _config, _dir) = fresh_state();
    let original = make_checkpoint(10, [0xaa; 32]);

    post_checkpoint(state.clone(), &tofu_request(original.clone())).await;
    post_checkpoint(
        state.clone(),
        &tofu_request(make_checkpoint(10, [0xbb; 32])),
    )
    .await;

    let (status, body) = post_checkpoint(state, &tofu_request(original.clone())).await;
    assert_eq!(status, StatusCode::OK);
    verify_cosignature(&original, &body);
}

#[tokio::test]
async fn rejected_rollback_does_not_overwrite_persisted_checkpoint() {
    let (state, config, _dir) = fresh_state();

    post_checkpoint(
        state.clone(),
        &tofu_request(make_checkpoint(10, [0xaa; 32])),
    )
    .await;
    let (status, _) = post_checkpoint(state, &tofu_request(make_checkpoint(5, [0xbb; 32]))).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    let persisted: SignedCheckpoint =
        serde_json::from_str(&std::fs::read_to_string(&config.checkpoint_path).unwrap()).unwrap();
    assert_eq!(persisted.checkpoint.size, 10);
    assert_eq!(
        persisted.checkpoint.root,
        MerkleHash::from_bytes([0xaa; 32])
    );
}

#[tokio::test]
async fn accepted_checkpoint_is_persisted_to_disk() {
    let (state, config, _dir) = fresh_state();
    let cp = make_checkpoint(12, [0xee; 32]);

    post_checkpoint(state, &tofu_request(cp.clone())).await;

    let persisted: SignedCheckpoint =
        serde_json::from_str(&std::fs::read_to_string(&config.checkpoint_path).unwrap()).unwrap();
    assert_eq!(persisted.checkpoint.size, cp.checkpoint.size);
    assert_eq!(persisted.checkpoint.root, cp.checkpoint.root);
}

// ---------------------------------------------------------------------------
// Malformed input
// ---------------------------------------------------------------------------

#[tokio::test]
async fn malformed_json_body_rejected() {
    let (state, _config, _dir) = fresh_state();
    let (status, _) = post_json(state, b"{ not valid json".to_vec()).await;
    assert!(status.is_client_error(), "got {status}");
}

#[tokio::test]
async fn valid_json_with_wrong_shape_rejected() {
    let (state, _config, _dir) = fresh_state();
    let (status, _) = post_json(state, br#"{"unexpected": "shape"}"#.to_vec()).await;
    assert!(status.is_client_error(), "got {status}");
}

#[tokio::test]
async fn missing_content_type_rejected() {
    let (state, _config, _dir) = fresh_state();
    let request = tofu_request(make_checkpoint(10, [0xaa; 32]));

    let app = build_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/add-checkpoint")
                .body(Body::from(serde_json::to_vec(&request).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn wrong_method_rejected() {
    let (state, _config, _dir) = fresh_state();
    let app = build_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/add-checkpoint")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn unknown_route_rejected() {
    let (state, _config, _dir) = fresh_state();
    let app = build_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/cosign")
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
