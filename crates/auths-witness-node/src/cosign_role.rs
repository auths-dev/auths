//! The checkpoint-cosign role: the C2SP tlog-witness cosignature protocol.
//!
//! Receives checkpoints from a log operator, verifies consistency with the
//! last-seen checkpoint, and returns timestamped cosignatures. Absorbed from
//! the standalone cosigner server when it folded into this node.

// CT cosignatures pin their curve by the signed-note spec; `ring` is the
// signing/verification primitive here (as in `auths-transparency`), not curve
// drift.
#![allow(clippy::disallowed_methods)]

use std::path::{Path, PathBuf};
use std::sync::Arc;

use auths_transparency::{
    ConsistencyProof, CosignRequest, CosignResponse, SignedCheckpoint, WitnessCosignature,
    cosignature_signed_message, verify_consistency,
};
use auths_verifier::{Ed25519PublicKey, Ed25519Signature};
use axum::http::StatusCode;
use axum::{Json, Router, extract::State, routing::post};
use chrono::{DateTime, Utc};
use ring::signature::KeyPair;
use serde::Serialize;
use tokio::sync::RwLock;

/// Cosign-role configuration. Binding is the node's job, not the role's.
///
/// Args:
/// * `signing_key_hex` — Hex-encoded PKCS#8 signing key (the node identity).
/// * `witness_name` — Human-readable witness name (used in cosignature lines).
/// * `checkpoint_path` — Path to persist the last-seen checkpoint JSON.
///
/// Usage:
/// ```ignore
/// let config = WitnessConfig {
///     signing_key_hex,
///     witness_name: "witness-1".into(),
///     checkpoint_path: data_dir.join("cosign-checkpoint.json"),
/// };
/// ```
#[derive(Debug, Clone)]
pub struct WitnessConfig {
    /// Hex-encoded PKCS#8 signing key.
    pub signing_key_hex: String,
    /// Human-readable witness name.
    pub witness_name: String,
    /// Filesystem path for persisting the last-seen checkpoint.
    pub checkpoint_path: PathBuf,
}

/// Shared witness state behind Arc<RwLock<...>>.
struct WitnessInner {
    signing_key: ring::signature::Ed25519KeyPair,
    public_key: Ed25519PublicKey,
    witness_name: String,
    checkpoint_path: PathBuf,
    last_checkpoint: Option<SignedCheckpoint>,
}

/// Thread-safe witness state handle.
#[derive(Clone)]
pub struct WitnessState {
    inner: Arc<RwLock<WitnessInner>>,
}

/// Error response from the witness.
#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

impl WitnessState {
    /// Create a new witness state from config.
    ///
    /// Loads the last-seen checkpoint from disk if it exists (TOFU semantics).
    ///
    /// Args:
    /// * `config` — Witness configuration.
    ///
    /// Usage:
    /// ```ignore
    /// let state = WitnessState::new(&config)?;
    /// ```
    pub fn new(config: &WitnessConfig) -> Result<Self, anyhow::Error> {
        let key_bytes = hex::decode(&config.signing_key_hex)
            .map_err(|e| anyhow::anyhow!("invalid hex signing key: {e}"))?;

        let signing_key = ring::signature::Ed25519KeyPair::from_pkcs8(&key_bytes)
            .map_err(|e| anyhow::anyhow!("invalid PKCS#8 key: {e}"))?;

        let pk_bytes = signing_key.public_key().as_ref();
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(pk_bytes);
        let public_key = Ed25519PublicKey::from_bytes(pk_arr);

        let last_checkpoint = load_checkpoint(&config.checkpoint_path);

        Ok(Self {
            inner: Arc::new(RwLock::new(WitnessInner {
                signing_key,
                public_key,
                witness_name: config.witness_name.clone(),
                checkpoint_path: config.checkpoint_path.clone(),
                last_checkpoint,
            })),
        })
    }
}

/// Build the Axum router for the cosign role.
///
/// Args:
/// * `state` — Shared witness state.
///
/// Usage:
/// ```ignore
/// let app = build_router(state);
/// ```
pub fn build_router(state: WitnessState) -> Router {
    Router::new()
        .route("/add-checkpoint", post(add_checkpoint))
        .with_state(state)
}

/// POST /add-checkpoint — C2SP tlog-witness cosigning endpoint.
///
/// Verifies consistency with the last-seen checkpoint, cosigns,
/// persists state, and returns the cosignature.
#[allow(clippy::disallowed_methods)] // Witness binary is the presentation boundary
async fn add_checkpoint(
    State(state): State<WitnessState>,
    Json(request): Json<CosignRequest>,
) -> Result<Json<CosignResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut inner = state.inner.write().await;

    let new_checkpoint = &request.signed_checkpoint;

    if let Some(ref last) = inner.last_checkpoint {
        // Reject smaller or equal-size checkpoints (no rollback)
        if new_checkpoint.checkpoint.size < last.checkpoint.size {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(ErrorResponse {
                    error: format!(
                        "checkpoint size {} is smaller than last-seen {}",
                        new_checkpoint.checkpoint.size, last.checkpoint.size
                    ),
                }),
            ));
        }

        // Same size, same root — no-op, return existing cosignature
        if new_checkpoint.checkpoint.size == last.checkpoint.size {
            if new_checkpoint.checkpoint.root == last.checkpoint.root {
                let cosig = cosign(&inner, new_checkpoint, Utc::now());
                return Ok(Json(CosignResponse { cosignature: cosig }));
            }
            // Same size, different root — equivocation
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(ErrorResponse {
                    error: "equivocation detected: same size but different root".into(),
                }),
            ));
        }

        // Larger checkpoint — must have consistency proof
        let proof = request.consistency_proof.as_ref().ok_or_else(|| {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(ErrorResponse {
                    error: "consistency proof required for non-TOFU request".into(),
                }),
            )
        })?;

        verify_consistency_proof(last, new_checkpoint, proof).map_err(|e| {
            (
                StatusCode::UNPROCESSABLE_ENTITY,
                Json(ErrorResponse {
                    error: format!("consistency verification failed: {e}"),
                }),
            )
        })?;
    }
    // else: TOFU — accept first checkpoint

    let now = Utc::now();
    let cosig = cosign(&inner, new_checkpoint, now);

    // Persist checkpoint to disk before returning (fsync)
    persist_checkpoint(&inner.checkpoint_path, new_checkpoint).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("failed to persist checkpoint: {e}"),
            }),
        )
    })?;

    inner.last_checkpoint = Some(new_checkpoint.clone());

    Ok(Json(CosignResponse { cosignature: cosig }))
}

fn cosign(
    inner: &WitnessInner,
    checkpoint: &SignedCheckpoint,
    now: DateTime<Utc>,
) -> WitnessCosignature {
    let body = checkpoint.checkpoint.to_note_body();
    let timestamp_secs = now.timestamp() as u64;
    let msg = cosignature_signed_message(&body, timestamp_secs);
    let sig = inner.signing_key.sign(&msg);

    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(sig.as_ref());

    WitnessCosignature {
        witness_name: inner.witness_name.clone(),
        witness_public_key: inner.public_key,
        signature: Ed25519Signature::from_bytes(sig_arr),
        timestamp: now,
    }
}

fn verify_consistency_proof(
    old: &SignedCheckpoint,
    new: &SignedCheckpoint,
    proof: &ConsistencyProof,
) -> Result<(), String> {
    if proof.old_size != old.checkpoint.size || proof.new_size != new.checkpoint.size {
        return Err(format!(
            "proof sizes ({},{}) don't match checkpoints ({},{})",
            proof.old_size, proof.new_size, old.checkpoint.size, new.checkpoint.size
        ));
    }

    if proof.old_root != old.checkpoint.root || proof.new_root != new.checkpoint.root {
        return Err("proof roots don't match checkpoint roots".into());
    }

    verify_consistency(
        proof.old_size,
        proof.new_size,
        &proof.hashes,
        &proof.old_root,
        &proof.new_root,
    )
    .map_err(|e| e.to_string())
}

fn load_checkpoint(path: &Path) -> Option<SignedCheckpoint> {
    let data = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

fn persist_checkpoint(path: &Path, checkpoint: &SignedCheckpoint) -> Result<(), std::io::Error> {
    use std::io::Write;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let json = serde_json::to_string_pretty(checkpoint).map_err(std::io::Error::other)?;

    let tmp_path = path.with_extension("tmp");
    let mut file = std::fs::File::create(&tmp_path)?;
    file.write_all(json.as_bytes())?;
    file.sync_all()?;
    std::fs::rename(&tmp_path, path)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_transparency::{Checkpoint, LogOrigin, MerkleHash};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[allow(clippy::disallowed_methods)]
    fn test_config(dir: &std::path::Path) -> WitnessConfig {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        WitnessConfig {
            signing_key_hex: hex::encode(pkcs8.as_ref()),
            witness_name: "test-witness".into(),
            checkpoint_path: dir.join("last_checkpoint.json"),
        }
    }

    fn make_checkpoint(size: u64, root: [u8; 32]) -> SignedCheckpoint {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();

        let checkpoint = Checkpoint {
            origin: LogOrigin::new("test.dev/log").unwrap(),
            size,
            root: MerkleHash::from_bytes(root),
            timestamp: DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        };

        let body = checkpoint.to_note_body();
        let sig = kp.sign(body.as_bytes());
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(sig.as_ref());

        let pk = kp.public_key().as_ref();
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(pk);

        SignedCheckpoint {
            checkpoint,
            log_signature: Ed25519Signature::from_bytes(sig_arr),
            log_public_key: Ed25519PublicKey::from_bytes(pk_arr),
            witnesses: vec![],
            ecdsa_checkpoint_signature: None,
            ecdsa_checkpoint_key: None,
        }
    }

    #[tokio::test]
    async fn tofu_accepts_first_checkpoint() {
        let dir = tempfile::TempDir::new().unwrap();
        let config = test_config(dir.path());
        let state = WitnessState::new(&config).unwrap();
        let app = build_router(state);

        let request = CosignRequest {
            old_size: 0,
            consistency_proof: None,
            signed_checkpoint: make_checkpoint(10, [0xaa; 32]),
        };

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/add-checkpoint")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&request).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn rejects_equivocation() {
        let dir = tempfile::TempDir::new().unwrap();
        let config = test_config(dir.path());
        let state = WitnessState::new(&config).unwrap();
        let app = build_router(state.clone());

        let cp1 = make_checkpoint(10, [0xaa; 32]);
        let req1 = CosignRequest {
            old_size: 0,
            consistency_proof: None,
            signed_checkpoint: cp1,
        };

        let _ = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/add-checkpoint")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&req1).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Send equivocating checkpoint (same size, different root)
        let cp2 = make_checkpoint(10, [0xbb; 32]);
        let req2 = CosignRequest {
            old_size: 0,
            consistency_proof: None,
            signed_checkpoint: cp2,
        };

        let app2 = build_router(state);
        let resp = app2
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/add-checkpoint")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&req2).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn rejects_smaller_size() {
        let dir = tempfile::TempDir::new().unwrap();
        let config = test_config(dir.path());
        let state = WitnessState::new(&config).unwrap();

        let cp1 = make_checkpoint(10, [0xaa; 32]);
        let req1 = CosignRequest {
            old_size: 0,
            consistency_proof: None,
            signed_checkpoint: cp1,
        };

        let app = build_router(state.clone());
        let _ = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/add-checkpoint")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&req1).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Send smaller checkpoint
        let cp2 = make_checkpoint(5, [0xbb; 32]);
        let req2 = CosignRequest {
            old_size: 0,
            consistency_proof: None,
            signed_checkpoint: cp2,
        };

        let app2 = build_router(state);
        let resp = app2
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/add-checkpoint")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&req2).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn requires_consistency_proof_for_growth() {
        let dir = tempfile::TempDir::new().unwrap();
        let config = test_config(dir.path());
        let state = WitnessState::new(&config).unwrap();

        let cp1 = make_checkpoint(10, [0xaa; 32]);
        let req1 = CosignRequest {
            old_size: 0,
            consistency_proof: None,
            signed_checkpoint: cp1,
        };

        let app = build_router(state.clone());
        let _ = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/add-checkpoint")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&req1).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Send larger checkpoint without proof
        let cp2 = make_checkpoint(20, [0xbb; 32]);
        let req2 = CosignRequest {
            old_size: 10,
            consistency_proof: None,
            signed_checkpoint: cp2,
        };

        let app2 = build_router(state);
        let resp = app2
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/add-checkpoint")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&req2).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn checkpoint_persistence_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("checkpoint.json");

        let cp = make_checkpoint(10, [0xaa; 32]);
        persist_checkpoint(&path, &cp).unwrap();

        let loaded = load_checkpoint(&path).unwrap();
        assert_eq!(loaded.checkpoint.size, 10);
        assert_eq!(loaded.checkpoint.root, cp.checkpoint.root);
    }
}
