//! HTTP witness server using Axum.
//!
//! This module implements a lightweight HTTP server that acts as a KERI witness,
//! receiving events, enforcing first-seen-always-seen, and issuing receipts.
//!
//! # Endpoints
//!
//! - `POST /witness/:prefix/event` - Submit an event for witnessing
//! - `GET /witness/:prefix/head` - Get the latest observed sequence
//! - `GET /witness/:prefix/receipt/:said` - Retrieve an issued receipt
//! - `GET /health` - Health check
//!
//! # Feature Gate
//!
//! This module requires the `witness-server` feature.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use auths_crypto::{CurveType, SecureSeed, TypedSignerKey};
use auths_keri::{Prefix, Said};
use auths_verifier::types::DeviceDID;
use axum::{
    Json, Router,
    extract::{Path as AxumPath, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

use auths_keri::{KeriSequence, VersionString};

use super::error::{DuplicityEvidence, WitnessError};
use super::receipt::{RECEIPT_TYPE, Receipt, SignedReceipt};
use super::storage::WitnessStorage;

/// Shared server state.
#[derive(Clone)]
pub struct WitnessServerState {
    inner: Arc<WitnessServerInner>,
}

#[allow(dead_code)]
struct WitnessServerInner {
    /// Witness identifier (DID)
    witness_did: DeviceDID,
    /// Curve-tagged signing key (fn-116.1/B1a). Carries curve so sign/DID
    /// paths dispatch correctly; replaces the historical
    /// `{seed: SecureSeed, public_key: [u8; 32]}` pair that was Ed25519-locked.
    signer: TypedSignerKey,
    /// SQLite storage (Mutex for thread safety since Connection is !Sync)
    storage: Mutex<WitnessStorage>,
    /// Clock function for getting current time
    clock: Box<dyn Fn() -> DateTime<Utc> + Send + Sync>,
}

/// Configuration for the witness server.
pub struct WitnessServerConfig {
    /// Witness identifier (DID)
    pub witness_did: DeviceDID,
    /// Curve-tagged signing key (fn-116.1/B1a).
    pub signer: TypedSignerKey,
    /// Path to SQLite database
    pub db_path: std::path::PathBuf,
    /// Path to TLS certificate (PEM format). Used by `run_server_tls()` when the `tls` feature is enabled.
    pub tls_cert_path: Option<PathBuf>,
    /// Path to TLS private key (PEM format). Used by `run_server_tls()` when the `tls` feature is enabled.
    pub tls_key_path: Option<PathBuf>,
}

impl WitnessServerConfig {
    /// Create a new config with a generated keypair for the given curve.
    ///
    /// fn-116.1/B1a: accepts `curve: CurveType` (default `CurveType::P256` at
    /// the CLI layer). DID derivation dispatches on curve via `DecodedDidKey`.
    pub fn with_generated_keypair(
        db_path: std::path::PathBuf,
        curve: CurveType,
    ) -> Result<Self, WitnessError> {
        let (seed_bytes, pubkey_bytes) = generate_keypair_for_curve(curve)?;
        let typed_seed = match curve {
            CurveType::Ed25519 => auths_crypto::TypedSeed::Ed25519(seed_bytes),
            CurveType::P256 => auths_crypto::TypedSeed::P256(seed_bytes),
        };
        let signer = TypedSignerKey::from_parts(typed_seed, pubkey_bytes.clone())
            .map_err(|e| WitnessError::Network(format!("invalid witness signer: {e}")))?;
        let witness_did = derive_witness_did(curve, &pubkey_bytes)?;

        Ok(Self {
            witness_did,
            signer,
            db_path,
            tls_cert_path: None,
            tls_key_path: None,
        })
    }
}

/// Generate a keypair for the given curve; returns (seed_bytes, pubkey_bytes).
///
/// Ed25519: 32-byte seed + 32-byte pubkey. P-256: 32-byte scalar + 33-byte
/// compressed SEC1 pubkey.
fn generate_keypair_for_curve(curve: CurveType) -> Result<([u8; 32], Vec<u8>), WitnessError> {
    match curve {
        CurveType::Ed25519 => {
            use crate::crypto::provider_bridge;
            let (seed, pubkey) = provider_bridge::generate_ed25519_keypair_sync()
                .map_err(|e| WitnessError::Network(format!("Ed25519 keygen: {e}")))?;
            Ok((*seed.as_bytes(), pubkey.to_vec()))
        }
        CurveType::P256 => {
            use p256::ecdsa::{SigningKey, VerifyingKey};
            use p256::elliptic_curve::rand_core::OsRng;
            let sk = SigningKey::random(&mut OsRng);
            let mut scalar = [0u8; 32];
            scalar.copy_from_slice(&sk.to_bytes());
            let vk = VerifyingKey::from(&sk);
            let pubkey = vk.to_encoded_point(true).as_bytes().to_vec();
            Ok((scalar, pubkey))
        }
    }
}

/// Derive a `did:key:` for the witness from a curve-tagged public key.
fn derive_witness_did(curve: CurveType, pubkey_bytes: &[u8]) -> Result<DeviceDID, WitnessError> {
    let did_str = match curve {
        CurveType::Ed25519 => {
            let pk: [u8; 32] = pubkey_bytes
                .try_into()
                .map_err(|_| WitnessError::Network("Ed25519 pubkey must be 32 bytes".into()))?;
            auths_crypto::ed25519_pubkey_to_did_key(&pk)
        }
        CurveType::P256 => auths_crypto::p256_pubkey_to_did_key(pubkey_bytes),
    };
    #[allow(clippy::disallowed_methods)]
    // INVARIANT: derived via auths_crypto::{ed25519,p256}_pubkey_to_did_key which
    // emits well-formed did:key URIs.
    Ok(DeviceDID::new_unchecked(did_str))
}

/// Event submission request.
#[derive(Debug, Deserialize)]
pub struct SubmitEventRequest {
    /// Event SAID
    pub d: String,
    /// Event sequence number
    pub s: u64,
    /// Event type
    pub t: String,
    /// Full event JSON (for signature verification)
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

/// Health check response.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    /// Witness server status string.
    pub status: String,
    /// DID of this witness.
    pub witness_did: DeviceDID,
    /// Number of first-seen events recorded.
    pub first_seen_count: usize,
    /// Total receipts issued.
    pub receipt_count: usize,
}

/// Head response.
#[derive(Debug, Serialize)]
pub struct HeadResponse {
    /// KERI prefix of the identity.
    pub prefix: Prefix,
    /// Latest observed sequence number.
    pub latest_seq: Option<u64>,
}

/// Error response.
#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    /// Error message.
    pub error: String,
    /// Duplicity evidence, if detected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duplicity: Option<DuplicityEvidence>,
}

#[allow(dead_code)]
impl WitnessServerState {
    /// Create a new server state.
    #[allow(clippy::disallowed_methods)] // Server constructor is a clock boundary
    pub fn new(config: WitnessServerConfig) -> Result<Self, WitnessError> {
        let storage = WitnessStorage::open(&config.db_path)?;

        Ok(Self {
            inner: Arc::new(WitnessServerInner {
                witness_did: config.witness_did,
                signer: config.signer,
                storage: Mutex::new(storage),
                clock: Box::new(Utc::now),
            }),
        })
    }

    /// Create a new server state with in-memory storage (for testing).
    #[allow(clippy::disallowed_methods)] // Server constructor is a clock boundary
    pub fn in_memory(witness_did: DeviceDID, signer: TypedSignerKey) -> Result<Self, WitnessError> {
        let storage = WitnessStorage::in_memory()?;

        Ok(Self {
            inner: Arc::new(WitnessServerInner {
                witness_did,
                signer,
                storage: Mutex::new(storage),
                clock: Box::new(Utc::now),
            }),
        })
    }

    /// Legacy helper for tests that have an Ed25519 seed + pubkey.
    #[allow(clippy::disallowed_methods)]
    pub fn in_memory_ed25519(
        witness_did: DeviceDID,
        seed: SecureSeed,
        public_key: [u8; 32],
    ) -> Result<Self, WitnessError> {
        let typed_seed = auths_crypto::TypedSeed::Ed25519(*seed.as_bytes());
        let signer = TypedSignerKey::from_parts(typed_seed, public_key.to_vec())
            .map_err(|e| WitnessError::Network(format!("invalid witness signer: {e}")))?;
        Self::in_memory(witness_did, signer)
    }

    /// Create a new server state with generated keypair (for testing).
    #[allow(clippy::disallowed_methods)] // Server constructor is a clock boundary
    pub fn in_memory_generated() -> Result<Self, WitnessError> {
        Self::in_memory_generated_for_curve(CurveType::Ed25519)
    }

    /// Create a new server state with a generated keypair of the specified curve.
    #[allow(clippy::disallowed_methods)]
    pub fn in_memory_generated_for_curve(curve: CurveType) -> Result<Self, WitnessError> {
        let (seed_bytes, pubkey_bytes) = generate_keypair_for_curve(curve)?;
        let typed_seed = match curve {
            CurveType::Ed25519 => auths_crypto::TypedSeed::Ed25519(seed_bytes),
            CurveType::P256 => auths_crypto::TypedSeed::P256(seed_bytes),
        };
        let signer = TypedSignerKey::from_parts(typed_seed, pubkey_bytes.clone())
            .map_err(|e| WitnessError::Network(format!("invalid witness signer: {e}")))?;
        let witness_did = derive_witness_did(curve, &pubkey_bytes)?;

        let storage = WitnessStorage::in_memory()?;
        Ok(Self {
            inner: Arc::new(WitnessServerInner {
                witness_did,
                signer,
                storage: Mutex::new(storage),
                clock: Box::new(Utc::now),
            }),
        })
    }

    /// Get the witness DID.
    pub fn witness_did(&self) -> &str {
        &self.inner.witness_did
    }

    /// Create a receipt for an event.
    fn create_receipt(
        &self,
        prefix: &Prefix,
        seq: u64,
        event_said: &Said,
    ) -> Result<Receipt, WitnessError> {
        let receipt = Receipt {
            v: VersionString::placeholder(),
            t: RECEIPT_TYPE.into(),
            d: event_said.clone(),
            i: prefix.clone(),
            s: KeriSequence::new(seq),
        };

        Ok(receipt)
    }

    /// Create a signed receipt for an event.
    fn create_signed_receipt(
        &self,
        prefix: &Prefix,
        seq: u64,
        event_said: &Said,
    ) -> Result<SignedReceipt, WitnessError> {
        let receipt = self.create_receipt(prefix, seq, event_said)?;

        let signing_payload =
            serde_json::to_vec(&receipt).map_err(|e| WitnessError::Serialization(e.to_string()))?;
        let signature = self.sign_payload(&signing_payload)?;

        Ok(SignedReceipt { receipt, signature })
    }

    /// Sign a payload with the witness keypair (curve-dispatched).
    ///
    /// fn-116.1/B1a: routes through `TypedSignerKey::sign` which dispatches
    /// on the seed's curve. No more hardcoded Ed25519.
    fn sign_payload(&self, payload: &[u8]) -> Result<Vec<u8>, WitnessError> {
        self.inner
            .signer
            .sign(payload)
            .map_err(|e| WitnessError::Serialization(format!("signing failed: {e}")))
    }

    /// Get the witness public key bytes.
    pub fn public_key(&self) -> Vec<u8> {
        self.inner.signer.public_key().to_vec()
    }

    /// Returns the curve of the witness signing key.
    pub fn curve(&self) -> CurveType {
        self.inner.signer.curve()
    }
}

/// Build the Axum router for the witness server.
pub fn router(state: WitnessServerState) -> Router {
    Router::new()
        .route("/witness/{prefix}/event", post(submit_event))
        .route("/witness/{prefix}/head", get(get_head))
        .route("/witness/{prefix}/receipt/{said}", get(get_receipt))
        .route("/health", get(health))
        .with_state(state)
}

/// Run the witness server.
pub async fn run_server(state: WitnessServerState, addr: SocketAddr) -> Result<(), WitnessError> {
    let app = router(state);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| WitnessError::Network(format!("failed to bind: {}", e)))?;

    axum::serve(listener, app)
        .await
        .map_err(|e| WitnessError::Network(format!("server error: {}", e)))?;

    Ok(())
}

/// Run the witness server with TLS (rustls).
///
/// Requires the `tls` feature flag. The certificate and key must be PEM-encoded files.
/// For production deployments behind a reverse proxy, prefer [`run_server`] and terminate
/// TLS at the proxy layer instead.
#[cfg(feature = "tls")]
#[allow(dead_code)] // feature-gated public API — available when tls feature is enabled
pub async fn run_server_tls(
    state: WitnessServerState,
    addr: SocketAddr,
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> Result<(), WitnessError> {
    let app = router(state);

    let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path)
        .await
        .map_err(|e| WitnessError::Network(format!("failed to load TLS config: {}", e)))?;

    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await
        .map_err(|e| WitnessError::Network(format!("TLS server error: {}", e)))?;

    Ok(())
}

/// Verify the SAID of a KERI event.
///
/// Zeros the `d` field, serializes to canonical JSON, computes Blake3 SAID,
/// and compares with the claimed `d` value.
fn verify_event_said(event: &serde_json::Value) -> Result<(), String> {
    let claimed_d = event
        .get("d")
        .and_then(|v| v.as_str())
        .ok_or("missing 'd' (SAID) field")?;

    let computed = crate::crypto::said::compute_said(event)
        .map_err(|e| format!("failed to compute SAID: {}", e))?;

    if computed.as_str() != claimed_d {
        return Err(format!(
            "SAID mismatch: claimed {} but computed {}",
            claimed_d, computed
        ));
    }
    Ok(())
}

/// Validate the structural requirements of a KERI event.
fn validate_event_structure(event: &serde_json::Value) -> Result<(), String> {
    let obj = event.as_object().ok_or("event must be a JSON object")?;

    // Required fields for all event types
    for field in &["v", "t", "d", "i", "s"] {
        if !obj.contains_key(*field) {
            return Err(format!("missing required field '{}'", field));
        }
    }

    let event_type = obj
        .get("t")
        .and_then(|v| v.as_str())
        .ok_or("'t' must be a string")?;

    match event_type {
        "icp" => {
            // Inception events require keys
            for field in &["k", "x"] {
                if !obj.contains_key(*field) {
                    return Err(format!(
                        "inception event missing required field '{}'",
                        field
                    ));
                }
            }
        }
        "rot" | "ixn" => {
            // Rotation/interaction events require prior event reference
            if !obj.contains_key("p") {
                return Err(format!(
                    "{} event missing required field 'p' (prior event reference)",
                    event_type
                ));
            }
        }
        _ => {
            // Unknown event types are allowed but logged
        }
    }

    Ok(())
}

/// Validate that the signature field is valid hex encoding of 64 bytes (Ed25519 signature).
fn validate_signature_format(event: &serde_json::Value) -> Result<(), String> {
    if let Some(sig_val) = event.get("x") {
        let sig_hex = sig_val.as_str().ok_or("'x' (signature) must be a string")?;
        let sig_bytes =
            hex::decode(sig_hex).map_err(|e| format!("'x' field is not valid hex: {}", e))?;
        if sig_bytes.len() != 64 {
            return Err(format!(
                "'x' field must be 64 bytes (Ed25519 signature), got {} bytes",
                sig_bytes.len()
            ));
        }
    }
    Ok(())
}

/// For inception events, verify the self-signature (signature over the event by k[0]).
///
/// fn-116.21/B1b: parses `k[0]` via `KeriPublicKey::parse` (CESR-aware — the
/// workspace emits CESR-tagged pubkeys `D...` / `1AAI...`) and dispatches
/// signature verification on the parsed curve. Accepts a hex-encoded `k[0]` as
/// a legacy back-compat branch (prior versions of this validator) but emits a
/// log-worthy error message telling the caller to migrate.
fn verify_inception_self_signature(event: &serde_json::Value) -> Result<(), String> {
    let event_type = event.get("t").and_then(|v| v.as_str()).unwrap_or("");
    if event_type != "icp" {
        return Ok(());
    }

    let k = event
        .get("k")
        .and_then(|v| v.as_array())
        .ok_or("inception event 'k' must be an array")?;

    if k.is_empty() {
        return Err("inception event 'k' array is empty".to_string());
    }

    let k0_str = k[0].as_str().ok_or("'k[0]' must be a string")?;

    // Try CESR parse first (canonical wire format).
    let keri_key = match auths_keri::KeriPublicKey::parse(k0_str) {
        Ok(pk) => pk,
        Err(_) => {
            // Legacy hex fallback: some older emitters produced raw 32-byte hex
            // instead of a CESR-tagged string. Accept Ed25519 32-byte hex as
            // transitional; anything else is an error.
            let pk_bytes =
                hex::decode(k0_str).map_err(|e| format!("'k[0]' is neither CESR nor hex: {e}"))?;
            if pk_bytes.len() != 32 {
                return Err(format!(
                    "'k[0]' legacy-hex path only accepts 32-byte Ed25519 pubkeys, got {} bytes; \
                     emit CESR (`D...` or `1AAI...`) instead",
                    pk_bytes.len()
                ));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&pk_bytes);
            auths_keri::KeriPublicKey::Ed25519(arr)
        }
    };

    let sig_hex = event
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or("inception event missing 'x' (signature)")?;
    let sig_bytes = hex::decode(sig_hex).map_err(|e| format!("'x' is not valid hex: {}", e))?;

    // Build the signing payload: canonical JSON with empty 'd' and 'x' fields
    let mut payload_event = event.clone();
    let obj = payload_event
        .as_object_mut()
        .ok_or("event is not a JSON object")?;
    obj.insert("d".to_string(), serde_json::Value::String(String::new()));
    obj.insert("x".to_string(), serde_json::Value::String(String::new()));
    let payload = serde_json::to_vec(&payload_event)
        .map_err(|e| format!("failed to serialize signing payload: {}", e))?;

    keri_key
        .verify_signature(&payload, &sig_bytes)
        .map_err(|e| format!("inception self-signature verification failed: {e}"))
}

/// POST /witness/:prefix/event - Submit an event for witnessing.
#[allow(clippy::too_many_lines)]
async fn submit_event(
    State(state): State<WitnessServerState>,
    AxumPath(prefix_str): AxumPath<String>,
    Json(event): Json<serde_json::Value>,
) -> Result<Json<Receipt>, (StatusCode, Json<ErrorResponse>)> {
    let prefix = Prefix::new_unchecked(prefix_str);

    // Validate event structure
    if let Err(e) = validate_event_structure(&event) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("invalid event structure: {}", e),
                duplicity: None,
            }),
        ));
    }

    // Verify SAID
    if let Err(e) = verify_event_said(&event) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("SAID verification failed: {}", e),
                duplicity: None,
            }),
        ));
    }

    // Validate signature format
    if let Err(e) = validate_signature_format(&event) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("invalid signature format: {}", e),
                duplicity: None,
            }),
        ));
    }

    // Verify inception self-signature
    if let Err(e) = verify_inception_self_signature(&event) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("signature verification failed: {}", e),
                duplicity: None,
            }),
        ));
    }

    let event_d = Said::new_unchecked(
        event
            .get("d")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
    );
    let event_s = event.get("s").and_then(|v| v.as_u64()).unwrap_or(0);

    let now = (state.inner.clock)();
    let storage = state.inner.storage.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "internal lock error".to_string(),
                duplicity: None,
            }),
        )
    })?;

    // Check for duplicity
    match storage.check_duplicity(now, &prefix, event_s, &event_d) {
        Ok(None) => {
            // No duplicity - create and store receipt
            let receipt = state
                .create_receipt(&prefix, event_s, &event_d)
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: format!("failed to create receipt: {e}"),
                            duplicity: None,
                        }),
                    )
                })?;

            if let Err(e) = storage.store_receipt(now, &prefix, &receipt) {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: format!("failed to store receipt: {}", e),
                        duplicity: None,
                    }),
                ));
            }

            Ok(Json(receipt))
        }
        Ok(Some(existing_said)) => {
            // Duplicity detected!
            Err((
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "duplicity detected".to_string(),
                    duplicity: Some(DuplicityEvidence {
                        prefix,
                        sequence: event_s,
                        event_a_said: existing_said,
                        event_b_said: event_d,
                        witness_reports: vec![],
                    }),
                }),
            ))
        }
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("storage error: {}", e),
                duplicity: None,
            }),
        )),
    }
}

/// GET /witness/:prefix/head - Get the latest observed sequence.
async fn get_head(
    State(state): State<WitnessServerState>,
    AxumPath(prefix_str): AxumPath<String>,
) -> Result<Json<HeadResponse>, (StatusCode, Json<ErrorResponse>)> {
    let prefix = Prefix::new_unchecked(prefix_str);
    let storage = state.inner.storage.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "internal lock error".to_string(),
                duplicity: None,
            }),
        )
    })?;

    match storage.get_latest_seq(&prefix) {
        Ok(latest_seq) => Ok(Json(HeadResponse { prefix, latest_seq })),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("storage error: {}", e),
                duplicity: None,
            }),
        )),
    }
}

/// GET /witness/:prefix/receipt/:said - Retrieve an issued receipt.
async fn get_receipt(
    State(state): State<WitnessServerState>,
    AxumPath((prefix_str, said_str)): AxumPath<(String, String)>,
) -> Result<Json<Receipt>, StatusCode> {
    let prefix = Prefix::new_unchecked(prefix_str);
    let said = Said::new_unchecked(said_str);
    let storage = state
        .inner
        .storage
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match storage.get_receipt(&prefix, &said) {
        Ok(Some(receipt)) => Ok(Json(receipt)),
        Ok(None) => Err(StatusCode::NOT_FOUND),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// GET /health - Health check.
async fn health(State(state): State<WitnessServerState>) -> Json<HealthResponse> {
    let storage = state
        .inner
        .storage
        .lock()
        .unwrap_or_else(|e| e.into_inner());

    let first_seen_count = storage.count_first_seen().unwrap_or(0);
    let receipt_count = storage.count_receipts().unwrap_or(0);

    Json(HealthResponse {
        status: "ok".to_string(),
        witness_did: state.inner.witness_did.clone(),
        first_seen_count,
        receipt_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use tower::ServiceExt;

    fn test_state() -> WitnessServerState {
        WitnessServerState::in_memory_generated().unwrap()
    }

    /// Generate an Ed25519 keypair and return (pkcs8, public_key_hex).
    fn test_keypair() -> (Vec<u8>, String) {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let pk_hex = hex::encode(kp.public_key().as_ref());
        (pkcs8.as_ref().to_vec(), pk_hex)
    }

    /// Build a valid KERI inception event with proper SAID and self-signature.
    fn make_valid_icp_event(prefix: &str, seq: u64) -> serde_json::Value {
        let (pkcs8, pk_hex) = test_keypair();
        let kp = Ed25519KeyPair::from_pkcs8(&pkcs8).unwrap();

        // Build event with empty d and x for SAID computation
        let mut event = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": prefix,
            "s": seq,
            "k": [pk_hex],
            "x": ""
        });

        // Sign the payload (with empty d and x)
        let payload = serde_json::to_vec(&event).unwrap();
        let sig = kp.sign(&payload);
        event["x"] = serde_json::Value::String(hex::encode(sig.as_ref()));

        // Compute SAID (x is already set; compute_said ignores x and injects d placeholder)
        let said = crate::crypto::said::compute_said(&event).unwrap();
        event["d"] = serde_json::Value::String(said.into_inner());

        event
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn health_endpoint() {
        let state = test_state();
        let app = router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn submit_valid_icp_event_success() {
        let state = test_state();
        let app = router(state);

        let event = make_valid_icp_event("EPrefix", 0);

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/witness/EPrefix/event")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&event).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn submit_event_with_mismatched_said_rejected() {
        let state = test_state();
        let app = router(state);

        let mut event = make_valid_icp_event("EPrefix", 0);
        // Tamper with the SAID
        event["d"] = serde_json::Value::String(
            "EFakeSAID_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        );

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/witness/EPrefix/event")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&event).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn submit_event_missing_required_fields_rejected() {
        let state = test_state();
        let app = router(state);

        // Missing 't', 'd', 'i', 's'
        let body = serde_json::json!({"v": "KERI10JSON000000_"});

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/witness/EPrefix/event")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn submit_event_invalid_signature_hex_rejected() {
        let state = test_state();
        let app = router(state);

        // Build event with invalid hex in x field
        let mut event = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": "EPrefix",
            "s": 0,
            "k": ["0000000000000000000000000000000000000000000000000000000000000000"],
            "x": "not_valid_hex!!!"
        });
        // Set proper SAID for the event as-is
        let said = crate::crypto::said::compute_said(&event).unwrap();
        event["d"] = serde_json::Value::String(said.into_inner());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/witness/EPrefix/event")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&event).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn submit_icp_event_wrong_self_signature_rejected() {
        let state = test_state();
        let app = router(state);

        let (_, pk_hex) = test_keypair();
        // Use a different keypair to produce wrong signature
        let (wrong_pkcs8, _) = test_keypair();
        let wrong_kp = Ed25519KeyPair::from_pkcs8(&wrong_pkcs8).unwrap();

        let mut event = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": "EPrefix",
            "s": 0,
            "k": [pk_hex],
            "x": ""
        });

        // Sign with wrong key
        let payload = serde_json::to_vec(&event).unwrap();
        let sig = wrong_kp.sign(&payload);
        event["x"] = serde_json::Value::String(hex::encode(sig.as_ref()));

        // Compute SAID (x is already set; compute_said ignores x and injects d placeholder)
        let said = crate::crypto::said::compute_said(&event).unwrap();
        event["d"] = serde_json::Value::String(said.into_inner());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/witness/EPrefix/event")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&event).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn submit_event_duplicity() {
        let state = test_state();

        let event_a = make_valid_icp_event("EPrefix", 0);
        let event_a_said = event_a["d"].as_str().unwrap().to_string();

        // First submission
        {
            let app = router(state.clone());
            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/witness/EPrefix/event")
                        .header("content-type", "application/json")
                        .body(Body::from(serde_json::to_string(&event_a).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::OK);
        }

        // Second submission with different event at same seq
        {
            let app = router(state.clone());
            let event_b = make_valid_icp_event("EPrefix", 0);
            // event_b will have a different SAID (different key)
            assert_ne!(event_a_said, event_b["d"].as_str().unwrap());

            let response = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/witness/EPrefix/event")
                        .header("content-type", "application/json")
                        .body(Body::from(serde_json::to_string(&event_b).unwrap()))
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), StatusCode::CONFLICT);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn get_head_empty() {
        let state = test_state();
        let app = router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/witness/EPrefix/head")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn get_receipt_not_found() {
        let state = test_state();
        let app = router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/witness/EPrefix/receipt/NONEXISTENT")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn receipt_d_matches_event_said() {
        let state = test_state();
        let prefix = Prefix::new_unchecked("EPrefix".into());
        let event_said = Said::new_unchecked("ESAID123".into());
        let receipt = state.create_receipt(&prefix, 0, &event_said).unwrap();
        assert_eq!(receipt.d, event_said);
    }

    #[test]
    fn receipt_d_changes_with_event_said() {
        let state = test_state();
        let prefix = Prefix::new_unchecked("EPrefix".into());
        let receipt_a = state
            .create_receipt(&prefix, 0, &Said::new_unchecked("ESAID_A".into()))
            .unwrap();
        let receipt_b = state
            .create_receipt(&prefix, 0, &Said::new_unchecked("ESAID_B".into()))
            .unwrap();
        assert_ne!(receipt_a.d, receipt_b.d);
    }

    #[test]
    fn signed_receipt_signature_verifies() {
        let state = test_state();
        let prefix = Prefix::new_unchecked("EPrefix".into());
        let signed = state
            .create_signed_receipt(&prefix, 0, &Said::new_unchecked("ESAID123".into()))
            .unwrap();
        let public_key = state.public_key();
        let payload = serde_json::to_vec(&signed.receipt).unwrap();

        let pk = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &public_key);
        pk.verify(&payload, &signed.signature)
            .expect("signed receipt signature should verify against serialized receipt");
    }

    #[test]
    fn verify_event_said_valid() {
        let event = make_valid_icp_event("EPrefix", 0);
        assert!(verify_event_said(&event).is_ok());
    }

    #[test]
    fn verify_event_said_tampered() {
        let mut event = make_valid_icp_event("EPrefix", 0);
        event["d"] = serde_json::Value::String(
            "EFakeSAID_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        );
        assert!(verify_event_said(&event).is_err());
    }

    #[test]
    fn validate_structure_missing_fields() {
        let event = serde_json::json!({"v": "KERI10JSON000000_"});
        assert!(validate_event_structure(&event).is_err());
    }

    #[test]
    fn validate_structure_icp_missing_k() {
        let event = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "E123",
            "i": "EPrefix",
            "s": 0
        });
        assert!(validate_event_structure(&event).is_err());
    }

    #[test]
    fn validate_structure_rot_missing_p() {
        let event = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "rot",
            "d": "E123",
            "i": "EPrefix",
            "s": 1
        });
        assert!(validate_event_structure(&event).is_err());
    }
}
