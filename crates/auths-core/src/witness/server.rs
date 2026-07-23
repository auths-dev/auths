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
use auths_verifier::types::CanonicalDid;
use axum::{
    Json, Router,
    extract::{Path as AxumPath, State},
    http::StatusCode,
    routing::{get, post},
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Mutex;

use auths_keri::{
    Event, KeriSequence, KeyState, KeyStateRecord, SignedEvent, TrustedKel, VersionString,
    parse_delegated_attachment, parse_kel_json, state_after_event, validate_signed_event,
};

use super::error::{DuplicityEvidence, WitnessError};
use super::receipt::{Receipt, ReceiptTag, SignedReceipt};
use super::sink::{KelSink, KelSinkError, KelSinkOutcome};
use super::storage::WitnessStorage;
use super::wire::split_submit_body;

/// Shared server state.
#[derive(Clone)]
pub struct WitnessServerState {
    inner: Arc<WitnessServerInner>,
}

#[allow(dead_code)]
struct WitnessServerInner {
    /// Witness identifier (DID)
    witness_did: CanonicalDid,
    /// Curve-tagged signing key (fn-116.1/B1a). Carries curve so sign/DID
    /// paths dispatch correctly; replaces the historical
    /// `{seed: SecureSeed, public_key: [u8; 32]}` pair that was Ed25519-locked.
    signer: TypedSignerKey,
    /// SQLite storage (Mutex for thread safety since Connection is !Sync)
    storage: Mutex<WitnessStorage>,
    /// Clock function for getting current time
    clock: Box<dyn Fn() -> DateTime<Utc> + Send + Sync>,
    /// The proof of which binary this node runs (version, self-measured digest,
    /// and the signed build attestation). `None` when the binary was started
    /// without a build attestation configured, in which case the `/build`
    /// surface 404s — a node that cannot prove its binary says so plainly.
    build_proof: Option<BuildProof>,
    /// The write bridge: accepted events are routed into the per-prefix KEL
    /// store the node serves. `None` runs the legacy receipt-only mode (the
    /// SQLite ledger still retains events, but nothing resolvable is served).
    kel_sink: Option<Arc<dyn KelSink>>,
}

/// The proof a node serves of which binary it is running.
///
/// Three facts, none of which the server interprets: the running binary's
/// `version`, the SHA-256 the binary measured of *itself* at startup
/// (`running_digest`), and the signed build attestation (`attestation`, the raw
/// `auths artifact sign` document). The server is a serving surface — it pairs
/// the self-measurement with the signed claim and hands both to whoever asks.
/// The *verification* (does the attestation's signature hold, and does it attest
/// THIS running digest?) is a relying party's job, done from these bytes alone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildProof {
    /// Version string of the running binary.
    pub version: String,
    /// SHA-256 (hex) the binary measured of its own on-disk image at startup.
    pub running_digest: String,
    /// The signed build attestation document (`auths artifact sign` output),
    /// carried verbatim so a relying party verifies the original signed bytes.
    pub attestation: serde_json::Value,
}

impl BuildProof {
    /// Measure the running binary's own on-disk image and pair the digest with
    /// its version and a signed build attestation.
    ///
    /// The digest is computed over the bytes of the executable this process is
    /// running (`current_exe`), so `running_digest` is the node's measurement of
    /// *itself* — not a number it was handed. A relying party then checks that
    /// the signed `attestation` attests this exact digest.
    ///
    /// Args:
    /// * `version`: the running binary's version string.
    /// * `attestation`: the parsed `auths artifact sign` document to serve verbatim.
    pub fn measure_self(
        version: impl Into<String>,
        attestation: serde_json::Value,
    ) -> std::io::Result<Self> {
        let exe = std::env::current_exe()?;
        let running_digest = sha256_file_hex(&exe)?;
        Ok(Self {
            version: version.into(),
            running_digest,
            attestation,
        })
    }
}

/// SHA-256 (hex) of a file's bytes.
///
/// Reads the file whole (the witness binary is a few MB) through `std::fs::read`
/// — the sans-IO crate's approved file read — then hashes it.
fn sha256_file_hex(path: &std::path::Path) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path)?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

/// Configuration for the witness server.
pub struct WitnessServerConfig {
    /// Witness identifier (DID)
    pub witness_did: CanonicalDid,
    /// Curve-tagged signing key (fn-116.1/B1a).
    pub signer: TypedSignerKey,
    /// Path to SQLite database
    pub db_path: std::path::PathBuf,
    /// Path to TLS certificate (PEM format). Used by `run_server_tls()` when the `tls` feature is enabled.
    pub tls_cert_path: Option<PathBuf>,
    /// Path to TLS private key (PEM format). Used by `run_server_tls()` when the `tls` feature is enabled.
    pub tls_key_path: Option<PathBuf>,
    /// Proof of which binary the node runs, served at `/build`. `None` leaves
    /// the build surface absent (404) — a node that was not given a build
    /// attestation does not pretend to have one.
    pub build_proof: Option<BuildProof>,
    /// Write bridge into the served per-prefix KEL store. `None` keeps the
    /// legacy receipt-only mode.
    pub kel_sink: Option<Arc<dyn KelSink>>,
}

impl WitnessServerConfig {
    /// Create a new config with a generated keypair for the given curve.
    ///
    /// accepts `curve: CurveType` (default `CurveType::P256` at
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
        let signer = TypedSignerKey::from_parts(typed_seed, pubkey_bytes)
            .map_err(|e| WitnessError::Network(format!("invalid witness signer: {e}")))?;
        Self::from_signer(db_path, signer)
    }

    /// Create a config from an already-constructed signer (e.g. a persisted
    /// witness identity loaded from a keystore).
    ///
    /// The advertised `/health` AID derives from the signer's curve-tagged public
    /// key, so a loaded key and its published identity cannot diverge.
    ///
    /// Args:
    /// * `db_path`: Path to the SQLite database for witness storage.
    /// * `signer`: The witness's persisted signing key.
    ///
    /// Usage:
    /// ```ignore
    /// let cfg = WitnessServerConfig::from_signer(db_path, signer)?;
    /// ```
    pub fn from_signer(
        db_path: std::path::PathBuf,
        signer: TypedSignerKey,
    ) -> Result<Self, WitnessError> {
        let witness_did = derive_witness_did(signer.curve(), signer.public_key())?;
        Ok(Self {
            witness_did,
            signer,
            db_path,
            tls_cert_path: None,
            tls_key_path: None,
            build_proof: None,
            kel_sink: None,
        })
    }

    /// Attach the proof of which binary this node runs (served at `/build`).
    ///
    /// Consuming-builder so a deployed binary that knows its own version,
    /// self-measured digest, and signed attestation threads them into the
    /// server in one call; a binary started without one simply never calls this
    /// and the build surface stays absent.
    pub fn with_build_proof(mut self, proof: BuildProof) -> Self {
        self.build_proof = Some(proof);
        self
    }

    /// Attach the write bridge into the served per-prefix KEL store.
    ///
    /// Accepted events are then persisted to (and validated by) the injected
    /// sink before a receipt is issued — "serve what you witness".
    pub fn with_kel_sink(mut self, sink: Arc<dyn KelSink>) -> Self {
        self.kel_sink = Some(sink);
        self
    }
}

/// Generate a keypair for the given curve; returns (seed_bytes, pubkey_bytes).
///
/// Ed25519: 32-byte seed + 32-byte pubkey. P-256: 32-byte scalar + 33-byte
/// compressed SEC1 pubkey.
pub(crate) fn generate_keypair_for_curve(
    curve: CurveType,
) -> Result<([u8; 32], Vec<u8>), WitnessError> {
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
fn derive_witness_did(curve: CurveType, pubkey_bytes: &[u8]) -> Result<CanonicalDid, WitnessError> {
    Ok(CanonicalDid::from_public_key_did_key(pubkey_bytes, curve))
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
    pub witness_did: CanonicalDid,
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

/// First-seen SAID at a chosen sequence number.
///
/// Lets a monitor compare witnesses by CONTENT (the SAID each first saw at a
/// sequence), not just by HEAD number — so a same-seq/different-SAID fork is
/// visible where two `/head` calls would return the identical `latest_seq`.
#[derive(Debug, Serialize)]
pub struct SaidAtSeqResponse {
    /// KERI prefix of the identity.
    pub prefix: Prefix,
    /// The queried sequence number.
    pub seq: u64,
    /// SAID of the event this witness first saw at `seq`.
    pub said: Said,
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
                build_proof: config.build_proof,
                kel_sink: config.kel_sink,
            }),
        })
    }

    /// Create a new server state with in-memory storage (for testing).
    #[allow(clippy::disallowed_methods)] // Server constructor is a clock boundary
    pub fn in_memory(
        witness_did: CanonicalDid,
        signer: TypedSignerKey,
    ) -> Result<Self, WitnessError> {
        let storage = WitnessStorage::in_memory()?;

        Ok(Self {
            inner: Arc::new(WitnessServerInner {
                witness_did,
                signer,
                storage: Mutex::new(storage),
                clock: Box::new(Utc::now),
                build_proof: None,
                kel_sink: None,
            }),
        })
    }

    /// Legacy helper for tests that have an Ed25519 seed + pubkey.
    #[allow(clippy::disallowed_methods)]
    pub fn in_memory_ed25519(
        witness_did: CanonicalDid,
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
                build_proof: None,
                kel_sink: None,
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
        seq: u128,
        event_said: &Said,
    ) -> Result<Receipt, WitnessError> {
        let receipt = Receipt {
            v: VersionString::placeholder(),
            t: ReceiptTag,
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
        seq: u128,
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
    /// routes through `TypedSignerKey::sign` which dispatches
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
        .route("/witness/{prefix}/said/{seq}", get(get_said_at_seq))
        .route("/witness/{prefix}/receipt/{said}", get(get_receipt))
        .route("/witness/{prefix}/key-state", get(get_key_state))
        .route("/build", get(get_build))
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

/// Ceiling on anchored seals per event (the bulk-onboarding batch bound).
///
/// One batch anchor `ixn` carries ~3 seals per onboarded agent; 256 seals
/// keeps the wire body far under the node's request-size envelope while
/// letting a batch of ~85 agents anchor in one receipt round. Clients chunk
/// above this (`add_bulk` batch sizing), so the bound is a backstop against
/// pathological events, not a throughput limit.
pub const MAX_SEALS_PER_EVENT: usize = 256;

/// Validate the structural requirements of a KERI event.
///
/// `has_attachment` selects the signature dialect: envelope submissions carry
/// detached CESR signatures, so the legacy inline `x` field is not required.
fn validate_event_structure(event: &serde_json::Value, has_attachment: bool) -> Result<(), String> {
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

    if let Some(seals) = obj.get("a").and_then(|v| v.as_array())
        && seals.len() > MAX_SEALS_PER_EVENT
    {
        return Err(format!(
            "event anchors {} seals, exceeding the {} per-event bound — chunk the batch",
            seals.len(),
            MAX_SEALS_PER_EVENT
        ));
    }

    match event_type {
        "icp" => {
            if !obj.contains_key("k") {
                return Err("inception event missing required field 'k'".to_string());
            }
            if !has_attachment && !obj.contains_key("x") {
                return Err(
                    "inception event missing 'x' (and no CESR attachment supplied)".to_string(),
                );
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

/// A 400 response with the given message.
fn bad_request(error: String) -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            error,
            duplicity: None,
        }),
    )
}

/// A 500 response for a poisoned storage mutex.
fn lock_error() -> (StatusCode, Json<ErrorResponse>) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            error: "internal lock error".to_string(),
            duplicity: None,
        }),
    )
}

/// Route an accepted event through the injected [`KelSink`], mapping sink
/// failures onto wire responses: a conflicting event is 409 duplicity
/// evidence, a ruleset rejection is 400, a store fault is 500.
// The Err IS axum's response pair, produced once per refused submission and
// immediately returned to the framework — boxing it would add indirection on
// the same cold path the lint is trying to protect.
#[allow(clippy::result_large_err)]
fn route_into_kel_sink(
    sink: &dyn KelSink,
    prefix: &Prefix,
    event: &serde_json::Value,
    attachment: &[u8],
    event_s: u128,
    event_d: &Said,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    match sink.append_signed_event(prefix, event, attachment) {
        Ok(KelSinkOutcome::Appended) | Ok(KelSinkOutcome::AlreadyStored) => Ok(()),
        Err(KelSinkError::Conflict { existing_said }) => Err((
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                error: "duplicity detected".to_string(),
                duplicity: Some(DuplicityEvidence {
                    prefix: prefix.clone(),
                    sequence: event_s,
                    event_a_said: Said::new_unchecked(existing_said.unwrap_or_default()),
                    event_b_said: event_d.clone(),
                    witness_reports: vec![],
                }),
            }),
        )),
        Err(KelSinkError::Invalid(reason)) => Err(bad_request(format!("event rejected: {reason}"))),
        Err(KelSinkError::Storage(e)) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("KEL store failure: {e}"),
                duplicity: None,
            }),
        )),
    }
}

/// Replay the SQLite-retained KEL into a key state (sink-less servers only).
fn replay_sqlite_state(
    storage: &WitnessStorage,
    prefix: &Prefix,
) -> Result<Option<KeyState>, String> {
    let kel = storage
        .get_kel(prefix)
        .map_err(|e| format!("stored KEL read failed: {e}"))?;
    let mut state: Option<KeyState> = None;
    for event_json in kel {
        let event: Event = serde_json::from_str(&event_json)
            .map_err(|e| format!("stored event unparseable: {e}"))?;
        state = Some(
            state_after_event(state.as_ref(), &event)
                .map_err(|e| format!("stored KEL replay failed: {e}"))?,
        );
    }
    Ok(state)
}

/// Verify an envelope submission's CESR attachment signatures when no sink is
/// configured, using state replayed from the SQLite event ledger.
fn verify_wire_attachment(
    storage: &WitnessStorage,
    prefix: &Prefix,
    event_value: &serde_json::Value,
    attachment: &[u8],
) -> Result<(), String> {
    let event: Event = serde_json::from_value(event_value.clone())
        .map_err(|e| format!("event unparseable as KERI event: {e}"))?;
    let (signatures, _seals) =
        parse_delegated_attachment(attachment).map_err(|e| format!("bad CESR attachment: {e}"))?;
    if signatures.is_empty() {
        return Err("attachment carries no signatures".to_string());
    }
    let state = replay_sqlite_state(storage, prefix)?;
    let signed = SignedEvent::new(event, signatures);
    validate_signed_event(&signed, state.as_ref()).map_err(|e| e.to_string())
}

/// Typed failure from inbound event signature/key validation.
///
/// Separates **routing** faults — material we cannot even dispatch to a curve
/// (an untagged or unknown-curve `k[0]`) — from **cryptographic** faults — a
/// well-formed, curve-tagged signature that fails to verify. Collapsing the two
/// into one "invalid signature" hides which bug actually occurred and which side
/// (emitter format vs. key mismatch) must change.
#[derive(Debug, thiserror::Error)]
enum EventSignatureError {
    /// The `x` field is present but not a JSON string.
    #[error("'x' (signature) must be a string")]
    SignatureNotString,

    /// The `x` field is not valid hex.
    #[error("'x' (signature) is not valid hex: {0}")]
    SignatureNotHex(String),

    /// An inception event has no `x` signature.
    #[error("inception event missing 'x' (signature)")]
    SignatureMissing,

    /// `k` is absent or empty on an inception event.
    #[error("inception event 'k' must be a non-empty array")]
    MissingKeys,

    /// `k[0]` is present but not a JSON string.
    #[error("'k[0]' must be a string")]
    KeyNotString,

    /// Routing fault: `k[0]` is not a curve-tagged CESR verkey, so verification
    /// cannot dispatch to a curve. Byte-length guessing is deliberately refused.
    #[error(
        "'k[0]' is not a curve-tagged CESR verkey (expected `D…` Ed25519 or \
         `1AAI…`/`1AAJ…` P-256); untagged or unknown-curve keys are rejected: {0}"
    )]
    UnroutableKey(String),

    /// The event JSON is not an object (cannot build the signing payload).
    #[error("event is not a JSON object")]
    NotAnObject,

    /// The signing payload could not be serialized.
    #[error("failed to serialize signing payload: {0}")]
    PayloadSerialization(String),

    /// Cryptographic fault: a curve-tagged signature that does not verify against
    /// `k[0]` (wrong key, wrong curve, or malformed for that curve).
    #[error("inception self-signature did not verify against k[0]: {0}")]
    SelfSignatureInvalid(String),
}

/// Validate that the `x` signature field, if present, is well-formed hex.
///
/// Curve-specific length/format is **not** asserted here — the in-band curve tag
/// on `k[0]` is authoritative, and the per-curve verifier (in
/// [`verify_inception_self_signature`]) rejects a wrong-length signature. Guessing
/// the curve from `x`'s byte length is exactly the silent-correctness hazard the
/// wire-format tagging rule forbids.
fn validate_signature_format(event: &serde_json::Value) -> Result<(), EventSignatureError> {
    if let Some(sig_val) = event.get("x") {
        let sig_hex = sig_val
            .as_str()
            .ok_or(EventSignatureError::SignatureNotString)?;
        hex::decode(sig_hex).map_err(|e| EventSignatureError::SignatureNotHex(e.to_string()))?;
    }
    Ok(())
}

/// For inception events, verify the self-signature (signature over the event by `k[0]`).
///
/// Parses `k[0]` via `KeriPublicKey::parse` (CESR-aware — the workspace emits
/// curve-tagged pubkeys `D…` Ed25519 / `1AAI…`/`1AAJ…` P-256) and dispatches
/// signature verification on the parsed curve. The in-band tag is authoritative:
/// there is no byte-length fallback and no legacy raw-hex path — an untagged or
/// unknown-curve `k[0]` is a typed [`EventSignatureError::UnroutableKey`], never a
/// silently-misrouted crypto check.
fn verify_inception_self_signature(event: &serde_json::Value) -> Result<(), EventSignatureError> {
    let event_type = event.get("t").and_then(|v| v.as_str()).unwrap_or("");
    if event_type != "icp" {
        return Ok(());
    }

    let k = event
        .get("k")
        .and_then(|v| v.as_array())
        .filter(|a| !a.is_empty())
        .ok_or(EventSignatureError::MissingKeys)?;

    let k0_str = k[0].as_str().ok_or(EventSignatureError::KeyNotString)?;

    // In-band curve tag is authoritative — no byte-length dispatch, no hex fallback.
    let keri_key = auths_keri::KeriPublicKey::parse(k0_str)
        .map_err(|e| EventSignatureError::UnroutableKey(e.to_string()))?;

    let sig_hex = event
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or(EventSignatureError::SignatureMissing)?;
    let sig_bytes =
        hex::decode(sig_hex).map_err(|e| EventSignatureError::SignatureNotHex(e.to_string()))?;

    // Build the signing payload: canonical JSON with empty 'd' and 'x' fields
    let mut payload_event = event.clone();
    let obj = payload_event
        .as_object_mut()
        .ok_or(EventSignatureError::NotAnObject)?;
    obj.insert("d".to_string(), serde_json::Value::String(String::new()));
    obj.insert("x".to_string(), serde_json::Value::String(String::new()));
    let payload = serde_json::to_vec(&payload_event)
        .map_err(|e| EventSignatureError::PayloadSerialization(e.to_string()))?;

    keri_key
        .verify_signature(&payload, &sig_bytes)
        .map_err(EventSignatureError::SelfSignatureInvalid)
}

/// POST /witness/:prefix/event - Submit an event for witnessing.
///
/// Accepts either the envelope dialect (`{"event": …, "attachment_b64": …}`,
/// detached CESR signatures — what the registry lifecycle emits) or a bare
/// legacy event with an inline `x` self-signature. When a [`KelSink`] is
/// configured, accepted events are validated against the full KERI ruleset
/// and persisted to the served per-prefix KEL store *before* a receipt is
/// issued — a witness never receipts what it will not serve.
#[allow(clippy::too_many_lines)]
async fn submit_event(
    State(state): State<WitnessServerState>,
    AxumPath(prefix_str): AxumPath<String>,
    Json(body): Json<serde_json::Value>,
) -> Result<Json<SignedReceipt>, (StatusCode, Json<ErrorResponse>)> {
    let prefix = Prefix::new_unchecked(prefix_str);

    let (event, attachment) = match split_submit_body(body) {
        Ok(parts) => parts,
        Err(e) => return Err(bad_request(format!("invalid submit body: {e}"))),
    };
    let has_attachment = !attachment.is_empty();

    // Validate event structure
    if let Err(e) = validate_event_structure(&event, has_attachment) {
        return Err(bad_request(format!("invalid event structure: {}", e)));
    }

    // Verify SAID
    if let Err(e) = verify_event_said(&event) {
        return Err(bad_request(format!("SAID verification failed: {}", e)));
    }

    // Validate signature format
    if let Err(e) = validate_signature_format(&event) {
        return Err(bad_request(format!("invalid signature format: {}", e)));
    }

    // Legacy dialect only: verify the inline `x` inception self-signature.
    // Envelope submissions carry their proof in the CESR attachment, verified
    // below (sink path) or against replayed state (sink-less path).
    if !has_attachment && let Err(e) = verify_inception_self_signature(&event) {
        return Err(bad_request(format!("signature verification failed: {}", e)));
    }

    let event_d = Said::new_unchecked(
        event
            .get("d")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
    );
    // KERI sequence numbers are hex strings in the wire format; parse as u128
    // to match `KeyState.sequence` / storage field width.
    let event_s: u128 = event
        .get("s")
        .and_then(|v| v.as_str())
        .and_then(|s| u128::from_str_radix(s, 16).ok())
        .unwrap_or(0);

    // The SQLite mutex is scoped tightly: it is never held across the sink's
    // git I/O, so requests for distinct prefixes do not serialize on it.
    //
    // First-seen ordering: the ledger is CONSULTED here but only RECORDED
    // after the event passes full validation — an invalid (badly-signed)
    // submission must never poison the sequence slot the honest event needs.
    let now = (state.inner.clock)();
    let first_seen = {
        let storage = state.inner.storage.lock().map_err(|_| lock_error())?;
        storage.get_first_seen(&prefix, event_s)
    };

    match first_seen {
        Ok(Some(existing_said)) if existing_said != event_d => {
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
        Ok(_) => {
            // The write bridge: route the accepted event into the KEL store
            // the witness serves. The sink re-runs the full KERI ruleset
            // (chain, pre-rotation, attachment signatures) against git truth;
            // a rejection means no receipt is issued. Without a sink, verify
            // envelope signatures here against SQLite-replayed state.
            if let Some(sink) = &state.inner.kel_sink {
                route_into_kel_sink(
                    sink.as_ref(),
                    &prefix,
                    &event,
                    &attachment,
                    event_s,
                    &event_d,
                )?;
            } else if has_attachment {
                let storage = state.inner.storage.lock().map_err(|_| lock_error())?;
                if let Err(e) = verify_wire_attachment(&storage, &prefix, &event, &attachment) {
                    return Err(bad_request(format!(
                        "attachment signature verification failed: {e}"
                    )));
                }
            }

            // Validated - sign and store the receipt. The wire `rct` body
            // stays spec-shaped; the witness signature travels detached in the
            // `SignedReceipt` so the collector can attribute and verify it.
            let signed = state
                .create_signed_receipt(&prefix, event_s, &event_d)
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: format!("failed to create receipt: {e}"),
                            duplicity: None,
                        }),
                    )
                })?;

            // Retain the verified event body so the witness can later replay this
            // identity's KEL into the current key-state it serves. The body is
            // canonical JSON of the event we just SAID- and signature-checked.
            let event_json = serde_json::to_string(&event).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: format!("failed to serialize event for retention: {e}"),
                        duplicity: None,
                    }),
                )
            })?;

            let storage = state.inner.storage.lock().map_err(|_| lock_error())?;
            if let Err(e) = storage.record_first_seen(now, &prefix, event_s, &event_d) {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: format!("failed to record first-seen: {}", e),
                        duplicity: None,
                    }),
                ));
            }
            if let Err(e) = storage.store_receipt(now, &prefix, &signed.receipt) {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: format!("failed to store receipt: {}", e),
                        duplicity: None,
                    }),
                ));
            }
            if let Err(e) = storage.store_event(now, &prefix, event_s, &event_json) {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: format!("failed to store event: {}", e),
                        duplicity: None,
                    }),
                ));
            }

            Ok(Json(signed))
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
        Ok(Some(seq)) => Ok(Json(HeadResponse {
            prefix,
            latest_seq: Some(seq),
        })),
        // An unheld prefix has no head: 404 (absent), matching `/key-state`,
        // rather than a 200 with `latest_seq: null` a careless reader could
        // misread as "sequence 0". (product-findings 20260721-node, N1.)
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!("no head for {prefix} — this witness holds no events for it"),
                duplicity: None,
            }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("storage error: {}", e),
                duplicity: None,
            }),
        )),
    }
}

/// `GET /witness/{prefix}/said/{seq}` — the SAID this witness first saw at `seq`.
///
/// Returns 404 (a gap, not divergence) when the sequence was never observed, so a
/// monitor can distinguish "not yet seen" from "seen a conflicting SAID".
async fn get_said_at_seq(
    State(state): State<WitnessServerState>,
    AxumPath((prefix_str, seq_str)): AxumPath<(String, String)>,
) -> Result<Json<SaidAtSeqResponse>, (StatusCode, Json<ErrorResponse>)> {
    let prefix = Prefix::new_unchecked(prefix_str);
    let seq: u64 = seq_str.parse().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("seq must be a non-negative integer, got '{seq_str}'"),
                duplicity: None,
            }),
        )
    })?;

    let storage = state.inner.storage.lock().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "internal lock error".to_string(),
                duplicity: None,
            }),
        )
    })?;

    match storage.get_first_seen(&prefix, seq as u128) {
        Ok(Some(said)) => Ok(Json(SaidAtSeqResponse { prefix, seq, said })),
        Ok(None) => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!(
                    "no event seen for prefix {} at seq {}",
                    prefix.as_str(),
                    seq
                ),
                duplicity: None,
            }),
        )),
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

/// `GET /witness/{prefix}/key-state` — the current key-state notice for `prefix`.
///
/// Replays the KEL this witness has corroborated for `prefix` into its current
/// key-state and serves it as a **KERI-conformant key-state record**
/// (`{vn,i,s,p,d,f,dt,et,kt,k,nt,n,bt,b,c,ee,di}`) — the wire shape a keripy /
/// keriox peer reads. A thin client can trust this identity's current keys
/// without replaying the whole log itself.
///
/// The notice describes exactly the history *this* witness saw: the record is
/// built only from retained, signature-verified events, never asserted. Returns
/// 404 when the witness has corroborated no events for the prefix (it cannot
/// notice a key-state it never observed), and 500 if a retained KEL fails to
/// replay (a corrupted store — surfaced, never papered over).
async fn get_key_state(
    State(state): State<WitnessServerState>,
    AxumPath(prefix_str): AxumPath<String>,
) -> Result<Json<KeyStateRecord>, (StatusCode, Json<ErrorResponse>)> {
    let prefix = Prefix::new_unchecked(prefix_str);

    let kel_json = {
        let storage = state.inner.storage.lock().map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "internal lock error".to_string(),
                    duplicity: None,
                }),
            )
        })?;
        storage.get_kel(&prefix).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("storage error: {e}"),
                    duplicity: None,
                }),
            )
        })?
    };

    if kel_json.is_empty() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: format!(
                    "no key-state for {} — this witness has corroborated no events for it",
                    prefix.as_str()
                ),
                duplicity: None,
            }),
        ));
    }

    // Each row is one canonical event; assemble the in-order KEL as a JSON array
    // and replay it through the platform's own validation, never a hand-rolled
    // parser — the key-state and the notice wire shape are the trust kernel's.
    let kel_array = format!("[{}]", kel_json.join(","));
    let events = parse_kel_json(&kel_array).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("retained KEL did not parse: {e}"),
                duplicity: None,
            }),
        )
    })?;
    let key_state = TrustedKel::from_trusted_source(&events)
        .replay()
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("retained KEL did not replay: {e}"),
                    duplicity: None,
                }),
            )
        })?;

    let dt = (state.inner.clock)().to_rfc3339();
    let record = KeyStateRecord::from_kel(&events, &key_state, dt).ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            error: "retained KEL is empty after replay".to_string(),
            duplicity: None,
        }),
    ))?;

    Ok(Json(record))
}

/// `GET /build` — the node's proof of which binary it runs.
///
/// Serves the [`BuildProof`] the binary measured of itself and was signed
/// against: version, self-measured running digest, and the verbatim signed
/// attestation. The server interprets none of it — a relying party decides,
/// from these bytes alone, whether the attestation's signature holds AND
/// attests this exact running digest. 404 when the node was started without a
/// build attestation: a node that cannot prove its binary says so plainly,
/// rather than serving an unprovable green.
async fn get_build(
    State(state): State<WitnessServerState>,
) -> Result<Json<BuildProof>, (StatusCode, Json<ErrorResponse>)> {
    match &state.inner.build_proof {
        Some(proof) => Ok(Json(proof.clone())),
        None => Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "this node was started without a build attestation — \
                        it cannot prove which binary it runs"
                    .to_string(),
                duplicity: None,
            }),
        )),
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
    fn make_valid_icp_event(prefix: &str, seq: u128) -> serde_json::Value {
        let (pkcs8, _pk_hex) = test_keypair();
        let kp = Ed25519KeyPair::from_pkcs8(&pkcs8).unwrap();
        // k[0] is the curve-tagged CESR verkey (`D…`), as production emitters use.
        let k0 = auths_keri::KeriPublicKey::ed25519(kp.public_key().as_ref())
            .unwrap()
            .to_qb64()
            .unwrap();

        // Build event with empty d and x for SAID computation
        let mut event = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": prefix,
            "s": seq,
            "k": [k0],
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

    /// Build a full, replay-able KERI inception event — every establishment field
    /// present (`kt,k,nt,n,bt,b,c,a`), `s` as a lowercase-hex string, a valid
    /// Ed25519 self-signature, and the auths-computed SAID. Unlike the minimal
    /// [`make_valid_icp_event`], this is a complete KEL the witness can replay
    /// into key-state — the shape a real controller submits.
    fn make_full_icp_event() -> serde_json::Value {
        let (pkcs8, _pk_hex) = test_keypair();
        let kp = Ed25519KeyPair::from_pkcs8(&pkcs8).unwrap();
        let k0 = auths_keri::KeriPublicKey::ed25519(kp.public_key().as_ref())
            .unwrap()
            .to_qb64()
            .unwrap();
        // A next-key commitment (a single-key kt=1/nt=1 inception).
        let next = auths_keri::KeriPublicKey::ed25519(&[9u8; 32]).unwrap();
        let ncommit = auths_keri::compute_next_commitment(&next);

        // Self-addressing inception: prefix is blanked during SAID computation,
        // then set equal to the SAID. Build with empty d/i and x.
        let mut event = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": "",
            "s": "0",
            "kt": "1",
            "k": [k0],
            "nt": "1",
            "n": [ncommit.as_str()],
            "bt": "0",
            "b": [],
            "c": [],
            "a": [],
            "x": ""
        });

        // The SAID self-addresses the inception (d and i both blanked during the
        // digest), so set i = d = SAID first.
        let said = crate::crypto::said::compute_said(&event).unwrap();
        let said_str = said.into_inner();
        event["d"] = serde_json::Value::String(said_str.clone());
        event["i"] = serde_json::Value::String(said_str);

        // Sign exactly what the witness verifies: the event with d and x blanked,
        // i left at the self-addressed prefix.
        let mut to_sign = event.clone();
        to_sign["d"] = serde_json::Value::String(String::new());
        to_sign["x"] = serde_json::Value::String(String::new());
        let payload = serde_json::to_vec(&to_sign).unwrap();
        let sig = kp.sign(&payload);
        event["x"] = serde_json::Value::String(hex::encode(sig.as_ref()));

        event
    }

    /// Submit `event` to a fresh server and return its (router, prefix).
    async fn submit_to_fresh_server(event: &serde_json::Value) -> (Router, String) {
        let prefix = event["i"].as_str().unwrap().to_string();
        let state = test_state();
        let app = router(state);
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(format!("/witness/{prefix}/event"))
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(event).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "full icp must be witnessed");
        (app, prefix)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn key_state_serves_keri_conformant_record() {
        let event = make_full_icp_event();
        let (app, prefix) = submit_to_fresh_server(&event).await;

        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/witness/{prefix}/key-state"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let record: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let obj = record.as_object().unwrap();

        // The KERI ksn wire shape — labels and field order — not the auths envelope.
        let keys: Vec<&str> = obj.keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            vec![
                "vn", "i", "s", "p", "d", "f", "dt", "et", "kt", "k", "nt", "n", "bt", "b", "c",
                "ee", "di"
            ]
        );
        assert_eq!(obj["vn"], serde_json::json!([1, 0]));
        assert_eq!(obj["i"], serde_json::Value::String(prefix.clone()));
        assert_eq!(obj["s"], "0");
        assert_eq!(obj["et"], "icp");
        assert_eq!(obj["d"], serde_json::Value::String(prefix));

        // The served record projects back to a usable key-state (parse-don't-validate).
        let parsed: auths_keri::KeyStateRecord = serde_json::from_slice(&body).unwrap();
        let state = parsed.into_key_state();
        assert_eq!(state.sequence, 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn key_state_unknown_prefix_is_404() {
        let app = router(test_state());
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/witness/ENeverWitnessed/key-state")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
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
    async fn build_endpoint_absent_without_a_proof_is_404() {
        // A node started without a build attestation must NOT serve a `/build`
        // surface — it says plainly it cannot prove its binary (404), never an
        // unprovable green.
        let state = test_state();
        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/build")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn build_endpoint_serves_the_configured_proof() {
        // With a proof configured, `/build` serves exactly the self-measurement
        // and signed attestation the binary handed in — verbatim, uninterpreted.
        let mut state = test_state();
        let proof = BuildProof {
            version: "1.2.3".to_string(),
            running_digest: "abc123".to_string(),
            attestation: serde_json::json!({"issuer": "did:key:zTest"}),
        };
        // Replace the inner with one carrying the proof (the only field that
        // differs from `test_state`'s default).
        let inner = Arc::get_mut(&mut state.inner).expect("sole owner in test");
        inner.build_proof = Some(proof.clone());

        let app = router(state);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/build")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let served: BuildProof = serde_json::from_slice(&body).unwrap();
        assert_eq!(served.version, "1.2.3");
        assert_eq!(served.running_digest, "abc123");
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
    async fn server_signs_receipt() {
        let state = test_state();
        let app = router(state.clone());

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

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let signed: SignedReceipt =
            serde_json::from_slice(&body).expect("witness response must be a SignedReceipt");

        assert!(
            !signed.signature.is_empty(),
            "witness must attach a signature"
        );

        // The signature must verify against the witness's own key.
        let key = auths_keri::KeriPublicKey::from_verkey_bytes(&state.public_key(), state.curve())
            .unwrap();
        let payload = serde_json::to_vec(&signed.receipt).unwrap();
        assert!(
            key.verify_signature(&payload, &signed.signature).is_ok(),
            "witness signature must verify against its advertised key"
        );
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

        let (pkcs8, _) = test_keypair();
        let kp = Ed25519KeyPair::from_pkcs8(&pkcs8).unwrap();
        // Correct, curve-tagged k[0] — so verification reaches the signature check.
        let k0 = auths_keri::KeriPublicKey::ed25519(kp.public_key().as_ref())
            .unwrap()
            .to_qb64()
            .unwrap();
        // Use a different keypair to produce a wrong signature.
        let (wrong_pkcs8, _) = test_keypair();
        let wrong_kp = Ed25519KeyPair::from_pkcs8(&wrong_pkcs8).unwrap();

        let mut event = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": "EPrefix",
            "s": 0,
            "k": [k0],
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

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
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

    #[tokio::test(flavor = "multi_thread")]
    async fn said_at_seq_returns_first_seen() {
        let state = test_state();
        let app = router(state);
        let event = make_valid_icp_event("EPrefix", 0);

        let submit = app
            .clone()
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
        assert_eq!(submit.status(), StatusCode::OK);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/witness/EPrefix/said/0")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn said_at_seq_unseen_is_404() {
        let app = router(test_state());
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/witness/EUnseen/said/0")
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
    fn ed25519_inception_self_signature_accepted() {
        // make_valid_icp_event now emits a curve-tagged `D…` k[0].
        let event = make_valid_icp_event("EPrefix", 0);
        assert!(verify_inception_self_signature(&event).is_ok());
    }

    #[test]
    fn p256_inception_self_signature_accepted() {
        use p256::ecdsa::{Signature, SigningKey, signature::Signer};

        let sk = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let compressed = sk
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        let k0 = auths_keri::KeriPublicKey::from_verkey_bytes(&compressed, CurveType::P256)
            .unwrap()
            .to_qb64()
            .unwrap();

        let mut event = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": "EPrefix",
            "s": 0,
            "k": [k0],
            "x": ""
        });
        // Sign the canonical payload (d and x already empty), matching the verifier.
        let payload = serde_json::to_vec(&event).unwrap();
        let sig: Signature = sk.sign(&payload);
        event["x"] = serde_json::Value::String(hex::encode(sig.to_bytes()));

        assert!(
            verify_inception_self_signature(&event).is_ok(),
            "P-256 inception with a valid self-signature must be accepted"
        );
    }

    #[test]
    fn untagged_hex_key_rejected_as_unroutable() {
        // A raw 32-byte hex k[0] (no curve tag) must be a routing error, NOT a
        // crypto failure — the legacy length-dispatched fallback is gone.
        let (_, pk_hex) = test_keypair();
        let event = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "",
            "i": "EPrefix",
            "s": 0,
            "k": [pk_hex],
            "x": hex::encode([0u8; 64])
        });

        let err = verify_inception_self_signature(&event).unwrap_err();
        assert!(
            matches!(err, EventSignatureError::UnroutableKey(_)),
            "untagged key must surface as a typed routing error, got: {err:?}"
        );
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
        assert!(validate_event_structure(&event, false).is_err());
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
        assert!(validate_event_structure(&event, false).is_err());
    }

    #[test]
    fn validate_structure_icp_attachment_dialect_needs_no_x() {
        let event = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "icp",
            "d": "E123",
            "i": "EPrefix",
            "s": "0",
            "k": ["DKey"]
        });
        assert!(validate_event_structure(&event, true).is_ok());
        assert!(validate_event_structure(&event, false).is_err());
    }

    #[test]
    fn validate_structure_seal_bound_enforced() {
        let seals: Vec<serde_json::Value> = (0..=MAX_SEALS_PER_EVENT)
            .map(|i| serde_json::json!({"d": format!("E{i}")}))
            .collect();
        let event = serde_json::json!({
            "v": "KERI10JSON000000_",
            "t": "ixn",
            "d": "E123",
            "i": "EPrefix",
            "s": "1",
            "p": "E122",
            "a": seals
        });
        assert!(validate_event_structure(&event, true).is_err());
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
        assert!(validate_event_structure(&event, false).is_err());
    }
}
