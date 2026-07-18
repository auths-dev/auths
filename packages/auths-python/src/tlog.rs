//! Transparency-log bindings: append an artifact digest to a local tile log,
//! emit offline inclusion evidence, and re-verify that evidence against a
//! pinned log key — all thin wrappers over `auths_sdk::workflows::transparency`
//! and the `auths_verifier` offline inclusion check.

use std::path::PathBuf;

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

use auths_sdk::workflows::transparency::{
    TransparencyWorkflowError, append_artifact_digest, prove_artifact_digest,
};
use auths_verifier::Ed25519PublicKey;
use auths_verifier::evidence_pack::{TransparencyInclusion, verify_artifact_log_inclusion};

use crate::runtime::runtime;

/// Result of appending an artifact digest to a local transparency log.
#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyLogAppendResult {
    /// Canonical `sha256:<hex>` digest that was logged.
    #[pyo3(get)]
    pub artifact_digest: String,
    /// Hex-encoded Merkle leaf hash the digest was stored under.
    #[pyo3(get)]
    pub leaf_hash: String,
    /// Zero-based index the leaf was sequenced at.
    #[pyo3(get)]
    pub index: u64,
    /// Tree size of the checkpoint that now includes the leaf.
    #[pyo3(get)]
    pub size: u64,
    /// Hex-encoded Merkle root of that checkpoint.
    #[pyo3(get)]
    pub root: String,
    /// The log's origin line.
    #[pyo3(get)]
    pub origin: String,
    /// Hex-encoded Ed25519 public key the checkpoint is signed with — pin this
    /// to verify the evidence `log_prove` mints.
    #[pyo3(get)]
    pub log_public_key: String,
    /// The full signed checkpoint, JSON-serialized.
    #[pyo3(get)]
    pub checkpoint_json: String,
}

#[pymethods]
impl PyLogAppendResult {
    fn __repr__(&self) -> String {
        format!(
            "LogAppendResult(index={}, size={}, origin={:?})",
            self.index, self.size, self.origin
        )
    }
}

/// Map a transparency workflow error onto a tagged Python exception.
fn map_tlog_err(e: TransparencyWorkflowError) -> PyErr {
    match e {
        TransparencyWorkflowError::InvalidInput(m) => {
            PyValueError::new_err(format!("[AUTHS_INVALID_INPUT] {m}"))
        }
        TransparencyWorkflowError::LogNotFound(p) => PyRuntimeError::new_err(format!(
            "[AUTHS_LOG_NOT_FOUND] no transparency log at {}",
            p.display()
        )),
        other => PyRuntimeError::new_err(format!("[AUTHS_TRANSPARENCY_ERROR] {other}")),
    }
}

/// Append an artifact digest to a local tile-backed transparency log.
///
/// Creates the log directory and its signing key on first use. The log is
/// append-only, so repeated calls grow the tree and return increasing indices.
///
/// Args:
/// * `artifact_digest`: The digest to log (`sha256:<64 hex>`).
/// * `log_dir`: Directory holding the tile store and `log.key`.
/// * `origin`: The log's origin line, written into every checkpoint.
///
/// Usage:
/// ```ignore
/// let r = log_append(py, "sha256:ab…".into(), "/tmp/log".into(), "acme.dev/releases")?;
/// println!("appended at index {}", r.index);
/// ```
#[pyfunction]
#[pyo3(signature = (artifact_digest, log_dir, origin="auths.local/log"))]
pub fn log_append(
    _py: Python<'_>,
    artifact_digest: String,
    log_dir: PathBuf,
    origin: &str,
) -> PyResult<PyLogAppendResult> {
    #[allow(clippy::disallowed_methods)] // FFI is the presentation boundary (checkpoint timestamp)
    let now = chrono::Utc::now();
    let appended = runtime()
        .block_on(append_artifact_digest(
            &log_dir,
            origin,
            &artifact_digest,
            now,
        ))
        .map_err(map_tlog_err)?;

    let checkpoint = &appended.signed_checkpoint.checkpoint;
    let checkpoint_json = serde_json::to_string(&appended.signed_checkpoint)
        .map_err(|e| PyRuntimeError::new_err(format!("failed to serialize checkpoint: {e}")))?;

    Ok(PyLogAppendResult {
        artifact_digest: appended.artifact_digest,
        leaf_hash: hex::encode(appended.leaf_hash.as_bytes()),
        index: appended.index,
        size: checkpoint.size,
        root: hex::encode(checkpoint.root.as_bytes()),
        origin: checkpoint.origin.to_string(),
        log_public_key: hex::encode(appended.signed_checkpoint.log_public_key.as_bytes()),
        checkpoint_json,
    })
}

/// Emit offline inclusion evidence (JSON) for an already-appended artifact
/// digest. The returned string is a serialized `TransparencyInclusion` that
/// `log_verify_inclusion` (or any auths verifier) can check with zero network.
///
/// Args:
/// * `artifact_digest`: The digest to prove (`sha256:<64 hex>`).
/// * `log_dir`: Directory holding the tile store and `log.key`.
/// * `origin`: The log's origin line (must match the appended log).
///
/// Usage:
/// ```ignore
/// let evidence = log_prove(py, "sha256:ab…".into(), "/tmp/log".into(), "acme.dev/releases")?;
/// ```
#[pyfunction]
#[pyo3(signature = (artifact_digest, log_dir, origin="auths.local/log"))]
pub fn log_prove(
    _py: Python<'_>,
    artifact_digest: String,
    log_dir: PathBuf,
    origin: &str,
) -> PyResult<String> {
    let inclusion = runtime()
        .block_on(prove_artifact_digest(&log_dir, origin, &artifact_digest))
        .map_err(map_tlog_err)?;
    serde_json::to_string(&inclusion).map_err(|e| {
        PyRuntimeError::new_err(format!("failed to serialize inclusion evidence: {e}"))
    })
}

/// Verify, fully offline, that inclusion evidence anchors an artifact digest in
/// a log operated by the **pinned** key.
///
/// Three fail-closed checks: the evidence binds to this artifact (its leaf
/// re-derives from the digest), the Merkle proof verifies against the embedded
/// signed checkpoint, and that checkpoint is signed by the pinned log key. A
/// forged, absent, or mismatched proof raises `ValueError`.
///
/// Args:
/// * `evidence_json`: The serialized inclusion evidence from `log_prove`.
/// * `artifact_digest`: The canonical `sha256:<hex>` digest the leaf must match.
/// * `log_public_key`: Hex-encoded Ed25519 key the checkpoint must be signed by.
///
/// Usage:
/// ```ignore
/// log_verify_inclusion(py, evidence, "sha256:ab…".into(), key_hex)?; // True or raises
/// ```
#[pyfunction]
pub fn log_verify_inclusion(
    _py: Python<'_>,
    evidence_json: String,
    artifact_digest: String,
    log_public_key: String,
) -> PyResult<bool> {
    let inclusion: TransparencyInclusion = serde_json::from_str(&evidence_json)
        .map_err(|e| PyValueError::new_err(format!("invalid inclusion evidence JSON: {e}")))?;

    let key_bytes: [u8; 32] = hex::decode(&log_public_key)
        .map_err(|e| PyValueError::new_err(format!("invalid log public key hex: {e}")))?
        .try_into()
        .map_err(|_| PyValueError::new_err("log public key must be 32 bytes"))?;
    let pinned = Ed25519PublicKey::from_bytes(key_bytes);

    verify_artifact_log_inclusion(&artifact_digest, &inclusion, &pinned)
        .map_err(|e| PyValueError::new_err(format!("[AUTHS_INCLUSION_UNVERIFIED] {e}")))?;
    Ok(true)
}
