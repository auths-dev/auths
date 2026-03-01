//! Python bindings for auths-verifier using PyO3

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

use ::auths_verifier::core::{Attestation, MAX_ATTESTATION_JSON_SIZE, MAX_JSON_BATCH_SIZE};
use ::auths_verifier::types::{
    ChainLink as RustChainLink,
    DeviceDID,
    VerificationReport as RustVerificationReport,
    VerificationStatus as RustVerificationStatus,
};
use ::auths_verifier::verify::{
    verify_chain as rust_verify_chain,
    verify_device_authorization as rust_verify_device_authorization,
    verify_with_keys,
};

/// Result of a single attestation verification
#[pyclass]
#[derive(Clone)]
pub struct VerificationResult {
    #[pyo3(get)]
    pub valid: bool,
    #[pyo3(get)]
    pub error: Option<String>,
}

#[pymethods]
impl VerificationResult {
    fn __repr__(&self) -> String {
        if self.valid {
            "VerificationResult(valid=True)".to_string()
        } else {
            format!(
                "VerificationResult(valid=False, error={:?})",
                self.error.as_deref().unwrap_or("None")
            )
        }
    }

    fn __bool__(&self) -> bool {
        self.valid
    }
}

/// Status of a verification operation
#[pyclass]
#[derive(Clone)]
pub struct VerificationStatus {
    #[pyo3(get)]
    pub status_type: String,
    #[pyo3(get)]
    pub at: Option<String>,
    #[pyo3(get)]
    pub step: Option<usize>,
    #[pyo3(get)]
    pub missing_link: Option<String>,
    // Fields for InsufficientWitnesses variant — None for all other variants.
    // Added when auths-verifier gained witness quorum support; the Python struct
    // must carry these so callers can read required/verified counts without
    // parsing the status_type string.
    #[pyo3(get)]
    pub required: Option<usize>,
    #[pyo3(get)]
    pub verified: Option<usize>,
}

#[pymethods]
impl VerificationStatus {
    fn __repr__(&self) -> String {
        format!("VerificationStatus(type='{}')", self.status_type)
    }

    fn is_valid(&self) -> bool {
        self.status_type == "Valid"
    }
}

impl From<RustVerificationStatus> for VerificationStatus {
    fn from(status: RustVerificationStatus) -> Self {
        match status {
            RustVerificationStatus::Valid => VerificationStatus {
                status_type: "Valid".to_string(),
                at: None,
                step: None,
                missing_link: None,
                required: None,
                verified: None,
            },
            RustVerificationStatus::Expired { at } => VerificationStatus {
                status_type: "Expired".to_string(),
                at: Some(at.to_rfc3339()),
                step: None,
                missing_link: None,
                required: None,
                verified: None,
            },
            RustVerificationStatus::Revoked { at } => VerificationStatus {
                status_type: "Revoked".to_string(),
                at: at.map(|t| t.to_rfc3339()),
                step: None,
                missing_link: None,
                required: None,
                verified: None,
            },
            RustVerificationStatus::InvalidSignature { step } => VerificationStatus {
                status_type: "InvalidSignature".to_string(),
                at: None,
                step: Some(step),
                missing_link: None,
                required: None,
                verified: None,
            },
            RustVerificationStatus::BrokenChain { missing_link } => VerificationStatus {
                status_type: "BrokenChain".to_string(),
                at: None,
                step: None,
                missing_link: Some(missing_link),
                required: None,
                verified: None,
            },
            // Added when auths-verifier gained witness quorum support (rc.6).
            // The match was non-exhaustive until this arm was added; required
            // and verified are exposed directly so Python callers don't need to
            // parse status_type to know how many witnesses were needed/seen.
            RustVerificationStatus::InsufficientWitnesses { required, verified } => {
                VerificationStatus {
                    status_type: "InsufficientWitnesses".to_string(),
                    at: None,
                    step: None,
                    missing_link: None,
                    required: Some(required),
                    verified: Some(verified),
                }
            }
        }
    }
}

/// A single link in the attestation chain
#[pyclass]
#[derive(Clone)]
pub struct ChainLink {
    #[pyo3(get)]
    pub issuer: String,
    #[pyo3(get)]
    pub subject: String,
    #[pyo3(get)]
    pub valid: bool,
    #[pyo3(get)]
    pub error: Option<String>,
}

#[pymethods]
impl ChainLink {
    fn __repr__(&self) -> String {
        format!(
            "ChainLink(issuer='{}', subject='{}', valid={})",
            self.issuer, self.subject, self.valid
        )
    }
}

impl From<RustChainLink> for ChainLink {
    fn from(link: RustChainLink) -> Self {
        ChainLink {
            issuer: link.issuer,
            subject: link.subject,
            valid: link.valid,
            error: link.error,
        }
    }
}

/// Complete verification report for chain verification
#[pyclass]
#[derive(Clone)]
pub struct VerificationReport {
    #[pyo3(get)]
    pub status: VerificationStatus,
    #[pyo3(get)]
    pub chain: Vec<ChainLink>,
    #[pyo3(get)]
    pub warnings: Vec<String>,
}

#[pymethods]
impl VerificationReport {
    fn __repr__(&self) -> String {
        format!(
            "VerificationReport(status={}, chain_length={})",
            self.status.status_type,
            self.chain.len()
        )
    }

    fn is_valid(&self) -> bool {
        self.status.is_valid()
    }
}

impl From<RustVerificationReport> for VerificationReport {
    fn from(report: RustVerificationReport) -> Self {
        VerificationReport {
            status: report.status.into(),
            chain: report.chain.into_iter().map(|l| l.into()).collect(),
            warnings: report.warnings,
        }
    }
}

/// Verify a single attestation against an issuer's public key.
///
/// Args:
///     attestation_json: The attestation as a JSON string
///     issuer_pk_hex: The issuer's Ed25519 public key in hex format (64 chars)
///
/// Returns:
///     VerificationResult with valid flag and optional error message
///
/// Example:
///     >>> result = verify_attestation(json_str, public_key_hex)
///     >>> if result.valid:
///     ...     print("Attestation is valid!")
///     >>> else:
///     ...     print(f"Invalid: {result.error}")
#[pyfunction]
pub fn verify_attestation(attestation_json: &str, issuer_pk_hex: &str) -> PyResult<VerificationResult> {
    if attestation_json.len() > MAX_ATTESTATION_JSON_SIZE {
        return Err(PyValueError::new_err(format!(
            "Attestation JSON too large: {} bytes, max {}",
            attestation_json.len(), MAX_ATTESTATION_JSON_SIZE
        )));
    }

    // Decode hex
    let issuer_pk_bytes = hex::decode(issuer_pk_hex)
        .map_err(|e| PyValueError::new_err(format!("Invalid issuer public key hex: {}", e)))?;

    if issuer_pk_bytes.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "Invalid issuer public key length: expected 32 bytes (64 hex chars), got {}",
            issuer_pk_bytes.len()
        )));
    }

    // Parse attestation
    let att: Attestation = serde_json::from_str(attestation_json)
        .map_err(|e| PyValueError::new_err(format!("Failed to parse attestation JSON: {}", e)))?;

    // Verify (async → sync bridge for Python FFI)
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| PyRuntimeError::new_err(format!("Failed to create runtime: {}", e)))?;
    match rt.block_on(verify_with_keys(&att, &issuer_pk_bytes)) {
        Ok(_verified) => Ok(VerificationResult {
            valid: true,
            error: None,
        }),
        Err(e) => Ok(VerificationResult {
            valid: false,
            error: Some(e.to_string()),
        }),
    }
}

/// Verify a chain of attestations from a root identity to a leaf device.
///
/// Args:
///     attestations_json: List of attestation JSON strings
///     root_pk_hex: The root identity's Ed25519 public key in hex format
///
/// Returns:
///     VerificationReport with status, chain details, and warnings
///
/// Example:
///     >>> report = verify_chain([att1_json, att2_json], root_pk_hex)
///     >>> if report.is_valid():
///     ...     print("Chain verified!")
///     >>> else:
///     ...     print(f"Chain invalid: {report.status.status_type}")
#[pyfunction]
pub fn verify_chain(attestations_json: Vec<String>, root_pk_hex: &str) -> PyResult<VerificationReport> {
    let total: usize = attestations_json.iter().map(|s| s.len()).sum();
    if total > MAX_JSON_BATCH_SIZE {
        return Err(PyValueError::new_err(format!(
            "Total attestation JSON too large: {} bytes, max {}",
            total, MAX_JSON_BATCH_SIZE
        )));
    }

    // Decode hex
    let root_pk_bytes = hex::decode(root_pk_hex)
        .map_err(|e| PyValueError::new_err(format!("Invalid root public key hex: {}", e)))?;

    if root_pk_bytes.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "Invalid root public key length: expected 32 bytes (64 hex chars), got {}",
            root_pk_bytes.len()
        )));
    }

    // Parse attestations
    let attestations: Vec<Attestation> = attestations_json
        .iter()
        .enumerate()
        .map(|(i, json)| {
            serde_json::from_str(json)
                .map_err(|e| PyValueError::new_err(format!("Failed to parse attestation {}: {}", i, e)))
        })
        .collect::<PyResult<Vec<_>>>()?;

    // Verify chain (async → sync bridge for Python FFI)
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| PyRuntimeError::new_err(format!("Failed to create runtime: {}", e)))?;
    match rt.block_on(rust_verify_chain(&attestations, &root_pk_bytes)) {
        Ok(report) => Ok(report.into()),
        Err(e) => Err(PyRuntimeError::new_err(format!("Chain verification failed: {}", e))),
    }
}

/// Full cryptographic verification that a device is authorized.
///
/// Unlike `is_device_listed()`, this function verifies cryptographic signatures
/// to ensure attestations have not been forged or tampered with.
///
/// Args:
///     identity_did: The identity DID string
///     device_did: The device DID string
///     attestations_json: List of attestation JSON strings
///     identity_pk_hex: The identity's Ed25519 public key in hex format (64 chars)
///
/// Returns:
///     VerificationReport with verification details
///
/// Example:
///     >>> report = verify_device_authorization(
///     ...     "did:key:z6Mk...",
///     ...     "did:key:z6MK...",
///     ...     attestation_jsons,
///     ...     identity_pk_hex
///     ... )
///     >>> if report.is_valid():
///     ...     print("Device is cryptographically authorized!")
#[pyfunction]
pub fn verify_device_authorization(
    identity_did: &str,
    device_did: &str,
    attestations_json: Vec<String>,
    identity_pk_hex: &str,
) -> PyResult<VerificationReport> {
    let total: usize = attestations_json.iter().map(|s| s.len()).sum();
    if total > MAX_JSON_BATCH_SIZE {
        return Err(PyValueError::new_err(format!(
            "Total attestation JSON too large: {} bytes, max {}",
            total, MAX_JSON_BATCH_SIZE
        )));
    }

    // Decode hex
    let identity_pk_bytes = hex::decode(identity_pk_hex)
        .map_err(|e| PyValueError::new_err(format!("Invalid identity public key hex: {}", e)))?;

    if identity_pk_bytes.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "Invalid identity public key length: expected 32 bytes (64 hex chars), got {}",
            identity_pk_bytes.len()
        )));
    }

    // Parse attestations
    let attestations: Vec<Attestation> = attestations_json
        .iter()
        .enumerate()
        .map(|(i, json)| {
            serde_json::from_str(json)
                .map_err(|e| PyValueError::new_err(format!("Failed to parse attestation {}: {}", i, e)))
        })
        .collect::<PyResult<Vec<_>>>()?;

    let device = DeviceDID::new(device_did);

    // Verify (async → sync bridge for Python FFI)
    let rt = tokio::runtime::Runtime::new()
        .map_err(|e| PyRuntimeError::new_err(format!("Failed to create runtime: {}", e)))?;
    match rt.block_on(rust_verify_device_authorization(identity_did, &device, &attestations, &identity_pk_bytes)) {
        Ok(report) => Ok(report.into()),
        Err(e) => Err(PyRuntimeError::new_err(format!("Device authorization verification failed: {}", e))),
    }
}

/// Sign arbitrary bytes with an Ed25519 private key.
///
/// Args:
///     private_key_hex: Ed25519 seed (private key) as hex string (64 chars = 32 bytes)
///     message: The bytes to sign
///
/// Returns:
///     Hex-encoded Ed25519 signature (128 chars = 64 bytes)
///
/// Raises:
///     ValueError: If the private key hex is invalid or wrong length
///     RuntimeError: If signing fails
///
/// Example:
///     >>> sig = sign_bytes(private_key_hex, b"hello")
///     >>> assert len(sig) == 128
///
/// Security Note:
///     Python strings are immutable and not zeroizable. For production use,
///     consider storing keys in a secure enclave or secret manager rather
///     than passing them as hex strings.
#[pyfunction]
pub fn sign_bytes(private_key_hex: &str, message: &[u8]) -> PyResult<String> {
    let seed = hex::decode(private_key_hex)
        .map_err(|e| PyValueError::new_err(format!("Invalid private key hex: {}", e)))?;

    if seed.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "Invalid private key length: expected 32 bytes (64 hex chars), got {}",
            seed.len()
        )));
    }

    let keypair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed)
        .map_err(|e| PyRuntimeError::new_err(format!("Failed to create keypair: {}", e)))?;

    let sig = keypair.sign(message);
    Ok(hex::encode(sig.as_ref()))
}

/// Sign an action envelope per the Auths action envelope specification.
///
/// Builds a signed JSON envelope with fields: version, type, identity, payload,
/// timestamp, signature. The signing input is the JSON Canonicalization (RFC 8785)
/// of all fields except `signature`.
///
/// Args:
///     private_key_hex: Ed25519 seed as hex string (64 chars = 32 bytes)
///     action_type: Application-defined action type (e.g. "tool_call", "api_request")
///     payload_json: JSON string for the payload field
///     identity_did: Signer's identity DID (e.g. "did:keri:E...")
///
/// Returns:
///     JSON string of the complete signed envelope
///
/// Raises:
///     ValueError: If the private key hex or payload JSON is invalid
///     RuntimeError: If signing or canonicalization fails
///
/// Example:
///     >>> envelope = sign_action(
///     ...     private_key_hex,
///     ...     "tool_call",
///     ...     '{"tool": "read_file", "path": "/etc/config.json"}',
///     ...     "did:keri:EBf7Y2p..."
///     ... )
#[pyfunction]
pub fn sign_action(
    private_key_hex: &str,
    action_type: &str,
    payload_json: &str,
    identity_did: &str,
) -> PyResult<String> {
    let seed = hex::decode(private_key_hex)
        .map_err(|e| PyValueError::new_err(format!("Invalid private key hex: {}", e)))?;

    if seed.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "Invalid private key length: expected 32 bytes (64 hex chars), got {}",
            seed.len()
        )));
    }

    if payload_json.len() > MAX_ATTESTATION_JSON_SIZE {
        return Err(PyValueError::new_err(format!(
            "Payload JSON too large: {} bytes, max {}",
            payload_json.len(), MAX_ATTESTATION_JSON_SIZE
        )));
    }

    let payload: serde_json::Value = serde_json::from_str(payload_json)
        .map_err(|e| PyValueError::new_err(format!("Invalid payload JSON: {}", e)))?;

    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    // Build the signing input (all fields except signature)
    let signing_data = serde_json::json!({
        "version": "1.0",
        "type": action_type,
        "identity": identity_did,
        "payload": payload,
        "timestamp": timestamp,
    });

    let canonical = json_canon::to_string(&signing_data)
        .map_err(|e| PyRuntimeError::new_err(format!("Canonicalization failed: {}", e)))?;

    let keypair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed)
        .map_err(|e| PyRuntimeError::new_err(format!("Failed to create keypair: {}", e)))?;

    let sig = keypair.sign(canonical.as_bytes());
    let sig_hex = hex::encode(sig.as_ref());

    // Build the complete envelope
    let envelope = serde_json::json!({
        "version": "1.0",
        "type": action_type,
        "identity": identity_did,
        "payload": payload,
        "timestamp": timestamp,
        "signature": sig_hex,
    });

    serde_json::to_string(&envelope)
        .map_err(|e| PyRuntimeError::new_err(format!("Failed to serialize envelope: {}", e)))
}

/// Verify an action envelope's Ed25519 signature.
///
/// Reconstructs the canonical signing input from the envelope fields (excluding
/// `signature`), then verifies the Ed25519 signature against the provided public key.
///
/// Args:
///     envelope_json: The complete action envelope as a JSON string
///     public_key_hex: The signer's Ed25519 public key in hex format (64 chars)
///
/// Returns:
///     VerificationResult with valid flag and optional error message
///
/// Raises:
///     ValueError: If the public key hex, envelope JSON, or signature is invalid
///
/// Example:
///     >>> result = verify_action_envelope(envelope_json, public_key_hex)
///     >>> if result.valid:
///     ...     print("Action verified!")
#[pyfunction]
pub fn verify_action_envelope(
    envelope_json: &str,
    public_key_hex: &str,
) -> PyResult<VerificationResult> {
    let pk_bytes = hex::decode(public_key_hex)
        .map_err(|e| PyValueError::new_err(format!("Invalid public key hex: {}", e)))?;

    if pk_bytes.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "Invalid public key length: expected 32 bytes (64 hex chars), got {}",
            pk_bytes.len()
        )));
    }

    if envelope_json.len() > MAX_ATTESTATION_JSON_SIZE {
        return Err(PyValueError::new_err(format!(
            "Envelope JSON too large: {} bytes, max {}",
            envelope_json.len(), MAX_ATTESTATION_JSON_SIZE
        )));
    }

    let envelope: serde_json::Value = serde_json::from_str(envelope_json)
        .map_err(|e| PyValueError::new_err(format!("Invalid envelope JSON: {}", e)))?;

    // Extract and validate required fields
    let version = envelope
        .get("version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PyValueError::new_err("Missing or invalid 'version' field"))?;

    if version != "1.0" {
        return Ok(VerificationResult {
            valid: false,
            error: Some(format!("Unsupported version: {}", version)),
        });
    }

    let sig_hex = envelope
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PyValueError::new_err("Missing or invalid 'signature' field"))?;

    let sig_bytes = hex::decode(sig_hex)
        .map_err(|e| PyValueError::new_err(format!("Invalid signature hex: {}", e)))?;

    // Reconstruct signing input (all fields except signature)
    let signing_data = serde_json::json!({
        "version": envelope.get("version"),
        "type": envelope.get("type"),
        "identity": envelope.get("identity"),
        "payload": envelope.get("payload"),
        "timestamp": envelope.get("timestamp"),
    });

    let canonical = json_canon::to_string(&signing_data).map_err(|e| {
        PyRuntimeError::new_err(format!("Canonicalization failed: {}", e))
    })?;

    // Verify Ed25519 signature
    let key = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &pk_bytes);
    match key.verify(canonical.as_bytes(), &sig_bytes) {
        Ok(()) => Ok(VerificationResult {
            valid: true,
            error: None,
        }),
        Err(_) => Ok(VerificationResult {
            valid: false,
            error: Some("Ed25519 signature verification failed".to_string()),
        }),
    }
}

/// Python module definition
#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<VerificationResult>()?;
    m.add_class::<VerificationStatus>()?;
    m.add_class::<ChainLink>()?;
    m.add_class::<VerificationReport>()?;
    m.add_function(wrap_pyfunction!(verify_attestation, m)?)?;
    m.add_function(wrap_pyfunction!(verify_chain, m)?)?;
    m.add_function(wrap_pyfunction!(verify_device_authorization, m)?)?;
    m.add_function(wrap_pyfunction!(sign_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(sign_action, m)?)?;
    m.add_function(wrap_pyfunction!(verify_action_envelope, m)?)?;
    Ok(())
}
