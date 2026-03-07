use auths_verifier::core::{
    Attestation, Capability, MAX_ATTESTATION_JSON_SIZE, MAX_JSON_BATCH_SIZE,
};
use auths_verifier::types::DeviceDID;
use auths_verifier::verify::{
    verify_at_time as rust_verify_at_time, verify_chain as rust_verify_chain,
    verify_chain_with_capability as rust_verify_chain_with_capability,
    verify_chain_with_witnesses as rust_verify_chain_with_witnesses,
    verify_device_authorization as rust_verify_device_authorization,
    verify_with_capability as rust_verify_with_capability, verify_with_keys,
};
use auths_verifier::witness::{WitnessReceipt, WitnessVerifyConfig};
use chrono::{DateTime, Utc};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

use crate::runtime::runtime;
use crate::types::{VerificationReport, VerificationResult};

/// Verify a single attestation against an issuer's public key.
///
/// Args:
/// * `attestation_json`: The attestation as a JSON string.
/// * `issuer_pk_hex`: The issuer's Ed25519 public key in hex format (64 chars).
///
/// Usage:
/// ```ignore
/// let result = verify_attestation(py, "...", "abcd1234...")?;
/// ```
#[pyfunction]
pub fn verify_attestation(
    py: Python<'_>,
    attestation_json: &str,
    issuer_pk_hex: &str,
) -> PyResult<VerificationResult> {
    if attestation_json.len() > MAX_ATTESTATION_JSON_SIZE {
        return Err(PyValueError::new_err(format!(
            "Attestation JSON too large: {} bytes, max {}",
            attestation_json.len(),
            MAX_ATTESTATION_JSON_SIZE
        )));
    }

    let issuer_pk_bytes = hex::decode(issuer_pk_hex)
        .map_err(|e| PyValueError::new_err(format!("Invalid issuer public key hex: {e}")))?;

    if issuer_pk_bytes.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "Invalid issuer public key length: expected 32 bytes (64 hex chars), got {}",
            issuer_pk_bytes.len()
        )));
    }

    let att: Attestation = match serde_json::from_str(attestation_json) {
        Ok(att) => att,
        Err(e) => {
            return Ok(VerificationResult {
                valid: false,
                error: Some(format!("Failed to parse attestation JSON: {e}")),
            });
        }
    };

    py.allow_threads(
        || match runtime().block_on(verify_with_keys(&att, &issuer_pk_bytes)) {
            Ok(_) => Ok(VerificationResult {
                valid: true,
                error: None,
            }),
            Err(e) => Ok(VerificationResult {
                valid: false,
                error: Some(e.to_string()),
            }),
        },
    )
}

/// Verify a chain of attestations from a root identity to a leaf device.
///
/// Args:
/// * `attestations_json`: List of attestation JSON strings.
/// * `root_pk_hex`: The root identity's Ed25519 public key in hex format.
///
/// Usage:
/// ```ignore
/// let report = verify_chain(py, vec!["...".into()], "abcd1234...")?;
/// ```
#[pyfunction]
pub fn verify_chain(
    py: Python<'_>,
    attestations_json: Vec<String>,
    root_pk_hex: &str,
) -> PyResult<VerificationReport> {
    let total: usize = attestations_json.iter().map(|s| s.len()).sum();
    if total > MAX_JSON_BATCH_SIZE {
        return Err(PyValueError::new_err(format!(
            "Total attestation JSON too large: {total} bytes, max {MAX_JSON_BATCH_SIZE}",
        )));
    }

    let root_pk_bytes = hex::decode(root_pk_hex)
        .map_err(|e| PyValueError::new_err(format!("Invalid root public key hex: {e}")))?;

    if root_pk_bytes.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "Invalid root public key length: expected 32 bytes (64 hex chars), got {}",
            root_pk_bytes.len()
        )));
    }

    let attestations: Vec<Attestation> = attestations_json
        .iter()
        .enumerate()
        .map(|(i, json)| {
            serde_json::from_str(json)
                .map_err(|e| PyValueError::new_err(format!("Failed to parse attestation {i}: {e}")))
        })
        .collect::<PyResult<Vec<_>>>()?;

    py.allow_threads(|| {
        match runtime().block_on(rust_verify_chain(&attestations, &root_pk_bytes)) {
            Ok(report) => Ok(report.into()),
            Err(e) => Err(PyRuntimeError::new_err(format!(
                "Chain verification failed: {e}"
            ))),
        }
    })
}

/// Full cryptographic verification that a device is authorized.
///
/// Args:
/// * `identity_did`: The identity DID string.
/// * `device_did`: The device DID string.
/// * `attestations_json`: List of attestation JSON strings.
/// * `identity_pk_hex`: The identity's Ed25519 public key in hex format (64 chars).
///
/// Usage:
/// ```ignore
/// let report = verify_device_authorization(py, "did:keri:...", "did:key:...", vec![], "ab12...")?;
/// ```
#[pyfunction]
pub fn verify_device_authorization(
    py: Python<'_>,
    identity_did: &str,
    device_did: &str,
    attestations_json: Vec<String>,
    identity_pk_hex: &str,
) -> PyResult<VerificationReport> {
    let total: usize = attestations_json.iter().map(|s| s.len()).sum();
    if total > MAX_JSON_BATCH_SIZE {
        return Err(PyValueError::new_err(format!(
            "Total attestation JSON too large: {total} bytes, max {MAX_JSON_BATCH_SIZE}",
        )));
    }

    let identity_pk_bytes = hex::decode(identity_pk_hex)
        .map_err(|e| PyValueError::new_err(format!("Invalid identity public key hex: {e}")))?;

    if identity_pk_bytes.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "Invalid identity public key length: expected 32 bytes (64 hex chars), got {}",
            identity_pk_bytes.len()
        )));
    }

    let attestations: Vec<Attestation> = attestations_json
        .iter()
        .enumerate()
        .map(|(i, json)| {
            serde_json::from_str(json)
                .map_err(|e| PyValueError::new_err(format!("Failed to parse attestation {i}: {e}")))
        })
        .collect::<PyResult<Vec<_>>>()?;

    let device = DeviceDID::new(device_did);

    py.allow_threads(|| {
        match runtime().block_on(rust_verify_device_authorization(
            identity_did,
            &device,
            &attestations,
            &identity_pk_bytes,
        )) {
            Ok(report) => Ok(report.into()),
            Err(e) => Err(PyRuntimeError::new_err(format!(
                "Device authorization verification failed: {e}"
            ))),
        }
    })
}

/// Verify a single attestation and check that it grants a required capability.
///
/// Args:
/// * `attestation_json`: The attestation as a JSON string.
/// * `issuer_pk_hex`: The issuer's Ed25519 public key in hex format (64 chars).
/// * `required_capability`: The capability string that must be present.
///
/// Usage:
/// ```ignore
/// let result = verify_attestation_with_capability(py, "...", "abcd...", "sign")?;
/// ```
#[pyfunction]
pub fn verify_attestation_with_capability(
    py: Python<'_>,
    attestation_json: &str,
    issuer_pk_hex: &str,
    required_capability: &str,
) -> PyResult<VerificationResult> {
    if attestation_json.len() > MAX_ATTESTATION_JSON_SIZE {
        return Err(PyValueError::new_err(format!(
            "Attestation JSON too large: {} bytes, max {}",
            attestation_json.len(),
            MAX_ATTESTATION_JSON_SIZE
        )));
    }

    let issuer_pk_bytes = hex::decode(issuer_pk_hex)
        .map_err(|e| PyValueError::new_err(format!("Invalid issuer public key hex: {e}")))?;

    if issuer_pk_bytes.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "Invalid issuer public key length: expected 32 bytes (64 hex chars), got {}",
            issuer_pk_bytes.len()
        )));
    }

    let att: Attestation = match serde_json::from_str(attestation_json) {
        Ok(att) => att,
        Err(e) => {
            return Ok(VerificationResult {
                valid: false,
                error: Some(format!("Failed to parse attestation JSON: {e}")),
            });
        }
    };

    let cap = Capability::parse(required_capability).map_err(|e| {
        PyValueError::new_err(format!("Invalid capability '{required_capability}': {e}"))
    })?;

    py.allow_threads(|| {
        match runtime().block_on(rust_verify_with_capability(&att, &cap, &issuer_pk_bytes)) {
            Ok(_) => Ok(VerificationResult {
                valid: true,
                error: None,
            }),
            Err(e) => Ok(VerificationResult {
                valid: false,
                error: Some(e.to_string()),
            }),
        }
    })
}

/// Verify a chain of attestations and check that all grant a required capability.
///
/// Args:
/// * `attestations_json`: List of attestation JSON strings.
/// * `root_pk_hex`: The root identity's Ed25519 public key in hex format.
/// * `required_capability`: The capability string that must be present in every link.
///
/// Usage:
/// ```ignore
/// let report = verify_chain_with_capability(py, vec!["...".into()], "ab12...", "sign")?;
/// ```
#[pyfunction]
pub fn verify_chain_with_capability(
    py: Python<'_>,
    attestations_json: Vec<String>,
    root_pk_hex: &str,
    required_capability: &str,
) -> PyResult<VerificationReport> {
    let total: usize = attestations_json.iter().map(|s| s.len()).sum();
    if total > MAX_JSON_BATCH_SIZE {
        return Err(PyValueError::new_err(format!(
            "Total attestation JSON too large: {total} bytes, max {MAX_JSON_BATCH_SIZE}",
        )));
    }

    let root_pk_bytes = hex::decode(root_pk_hex)
        .map_err(|e| PyValueError::new_err(format!("Invalid root public key hex: {e}")))?;

    if root_pk_bytes.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "Invalid root public key length: expected 32 bytes (64 hex chars), got {}",
            root_pk_bytes.len()
        )));
    }

    let attestations: Vec<Attestation> = attestations_json
        .iter()
        .enumerate()
        .map(|(i, json)| {
            serde_json::from_str(json)
                .map_err(|e| PyValueError::new_err(format!("Failed to parse attestation {i}: {e}")))
        })
        .collect::<PyResult<Vec<_>>>()?;

    let cap = Capability::parse(required_capability).map_err(|e| {
        PyValueError::new_err(format!("Invalid capability '{required_capability}': {e}"))
    })?;

    py.allow_threads(|| {
        match runtime().block_on(rust_verify_chain_with_capability(
            &attestations,
            &cap,
            &root_pk_bytes,
        )) {
            Ok(report) => Ok(report.into()),
            Err(e) => Err(PyRuntimeError::new_err(format!(
                "Chain verification with capability failed: {e}"
            ))),
        }
    })
}

fn parse_rfc3339_timestamp(at_rfc3339: &str) -> PyResult<DateTime<Utc>> {
    let at: DateTime<Utc> = at_rfc3339.parse::<DateTime<Utc>>().map_err(|_| {
        if at_rfc3339.contains(' ') && !at_rfc3339.contains('T') {
            PyValueError::new_err(format!(
                "Expected RFC 3339 format like '2024-06-15T00:00:00Z', got '{at_rfc3339}'. \
                 Hint: use 'T' between date and time, and append 'Z' or a UTC offset. \
                 See https://www.rfc-editor.org/rfc/rfc3339"
            ))
        } else {
            PyValueError::new_err(format!(
                "Expected RFC 3339 format like '2024-06-15T00:00:00Z', got '{at_rfc3339}'. \
                 See https://www.rfc-editor.org/rfc/rfc3339"
            ))
        }
    })?;

    let now = Utc::now();
    let skew_tolerance = chrono::Duration::seconds(60);
    if at > now + skew_tolerance {
        return Err(PyValueError::new_err(format!(
            "Timestamp {at_rfc3339} is in the future. \
             Time-pinned verification requires a past or present timestamp."
        )));
    }

    Ok(at)
}

fn validate_attestation_key(attestation_json: &str, issuer_pk_hex: &str) -> PyResult<Vec<u8>> {
    if attestation_json.len() > MAX_ATTESTATION_JSON_SIZE {
        return Err(PyValueError::new_err(format!(
            "Attestation JSON too large: {} bytes, max {}",
            attestation_json.len(),
            MAX_ATTESTATION_JSON_SIZE
        )));
    }

    let issuer_pk_bytes = hex::decode(issuer_pk_hex)
        .map_err(|e| PyValueError::new_err(format!("Invalid issuer public key hex: {e}")))?;

    if issuer_pk_bytes.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "Invalid issuer public key length: expected 32 bytes (64 hex chars), got {}",
            issuer_pk_bytes.len()
        )));
    }

    Ok(issuer_pk_bytes)
}

/// Verify an attestation at a specific historical timestamp.
///
/// Args:
/// * `attestation_json`: The attestation as a JSON string.
/// * `issuer_pk_hex`: The issuer's Ed25519 public key in hex format (64 chars).
/// * `at_rfc3339`: RFC 3339 timestamp to verify against (e.g., "2024-06-15T00:00:00Z").
///
/// Usage:
/// ```ignore
/// let result = verify_at_time(py, "...", "abcd...", "2024-06-15T00:00:00Z")?;
/// ```
#[pyfunction]
pub fn verify_at_time(
    py: Python<'_>,
    attestation_json: &str,
    issuer_pk_hex: &str,
    at_rfc3339: &str,
) -> PyResult<VerificationResult> {
    let at = parse_rfc3339_timestamp(at_rfc3339)?;
    let issuer_pk_bytes = validate_attestation_key(attestation_json, issuer_pk_hex)?;

    let att: Attestation = match serde_json::from_str(attestation_json) {
        Ok(att) => att,
        Err(e) => {
            return Ok(VerificationResult {
                valid: false,
                error: Some(format!("Failed to parse attestation JSON: {e}")),
            });
        }
    };

    py.allow_threads(
        || match runtime().block_on(rust_verify_at_time(&att, &issuer_pk_bytes, at)) {
            Ok(_) => Ok(VerificationResult {
                valid: true,
                error: None,
            }),
            Err(e) => Ok(VerificationResult {
                valid: false,
                error: Some(e.to_string()),
            }),
        },
    )
}

/// Verify an attestation at a specific historical timestamp with capability check.
///
/// Args:
/// * `attestation_json`: The attestation as a JSON string.
/// * `issuer_pk_hex`: The issuer's Ed25519 public key in hex format (64 chars).
/// * `at_rfc3339`: RFC 3339 timestamp to verify against (e.g., "2024-06-15T00:00:00Z").
/// * `required_capability`: The capability string that must be present.
///
/// Usage:
/// ```ignore
/// let result = verify_at_time_with_capability(py, "...", "abcd...", "2024-06-15T00:00:00Z", "sign")?;
/// ```
#[pyfunction]
pub fn verify_at_time_with_capability(
    py: Python<'_>,
    attestation_json: &str,
    issuer_pk_hex: &str,
    at_rfc3339: &str,
    required_capability: &str,
) -> PyResult<VerificationResult> {
    let at = parse_rfc3339_timestamp(at_rfc3339)?;
    let issuer_pk_bytes = validate_attestation_key(attestation_json, issuer_pk_hex)?;

    let att: Attestation = match serde_json::from_str(attestation_json) {
        Ok(att) => att,
        Err(e) => {
            return Ok(VerificationResult {
                valid: false,
                error: Some(format!("Failed to parse attestation JSON: {e}")),
            });
        }
    };

    let cap = Capability::parse(required_capability).map_err(|e| {
        PyValueError::new_err(format!("Invalid capability '{required_capability}': {e}"))
    })?;

    py.allow_threads(
        || match runtime().block_on(rust_verify_at_time(&att, &issuer_pk_bytes, at)) {
            Ok(_) => {
                if att.capabilities.contains(&cap) {
                    Ok(VerificationResult {
                        valid: true,
                        error: None,
                    })
                } else {
                    Ok(VerificationResult {
                        valid: false,
                        error: Some(format!(
                            "Attestation does not grant required capability '{required_capability}'"
                        )),
                    })
                }
            }
            Err(e) => Ok(VerificationResult {
                valid: false,
                error: Some(e.to_string()),
            }),
        },
    )
}

/// Verify a chain of attestations with witness receipt quorum enforcement.
///
/// Args:
/// * `attestations_json`: List of attestation JSON strings.
/// * `root_pk_hex`: The root identity's Ed25519 public key in hex format.
/// * `receipts_json`: List of JSON-serialized witness receipt objects.
/// * `witness_keys_json`: List of JSON objects with `{"did": "...", "public_key_hex": "..."}`.
/// * `threshold`: Minimum number of valid receipts required.
///
/// Usage:
/// ```ignore
/// let report = verify_chain_with_witnesses(py, vec!["...".into()], "ab12...", vec![], vec![], 2)?;
/// ```
#[pyfunction]
pub fn verify_chain_with_witnesses(
    py: Python<'_>,
    attestations_json: Vec<String>,
    root_pk_hex: &str,
    receipts_json: Vec<String>,
    witness_keys_json: Vec<String>,
    threshold: usize,
) -> PyResult<VerificationReport> {
    let total: usize = attestations_json.iter().map(|s| s.len()).sum();
    if total > MAX_JSON_BATCH_SIZE {
        return Err(PyValueError::new_err(format!(
            "Total attestation JSON too large: {total} bytes, max {MAX_JSON_BATCH_SIZE}",
        )));
    }

    let root_pk_bytes = hex::decode(root_pk_hex)
        .map_err(|e| PyValueError::new_err(format!("Invalid root public key hex: {e}")))?;

    if root_pk_bytes.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "Invalid root public key length: expected 32 bytes (64 hex chars), got {}",
            root_pk_bytes.len()
        )));
    }

    let attestations: Vec<Attestation> = attestations_json
        .iter()
        .enumerate()
        .map(|(i, json)| {
            serde_json::from_str(json)
                .map_err(|e| PyValueError::new_err(format!("Failed to parse attestation {i}: {e}")))
        })
        .collect::<PyResult<Vec<_>>>()?;

    let receipts: Vec<WitnessReceipt> = receipts_json
        .iter()
        .enumerate()
        .map(|(i, json)| {
            serde_json::from_str(json).map_err(|e| {
                PyValueError::new_err(format!("Failed to parse witness receipt {i}: {e}"))
            })
        })
        .collect::<PyResult<Vec<_>>>()?;

    #[derive(serde::Deserialize)]
    struct WitnessKeyInput {
        did: String,
        public_key_hex: String,
    }

    let witness_keys: Vec<(String, Vec<u8>)> = witness_keys_json
        .iter()
        .enumerate()
        .map(|(i, json)| {
            let input: WitnessKeyInput = serde_json::from_str(json).map_err(|e| {
                PyValueError::new_err(format!("Failed to parse witness key {i}: {e}"))
            })?;
            let pk_bytes = hex::decode(&input.public_key_hex)
                .map_err(|e| PyValueError::new_err(format!("Invalid witness key {i} hex: {e}")))?;
            if pk_bytes.len() != 32 {
                return Err(PyValueError::new_err(format!(
                    "Invalid witness key {i} length: expected 32 bytes, got {}",
                    pk_bytes.len()
                )));
            }
            Ok((input.did, pk_bytes))
        })
        .collect::<PyResult<Vec<_>>>()?;

    let config = WitnessVerifyConfig {
        receipts: &receipts,
        witness_keys: &witness_keys,
        threshold,
    };

    py.allow_threads(|| {
        match runtime().block_on(rust_verify_chain_with_witnesses(
            &attestations,
            &root_pk_bytes,
            &config,
        )) {
            Ok(report) => Ok(report.into()),
            Err(e) => Err(PyRuntimeError::new_err(format!(
                "Chain verification with witnesses failed: {e}"
            ))),
        }
    })
}
