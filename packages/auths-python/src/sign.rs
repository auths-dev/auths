use auths_verifier::core::MAX_ATTESTATION_JSON_SIZE;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

use crate::types::VerificationResult;

/// Sign arbitrary bytes with an Ed25519 private key.
///
/// Args:
/// * `private_key_hex`: Ed25519 seed as hex string (64 chars = 32 bytes).
/// * `message`: The bytes to sign.
///
/// Usage:
/// ```ignore
/// let sig = sign_bytes("deadbeef...", b"hello")?;
/// ```
#[pyfunction]
pub fn sign_bytes(private_key_hex: &str, message: &[u8]) -> PyResult<String> {
    let seed = hex::decode(private_key_hex)
        .map_err(|e| PyValueError::new_err(format!("Invalid private key hex: {e}")))?;

    if seed.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "Invalid private key length: expected 32 bytes (64 hex chars), got {}",
            seed.len()
        )));
    }

    let keypair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed)
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_CRYPTO_ERROR] Failed to create keypair: {e}")))?;

    let sig = keypair.sign(message);
    Ok(hex::encode(sig.as_ref()))
}

/// Sign an action envelope per the Auths action envelope specification.
///
/// Args:
/// * `private_key_hex`: Ed25519 seed as hex string (64 chars = 32 bytes).
/// * `action_type`: Application-defined action type (e.g. "tool_call").
/// * `payload_json`: JSON string for the payload field.
/// * `identity_did`: Signer's identity DID (e.g. "did:keri:E...").
///
/// Usage:
/// ```ignore
/// let envelope = sign_action("deadbeef...", "tool_call", "{}", "did:keri:E...")?;
/// ```
#[pyfunction]
pub fn sign_action(
    private_key_hex: &str,
    action_type: &str,
    payload_json: &str,
    identity_did: &str,
) -> PyResult<String> {
    let seed = hex::decode(private_key_hex)
        .map_err(|e| PyValueError::new_err(format!("Invalid private key hex: {e}")))?;

    if seed.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "Invalid private key length: expected 32 bytes (64 hex chars), got {}",
            seed.len()
        )));
    }

    if payload_json.len() > MAX_ATTESTATION_JSON_SIZE {
        return Err(PyValueError::new_err(format!(
            "Payload JSON too large: {} bytes, max {MAX_ATTESTATION_JSON_SIZE}",
            payload_json.len()
        )));
    }

    let payload: serde_json::Value = serde_json::from_str(payload_json)
        .map_err(|e| PyValueError::new_err(format!("Invalid payload JSON: {e}")))?;

    #[allow(clippy::disallowed_methods)] // Presentation boundary
    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let signing_data = serde_json::json!({
        "version": "1.0",
        "type": action_type,
        "identity": identity_did,
        "payload": payload,
        "timestamp": timestamp,
    });

    let canonical = json_canon::to_string(&signing_data)
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_SERIALIZATION_ERROR] Canonicalization failed: {e}")))?;

    let keypair = ring::signature::Ed25519KeyPair::from_seed_unchecked(&seed)
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_CRYPTO_ERROR] Failed to create keypair: {e}")))?;

    let sig = keypair.sign(canonical.as_bytes());
    let sig_hex = hex::encode(sig.as_ref());

    let envelope = serde_json::json!({
        "version": "1.0",
        "type": action_type,
        "identity": identity_did,
        "payload": payload,
        "timestamp": timestamp,
        "signature": sig_hex,
    });

    serde_json::to_string(&envelope)
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_SERIALIZATION_ERROR] Failed to serialize envelope: {e}")))
}

/// Verify an action envelope's Ed25519 signature.
///
/// Args:
/// * `envelope_json`: The complete action envelope as a JSON string.
/// * `public_key_hex`: The signer's Ed25519 public key in hex format (64 chars).
///
/// Usage:
/// ```ignore
/// let result = verify_action_envelope("{...}", "abcd1234...")?;
/// ```
#[pyfunction]
pub fn verify_action_envelope(
    envelope_json: &str,
    public_key_hex: &str,
) -> PyResult<VerificationResult> {
    let pk_bytes = hex::decode(public_key_hex)
        .map_err(|e| PyValueError::new_err(format!("Invalid public key hex: {e}")))?;

    if pk_bytes.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "Invalid public key length: expected 32 bytes (64 hex chars), got {}",
            pk_bytes.len()
        )));
    }

    if envelope_json.len() > MAX_ATTESTATION_JSON_SIZE {
        return Err(PyValueError::new_err(format!(
            "Envelope JSON too large: {} bytes, max {MAX_ATTESTATION_JSON_SIZE}",
            envelope_json.len()
        )));
    }

    let envelope: serde_json::Value = serde_json::from_str(envelope_json)
        .map_err(|e| PyValueError::new_err(format!("Invalid envelope JSON: {e}")))?;

    let version = envelope
        .get("version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PyValueError::new_err("Missing or invalid 'version' field"))?;

    if version != "1.0" {
        return Ok(VerificationResult {
            valid: false,
            error: Some(format!("Unsupported version: {version}")),
            error_code: Some("AUTHS_INVALID_INPUT".to_string()),
        });
    }

    let sig_hex = envelope
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PyValueError::new_err("Missing or invalid 'signature' field"))?;

    let sig_bytes = hex::decode(sig_hex)
        .map_err(|e| PyValueError::new_err(format!("Invalid signature hex: {e}")))?;

    let signing_data = serde_json::json!({
        "version": envelope.get("version"),
        "type": envelope.get("type"),
        "identity": envelope.get("identity"),
        "payload": envelope.get("payload"),
        "timestamp": envelope.get("timestamp"),
    });

    let canonical = json_canon::to_string(&signing_data)
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_SERIALIZATION_ERROR] Canonicalization failed: {e}")))?;

    let key = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &pk_bytes);
    match key.verify(canonical.as_bytes(), &sig_bytes) {
        Ok(()) => Ok(VerificationResult {
            valid: true,
            error: None,
            error_code: None,
        }),
        Err(_) => Ok(VerificationResult {
            valid: false,
            error: Some("Ed25519 signature verification failed".to_string()),
            error_code: Some("AUTHS_ISSUER_SIG_FAILED".to_string()),
        }),
    }
}
