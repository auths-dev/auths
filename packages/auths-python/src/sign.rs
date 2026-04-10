use auths_crypto::CurveType;
use auths_verifier::action::ActionEnvelope;
use auths_verifier::core::MAX_ATTESTATION_JSON_SIZE;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

use crate::types::VerificationResult;

/// Parse an optional curve string into CurveType. Defaults to P256.
fn parse_curve(curve: Option<&str>) -> PyResult<CurveType> {
    match curve {
        None | Some("p256") => Ok(CurveType::P256),
        Some("ed25519") => Ok(CurveType::Ed25519),
        Some(other) => Err(PyValueError::new_err(format!(
            "Unknown curve: {other}. Supported: \"p256\" (default), \"ed25519\""
        ))),
    }
}

use crate::types::validate_pk_hex;

/// Sign arbitrary bytes with a private key.
///
/// Args:
/// * `private_key_hex`: Seed as hex string (64 chars = 32 bytes).
/// * `message`: The bytes to sign.
/// * `curve`: Optional curve name ("p256" or "ed25519"). Defaults to "p256".
///
/// Usage:
/// ```ignore
/// let sig = sign_bytes("deadbeef...", b"hello", None)?;       // P-256
/// let sig = sign_bytes("deadbeef...", b"hello", Some("ed25519"))?; // Ed25519
/// ```
#[pyfunction]
#[pyo3(signature = (private_key_hex, message, curve=None))]
pub fn sign_bytes(private_key_hex: &str, message: &[u8], curve: Option<&str>) -> PyResult<String> {
    let seed_bytes = hex::decode(private_key_hex)
        .map_err(|e| PyValueError::new_err(format!("Invalid private key hex: {e}")))?;

    if seed_bytes.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "Invalid seed length: expected 32 bytes (64 hex chars), got {}",
            seed_bytes.len()
        )));
    }

    let curve_type = parse_curve(curve)?;
    let typed_seed = match curve_type {
        CurveType::Ed25519 => {
            #[allow(clippy::unwrap_used)] // INVARIANT: length checked above
            auths_crypto::TypedSeed::Ed25519(seed_bytes.as_slice().try_into().unwrap())
        }
        CurveType::P256 => {
            #[allow(clippy::unwrap_used)] // INVARIANT: length checked above
            auths_crypto::TypedSeed::P256(seed_bytes.as_slice().try_into().unwrap())
        }
    };

    let sig = auths_crypto::typed_sign(&typed_seed, message).map_err(|e| {
        PyRuntimeError::new_err(format!("[AUTHS_CRYPTO_ERROR] Signing failed: {e}"))
    })?;

    Ok(hex::encode(&sig))
}

/// Sign an action envelope per the Auths action envelope specification.
///
/// Args:
/// * `private_key_hex`: Seed as hex string (64 chars = 32 bytes).
/// * `action_type`: Application-defined action type (e.g. "tool_call").
/// * `payload_json`: JSON string for the payload field.
/// * `identity_did`: Signer's identity DID (e.g. "did:keri:E...").
/// * `curve`: Optional curve name ("p256" or "ed25519"). Defaults to "p256".
///
/// Usage:
/// ```ignore
/// let envelope = sign_action("deadbeef...", "tool_call", "{}", "did:keri:E...", None)?;
/// ```
#[pyfunction]
#[pyo3(signature = (private_key_hex, action_type, payload_json, identity_did, curve=None))]
pub fn sign_action(
    private_key_hex: &str,
    action_type: &str,
    payload_json: &str,
    identity_did: &str,
    curve: Option<&str>,
) -> PyResult<String> {
    let seed = hex::decode(private_key_hex)
        .map_err(|e| PyValueError::new_err(format!("Invalid private key hex: {e}")))?;

    if seed.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "Invalid seed length: expected 32 bytes (64 hex chars), got {}",
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

    let mut envelope = ActionEnvelope {
        version: "1.0".into(),
        action_type: action_type.into(),
        identity: identity_did.into(),
        payload,
        timestamp,
        signature: String::new(),
        attestation_chain: None,
        environment: None,
    };

    let canonical = envelope
        .canonical_bytes()
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_SERIALIZATION_ERROR] {e}")))?;

    let curve_type = parse_curve(curve)?;
    let typed_seed = match curve_type {
        CurveType::Ed25519 => {
            #[allow(clippy::unwrap_used)] // INVARIANT: length checked above
            auths_crypto::TypedSeed::Ed25519(seed.as_slice().try_into().unwrap())
        }
        CurveType::P256 => {
            #[allow(clippy::unwrap_used)] // INVARIANT: length checked above
            auths_crypto::TypedSeed::P256(seed.as_slice().try_into().unwrap())
        }
    };

    let sig = auths_crypto::typed_sign(&typed_seed, &canonical).map_err(|e| {
        PyRuntimeError::new_err(format!("[AUTHS_CRYPTO_ERROR] Signing failed: {e}"))
    })?;
    envelope.signature = hex::encode(&sig);

    serde_json::to_string(&envelope).map_err(|e| {
        PyRuntimeError::new_err(format!(
            "[AUTHS_SERIALIZATION_ERROR] Failed to serialize envelope: {e}"
        ))
    })
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
    let (pk_bytes, _curve) = validate_pk_hex(public_key_hex)?;

    if envelope_json.len() > MAX_ATTESTATION_JSON_SIZE {
        return Err(PyValueError::new_err(format!(
            "Envelope JSON too large: {} bytes, max {MAX_ATTESTATION_JSON_SIZE}",
            envelope_json.len()
        )));
    }

    let envelope: ActionEnvelope = serde_json::from_str(envelope_json)
        .map_err(|e| PyValueError::new_err(format!("Invalid envelope JSON: {e}")))?;

    if envelope.version != "1.0" {
        return Ok(VerificationResult {
            valid: false,
            error: Some(format!("Unsupported version: {}", envelope.version)),
            error_code: Some("AUTHS_INVALID_INPUT".to_string()),
        });
    }

    let sig_bytes = hex::decode(&envelope.signature)
        .map_err(|e| PyValueError::new_err(format!("Invalid signature hex: {e}")))?;

    let canonical = envelope
        .canonical_bytes()
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_SERIALIZATION_ERROR] {e}")))?;

    let key = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &pk_bytes);
    match key.verify(&canonical, &sig_bytes) {
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
