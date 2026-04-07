use crate::clock::{ClockProvider, SystemClock};
use crate::core::{
    Attestation, MAX_ATTESTATION_JSON_SIZE, MAX_FILE_HASH_HEX_LEN, MAX_JSON_BATCH_SIZE,
    MAX_PUBLIC_KEY_HEX_LEN, MAX_SIGNATURE_HEX_LEN,
};
use crate::error::{AttestationError, AuthsErrorInfo};
use crate::types::VerificationReport;
use crate::verify;
use crate::witness::WitnessVerifyConfig;
use auths_crypto::{CryptoProvider, ED25519_PUBLIC_KEY_LEN, WebCryptoProvider};
use auths_keri::witness::Receipt;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
}
macro_rules! console_log { ($($t:tt)*) => (log(&format_args!($($t)*).to_string())) }

fn provider() -> WebCryptoProvider {
    WebCryptoProvider
}

/// Result of a WASM attestation verification operation.
#[derive(Serialize, Deserialize)]
pub struct WasmVerificationResult {
    /// Whether the attestation verified successfully.
    pub valid: bool,
    /// Human-readable error message if verification failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Structured error code for programmatic handling.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

/// Verifies an attestation provided as a JSON string against an explicit issuer public key hex string.
#[wasm_bindgen(js_name = verifyAttestationJson)]
pub async fn wasm_verify_attestation_json(
    attestation_json_str: &str,
    issuer_pk_hex: &str,
) -> Result<(), JsValue> {
    console_log!("WASM: Verifying attestation...");

    if attestation_json_str.len() > MAX_ATTESTATION_JSON_SIZE {
        return Err(JsValue::from_str(&format!(
            "Attestation JSON too large: {} bytes, max {}",
            attestation_json_str.len(),
            MAX_ATTESTATION_JSON_SIZE
        )));
    }

    let issuer_pk_bytes = hex::decode(issuer_pk_hex)
        .map_err(|e| JsValue::from_str(&format!("Invalid issuer public key hex: {}", e)))?;
    if issuer_pk_bytes.len() != ED25519_PUBLIC_KEY_LEN {
        return Err(JsValue::from_str(&format!(
            "Invalid issuer public key length: expected {}, got {}",
            ED25519_PUBLIC_KEY_LEN,
            issuer_pk_bytes.len()
        )));
    }

    let att: Attestation = serde_json::from_str(attestation_json_str)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse attestation JSON: {}", e)))?;

    match verify::verify_with_keys_at(&att, &issuer_pk_bytes, SystemClock.now(), true, &provider())
        .await
    {
        Ok(()) => {
            console_log!("WASM: Verification successful.");
            Ok(())
        }
        Err(e) => {
            console_log!("WASM: Verification failed: {}", e);
            Err(JsValue::from_str(&format!("[{}] {}", e.error_code(), e)))
        }
    }
}

/// Verifies an attestation and returns a JSON result object.
#[wasm_bindgen(js_name = verifyAttestationWithResult)]
pub async fn wasm_verify_attestation_with_result(
    attestation_json_str: &str,
    issuer_pk_hex: &str,
) -> String {
    let result =
        match verify_attestation_internal(attestation_json_str, issuer_pk_hex, &provider()).await {
            Ok(()) => WasmVerificationResult {
                valid: true,
                error: None,
                error_code: None,
            },
            Err(e) => WasmVerificationResult {
                valid: false,
                error: Some(e.to_string()),
                error_code: Some(e.error_code().to_string()),
            },
        };
    serde_json::to_string(&result)
        .unwrap_or_else(|_| r#"{"valid":false,"error":"Serialization failed"}"#.to_string())
}

async fn verify_attestation_internal(
    attestation_json_str: &str,
    issuer_pk_hex: &str,
    provider: &dyn CryptoProvider,
) -> Result<(), AttestationError> {
    if attestation_json_str.len() > MAX_ATTESTATION_JSON_SIZE {
        return Err(AttestationError::InputTooLarge(format!(
            "Attestation JSON too large: {} bytes, max {}",
            attestation_json_str.len(),
            MAX_ATTESTATION_JSON_SIZE
        )));
    }

    let issuer_pk_bytes = hex::decode(issuer_pk_hex).map_err(|e| {
        AttestationError::InvalidInput(format!("Invalid issuer public key hex: {}", e))
    })?;

    if issuer_pk_bytes.len() != ED25519_PUBLIC_KEY_LEN {
        return Err(AttestationError::InvalidInput(format!(
            "Invalid issuer public key length: expected {}, got {}",
            ED25519_PUBLIC_KEY_LEN,
            issuer_pk_bytes.len()
        )));
    }

    let att: Attestation = serde_json::from_str(attestation_json_str).map_err(|e| {
        AttestationError::SerializationError(format!("Failed to parse attestation JSON: {}", e))
    })?;

    verify::verify_with_keys_at(&att, &issuer_pk_bytes, SystemClock.now(), true, provider).await
}

/// Verifies a detached Ed25519 signature over a file hash (all inputs hex-encoded).
#[wasm_bindgen(js_name = verifyArtifactSignature)]
pub async fn wasm_verify_artifact_signature(
    file_hash_hex: &str,
    signature_hex: &str,
    public_key_hex: &str,
) -> bool {
    if file_hash_hex.len() > MAX_FILE_HASH_HEX_LEN
        || signature_hex.len() > MAX_SIGNATURE_HEX_LEN
        || public_key_hex.len() > MAX_PUBLIC_KEY_HEX_LEN
    {
        return false;
    }

    let Ok(hash_bytes) = hex::decode(file_hash_hex) else {
        return false;
    };
    let Ok(sig_bytes) = hex::decode(signature_hex) else {
        return false;
    };
    let Ok(pk_bytes) = hex::decode(public_key_hex) else {
        return false;
    };

    if pk_bytes.len() != ED25519_PUBLIC_KEY_LEN {
        return false;
    }
    // Ed25519 signatures are always 64 bytes
    if sig_bytes.len() != 64 {
        return false;
    }

    provider()
        .verify_ed25519(&pk_bytes, &hash_bytes, &sig_bytes)
        .await
        .is_ok()
}

/// Verifies a chain of attestations and returns a VerificationReport as JSON.
#[wasm_bindgen(js_name = verifyChainJson)]
pub async fn wasm_verify_chain_json(attestations_json_array: &str, root_pk_hex: &str) -> String {
    match verify_chain_internal(attestations_json_array, root_pk_hex, &provider()).await {
        Ok(report) => serde_json::to_string(&report)
            .unwrap_or_else(|_| r#"{"status":{"type":"BrokenChain","missingLink":"Serialization failed"},"chain":[],"warnings":[]}"#.to_string()),
        Err(e) => {
            let error_response = serde_json::json!({
                "status": { "type": "BrokenChain", "missing_link": e.to_string() },
                "chain": [],
                "warnings": [],
                "error_code": e.error_code(),
            });
            error_response.to_string()
        }
    }
}

async fn verify_chain_internal(
    attestations_json_array: &str,
    root_pk_hex: &str,
    provider: &dyn CryptoProvider,
) -> Result<VerificationReport, AttestationError> {
    if attestations_json_array.len() > MAX_JSON_BATCH_SIZE {
        return Err(AttestationError::InputTooLarge(format!(
            "Attestations JSON too large: {} bytes, max {}",
            attestations_json_array.len(),
            MAX_JSON_BATCH_SIZE
        )));
    }

    let root_pk_bytes = hex::decode(root_pk_hex).map_err(|e| {
        AttestationError::InvalidInput(format!("Invalid root public key hex: {}", e))
    })?;

    if root_pk_bytes.len() != ED25519_PUBLIC_KEY_LEN {
        return Err(AttestationError::InvalidInput(format!(
            "Invalid root public key length: expected {}, got {}",
            ED25519_PUBLIC_KEY_LEN,
            root_pk_bytes.len()
        )));
    }

    let attestations: Vec<Attestation> =
        serde_json::from_str(attestations_json_array).map_err(|e| {
            AttestationError::SerializationError(format!(
                "Failed to parse attestations JSON array: {}",
                e
            ))
        })?;

    verify::verify_chain_inner(&attestations, &root_pk_bytes, provider, SystemClock.now()).await
}

/// Verifies a chain of attestations with witness quorum checking.
#[wasm_bindgen(js_name = verifyChainWithWitnesses)]
pub async fn wasm_verify_chain_with_witnesses_json(
    chain_json: &str,
    root_pk_hex: &str,
    receipts_json: &str,
    witness_keys_json: &str,
    threshold: u32,
) -> String {
    match verify_chain_with_witnesses_internal(
        chain_json,
        root_pk_hex,
        receipts_json,
        witness_keys_json,
        threshold,
        &provider(),
    )
    .await
    {
        Ok(report) => serde_json::to_string(&report)
            .unwrap_or_else(|_| r#"{"status":{"type":"BrokenChain","missing_link":"Serialization failed"},"chain":[],"warnings":[]}"#.to_string()),
        Err(e) => {
            let error_response = serde_json::json!({
                "status": { "type": "BrokenChain", "missing_link": e.to_string() },
                "chain": [],
                "warnings": [],
                "error_code": e.error_code(),
            });
            error_response.to_string()
        }
    }
}

async fn verify_chain_with_witnesses_internal(
    chain_json: &str,
    root_pk_hex: &str,
    receipts_json: &str,
    witness_keys_json: &str,
    threshold: u32,
    provider: &dyn CryptoProvider,
) -> Result<VerificationReport, AttestationError> {
    if chain_json.len() > MAX_JSON_BATCH_SIZE {
        return Err(AttestationError::InputTooLarge(format!(
            "Chain JSON too large: {} bytes, max {}",
            chain_json.len(),
            MAX_JSON_BATCH_SIZE
        )));
    }
    if receipts_json.len() > MAX_JSON_BATCH_SIZE {
        return Err(AttestationError::InputTooLarge(format!(
            "Receipts JSON too large: {} bytes, max {}",
            receipts_json.len(),
            MAX_JSON_BATCH_SIZE
        )));
    }
    if witness_keys_json.len() > MAX_JSON_BATCH_SIZE {
        return Err(AttestationError::InputTooLarge(format!(
            "Witness keys JSON too large: {} bytes, max {}",
            witness_keys_json.len(),
            MAX_JSON_BATCH_SIZE
        )));
    }

    let root_pk_bytes = hex::decode(root_pk_hex).map_err(|e| {
        AttestationError::InvalidInput(format!("Invalid root public key hex: {}", e))
    })?;

    if root_pk_bytes.len() != ED25519_PUBLIC_KEY_LEN {
        return Err(AttestationError::InvalidInput(format!(
            "Invalid root public key length: expected {}, got {}",
            ED25519_PUBLIC_KEY_LEN,
            root_pk_bytes.len()
        )));
    }

    let attestations: Vec<Attestation> = serde_json::from_str(chain_json).map_err(|e| {
        AttestationError::SerializationError(format!("Failed to parse attestations JSON: {}", e))
    })?;

    let receipts: Vec<Receipt> = serde_json::from_str(receipts_json).map_err(|e| {
        AttestationError::SerializationError(format!("Failed to parse receipts JSON: {}", e))
    })?;

    #[derive(Deserialize)]
    struct WitnessKeyEntry {
        did: String,
        pk_hex: String,
    }
    let key_entries: Vec<WitnessKeyEntry> =
        serde_json::from_str(witness_keys_json).map_err(|e| {
            AttestationError::SerializationError(format!(
                "Failed to parse witness keys JSON: {}",
                e
            ))
        })?;

    let witness_keys: Vec<(String, Vec<u8>)> = key_entries
        .into_iter()
        .map(|e| {
            hex::decode(&e.pk_hex).map(|pk| (e.did, pk)).map_err(|err| {
                AttestationError::InvalidInput(format!("Invalid witness key hex: {}", err))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let config = WitnessVerifyConfig {
        receipts: &receipts,
        witness_keys: &witness_keys,
        threshold: threshold as usize,
    };

    let mut report =
        verify::verify_chain_inner(&attestations, &root_pk_bytes, provider, SystemClock.now())
            .await?;

    if report.is_valid() {
        let quorum = crate::witness::verify_witness_receipts(&config, provider).await;
        if quorum.verified < quorum.required {
            report.status = crate::types::VerificationStatus::InsufficientWitnesses {
                required: quorum.required,
                verified: quorum.verified,
            };
            report.warnings.push(format!(
                "Witness quorum not met: {}/{} verified",
                quorum.verified, quorum.required
            ));
        }
        report.witness_quorum = Some(quorum);
    }

    Ok(report)
}

/// Verifies a KERI Key Event Log and returns the resulting key state as JSON.
///
/// Args:
/// * `kel_json`: JSON array of KEL events (inception, rotation, interaction).
///
/// Usage:
/// ```ignore
/// let key_state_json = validateKelJson("[{\"v\":\"KERI10JSON\",\"t\":\"icp\",...}]").await?;
/// ```
#[wasm_bindgen(js_name = validateKelJson)]
pub async fn wasm_validate_kel_json(kel_json: &str) -> Result<String, JsValue> {
    console_log!("WASM: Verifying KEL...");

    if kel_json.len() > MAX_JSON_BATCH_SIZE {
        return Err(JsValue::from_str(&format!(
            "KEL JSON too large: {} bytes, max {}",
            kel_json.len(),
            MAX_JSON_BATCH_SIZE
        )));
    }

    let events = auths_keri::parse_kel_json(kel_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse KEL JSON: {}", e)))?;

    let key_state = auths_keri::validate_kel(&events)
        .map_err(|e| JsValue::from_str(&format!("KEL verification failed: {}", e)))?;

    console_log!(
        "WASM: KEL verification successful, sequence: {}",
        key_state.sequence
    );

    serde_json::to_string(&key_state)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize key state: {}", e)))
}

/// Verifies that a device is cryptographically linked to a KERI identity.
///
/// Composes KEL verification, attestation signature verification, device DID matching,
/// and seal anchoring. Returns a JSON result (never throws for verification failures).
///
/// Args:
/// * `kel_json`: JSON array of KEL events.
/// * `attestation_json`: JSON attestation linking identity to device.
/// * `device_did`: Expected device DID string (e.g. `"did:key:z6Mk..."`).
///
/// Usage:
/// ```ignore
/// let result = verifyDeviceLink(kelJson, attestationJson, "did:key:z6Mk...").await;
/// // result: {"valid": true, "key_state": {...}, "seal_sequence": 2}
/// // or:     {"valid": false, "error": "..."}
/// ```
#[wasm_bindgen(js_name = verifyDeviceLink)]
pub async fn wasm_verify_device_link(
    kel_json: &str,
    attestation_json: &str,
    device_did: &str,
) -> Result<String, JsValue> {
    console_log!("WASM: Verifying device link for {}", device_did);

    if kel_json.len() > MAX_JSON_BATCH_SIZE {
        return Err(JsValue::from_str(&format!(
            "KEL JSON too large: {} bytes, max {}",
            kel_json.len(),
            MAX_JSON_BATCH_SIZE
        )));
    }
    if attestation_json.len() > MAX_ATTESTATION_JSON_SIZE {
        return Err(JsValue::from_str(&format!(
            "Attestation JSON too large: {} bytes, max {}",
            attestation_json.len(),
            MAX_ATTESTATION_JSON_SIZE
        )));
    }

    let events = auths_keri::parse_kel_json(kel_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse KEL JSON: {}", e)))?;

    let attestation: Attestation = serde_json::from_str(attestation_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse attestation JSON: {}", e)))?;

    let result = crate::verify::verify_device_link(
        &events,
        &attestation,
        device_did,
        SystemClock.now(),
        &provider(),
    )
    .await;

    console_log!(
        "WASM: Device link verification result: valid={}",
        result.valid
    );

    serde_json::to_string(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
}
