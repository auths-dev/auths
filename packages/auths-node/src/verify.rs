use auths_crypto::CurveType;
use auths_verifier::DevicePublicKey;
use auths_verifier::action::ActionEnvelope;
use auths_verifier::core::{
    Attestation, Capability, MAX_ATTESTATION_JSON_SIZE, MAX_JSON_BATCH_SIZE,
};
use auths_verifier::error::AuthsErrorInfo;
use auths_verifier::types::DeviceDID;
use auths_verifier::verify::{
    verify_at_time as rust_verify_at_time, verify_chain as rust_verify_chain,
    verify_chain_with_capability as rust_verify_chain_with_capability,
    verify_chain_with_witnesses as rust_verify_chain_with_witnesses,
    verify_device_authorization as rust_verify_device_authorization,
    verify_with_capability as rust_verify_with_capability, verify_with_keys,
};
use auths_verifier::witness::WitnessVerifyConfig;
use chrono::{DateTime, Utc};
use napi_derive::napi;

use crate::error::format_error;
use crate::types::{NapiVerificationReport, NapiVerificationResult};

fn decode_pk_hex(hex_str: &str, label: &str) -> napi::Result<Vec<u8>> {
    let bytes = hex::decode(hex_str)
        .map_err(|e| format_error("AUTHS_INVALID_INPUT", format!("Invalid {label} hex: {e}")))?;
    match bytes.len() {
        32 | 33 | 65 => Ok(bytes),
        n => Err(format_error(
            "AUTHS_INVALID_INPUT",
            format!("Invalid {label} length: expected 32 (Ed25519), 33/65 (P-256), got {n}",),
        )),
    }
}

fn curve_from_len(len: usize) -> Option<CurveType> {
    match len {
        32 => Some(CurveType::Ed25519),
        33 | 65 => Some(CurveType::P256),
        _ => None,
    }
}

fn decode_device_public_key(hex_str: &str, label: &str) -> napi::Result<DevicePublicKey> {
    let bytes = decode_pk_hex(hex_str, label)?;
    let curve = curve_from_len(bytes.len()).ok_or_else(|| {
        format_error(
            "AUTHS_INVALID_INPUT",
            format!("Invalid {label} length: {}", bytes.len()),
        )
    })?;
    DevicePublicKey::try_new(curve, &bytes).map_err(|e| {
        format_error(
            "AUTHS_INVALID_INPUT",
            format!("Invalid {label} public key: {e}"),
        )
    })
}

fn parse_attestations(jsons: &[String]) -> napi::Result<Vec<Attestation>> {
    jsons
        .iter()
        .enumerate()
        .map(|(i, json)| {
            serde_json::from_str(json).map_err(|e| {
                format_error(
                    "AUTHS_SERIALIZATION_ERROR",
                    format!("Failed to parse attestation {i}: {e}"),
                )
            })
        })
        .collect()
}

fn check_batch_size(jsons: &[String]) -> napi::Result<()> {
    let total: usize = jsons.iter().map(|s| s.len()).sum();
    if total > MAX_JSON_BATCH_SIZE {
        return Err(format_error(
            "AUTHS_INVALID_INPUT",
            format!("Total attestation JSON too large: {total} bytes, max {MAX_JSON_BATCH_SIZE}"),
        ));
    }
    Ok(())
}

#[napi]
pub async fn verify_attestation(
    attestation_json: String,
    issuer_pk_hex: String,
) -> napi::Result<NapiVerificationResult> {
    if attestation_json.len() > MAX_ATTESTATION_JSON_SIZE {
        return Err(format_error(
            "AUTHS_INVALID_INPUT",
            format!(
                "Attestation JSON too large: {} bytes, max {}",
                attestation_json.len(),
                MAX_ATTESTATION_JSON_SIZE
            ),
        ));
    }

    let issuer_pk = decode_device_public_key(&issuer_pk_hex, "issuer public key")?;

    let att: Attestation = match serde_json::from_str(&attestation_json) {
        Ok(att) => att,
        Err(e) => {
            return Ok(NapiVerificationResult {
                valid: false,
                error: Some(format!("Failed to parse attestation JSON: {e}")),
                error_code: Some("AUTHS_SERIALIZATION_ERROR".to_string()),
            });
        }
    };

    match verify_with_keys(&att, &issuer_pk).await {
        Ok(_) => Ok(NapiVerificationResult {
            valid: true,
            error: None,
            error_code: None,
        }),
        Err(e) => Ok(NapiVerificationResult {
            valid: false,
            error_code: Some(e.error_code().to_string()),
            error: Some(e.to_string()),
        }),
    }
}

#[napi]
pub async fn verify_chain(
    attestations_json: Vec<String>,
    root_pk_hex: String,
) -> napi::Result<NapiVerificationReport> {
    check_batch_size(&attestations_json)?;
    let root_pk = decode_device_public_key(&root_pk_hex, "root public key")?;
    let attestations = parse_attestations(&attestations_json)?;

    match rust_verify_chain(&attestations, &root_pk).await {
        Ok(report) => Ok(report.into()),
        Err(e) => Err(format_error(
            e.error_code(),
            format!("Chain verification failed: {e}"),
        )),
    }
}

#[napi]
pub async fn verify_device_authorization(
    identity_did: String,
    device_did: String,
    attestations_json: Vec<String>,
    identity_pk_hex: String,
) -> napi::Result<NapiVerificationReport> {
    check_batch_size(&attestations_json)?;
    let identity_pk = decode_device_public_key(&identity_pk_hex, "identity public key")?;
    let attestations = parse_attestations(&attestations_json)?;
    let device =
        DeviceDID::parse(&device_did).map_err(|e| format_error("AUTHS_INVALID_INPUT", e))?;

    match rust_verify_device_authorization(&identity_did, &device, &attestations, &identity_pk)
        .await
    {
        Ok(report) => Ok(report.into()),
        Err(e) => Err(format_error(
            e.error_code(),
            format!("Device authorization verification failed: {e}"),
        )),
    }
}

#[napi]
pub async fn verify_attestation_with_capability(
    attestation_json: String,
    issuer_pk_hex: String,
    required_capability: String,
) -> napi::Result<NapiVerificationResult> {
    if attestation_json.len() > MAX_ATTESTATION_JSON_SIZE {
        return Err(format_error(
            "AUTHS_INVALID_INPUT",
            format!(
                "Attestation JSON too large: {} bytes, max {}",
                attestation_json.len(),
                MAX_ATTESTATION_JSON_SIZE
            ),
        ));
    }

    let issuer_pk = decode_device_public_key(&issuer_pk_hex, "issuer public key")?;

    let att: Attestation = match serde_json::from_str(&attestation_json) {
        Ok(att) => att,
        Err(e) => {
            return Ok(NapiVerificationResult {
                valid: false,
                error: Some(format!("Failed to parse attestation JSON: {e}")),
                error_code: Some("AUTHS_SERIALIZATION_ERROR".to_string()),
            });
        }
    };

    let cap = Capability::parse(&required_capability).map_err(|e| {
        format_error(
            "AUTHS_INVALID_INPUT",
            format!("Invalid capability '{required_capability}': {e}"),
        )
    })?;

    match rust_verify_with_capability(&att, &cap, &issuer_pk).await {
        Ok(_) => Ok(NapiVerificationResult {
            valid: true,
            error: None,
            error_code: None,
        }),
        Err(e) => Ok(NapiVerificationResult {
            valid: false,
            error_code: Some(e.error_code().to_string()),
            error: Some(e.to_string()),
        }),
    }
}

#[napi]
pub async fn verify_chain_with_capability(
    attestations_json: Vec<String>,
    root_pk_hex: String,
    required_capability: String,
) -> napi::Result<NapiVerificationReport> {
    check_batch_size(&attestations_json)?;
    let root_pk = decode_device_public_key(&root_pk_hex, "root public key")?;
    let attestations = parse_attestations(&attestations_json)?;

    let cap = Capability::parse(&required_capability).map_err(|e| {
        format_error(
            "AUTHS_INVALID_INPUT",
            format!("Invalid capability '{required_capability}': {e}"),
        )
    })?;

    match rust_verify_chain_with_capability(&attestations, &cap, &root_pk).await {
        Ok(report) => Ok(report.into()),
        Err(e) => Err(format_error(
            e.error_code(),
            format!("Chain verification with capability failed: {e}"),
        )),
    }
}

fn parse_rfc3339_timestamp(at_rfc3339: &str) -> napi::Result<DateTime<Utc>> {
    let at: DateTime<Utc> = at_rfc3339.parse::<DateTime<Utc>>().map_err(|_| {
        if at_rfc3339.contains(' ') && !at_rfc3339.contains('T') {
            format_error(
                "AUTHS_INVALID_INPUT",
                format!(
                    "Expected RFC 3339 format like '2024-06-15T00:00:00Z', got '{at_rfc3339}'. \
                     Hint: use 'T' between date and time, and append 'Z' or a UTC offset."
                ),
            )
        } else {
            format_error(
                "AUTHS_INVALID_INPUT",
                format!(
                    "Expected RFC 3339 format like '2024-06-15T00:00:00Z', got '{at_rfc3339}'."
                ),
            )
        }
    })?;

    #[allow(clippy::disallowed_methods)] // Presentation boundary
    let now = Utc::now();
    let skew_tolerance = chrono::Duration::seconds(60);
    if at > now + skew_tolerance {
        return Err(format_error(
            "AUTHS_INVALID_INPUT",
            format!(
                "Timestamp {at_rfc3339} is in the future. \
                 Time-pinned verification requires a past or present timestamp."
            ),
        ));
    }

    Ok(at)
}

#[napi]
pub async fn verify_at_time(
    attestation_json: String,
    issuer_pk_hex: String,
    at_rfc3339: String,
) -> napi::Result<NapiVerificationResult> {
    if attestation_json.len() > MAX_ATTESTATION_JSON_SIZE {
        return Err(format_error(
            "AUTHS_INVALID_INPUT",
            format!(
                "Attestation JSON too large: {} bytes, max {}",
                attestation_json.len(),
                MAX_ATTESTATION_JSON_SIZE
            ),
        ));
    }

    let at = parse_rfc3339_timestamp(&at_rfc3339)?;
    let issuer_pk = decode_device_public_key(&issuer_pk_hex, "issuer public key")?;

    let att: Attestation = match serde_json::from_str(&attestation_json) {
        Ok(att) => att,
        Err(e) => {
            return Ok(NapiVerificationResult {
                valid: false,
                error: Some(format!("Failed to parse attestation JSON: {e}")),
                error_code: Some("AUTHS_SERIALIZATION_ERROR".to_string()),
            });
        }
    };

    match rust_verify_at_time(&att, &issuer_pk, at).await {
        Ok(_) => Ok(NapiVerificationResult {
            valid: true,
            error: None,
            error_code: None,
        }),
        Err(e) => Ok(NapiVerificationResult {
            valid: false,
            error_code: Some(e.error_code().to_string()),
            error: Some(e.to_string()),
        }),
    }
}

#[napi]
pub async fn verify_at_time_with_capability(
    attestation_json: String,
    issuer_pk_hex: String,
    at_rfc3339: String,
    required_capability: String,
) -> napi::Result<NapiVerificationResult> {
    if attestation_json.len() > MAX_ATTESTATION_JSON_SIZE {
        return Err(format_error(
            "AUTHS_INVALID_INPUT",
            format!(
                "Attestation JSON too large: {} bytes, max {}",
                attestation_json.len(),
                MAX_ATTESTATION_JSON_SIZE
            ),
        ));
    }

    let at = parse_rfc3339_timestamp(&at_rfc3339)?;
    let issuer_pk = decode_device_public_key(&issuer_pk_hex, "issuer public key")?;

    let att: Attestation = match serde_json::from_str(&attestation_json) {
        Ok(att) => att,
        Err(e) => {
            return Ok(NapiVerificationResult {
                valid: false,
                error: Some(format!("Failed to parse attestation JSON: {e}")),
                error_code: Some("AUTHS_SERIALIZATION_ERROR".to_string()),
            });
        }
    };

    let cap = Capability::parse(&required_capability).map_err(|e| {
        format_error(
            "AUTHS_INVALID_INPUT",
            format!("Invalid capability '{required_capability}': {e}"),
        )
    })?;

    match rust_verify_at_time(&att, &issuer_pk, at).await {
        Ok(_) => {
            if att.capabilities.contains(&cap) {
                Ok(NapiVerificationResult {
                    valid: true,
                    error: None,
                    error_code: None,
                })
            } else {
                Ok(NapiVerificationResult {
                    valid: false,
                    error: Some(format!(
                        "Attestation does not grant required capability '{required_capability}'"
                    )),
                    error_code: Some("AUTHS_MISSING_CAPABILITY".to_string()),
                })
            }
        }
        Err(e) => Ok(NapiVerificationResult {
            valid: false,
            error_code: Some(e.error_code().to_string()),
            error: Some(e.to_string()),
        }),
    }
}

#[napi]
pub async fn verify_chain_with_witnesses(
    attestations_json: Vec<String>,
    root_pk_hex: String,
    receipts_json: Vec<String>,
    witness_keys_json: Vec<String>,
    threshold: u32,
) -> napi::Result<NapiVerificationReport> {
    check_batch_size(&attestations_json)?;
    let root_pk = decode_device_public_key(&root_pk_hex, "root public key")?;
    let attestations = parse_attestations(&attestations_json)?;

    let receipts: Vec<auths_verifier::SignedReceipt> = receipts_json
        .iter()
        .enumerate()
        .map(|(i, json)| {
            serde_json::from_str(json).map_err(|e| {
                format_error(
                    "AUTHS_SERIALIZATION_ERROR",
                    format!("Failed to parse witness receipt {i}: {e}"),
                )
            })
        })
        .collect::<napi::Result<Vec<_>>>()?;

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
                format_error(
                    "AUTHS_SERIALIZATION_ERROR",
                    format!("Failed to parse witness key {i}: {e}"),
                )
            })?;
            let pk_bytes = decode_pk_hex(&input.public_key_hex, &format!("witness key {i}"))?;
            Ok((input.did, pk_bytes))
        })
        .collect::<napi::Result<Vec<_>>>()?;

    let config = WitnessVerifyConfig {
        receipts: &receipts,
        witness_keys: &witness_keys,
        threshold: threshold as usize,
    };

    match rust_verify_chain_with_witnesses(&attestations, &root_pk, &config).await {
        Ok(report) => Ok(report.into()),
        Err(e) => Err(format_error(
            e.error_code(),
            format!("Chain verification with witnesses failed: {e}"),
        )),
    }
}

/// Verify an action envelope's Ed25519 signature with a raw public key.
///
/// Args:
/// * `envelope_json`: The complete action envelope as a JSON string.
/// * `public_key_hex`: The signer's public key in hex format
///   (64 chars for Ed25519, 66 or 130 chars for P-256).
/// * `curve`: Optional curve hint (`"Ed25519"` / `"P256"`). Absent → P-256
///   default per the workspace wire-format curve-tagging rule.
///
/// Usage:
/// ```ignore
/// let result = verify_action_envelope("{...}".into(), "abcd1234...".into(), Some("P256".into()))?;
/// ```
#[napi]
pub fn verify_action_envelope(
    envelope_json: String,
    public_key_hex: String,
    curve: Option<String>,
) -> napi::Result<NapiVerificationResult> {
    if envelope_json.len() > MAX_ATTESTATION_JSON_SIZE {
        return Err(format_error(
            "AUTHS_INVALID_INPUT",
            format!(
                "Envelope JSON too large: {} bytes, max {MAX_ATTESTATION_JSON_SIZE}",
                envelope_json.len()
            ),
        ));
    }

    let pk_bytes = hex::decode(&public_key_hex).map_err(|e| {
        format_error(
            "AUTHS_INVALID_INPUT",
            format!("Invalid public key hex: {e}"),
        )
    })?;
    let curve_type = parse_curve_hint(curve);
    validate_pk_len_for_curve(&pk_bytes, curve_type)?;

    let envelope: ActionEnvelope = serde_json::from_str(&envelope_json)
        .map_err(|e| format_error("AUTHS_INVALID_INPUT", format!("Invalid envelope JSON: {e}")))?;

    if envelope.version != "1.0" {
        return Ok(NapiVerificationResult {
            valid: false,
            error: Some(format!("Unsupported version: {}", envelope.version)),
            error_code: Some("AUTHS_INVALID_INPUT".to_string()),
        });
    }

    let sig_bytes = hex::decode(&envelope.signature)
        .map_err(|e| format_error("AUTHS_INVALID_INPUT", format!("Invalid signature hex: {e}")))?;

    let canonical = envelope
        .canonical_bytes()
        .map_err(|e| format_error("AUTHS_SERIALIZATION_ERROR", e))?;

    let verify_result = match curve_type {
        CurveType::Ed25519 => {
            auths_crypto::RingCryptoProvider::ed25519_verify(&pk_bytes, &canonical, &sig_bytes)
        }
        CurveType::P256 => {
            auths_crypto::RingCryptoProvider::p256_verify(&pk_bytes, &canonical, &sig_bytes)
        }
    };

    match verify_result {
        Ok(()) => Ok(NapiVerificationResult {
            valid: true,
            error: None,
            error_code: None,
        }),
        Err(_) => Ok(NapiVerificationResult {
            valid: false,
            error: Some(format!("{curve_type} signature verification failed")),
            error_code: Some("AUTHS_ISSUER_SIG_FAILED".to_string()),
        }),
    }
}

/// Parse the FFI `curve` hint. `None` or unrecognized → P-256 default.
fn parse_curve_hint(curve: Option<String>) -> CurveType {
    match curve.as_deref() {
        Some("Ed25519") | Some("ed25519") => CurveType::Ed25519,
        _ => CurveType::P256,
    }
}

/// Validate that a raw pubkey's byte length matches the declared curve.
/// Curve comes from an explicit in-band tag; length dispatch never runs.
fn validate_pk_len_for_curve(bytes: &[u8], curve: CurveType) -> napi::Result<()> {
    let ok = match curve {
        CurveType::Ed25519 => bytes.len() == 32,
        CurveType::P256 => matches!(bytes.len(), 33 | 65),
    };
    if ok {
        Ok(())
    } else {
        Err(format_error(
            "AUTHS_INVALID_INPUT",
            format!(
                "Public key length {} does not match {} (expected {} bytes)",
                bytes.len(),
                curve,
                curve.public_key_len(),
            ),
        ))
    }
}
