use crate::clock::{ClockProvider, SystemClock};
use crate::core::{
    Attestation, DevicePublicKey, MAX_ATTESTATION_JSON_SIZE, MAX_FILE_HASH_HEX_LEN,
    MAX_JSON_BATCH_SIZE, MAX_PUBLIC_KEY_HEX_LEN, MAX_SIGNATURE_HEX_LEN,
};
use crate::error::{AttestationError, AuthsErrorInfo};
use crate::types::VerificationReport;
use crate::verify;
use crate::witness::WitnessVerifyConfig;
use auths_crypto::{CryptoProvider, CurveType, WebCryptoProvider};
use auths_keri::witness::SignedReceipt;
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

/// Decode a hex-encoded public key and infer its curve from length.
///
/// Accepts 32 bytes (Ed25519), 33 or 65 bytes (P-256).
fn pk_from_hex_wasm(pk_hex: &str) -> Result<DevicePublicKey, AttestationError> {
    let bytes = hex::decode(pk_hex)
        .map_err(|e| AttestationError::InvalidInput(format!("Invalid public key hex: {}", e)))?;
    let curve = match bytes.len() {
        32 => auths_crypto::CurveType::Ed25519,
        33 | 65 => auths_crypto::CurveType::P256,
        n => {
            return Err(AttestationError::InvalidInput(format!(
                "Invalid public key length: expected 32 (Ed25519) or 33/65 (P-256), got {n}"
            )));
        }
    };
    DevicePublicKey::try_new(curve, &bytes)
        .map_err(|e| AttestationError::InvalidInput(e.to_string()))
}

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

    let issuer_pk =
        pk_from_hex_wasm(issuer_pk_hex).map_err(|e| JsValue::from_str(&e.to_string()))?;

    let att: Attestation = serde_json::from_str(attestation_json_str)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse attestation JSON: {}", e)))?;

    match verify::verify_with_keys_at(&att, &issuer_pk, SystemClock.now(), true, &provider()).await
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

    let issuer_pk = pk_from_hex_wasm(issuer_pk_hex)?;

    let att: Attestation = serde_json::from_str(attestation_json_str).map_err(|e| {
        AttestationError::SerializationError(format!("Failed to parse attestation JSON: {}", e))
    })?;

    verify::verify_with_keys_at(&att, &issuer_pk, SystemClock.now(), true, provider).await
}

/// Verifies a detached signature over a file hash (all inputs hex-encoded).
///
/// Args:
/// * `file_hash_hex`: Hex-encoded file hash.
/// * `signature_hex`: Hex-encoded signature.
/// * `public_key_hex`: Hex-encoded public key.
/// * `curve`: Curve name ("ed25519" or "p256"). Defaults to P-256.
#[wasm_bindgen(js_name = verifyArtifactSignature)]
pub async fn wasm_verify_artifact_signature(
    file_hash_hex: &str,
    signature_hex: &str,
    public_key_hex: &str,
    curve: Option<String>,
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

    let curve_type = match curve.as_deref() {
        Some("ed25519") | Some("Ed25519") => CurveType::Ed25519,
        _ => CurveType::P256,
    };

    if sig_bytes.len() != 64 {
        return false;
    }

    let Ok(typed_pk) = DevicePublicKey::try_new(curve_type, &pk_bytes) else {
        return false;
    };

    typed_pk
        .verify(&hash_bytes, &sig_bytes, &provider())
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

    let root_pk = pk_from_hex_wasm(root_pk_hex)?;

    let attestations: Vec<Attestation> =
        serde_json::from_str(attestations_json_array).map_err(|e| {
            AttestationError::SerializationError(format!(
                "Failed to parse attestations JSON array: {}",
                e
            ))
        })?;

    verify::verify_chain_inner(&attestations, &root_pk, provider, SystemClock.now()).await
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

    let root_pk = pk_from_hex_wasm(root_pk_hex)?;

    let attestations: Vec<Attestation> = serde_json::from_str(chain_json).map_err(|e| {
        AttestationError::SerializationError(format!("Failed to parse attestations JSON: {}", e))
    })?;

    let receipts: Vec<SignedReceipt> = serde_json::from_str(receipts_json).map_err(|e| {
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
        verify::verify_chain_inner(&attestations, &root_pk, provider, SystemClock.now()).await?;

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

/// Authenticates a KERI Key Event Log and returns the resulting key state as JSON.
///
/// Every event must carry a valid CESR signature from its controlling key-state:
/// `kel_json` is the JSON array of events and `attachments_json` a parallel JSON
/// array of hex-encoded CESR signature attachments (one per event). The KEL is
/// replayed through [`validate_signed_kel`](auths_keri::validate_signed_kel), so a
/// forged or unsigned KEL fails closed (RT-002) — the structural-only
/// `validate_kel` is deliberately NOT exposed across this untrusted boundary. A
/// delegated (`dip`/`drt`) KEL also fails closed here, because a single-KEL
/// entrypoint cannot supply the delegator's anchoring seals; resolve those through
/// the bundle/org path that carries the delegator KEL alongside it.
///
/// Args:
/// * `kel_json`: JSON array of KEL events (inception, rotation, interaction).
/// * `attachments_json`: JSON array of hex CESR signature attachments, one per event.
///
/// Usage:
/// ```ignore
/// let key_state_json = validateKelJson(kelJson, attachmentsJson).await?;
/// ```
#[wasm_bindgen(js_name = validateKelJson)]
pub async fn wasm_validate_kel_json(
    kel_json: &str,
    attachments_json: &str,
) -> Result<String, JsValue> {
    console_log!("WASM: Authenticating KEL...");

    if kel_json.len() > MAX_JSON_BATCH_SIZE || attachments_json.len() > MAX_JSON_BATCH_SIZE {
        return Err(JsValue::from_str(&format!(
            "KEL input too large: max {MAX_JSON_BATCH_SIZE} bytes per field"
        )));
    }

    let events = auths_keri::parse_kel_json(kel_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse KEL JSON: {}", e)))?;
    let attachments: Vec<String> = serde_json::from_str(attachments_json)
        .map_err(|e| JsValue::from_str(&format!("Failed to parse attachments JSON: {}", e)))?;

    // This entrypoint's wire carries hex; decode to the raw CESR attachment
    // bytes the shared pairing step consumes.
    let attachment_bytes: Vec<Vec<u8>> = attachments
        .iter()
        .map(|att_hex| {
            hex::decode(att_hex)
                .map_err(|e| JsValue::from_str(&format!("Invalid attachment hex: {}", e)))
        })
        .collect::<Result<_, JsValue>>()?;

    // Pairing fails closed on an absent/short attachment list (an
    // unauthenticated KEL must never degrade to a structural-only replay —
    // that fallback is exactly RT-002). The rule lives once, in auths-keri.
    let signed = auths_keri::pair_kel_attachments(events, &attachment_bytes)
        .map_err(|e| JsValue::from_str(&format!("Invalid CESR attachment: {}", e)))?;

    let key_state = auths_keri::validate_signed_kel(&signed, None)
        .map_err(|e| JsValue::from_str(&format!("KEL authentication failed: {}", e)))?;

    console_log!("WASM: KEL authenticated, sequence: {}", key_state.sequence);

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

/// Verify a credential **presentation** from a bundled JSON request (the fn-153.3 contract),
/// returning the tagged discriminated-union verdict as a JSON string.
///
/// Synchronous by construction: the verify core (fn-153.1/.3) runs the pure-Rust
/// `software_verify` path, so there is no `block_on`/executor — which is mandatory in
/// single-threaded browser WASM. Keys travel CESR-tagged inside the request JSON; there is
/// no raw-pubkey argument and no byte-length curve dispatch (`pk_from_hex_wasm` is not used).
///
/// Args:
/// * `bundle_json`: A `VerifyPresentationRequest` JSON document (see `contract` module docs).
///
/// Usage (TypeScript):
/// ```ignore
/// import { verifyPresentationJson } from "auths-verifier";
/// import type { PresentationVerdictEnvelope } from "auths-verifier/ts/verdict";
/// const verdict = JSON.parse(verifyPresentationJson(bundle)) as PresentationVerdictEnvelope;
/// if (verdict.kind === "valid") {
///   // verdict.subject and verdict.caps are now available, fully typed
/// }
/// ```
#[wasm_bindgen(js_name = verifyPresentationJson)]
pub fn wasm_verify_presentation_json(bundle_json: &str) -> String {
    crate::contract::verify_presentation_json(bundle_json)
}

/// Verify an issued **credential** from a bundled JSON request (the fn-153.3 contract),
/// returning the tagged discriminated-union verdict as a JSON string. Same synchronous,
/// executor-free, CESR-tagged-key contract as [`wasm_verify_presentation_json`].
///
/// Args:
/// * `bundle_json`: A `VerifyCredentialRequest` JSON document (see `contract` module docs).
#[wasm_bindgen(js_name = verifyCredentialJson)]
pub fn wasm_verify_credential_json(bundle_json: &str) -> String {
    crate::contract::verify_credential_json(bundle_json)
}

/// Verify an **air-gapped org bundle** offline, returning the tagged verdict
/// envelope (`kind`: `"report"` | `"error"`) as a JSON string.
///
/// Synchronous, executor-free, and panic-free: the verify core
/// ([`crate::org_bundle::verify_org_bundle`]) is a pure function of the
/// bundle's bytes — every event's SAID recomputed, every signature
/// authenticated against the controlling key-state (RT-002), duplicity
/// flagged, and authority classified by KEL position — so the browser
/// computes the same verdict the native CLI does, with zero network.
///
/// Args:
/// * `bundle_json`: The `AirGappedOrgBundle` JSON (the `.auths-offline` file).
/// * `pinned_roots_json`: JSON array of pinned `did:keri:` roots.
/// * `member_did`: Optional member to classify (`did:keri:` or bare prefix).
/// * `signed_at`: Optional in-band signing KEL position, as a decimal string.
#[wasm_bindgen(js_name = verifyOrgBundle)]
pub fn wasm_verify_org_bundle(
    bundle_json: &str,
    pinned_roots_json: &str,
    member_did: Option<String>,
    signed_at: Option<String>,
) -> String {
    crate::org_bundle::verify_org_bundle_json(
        bundle_json,
        pinned_roots_json,
        member_did.as_deref(),
        signed_at.as_deref(),
    )
}

/// Verify an **offline compliance evidence pack** with zero network, returning
/// the tagged verdict envelope (`kind`: `"verdicts"` | `"error"`) as a JSON
/// string — one verdict per evidence row.
///
/// Synchronous, executor-free, and panic-free: the verify core
/// ([`crate::evidence_pack::verify_evidence_pack_offline`]) authenticates the
/// embedded org bundle, re-derives each row's authority-at-release from the
/// embedded KEL (tamper check), and checks each row's transparency-log
/// inclusion/consistency proof — so the dashboard computes the verdict live
/// instead of replaying a recorded native run. With a pinned log key, each
/// row's checkpoint signature is verified against that operator key too
/// (`checkpoint_attested` in the verdict); without one the verdict honestly
/// reports membership only.
///
/// Args:
/// * `pack_json`: The `EvidencePack` JSON (the `.evidence` file).
/// * `pinned_roots_json`: JSON array of pinned `did:keri:` roots.
/// * `pinned_log_key_hex`: The pinned log operator key (64 hex chars,
///   Ed25519), or `undefined` for a membership-only verdict.
#[wasm_bindgen(js_name = verifyEvidencePackOffline)]
pub fn wasm_verify_evidence_pack_offline(
    pack_json: &str,
    pinned_roots_json: &str,
    pinned_log_key_hex: Option<String>,
) -> String {
    crate::evidence_pack::verify_evidence_pack_offline_json(
        pack_json,
        pinned_roots_json,
        pinned_log_key_hex.as_deref(),
    )
}
