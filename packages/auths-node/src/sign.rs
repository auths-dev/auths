use auths_core::signing::{PrefilledPassphraseProvider, SecureSigner, StorageSigner};
use auths_core::storage::keychain::{KeyAlias, get_platform_keychain_with_config};
use auths_verifier::action::ActionEnvelope;
use auths_verifier::core::MAX_ATTESTATION_JSON_SIZE;
use auths_verifier::types::IdentityDID;
use napi_derive::napi;

use crate::error::format_error;
use crate::helpers::{make_env_config, resolve_passphrase};
use crate::types::{NapiActionEnvelope, NapiCommitSignResult};

fn make_signer(
    passphrase: &str,
    repo_path: &str,
) -> napi::Result<(
    StorageSigner<Box<dyn auths_core::storage::keychain::KeyStorage + Send + Sync>>,
    PrefilledPassphraseProvider,
)> {
    let env_config = make_env_config(passphrase, repo_path);
    let keychain = get_platform_keychain_with_config(&env_config)
        .map_err(|e| format_error("AUTHS_KEYCHAIN_ERROR", format!("Keychain error: {e}")))?;
    let signer = StorageSigner::new(keychain);
    let provider = PrefilledPassphraseProvider::new(passphrase);
    Ok((signer, provider))
}

#[napi]
pub fn sign_as_identity(
    message: napi::bindgen_prelude::Buffer,
    identity_did: String,
    repo_path: String,
    passphrase: Option<String>,
) -> napi::Result<NapiCommitSignResult> {
    let passphrase_str = resolve_passphrase(passphrase);
    let (signer, provider) = make_signer(&passphrase_str, &repo_path)?;
    let did =
        IdentityDID::parse(&identity_did).map_err(|e| format_error("AUTHS_INVALID_INPUT", e))?;

    let sig_bytes = signer
        .sign_for_identity(&did, &provider, message.as_ref())
        .map_err(|e| format_error("AUTHS_SIGNING_FAILED", format!("Signing failed: {e}")))?;

    Ok(NapiCommitSignResult {
        signature: hex::encode(sig_bytes),
        signer_did: identity_did,
    })
}

#[napi]
pub fn sign_action_as_identity(
    action_type: String,
    payload_json: String,
    identity_did: String,
    repo_path: String,
    passphrase: Option<String>,
) -> napi::Result<NapiActionEnvelope> {
    if payload_json.len() > MAX_ATTESTATION_JSON_SIZE {
        return Err(format_error(
            "AUTHS_INVALID_INPUT",
            format!(
                "Payload JSON too large: {} bytes, max {MAX_ATTESTATION_JSON_SIZE}",
                payload_json.len()
            ),
        ));
    }

    let payload: serde_json::Value = serde_json::from_str(&payload_json)
        .map_err(|e| format_error("AUTHS_INVALID_INPUT", format!("Invalid payload JSON: {e}")))?;

    #[allow(clippy::disallowed_methods)] // Presentation boundary
    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let signing_data = serde_json::json!({
        "version": "1.0",
        "type": action_type,
        "identity": identity_did,
        "payload": payload,
        "timestamp": &timestamp,
    });

    let canonical = json_canon::to_string(&signing_data).map_err(|e| {
        format_error(
            "AUTHS_SERIALIZATION_ERROR",
            format!("Canonicalization failed: {e}"),
        )
    })?;

    let passphrase_str = resolve_passphrase(passphrase);
    let (signer, provider) = make_signer(&passphrase_str, &repo_path)?;
    let did =
        IdentityDID::parse(&identity_did).map_err(|e| format_error("AUTHS_INVALID_INPUT", e))?;

    let sig_bytes = signer
        .sign_for_identity(&did, &provider, canonical.as_bytes())
        .map_err(|e| format_error("AUTHS_SIGNING_FAILED", format!("Signing failed: {e}")))?;

    let sig_hex = hex::encode(sig_bytes);

    let envelope = serde_json::json!({
        "version": "1.0",
        "type": action_type,
        "identity": identity_did,
        "payload": payload,
        "timestamp": timestamp,
        "signature": sig_hex,
    });

    let envelope_json = serde_json::to_string(&envelope).map_err(|e| {
        format_error(
            "AUTHS_SERIALIZATION_ERROR",
            format!("Failed to serialize envelope: {e}"),
        )
    })?;

    Ok(NapiActionEnvelope {
        envelope_json,
        signature_hex: sig_hex,
        signer_did: identity_did,
    })
}

#[napi]
pub fn sign_as_agent(
    message: napi::bindgen_prelude::Buffer,
    key_alias: String,
    repo_path: String,
    passphrase: Option<String>,
) -> napi::Result<NapiCommitSignResult> {
    let passphrase_str = resolve_passphrase(passphrase);
    let (signer, provider) = make_signer(&passphrase_str, &repo_path)?;
    let alias = KeyAlias::new(&key_alias)
        .map_err(|e| format_error("AUTHS_KEY_NOT_FOUND", format!("Invalid key alias: {e}")))?;

    let sig_bytes = signer
        .sign_with_alias(&alias, &provider, message.as_ref())
        .map_err(|e| format_error("AUTHS_SIGNING_FAILED", format!("Signing failed: {e}")))?;

    Ok(NapiCommitSignResult {
        signature: hex::encode(sig_bytes),
        signer_did: key_alias,
    })
}

#[napi]
pub fn sign_action_as_agent(
    action_type: String,
    payload_json: String,
    key_alias: String,
    agent_did: String,
    repo_path: String,
    passphrase: Option<String>,
) -> napi::Result<NapiActionEnvelope> {
    if payload_json.len() > MAX_ATTESTATION_JSON_SIZE {
        return Err(format_error(
            "AUTHS_INVALID_INPUT",
            format!(
                "Payload JSON too large: {} bytes, max {MAX_ATTESTATION_JSON_SIZE}",
                payload_json.len()
            ),
        ));
    }

    let payload: serde_json::Value = serde_json::from_str(&payload_json)
        .map_err(|e| format_error("AUTHS_INVALID_INPUT", format!("Invalid payload JSON: {e}")))?;

    #[allow(clippy::disallowed_methods)]
    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let signing_data = serde_json::json!({
        "version": "1.0",
        "type": action_type,
        "identity": agent_did,
        "payload": payload,
        "timestamp": &timestamp,
    });

    let canonical = json_canon::to_string(&signing_data).map_err(|e| {
        format_error(
            "AUTHS_SERIALIZATION_ERROR",
            format!("Canonicalization failed: {e}"),
        )
    })?;

    let passphrase_str = resolve_passphrase(passphrase);
    let (signer, provider) = make_signer(&passphrase_str, &repo_path)?;
    let alias = KeyAlias::new(&key_alias)
        .map_err(|e| format_error("AUTHS_KEY_NOT_FOUND", format!("Invalid key alias: {e}")))?;

    let sig_bytes = signer
        .sign_with_alias(&alias, &provider, canonical.as_bytes())
        .map_err(|e| format_error("AUTHS_SIGNING_FAILED", format!("Signing failed: {e}")))?;

    let sig_hex = hex::encode(sig_bytes);

    let envelope = serde_json::json!({
        "version": "1.0",
        "type": action_type,
        "identity": agent_did,
        "payload": payload,
        "timestamp": timestamp,
        "signature": sig_hex,
    });

    let envelope_json = serde_json::to_string(&envelope).map_err(|e| {
        format_error(
            "AUTHS_SERIALIZATION_ERROR",
            format!("Failed to serialize envelope: {e}"),
        )
    })?;

    Ok(NapiActionEnvelope {
        envelope_json,
        signature_hex: sig_hex,
        signer_did: agent_did,
    })
}

/// Decode a hex-encoded signing seed and validate its length.
///
/// Seeds are always 32 bytes for both Ed25519 (RFC 8032) and P-256
/// (NIST scalar). The curve is supplied separately via the `curve` FFI param
/// and bound to the seed via `TypedSeed` at the call site.
fn decode_seed_hex(private_key_hex: &str) -> napi::Result<[u8; 32]> {
    let seed = hex::decode(private_key_hex).map_err(|e| {
        format_error(
            "AUTHS_INVALID_INPUT",
            format!("Invalid private key hex: {e}"),
        )
    })?;
    seed.as_slice().try_into().map_err(|_| {
        format_error(
            "AUTHS_INVALID_INPUT",
            format!(
                "Invalid seed length: expected 32 bytes (64 hex chars), got {}",
                seed.len()
            ),
        )
    })
}

/// Parse a CLI/FFI curve hint. `None` or unrecognized → P-256 default.
fn parse_curve_hint(curve: Option<String>) -> auths_crypto::CurveType {
    match curve.as_deref() {
        Some("Ed25519") | Some("ed25519") => auths_crypto::CurveType::Ed25519,
        _ => auths_crypto::CurveType::P256,
    }
}

fn typed_seed_for(curve: auths_crypto::CurveType, seed: [u8; 32]) -> auths_crypto::TypedSeed {
    match curve {
        auths_crypto::CurveType::Ed25519 => auths_crypto::TypedSeed::Ed25519(seed),
        auths_crypto::CurveType::P256 => auths_crypto::TypedSeed::P256(seed),
    }
}

/// Sign raw bytes with a hex-encoded signing seed.
///
/// Curve is dispatched via the `curve` argument (defaults to P-256 per the
/// workspace wire-format curve-tagging rule).
///
/// Args:
/// * `private_key_hex`: 32-byte signing seed as hex string (64 chars).
/// * `message`: The bytes to sign.
/// * `curve`: Optional curve hint (`"Ed25519"` / `"P256"`). Absent → P-256.
///
/// Usage:
/// ```ignore
/// let sig = sign_bytes_raw("deadbeef...".into(), buffer, Some("P256".into()))?;
/// ```
#[napi]
pub fn sign_bytes_raw(
    private_key_hex: String,
    message: napi::bindgen_prelude::Buffer,
    curve: Option<String>,
) -> napi::Result<String> {
    let seed = decode_seed_hex(&private_key_hex)?;
    let typed = typed_seed_for(parse_curve_hint(curve), seed);
    let sig_bytes = auths_crypto::typed_sign(&typed, message.as_ref())
        .map_err(|e| format_error("AUTHS_CRYPTO_ERROR", format!("Failed to sign: {e}")))?;
    Ok(hex::encode(sig_bytes))
}

/// Sign an action envelope with a hex-encoded signing seed.
///
/// Curve is dispatched via the `curve` argument (defaults to P-256 per the
/// workspace wire-format curve-tagging rule).
///
/// Args:
/// * `private_key_hex`: 32-byte signing seed as hex string (64 chars).
/// * `action_type`: Application-defined action type (e.g. "tool_call").
/// * `payload_json`: JSON string for the payload field.
/// * `identity_did`: Signer's identity DID (e.g. "did:keri:E...").
/// * `curve`: Optional curve hint (`"Ed25519"` / `"P256"`). Absent → P-256.
///
/// Usage:
/// ```ignore
/// let envelope = sign_action_raw("deadbeef...".into(), "tool_call".into(), "{}".into(), "did:keri:E...".into(), Some("P256".into()))?;
/// ```
#[napi]
pub fn sign_action_raw(
    private_key_hex: String,
    action_type: String,
    payload_json: String,
    identity_did: String,
    curve: Option<String>,
) -> napi::Result<String> {
    if payload_json.len() > MAX_ATTESTATION_JSON_SIZE {
        return Err(format_error(
            "AUTHS_INVALID_INPUT",
            format!(
                "Payload JSON too large: {} bytes, max {MAX_ATTESTATION_JSON_SIZE}",
                payload_json.len()
            ),
        ));
    }

    let payload: serde_json::Value = serde_json::from_str(&payload_json)
        .map_err(|e| format_error("AUTHS_INVALID_INPUT", format!("Invalid payload JSON: {e}")))?;

    let seed = decode_seed_hex(&private_key_hex)?;

    #[allow(clippy::disallowed_methods)] // Presentation boundary
    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let mut envelope = ActionEnvelope {
        version: "1.0".into(),
        action_type,
        identity: identity_did,
        payload,
        timestamp,
        signature: String::new(),
        attestation_chain: None,
        environment: None,
    };

    let canonical = envelope
        .canonical_bytes()
        .map_err(|e| format_error("AUTHS_SERIALIZATION_ERROR", e))?;

    let typed = typed_seed_for(parse_curve_hint(curve), seed);
    let sig_bytes = auths_crypto::typed_sign(&typed, &canonical)
        .map_err(|e| format_error("AUTHS_CRYPTO_ERROR", format!("Failed to sign: {e}")))?;
    envelope.signature = hex::encode(sig_bytes);

    serde_json::to_string(&envelope).map_err(|e| {
        format_error(
            "AUTHS_SERIALIZATION_ERROR",
            format!("Failed to serialize envelope: {e}"),
        )
    })
}
