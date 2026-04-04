use auths_core::signing::{PrefilledPassphraseProvider, SecureSigner, StorageSigner};
use auths_core::storage::keychain::{KeyAlias, get_platform_keychain_with_config};
use auths_verifier::action::ActionEnvelope;
use auths_verifier::core::MAX_ATTESTATION_JSON_SIZE;
use auths_verifier::types::IdentityDID;
use napi_derive::napi;
use ring::signature::Ed25519KeyPair;

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

/// Decode a hex-encoded Ed25519 seed and validate its length.
fn decode_seed_hex(private_key_hex: &str) -> napi::Result<Vec<u8>> {
    let seed = hex::decode(private_key_hex)
        .map_err(|e| format_error("AUTHS_INVALID_INPUT", format!("Invalid private key hex: {e}")))?;
    if seed.len() != 32 {
        return Err(format_error(
            "AUTHS_INVALID_INPUT",
            format!(
                "Invalid private key length: expected 32 bytes (64 hex chars), got {}",
                seed.len()
            ),
        ));
    }
    Ok(seed)
}

/// Sign raw bytes with a hex-encoded Ed25519 private key.
///
/// Args:
/// * `private_key_hex`: Ed25519 seed as hex string (64 chars = 32 bytes).
/// * `message`: The bytes to sign.
///
/// Usage:
/// ```ignore
/// let sig = sign_bytes_raw("deadbeef...".into(), buffer)?;
/// ```
#[napi]
pub fn sign_bytes_raw(
    private_key_hex: String,
    message: napi::bindgen_prelude::Buffer,
) -> napi::Result<String> {
    let seed = decode_seed_hex(&private_key_hex)?;
    let keypair = Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|e| {
        format_error(
            "AUTHS_CRYPTO_ERROR",
            format!("Failed to create keypair: {e}"),
        )
    })?;
    let sig = keypair.sign(message.as_ref());
    Ok(hex::encode(sig.as_ref()))
}

/// Sign an action envelope with a hex-encoded Ed25519 private key.
///
/// Args:
/// * `private_key_hex`: Ed25519 seed as hex string (64 chars = 32 bytes).
/// * `action_type`: Application-defined action type (e.g. "tool_call").
/// * `payload_json`: JSON string for the payload field.
/// * `identity_did`: Signer's identity DID (e.g. "did:keri:E...").
///
/// Usage:
/// ```ignore
/// let envelope = sign_action_raw("deadbeef...".into(), "tool_call".into(), "{}".into(), "did:keri:E...".into())?;
/// ```
#[napi]
pub fn sign_action_raw(
    private_key_hex: String,
    action_type: String,
    payload_json: String,
    identity_did: String,
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

    let canonical = envelope.canonical_bytes().map_err(|e| {
        format_error("AUTHS_SERIALIZATION_ERROR", e)
    })?;

    let keypair = Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|e| {
        format_error(
            "AUTHS_CRYPTO_ERROR",
            format!("Failed to create keypair: {e}"),
        )
    })?;

    let sig = keypair.sign(&canonical);
    envelope.signature = hex::encode(sig.as_ref());

    serde_json::to_string(&envelope).map_err(|e| {
        format_error(
            "AUTHS_SERIALIZATION_ERROR",
            format!("Failed to serialize envelope: {e}"),
        )
    })
}
