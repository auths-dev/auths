use auths_core::config::{EnvironmentConfig, KeychainConfig};
use auths_core::signing::{PrefilledPassphraseProvider, SecureSigner, StorageSigner};
use auths_core::storage::keychain::get_platform_keychain_with_config;
use auths_verifier::core::MAX_ATTESTATION_JSON_SIZE;
use auths_verifier::types::IdentityDID;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;

fn make_signer(
    passphrase: Option<String>,
) -> PyResult<(
    StorageSigner<Box<dyn auths_core::storage::keychain::KeyStorage + Send + Sync>>,
    PrefilledPassphraseProvider,
)> {
    let passphrase_str =
        passphrase.unwrap_or_else(|| std::env::var("AUTHS_PASSPHRASE").unwrap_or_default());
    let env_config = EnvironmentConfig {
        auths_home: None,
        keychain: KeychainConfig {
            backend: Some("file".to_string()),
            file_path: None,
            passphrase: Some(passphrase_str.clone()),
        },
        ssh_agent_socket: None,
        #[cfg(feature = "keychain-pkcs11")]
        pkcs11: None,
    };

    let keychain = get_platform_keychain_with_config(&env_config)
        .map_err(|e| PyRuntimeError::new_err(format!("Keychain error: {e}")))?;

    let signer = StorageSigner::new(keychain);
    let provider = PrefilledPassphraseProvider::new(&passphrase_str);
    Ok((signer, provider))
}

/// Sign arbitrary bytes using a keychain-stored identity key.
///
/// Args:
/// * `message`: The bytes to sign.
/// * `identity_did`: The identity DID (did:keri:...) whose key to use.
/// * `repo_path`: Path to the auths repository.
/// * `passphrase`: Optional passphrase for the keychain (reads AUTHS_PASSPHRASE if None).
///
/// Usage:
/// ```ignore
/// let sig = sign_as_identity(py, b"hello", "did:keri:E...", "~/.auths", None)?;
/// ```
#[pyfunction]
#[pyo3(signature = (message, identity_did, repo_path, passphrase=None))]
pub fn sign_as_identity(
    py: Python<'_>,
    message: &[u8],
    identity_did: &str,
    repo_path: &str,
    passphrase: Option<String>,
) -> PyResult<String> {
    let _ = repo_path;
    let (signer, provider) = make_signer(passphrase)?;
    let did = IdentityDID::new(identity_did);

    let msg = message.to_vec();
    py.allow_threads(move || {
        let sig_bytes = signer
            .sign_for_identity(&did, &provider, &msg)
            .map_err(|e| PyRuntimeError::new_err(format!("Signing failed: {e}")))?;
        Ok(hex::encode(sig_bytes))
    })
}

/// Sign an action envelope using a keychain-stored identity key.
///
/// Args:
/// * `action_type`: Application-defined action type (e.g. "tool_call").
/// * `payload_json`: JSON string for the payload field.
/// * `identity_did`: The identity DID (did:keri:...) whose key to use.
/// * `repo_path`: Path to the auths repository.
/// * `passphrase`: Optional passphrase for the keychain (reads AUTHS_PASSPHRASE if None).
///
/// Usage:
/// ```ignore
/// let envelope = sign_action_as_identity(py, "deploy", "{}", "did:keri:E...", "~/.auths", None)?;
/// ```
#[pyfunction]
#[pyo3(signature = (action_type, payload_json, identity_did, repo_path, passphrase=None))]
pub fn sign_action_as_identity(
    py: Python<'_>,
    action_type: &str,
    payload_json: &str,
    identity_did: &str,
    repo_path: &str,
    passphrase: Option<String>,
) -> PyResult<String> {
    let _ = repo_path;

    if payload_json.len() > MAX_ATTESTATION_JSON_SIZE {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "Payload JSON too large: {} bytes, max {MAX_ATTESTATION_JSON_SIZE}",
            payload_json.len()
        )));
    }

    let payload: serde_json::Value = serde_json::from_str(payload_json).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("Invalid payload JSON: {e}"))
    })?;

    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);

    let signing_data = serde_json::json!({
        "version": "1.0",
        "type": action_type,
        "identity": identity_did,
        "payload": payload,
        "timestamp": &timestamp,
    });

    let canonical = json_canon::to_string(&signing_data)
        .map_err(|e| PyRuntimeError::new_err(format!("Canonicalization failed: {e}")))?;

    let (signer, provider) = make_signer(passphrase)?;
    let did = IdentityDID::new(identity_did);

    let action_type_owned = action_type.to_string();
    let identity_did_owned = identity_did.to_string();

    let sig_hex = py.allow_threads(move || {
        let sig_bytes = signer
            .sign_for_identity(&did, &provider, canonical.as_bytes())
            .map_err(|e| PyRuntimeError::new_err(format!("Signing failed: {e}")))?;
        Ok::<String, PyErr>(hex::encode(sig_bytes))
    })?;

    let envelope = serde_json::json!({
        "version": "1.0",
        "type": action_type_owned,
        "identity": identity_did_owned,
        "payload": payload,
        "timestamp": timestamp,
        "signature": sig_hex,
    });

    serde_json::to_string(&envelope)
        .map_err(|e| PyRuntimeError::new_err(format!("Failed to serialize envelope: {e}")))
}
