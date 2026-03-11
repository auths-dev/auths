use auths_core::config::{EnvironmentConfig, KeychainConfig};
use auths_core::signing::{PrefilledPassphraseProvider, SecureSigner, StorageSigner};
use auths_core::storage::keychain::{KeyAlias, KeyRole, get_platform_keychain_with_config};
use auths_verifier::core::MAX_ATTESTATION_JSON_SIZE;
use auths_verifier::types::IdentityDID;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;

fn make_signer(
    repo_path: Option<&str>,
    passphrase: Option<String>,
) -> PyResult<(
    StorageSigner<Box<dyn auths_core::storage::keychain::KeyStorage + Send + Sync>>,
    PrefilledPassphraseProvider,
)> {
    #[allow(clippy::disallowed_methods)] // Presentation boundary: env var read is intentional
    let passphrase_str =
        passphrase.unwrap_or_else(|| std::env::var("AUTHS_PASSPHRASE").unwrap_or_default());
    let mut keychain_config = KeychainConfig::from_env();
    if keychain_config.backend.is_none() {
        keychain_config.backend = Some("file".to_string());
    }
    keychain_config.passphrase = Some(passphrase_str.clone());
    let env_config = EnvironmentConfig {
        auths_home: repo_path.map(Into::into),
        keychain: keychain_config,
        ssh_agent_socket: None,
    };

    let keychain = get_platform_keychain_with_config(&env_config).map_err(|e| {
        PyRuntimeError::new_err(format!("[AUTHS_KEYCHAIN_ERROR] Keychain error: {e}"))
    })?;

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
    let (signer, provider) = make_signer(Some(repo_path), passphrase)?;
    let did = IdentityDID::new_unchecked(identity_did);

    let msg = message.to_vec();
    py.allow_threads(move || {
        let sig_bytes = signer
            .sign_for_identity(&did, &provider, &msg)
            .map_err(|e| {
                PyRuntimeError::new_err(format!("[AUTHS_SIGNING_FAILED] Signing failed: {e}"))
            })?;
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
    if payload_json.len() > MAX_ATTESTATION_JSON_SIZE {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "Payload JSON too large: {} bytes, max {MAX_ATTESTATION_JSON_SIZE}",
            payload_json.len()
        )));
    }

    let payload: serde_json::Value = serde_json::from_str(payload_json).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("Invalid payload JSON: {e}"))
    })?;

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
        PyRuntimeError::new_err(format!(
            "[AUTHS_SERIALIZATION_ERROR] Canonicalization failed: {e}"
        ))
    })?;

    let (signer, provider) = make_signer(Some(repo_path), passphrase)?;
    let did = IdentityDID::new_unchecked(identity_did);

    let action_type_owned = action_type.to_string();
    let identity_did_owned = identity_did.to_string();

    let sig_hex = py.allow_threads(move || {
        let sig_bytes = signer
            .sign_for_identity(&did, &provider, canonical.as_bytes())
            .map_err(|e| {
                PyRuntimeError::new_err(format!("[AUTHS_SIGNING_FAILED] Signing failed: {e}"))
            })?;
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

    serde_json::to_string(&envelope).map_err(|e| {
        PyRuntimeError::new_err(format!(
            "[AUTHS_SERIALIZATION_ERROR] Failed to serialize envelope: {e}"
        ))
    })
}

/// Retrieve the Ed25519 public key (hex) for an identity DID.
///
/// Args:
/// * `identity_did`: The identity DID (did:keri:...).
/// * `repo_path`: Path to the auths repository.
/// * `passphrase`: Optional passphrase for keychain access.
///
/// Usage:
/// ```ignore
/// let pub_hex = get_identity_public_key(py, "did:keri:E...", "~/.auths", None)?;
/// ```
#[pyfunction]
#[pyo3(signature = (identity_did, repo_path, passphrase=None))]
pub fn get_identity_public_key(
    py: Python<'_>,
    identity_did: &str,
    repo_path: &str,
    passphrase: Option<String>,
) -> PyResult<String> {
    let (signer, provider) = make_signer(Some(repo_path), passphrase)?;
    let did = IdentityDID::new_unchecked(identity_did);

    py.allow_threads(move || {
        let aliases = signer
            .inner()
            .list_aliases_for_identity_with_role(&did, KeyRole::Primary)
            .map_err(|e| {
                PyRuntimeError::new_err(format!("[AUTHS_KEY_NOT_FOUND] Key lookup failed: {e}"))
            })?;
        let alias = aliases.first().ok_or_else(|| {
            PyRuntimeError::new_err(format!(
                "[AUTHS_KEY_NOT_FOUND] No primary key found for identity '{identity_did}'"
            ))
        })?;
        let pub_bytes = auths_core::storage::keychain::extract_public_key_bytes(
            signer.inner().as_ref(),
            alias,
            &provider,
        )
        .map_err(|e| {
            PyRuntimeError::new_err(format!(
                "[AUTHS_CRYPTO_ERROR] Public key extraction failed: {e}"
            ))
        })?;
        Ok(hex::encode(pub_bytes))
    })
}

/// Sign arbitrary bytes using a keychain-stored agent key (by alias).
///
/// Unlike `sign_as_identity` which resolves by DID, this signs using a key alias
/// directly — enabling delegated agents (did:key:) to sign with their own key.
///
/// Args:
/// * `message`: The bytes to sign.
/// * `key_alias`: The agent's key alias (e.g., "deploy-agent").
/// * `repo_path`: Path to the auths repository.
/// * `passphrase`: Optional passphrase for keychain access.
///
/// Usage:
/// ```ignore
/// let sig = sign_as_agent(py, b"hello", "deploy-bot-agent", "~/.auths", None)?;
/// ```
#[pyfunction]
#[pyo3(signature = (message, key_alias, repo_path, passphrase=None))]
pub fn sign_as_agent(
    py: Python<'_>,
    message: &[u8],
    key_alias: &str,
    repo_path: &str,
    passphrase: Option<String>,
) -> PyResult<String> {
    let (signer, provider) = make_signer(Some(repo_path), passphrase)?;
    let alias = KeyAlias::new(key_alias).map_err(|e| {
        PyRuntimeError::new_err(format!("[AUTHS_KEY_NOT_FOUND] Invalid key alias: {e}"))
    })?;

    let msg = message.to_vec();
    py.allow_threads(move || {
        let sig_bytes = signer
            .sign_with_alias(&alias, &provider, &msg)
            .map_err(|e| {
                PyRuntimeError::new_err(format!("[AUTHS_SIGNING_FAILED] Signing failed: {e}"))
            })?;
        Ok(hex::encode(sig_bytes))
    })
}

/// Sign an action envelope using an agent's key alias.
///
/// Args:
/// * `action_type`: Application-defined action type.
/// * `payload_json`: JSON string for the payload field.
/// * `key_alias`: The agent's key alias.
/// * `agent_did`: The agent's DID (included in the envelope).
/// * `repo_path`: Path to the auths repository.
/// * `passphrase`: Optional passphrase for keychain access.
///
/// Usage:
/// ```ignore
/// let envelope = sign_action_as_agent(py, "deploy", "{}", "deploy-bot-agent", "did:key:z6Mk...", "~/.auths", None)?;
/// ```
#[pyfunction]
#[pyo3(signature = (action_type, payload_json, key_alias, agent_did, repo_path, passphrase=None))]
pub fn sign_action_as_agent(
    py: Python<'_>,
    action_type: &str,
    payload_json: &str,
    key_alias: &str,
    agent_did: &str,
    repo_path: &str,
    passphrase: Option<String>,
) -> PyResult<String> {
    if payload_json.len() > MAX_ATTESTATION_JSON_SIZE {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "Payload JSON too large: {} bytes, max {MAX_ATTESTATION_JSON_SIZE}",
            payload_json.len()
        )));
    }

    let payload: serde_json::Value = serde_json::from_str(payload_json).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("Invalid payload JSON: {e}"))
    })?;

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
        PyRuntimeError::new_err(format!(
            "[AUTHS_SERIALIZATION_ERROR] Canonicalization failed: {e}"
        ))
    })?;

    let (signer, provider) = make_signer(Some(repo_path), passphrase)?;
    let alias = KeyAlias::new(key_alias).map_err(|e| {
        PyRuntimeError::new_err(format!("[AUTHS_KEY_NOT_FOUND] Invalid key alias: {e}"))
    })?;

    let action_type_owned = action_type.to_string();
    let agent_did_owned = agent_did.to_string();

    let sig_hex = py.allow_threads(move || {
        let sig_bytes = signer
            .sign_with_alias(&alias, &provider, canonical.as_bytes())
            .map_err(|e| {
                PyRuntimeError::new_err(format!("[AUTHS_SIGNING_FAILED] Signing failed: {e}"))
            })?;
        Ok::<String, PyErr>(hex::encode(sig_bytes))
    })?;

    let envelope = serde_json::json!({
        "version": "1.0",
        "type": action_type_owned,
        "identity": agent_did_owned,
        "payload": payload,
        "timestamp": timestamp,
        "signature": sig_hex,
    });

    serde_json::to_string(&envelope).map_err(|e| {
        PyRuntimeError::new_err(format!(
            "[AUTHS_SERIALIZATION_ERROR] Failed to serialize envelope: {e}"
        ))
    })
}
