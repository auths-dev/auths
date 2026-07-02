//! Generic DSSE bindings: DSSE-sign an arbitrary in-toto Statement with an agent
//! identity, and verify a DSSE envelope offline against a pinned key. Thin
//! wrappers over `auths_sdk::workflows::dsse` — the predicate is entirely the
//! caller's (e.g. a `recurve.dev/verdict/v1` verdict).

use std::sync::Arc;

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

use auths_core::signing::PrefilledPassphraseProvider;
use auths_core::storage::keychain::{
    KeyAlias, KeyStorage, extract_public_key_bytes, get_platform_keychain_with_config,
};
use auths_sdk::workflows::dsse::{
    DsseError, sign_intoto_statement, sign_intoto_statement_with_seed, verify_intoto_statement,
};

use crate::identity::{make_keychain_config, resolve_passphrase};

/// Map a DSSE workflow error onto a tagged Python exception.
fn map_dsse_err(e: DsseError) -> PyErr {
    match e {
        DsseError::InvalidStatement(m) => {
            PyValueError::new_err(format!("[AUTHS_INVALID_INPUT] {m}"))
        }
        DsseError::Decode(m) => PyValueError::new_err(format!("[AUTHS_INVALID_INPUT] {m}")),
        DsseError::Verification(m) => {
            PyValueError::new_err(format!("[AUTHS_VERIFICATION_FAILED] {m}"))
        }
        DsseError::Signing(m) => PyRuntimeError::new_err(format!("[AUTHS_SIGNING_FAILED] {m}")),
    }
}

/// DSSE-sign an in-toto Statement with an agent identity's key.
///
/// The statement's `predicateType` is entirely the caller's; the key's curve is
/// resolved from the keychain (never guessed) and travels in-band on the
/// signature. Returns the DSSE envelope as a JSON string.
///
/// Args:
/// * `statement_json`: The complete in-toto Statement to wrap and sign.
/// * `key_alias`: Keychain alias of the agent's signing key.
/// * `keyid_did`: The agent's `did:keri:`, recorded as the signature keyid.
/// * `repo_path`: Path to the agent's auths keychain/repo.
/// * `passphrase`: Optional passphrase (else `AUTHS_PASSPHRASE`).
///
/// Usage:
/// ```ignore
/// let env = dsse_sign_statement(py, statement, "recurve-ci-agent", did, keychain, None)?;
/// ```
#[pyfunction]
#[pyo3(signature = (statement_json, key_alias, keyid_did, repo_path, passphrase=None))]
pub fn dsse_sign_statement(
    _py: Python<'_>,
    statement_json: String,
    key_alias: String,
    keyid_did: String,
    repo_path: String,
    passphrase: Option<String>,
) -> PyResult<String> {
    let passphrase_str = resolve_passphrase(passphrase);
    let env_config = make_keychain_config(&passphrase_str, &repo_path);
    let keychain: Arc<dyn KeyStorage + Send + Sync> = Arc::from(
        get_platform_keychain_with_config(&env_config)
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_KEYCHAIN_ERROR] {e}")))?,
    );
    let provider = PrefilledPassphraseProvider::new(&passphrase_str);
    let alias = KeyAlias::new(&key_alias).map_err(|e| {
        PyValueError::new_err(format!("[AUTHS_KEY_NOT_FOUND] invalid key alias: {e}"))
    })?;

    let (_pk, curve) = extract_public_key_bytes(keychain.as_ref(), &alias, &provider)
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_KEY_NOT_FOUND] {e}")))?;

    let envelope = sign_intoto_statement(
        keychain,
        &provider,
        &keyid_did,
        &alias,
        curve,
        &statement_json,
    )
    .map_err(map_dsse_err)?;

    serde_json::to_string(&envelope)
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_SERIALIZATION_ERROR] {e}")))
}

/// DSSE-sign an in-toto Statement with a raw private seed (an ephemeral agent).
///
/// The same as `dsse_sign_statement` but for an in-memory identity whose 32-byte
/// seed is held directly rather than in a keychain. The envelope verifies through
/// the same `dsse_verify_statement` path.
///
/// Args:
/// * `statement_json`: The complete in-toto Statement to wrap and sign.
/// * `private_key_hex`: The agent's 32-byte private seed, hex-encoded.
/// * `keyid_did`: The agent's `did:keri:`, recorded as the signature keyid.
/// * `curve`: Optional curve (`"p256"` default, `"ed25519"`).
#[pyfunction]
#[pyo3(signature = (statement_json, private_key_hex, keyid_did, curve=None))]
pub fn dsse_sign_statement_with_key(
    _py: Python<'_>,
    statement_json: String,
    private_key_hex: String,
    keyid_did: String,
    curve: Option<&str>,
) -> PyResult<String> {
    let seed_vec = hex::decode(&private_key_hex).map_err(|e| {
        PyValueError::new_err(format!(
            "[AUTHS_INVALID_INPUT] invalid private key hex: {e}"
        ))
    })?;
    let seed: [u8; 32] = seed_vec
        .as_slice()
        .try_into()
        .map_err(|_| PyValueError::new_err("[AUTHS_INVALID_INPUT] private key must be 32 bytes"))?;
    let curve_type = match curve {
        Some("ed25519") | Some("Ed25519") => auths_crypto::CurveType::Ed25519,
        _ => auths_crypto::CurveType::default(),
    };
    let envelope = sign_intoto_statement_with_seed(&seed, curve_type, &keyid_did, &statement_json)
        .map_err(map_dsse_err)?;
    serde_json::to_string(&envelope)
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_SERIALIZATION_ERROR] {e}")))
}

/// Verify a DSSE-wrapped in-toto Statement offline against a pinned public key.
///
/// Returns the in-toto Statement (JSON string) on success; raises ValueError if
/// no signature verifies against the key (forged, absent, or wrong key). The
/// signature's curve is read in-band, so only the raw verkey hex is needed.
///
/// Args:
/// * `envelope_json`: The DSSE envelope from `dsse_sign_statement`.
/// * `public_key_hex`: The agent's verkey, hex-encoded.
///
/// Usage:
/// ```ignore
/// let statement = dsse_verify_statement(py, envelope, agent_pubkey_hex)?;
/// ```
#[pyfunction]
pub fn dsse_verify_statement(
    _py: Python<'_>,
    envelope_json: String,
    public_key_hex: String,
) -> PyResult<String> {
    let pk = hex::decode(&public_key_hex).map_err(|e| {
        PyValueError::new_err(format!("[AUTHS_INVALID_INPUT] invalid public key hex: {e}"))
    })?;
    let statement = verify_intoto_statement(&envelope_json, &pk).map_err(map_dsse_err)?;
    serde_json::to_string(&statement)
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_SERIALIZATION_ERROR] {e}")))
}
