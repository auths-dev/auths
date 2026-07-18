//! Ephemeral in-memory agent identity: a did:keri agent minted with no
//! passphrase KDF and no persistent keychain. Its private seed is returned so a
//! caller signs directly (raw-key `sign_action` / `dsse_sign_statement_with_key`)
//! instead of through a keychain. The identity lives only in the returned values.

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

use auths_verifier::types::CanonicalDid;

use crate::identity::validate_capabilities;

/// An ephemeral agent identity (in-memory; not persisted).
#[pyclass(frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PyEphemeralAgent {
    /// The agent's `did:keri:` identifier.
    #[pyo3(get)]
    pub did: String,
    /// The agent's public key, hex-encoded.
    #[pyo3(get)]
    pub public_key: String,
    /// The agent's raw 32-byte private seed, hex-encoded (for direct signing).
    #[pyo3(get)]
    pub private_key: String,
    /// A self-attestation binding the agent's capabilities (the mark of an agent).
    #[pyo3(get)]
    pub attestation_json: String,
}

#[pymethods]
impl PyEphemeralAgent {
    fn __repr__(&self) -> String {
        format!("EphemeralAgent(did='{}')", self.did)
    }
}

/// Mint an ephemeral `did:keri` agent identity in-memory, with no passphrase KDF.
///
/// Runs a KERI inception in a throwaway repository and returns the agent's
/// `did:keri`, its public key, its raw private seed (hex, for direct signing),
/// and a self-attestation binding the requested capabilities. Nothing is
/// persisted — the throwaway repository is discarded.
///
/// Args:
/// * `agent_name`: Human-readable agent name.
/// * `capabilities`: Capabilities to bind into the attestation.
///
/// Usage:
/// ```ignore
/// let agent = create_ephemeral_agent(py, "recurve-ci-agent", vec!["sign".into()])?;
/// ```
#[pyfunction]
#[pyo3(signature = (agent_name, capabilities))]
pub fn create_ephemeral_agent(
    _py: Python<'_>,
    agent_name: &str,
    capabilities: Vec<String>,
) -> PyResult<PyEphemeralAgent> {
    validate_capabilities(&capabilities)?;

    let tmp = tempfile::tempdir()
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_IO_ERROR] tempdir: {e}")))?;
    let repo = git2::Repository::init(tmp.path())
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_REGISTRY_ERROR] repo init: {e}")))?;

    #[allow(clippy::disallowed_methods)] // presentation boundary: ephemeral inception timestamp
    let now = chrono::Utc::now();
    let inception = auths_id::keri::create_keri_identity(&repo, None, now)
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_IDENTITY_ERROR] inception: {e}")))?;

    let did = inception.did();
    let signer = auths_crypto::TypedSignerKey::from_pkcs8(inception.current_keypair_pkcs8.as_ref())
        .map_err(|e| PyValueError::new_err(format!("[AUTHS_CRYPTO_ERROR] key parse: {e}")))?;
    let seed_hex = hex::encode(signer.seed().as_bytes());
    let pub_hex = hex::encode(&inception.current_public_key);
    let curve = signer.curve();

    let device_did = CanonicalDid::from_public_key_did_key(&inception.current_public_key, curve);
    let attestation = serde_json::json!({
        "version": 1,
        "rid": "ephemeral",
        "issuer": did,
        "subject": device_did.to_string(),
        "device_public_key": pub_hex,
        "timestamp": now.to_rfc3339(),
        "capabilities": capabilities,
        "note": format!("Ephemeral agent: {agent_name}"),
    });

    Ok(PyEphemeralAgent {
        did,
        public_key: pub_hex,
        private_key: seed_hex,
        attestation_json: attestation.to_string(),
    })
}
