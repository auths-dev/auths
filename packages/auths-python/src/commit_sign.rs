use std::path::PathBuf;
use std::sync::Arc;

use auths_core::signing::PrefilledPassphraseProvider;
use auths_core::storage::keychain::get_platform_keychain_with_config;
use auths_sdk::workflows::signing::{
    CommitSigningContext, CommitSigningParams, CommitSigningWorkflow,
};
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;

use crate::identity::{make_keychain_config, resolve_passphrase};

#[pyclass]
#[derive(Clone)]
pub struct PyCommitSignResult {
    #[pyo3(get)]
    pub signature_pem: String,
    #[pyo3(get)]
    pub method: String,
    #[pyo3(get)]
    pub namespace: String,
}

#[pymethods]
impl PyCommitSignResult {
    fn __repr__(&self) -> String {
        let pem_preview = if self.signature_pem.len() > 40 {
            format!("{}...", &self.signature_pem[..40])
        } else {
            self.signature_pem.clone()
        };
        format!(
            "CommitSignResult(method='{}', pem='{}')",
            self.method, pem_preview,
        )
    }
}

/// Sign git commit/tag data, producing an SSHSIG PEM signature.
///
/// Uses a 3-tier fallback: ssh-agent -> auto-start -> direct signing.
/// In headless environments (Python SDK), falls through to direct signing.
///
/// Args:
/// * `data`: The raw commit or tag bytes to sign.
/// * `identity_key_alias`: Keychain alias for the identity key.
/// * `repo_path`: Path to the auths repository.
/// * `passphrase`: Optional passphrase for the keychain.
///
/// Usage:
/// ```ignore
/// let result = sign_commit(py, b"commit data", "main", "~/.auths", None)?;
/// ```
#[pyfunction]
#[pyo3(signature = (data, identity_key_alias, repo_path, passphrase=None))]
pub fn sign_commit(
    py: Python<'_>,
    data: &[u8],
    identity_key_alias: &str,
    repo_path: &str,
    passphrase: Option<String>,
) -> PyResult<PyCommitSignResult> {
    let passphrase_str = resolve_passphrase(passphrase);
    let env_config = make_keychain_config(&passphrase_str);
    let provider = Arc::new(PrefilledPassphraseProvider::new(&passphrase_str));

    let keychain = get_platform_keychain_with_config(&env_config)
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_KEYCHAIN_ERROR] Keychain error: {e}")))?;
    let keychain = Arc::from(keychain);

    let repo = PathBuf::from(shellexpand::tilde(repo_path).as_ref());

    let params =
        CommitSigningParams::new(identity_key_alias, "git", data.to_vec()).with_repo_path(repo);

    let signing_ctx = CommitSigningContext {
        key_storage: keychain,
        passphrase_provider: provider,
        agent_signing: Arc::new(auths_sdk::ports::agent::NoopAgentProvider),
    };

    #[allow(clippy::disallowed_methods)] // Presentation boundary
    let now = chrono::Utc::now();

    py.allow_threads(move || {
        let pem = CommitSigningWorkflow::execute(&signing_ctx, params, now)
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_SIGNING_FAILED] Commit signing failed: {e}")))?;

        Ok(PyCommitSignResult {
            signature_pem: pem,
            method: "direct".to_string(),
            namespace: "git".to_string(),
        })
    })
}
