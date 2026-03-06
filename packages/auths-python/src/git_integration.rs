use std::path::PathBuf;

use auths_sdk::workflows::git_integration::{generate_allowed_signers, format_allowed_signers_file};
use auths_storage::git::RegistryAttestationStorage;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;

/// Generate an `allowed_signers` file content from live Auths storage.
///
/// Reads device attestations from the Git-backed identity store and formats
/// them for `gpg.ssh.allowedSignersFile`. Skips revoked attestations and
/// devices whose public key cannot be parsed.
///
/// Args:
/// * `repo_path`: Path to the Auths identity repository (default: `~/.auths`).
///
/// Usage:
/// ```ignore
/// let content = generate_allowed_signers_file(py, "~/.auths")?;
/// std::fs::write(".auths/allowed_signers", content).unwrap();
/// ```
#[pyfunction]
#[pyo3(signature = (repo_path = "~/.auths"))]
pub fn generate_allowed_signers_file(py: Python<'_>, repo_path: &str) -> PyResult<String> {
    let rp = repo_path.to_string();
    py.allow_threads(move || {
        let repo = PathBuf::from(shellexpand::tilde(&rp).as_ref());
        let storage = RegistryAttestationStorage::new(&repo);
        let entries = generate_allowed_signers(&storage)
            .map_err(|e: auths_sdk::workflows::git_integration::GitIntegrationError| PyRuntimeError::new_err(e.to_string()))?;
        Ok(format_allowed_signers_file(&entries))
    })
}
