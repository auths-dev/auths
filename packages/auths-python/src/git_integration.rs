use std::path::PathBuf;

use auths_sdk::workflows::allowed_signers::AllowedSigners;
use auths_sdk::workflows::git_integration::public_key_to_ssh;
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
pub fn generate_allowed_signers_file(_py: Python<'_>, repo_path: &str) -> PyResult<String> {
    let rp = repo_path.to_string();
    {
        let repo = PathBuf::from(shellexpand::tilde(&rp).as_ref());
        let storage = RegistryAttestationStorage::new(&repo);
        let mut signers = AllowedSigners::new("/dev/null");
        signers
            .sync(&storage)
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_REGISTRY_ERROR] {e}")))?;
        let lines: Vec<String> = signers
            .list()
            .iter()
            .filter_map(|entry| {
                let ssh_key = public_key_to_ssh(&entry.public_key).ok()?;
                Some(format!(
                    "{} namespaces=\"git\" {}",
                    entry.principal, ssh_key
                ))
            })
            .collect();
        if lines.is_empty() {
            Ok(String::new())
        } else {
            Ok(format!("{}\n", lines.join("\n")))
        }
    }
}
