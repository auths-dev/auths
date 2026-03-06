use std::path::PathBuf;
use std::sync::Arc;

use auths_id::attestation::group::AttestationGroup;
use auths_id::storage::attestation::AttestationSource;
use auths_storage::git::{GitRegistryBackend, RegistryAttestationStorage, RegistryConfig};
use auths_verifier::core::Attestation;
use auths_verifier::types::DeviceDID;
use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;

#[pyclass]
#[derive(Clone)]
pub struct PyAttestation {
    #[pyo3(get)]
    pub rid: String,
    #[pyo3(get)]
    pub issuer: String,
    #[pyo3(get)]
    pub subject: String,
    #[pyo3(get)]
    pub device_did: String,
    #[pyo3(get)]
    pub capabilities: Vec<String>,
    #[pyo3(get)]
    pub signer_type: Option<String>,
    #[pyo3(get)]
    pub expires_at: Option<String>,
    #[pyo3(get)]
    pub revoked_at: Option<String>,
    #[pyo3(get)]
    pub created_at: Option<String>,
    #[pyo3(get)]
    pub delegated_by: Option<String>,
    #[pyo3(get)]
    pub json: String,
}

#[pymethods]
impl PyAttestation {
    fn __repr__(&self) -> String {
        let status = if self.revoked_at.is_some() {
            "revoked"
        } else {
            "active"
        };
        let rid_short = if self.rid.len() > 16 {
            &self.rid[..16]
        } else {
            &self.rid
        };
        format!(
            "PyAttestation(rid='{rid_short}...', subject='{}...', status={status})",
            &self.subject[..self.subject.len().min(20)],
        )
    }
}

fn attestation_to_py(att: &Attestation) -> PyAttestation {
    let json = serde_json::to_string(att).unwrap_or_default();
    PyAttestation {
        rid: att.rid.to_string(),
        issuer: att.issuer.to_string(),
        subject: att.subject.to_string(),
        device_did: att.subject.to_string(),
        capabilities: att.capabilities.iter().map(|c| c.to_string()).collect(),
        signer_type: att.signer_type.as_ref().map(|s| format!("{s:?}")),
        expires_at: att.expires_at.map(|t| t.to_rfc3339()),
        revoked_at: att.revoked_at.map(|t| t.to_rfc3339()),
        created_at: att.timestamp.map(|t| t.to_rfc3339()),
        delegated_by: att.delegated_by.as_ref().map(|d| d.to_string()),
        json,
    }
}

fn open_attestation_storage(
    repo_path: &str,
) -> PyResult<Arc<RegistryAttestationStorage>> {
    let repo = PathBuf::from(shellexpand::tilde(repo_path).as_ref());
    let config = RegistryConfig::single_tenant(&repo);
    let _backend = GitRegistryBackend::open_existing(config)
        .map_err(|e| PyRuntimeError::new_err(format!("Failed to open registry: {e}")))?;
    Ok(Arc::new(RegistryAttestationStorage::new(&repo)))
}

/// List all attestations in the repository.
///
/// Args:
/// * `repo_path`: Path to the auths repository.
///
/// Usage:
/// ```ignore
/// let atts = list_attestations(py, "~/.auths")?;
/// ```
#[pyfunction]
pub fn list_attestations(py: Python<'_>, repo_path: &str) -> PyResult<Vec<PyAttestation>> {
    let storage = open_attestation_storage(repo_path)?;
    py.allow_threads(|| {
        let all = storage
            .load_all_attestations()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to load attestations: {e}")))?;
        Ok(all.iter().map(attestation_to_py).collect())
    })
}

/// List attestations for a specific device DID.
///
/// Args:
/// * `repo_path`: Path to the auths repository.
/// * `device_did`: The device DID to filter by.
///
/// Usage:
/// ```ignore
/// let atts = list_attestations_by_device(py, "~/.auths", "did:key:z6Mk...")?;
/// ```
#[pyfunction]
pub fn list_attestations_by_device(
    py: Python<'_>,
    repo_path: &str,
    device_did: &str,
) -> PyResult<Vec<PyAttestation>> {
    let storage = open_attestation_storage(repo_path)?;
    py.allow_threads(|| {
        let all = storage
            .load_all_attestations()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to load attestations: {e}")))?;
        let group = AttestationGroup::from_list(all);
        Ok(group
            .get(device_did)
            .map(|atts| atts.iter().map(attestation_to_py).collect())
            .unwrap_or_default())
    })
}

/// Get the latest attestation for a specific device DID.
///
/// Args:
/// * `repo_path`: Path to the auths repository.
/// * `device_did`: The device DID to look up.
///
/// Usage:
/// ```ignore
/// let latest = get_latest_attestation(py, "~/.auths", "did:key:z6Mk...")?;
/// ```
#[pyfunction]
pub fn get_latest_attestation(
    py: Python<'_>,
    repo_path: &str,
    device_did: &str,
) -> PyResult<Option<PyAttestation>> {
    let storage = open_attestation_storage(repo_path)?;
    py.allow_threads(|| {
        let all = storage
            .load_all_attestations()
            .map_err(|e| PyRuntimeError::new_err(format!("Failed to load attestations: {e}")))?;
        let group = AttestationGroup::from_list(all);
        let did = DeviceDID(device_did.to_string());
        Ok(group.latest(&did).map(attestation_to_py))
    })
}
