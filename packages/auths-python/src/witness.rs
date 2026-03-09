use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use std::path::PathBuf;

use auths_id::storage::identity::IdentityStorage;
use auths_id::witness_config::WitnessConfig;
use auths_storage::git::RegistryIdentityStorage;

fn resolve_repo(repo_path: &str) -> PathBuf {
    PathBuf::from(shellexpand::tilde(repo_path).as_ref())
}

fn load_witness_config(repo_path: &PathBuf) -> PyResult<WitnessConfig> {
    let storage = RegistryIdentityStorage::new(repo_path.clone());
    let identity = storage
        .load_identity()
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_WITNESS_ERROR] {e}")))?;

    if let Some(ref metadata) = identity.metadata {
        if let Some(wc) = metadata.get("witness_config") {
            let config: WitnessConfig = serde_json::from_value(wc.clone())
                .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_WITNESS_ERROR] {e}")))?;
            return Ok(config);
        }
    }
    Ok(WitnessConfig::default())
}

fn save_witness_config(repo_path: &PathBuf, config: &WitnessConfig) -> PyResult<()> {
    let storage = RegistryIdentityStorage::new(repo_path.clone());
    let mut identity = storage
        .load_identity()
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_WITNESS_ERROR] {e}")))?;

    let metadata = identity
        .metadata
        .get_or_insert_with(|| serde_json::json!({}));
    if let Some(obj) = metadata.as_object_mut() {
        obj.insert(
            "witness_config".to_string(),
            serde_json::to_value(config)
                .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_WITNESS_ERROR] {e}")))?,
        );
    }

    storage
        .create_identity(identity.controller_did.as_str(), identity.metadata)
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_WITNESS_ERROR] {e}")))?;
    Ok(())
}

#[pyfunction]
#[pyo3(signature = (url, repo_path, label=None))]
pub fn add_witness(
    py: Python<'_>,
    url: &str,
    repo_path: &str,
    label: Option<String>,
) -> PyResult<(String, Option<String>, Option<String>)> {
    let url_str = url.to_string();
    let repo = resolve_repo(repo_path);
    let label = label;

    py.allow_threads(move || {
        let parsed_url: url::Url = url_str.parse().map_err(|e| {
            PyRuntimeError::new_err(format!("[AUTHS_WITNESS_ERROR] Invalid URL '{}': {}", url_str, e))
        })?;

        let mut config = load_witness_config(&repo)?;

        if config.witness_urls.contains(&parsed_url) {
            return Ok((url_str, None, label));
        }

        config.witness_urls.push(parsed_url);
        if config.threshold == 0 {
            config.threshold = 1;
        }

        save_witness_config(&repo, &config)?;
        Ok((url_str, None, label))
    })
}

#[pyfunction]
#[pyo3(signature = (url, repo_path))]
pub fn remove_witness(
    py: Python<'_>,
    url: &str,
    repo_path: &str,
) -> PyResult<()> {
    let url_str = url.to_string();
    let repo = resolve_repo(repo_path);

    py.allow_threads(move || {
        let parsed_url: url::Url = url_str.parse().map_err(|e| {
            PyRuntimeError::new_err(format!("[AUTHS_WITNESS_ERROR] Invalid URL '{}': {}", url_str, e))
        })?;

        let mut config = load_witness_config(&repo)?;
        config.witness_urls.retain(|u| u != &parsed_url);

        if config.threshold > config.witness_urls.len() {
            config.threshold = config.witness_urls.len();
        }

        save_witness_config(&repo, &config)?;
        Ok(())
    })
}

#[pyfunction]
#[pyo3(signature = (repo_path,))]
pub fn list_witnesses(
    py: Python<'_>,
    repo_path: &str,
) -> PyResult<String> {
    let repo = resolve_repo(repo_path);

    py.allow_threads(move || {
        let config = load_witness_config(&repo)?;

        let entries: Vec<serde_json::Value> = config
            .witness_urls
            .iter()
            .map(|u| {
                serde_json::json!({
                    "url": u.to_string(),
                    "did": null,
                    "label": null,
                })
            })
            .collect();

        serde_json::to_string(&entries)
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_WITNESS_ERROR] {e}")))
    })
}
