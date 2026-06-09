use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use std::path::{Path, PathBuf};

use auths_id::keri::types::Prefix;
use auths_id::storage::identity::IdentityStorage;
use auths_id::witness_config::{WitnessConfig, WitnessRef};
use auths_storage::git::RegistryIdentityStorage;

fn resolve_repo(repo_path: &str) -> PathBuf {
    PathBuf::from(shellexpand::tilde(repo_path).as_ref())
}

fn load_witness_config(repo_path: &Path) -> PyResult<WitnessConfig> {
    let storage = RegistryIdentityStorage::new(repo_path.to_path_buf());
    let identity = storage
        .load_identity()
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_WITNESS_ERROR] {e}")))?;

    if let Some(ref metadata) = identity.metadata
        && let Some(wc) = metadata.get("witness_config")
    {
        let config: WitnessConfig = serde_json::from_value(wc.clone())
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_WITNESS_ERROR] {e}")))?;
        return Ok(config);
    }
    Ok(WitnessConfig::default())
}

fn save_witness_config(repo_path: &Path, config: &WitnessConfig) -> PyResult<()> {
    let storage = RegistryIdentityStorage::new(repo_path.to_path_buf());
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
#[pyo3(signature = (url, aid, repo_path, label=None))]
pub fn add_witness(
    _py: Python<'_>,
    url: &str,
    aid: &str,
    repo_path: &str,
    label: Option<String>,
) -> PyResult<(String, Option<String>, Option<String>)> {
    let url_str = url.to_string();
    let repo = resolve_repo(repo_path);

    {
        let parsed_url: url::Url = url_str.parse().map_err(|e| {
            PyRuntimeError::new_err(format!(
                "[AUTHS_WITNESS_ERROR] Invalid URL '{}': {}",
                url_str, e
            ))
        })?;
        let aid = Prefix::new_unchecked(aid.to_string());

        let mut config = load_witness_config(&repo)?;

        if config.witnesses.iter().any(|w| w.url == parsed_url) {
            return Ok((url_str, Some(aid.as_str().to_string()), label));
        }

        config.witnesses.push(WitnessRef {
            url: parsed_url,
            aid: aid.clone(),
            // No operator-independence attributes via this binding — fail-closed:
            // such a witness cannot contribute to proving quorum independence.
            operator_info: None,
        });
        if config.threshold == 0 {
            config.threshold = 1;
        }

        save_witness_config(&repo, &config)?;
        Ok((url_str, Some(aid.as_str().to_string()), label))
    }
}

#[pyfunction]
#[pyo3(signature = (url, repo_path))]
pub fn remove_witness(_py: Python<'_>, url: &str, repo_path: &str) -> PyResult<()> {
    let url_str = url.to_string();
    let repo = resolve_repo(repo_path);

    {
        let parsed_url: url::Url = url_str.parse().map_err(|e| {
            PyRuntimeError::new_err(format!(
                "[AUTHS_WITNESS_ERROR] Invalid URL '{}': {}",
                url_str, e
            ))
        })?;

        let mut config = load_witness_config(&repo)?;
        config.witnesses.retain(|w| w.url != parsed_url);

        if config.threshold > config.witnesses.len() {
            config.threshold = config.witnesses.len();
        }

        save_witness_config(&repo, &config)?;
        Ok(())
    }
}

#[pyfunction]
#[pyo3(signature = (repo_path,))]
pub fn list_witnesses(_py: Python<'_>, repo_path: &str) -> PyResult<String> {
    let repo = resolve_repo(repo_path);

    {
        let config = load_witness_config(&repo)?;

        let entries: Vec<serde_json::Value> = config
            .witnesses
            .iter()
            .map(|w| {
                serde_json::json!({
                    "url": w.url.to_string(),
                    "did": w.aid.as_str(),
                    "label": null,
                })
            })
            .collect();

        serde_json::to_string(&entries)
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_WITNESS_ERROR] {e}")))
    }
}
