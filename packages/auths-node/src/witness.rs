use std::path::PathBuf;

use auths_id::storage::identity::IdentityStorage;
use auths_id::witness_config::WitnessConfig;
use auths_storage::git::RegistryIdentityStorage;
use napi_derive::napi;

use crate::error::format_error;

fn resolve_repo(repo_path: &str) -> PathBuf {
    PathBuf::from(shellexpand::tilde(repo_path).as_ref())
}

fn load_witness_config(repo_path: &PathBuf) -> napi::Result<WitnessConfig> {
    let storage = RegistryIdentityStorage::new(repo_path);
    let identity = storage
        .load_identity()
        .map_err(|e| format_error("AUTHS_WITNESS_ERROR", e))?;

    if let Some(wc) = identity
        .metadata
        .as_ref()
        .and_then(|m| m.get("witness_config"))
    {
        let config: WitnessConfig = serde_json::from_value(wc.clone())
            .map_err(|e| format_error("AUTHS_WITNESS_ERROR", e))?;
        return Ok(config);
    }
    Ok(WitnessConfig::default())
}

fn save_witness_config(repo_path: &PathBuf, config: &WitnessConfig) -> napi::Result<()> {
    let storage = RegistryIdentityStorage::new(repo_path);
    let mut identity = storage
        .load_identity()
        .map_err(|e| format_error("AUTHS_WITNESS_ERROR", e))?;

    let metadata = identity
        .metadata
        .get_or_insert_with(|| serde_json::json!({}));
    if let Some(obj) = metadata.as_object_mut() {
        obj.insert(
            "witness_config".to_string(),
            serde_json::to_value(config).map_err(|e| format_error("AUTHS_WITNESS_ERROR", e))?,
        );
    }

    storage
        .create_identity(identity.controller_did.as_str(), identity.metadata)
        .map_err(|e| format_error("AUTHS_WITNESS_ERROR", e))?;
    Ok(())
}

#[napi(object)]
#[derive(Clone)]
pub struct NapiWitnessResult {
    pub url: String,
    pub did: Option<String>,
    pub label: Option<String>,
}

#[napi]
pub fn add_witness(
    url_str: String,
    repo_path: String,
    label: Option<String>,
) -> napi::Result<NapiWitnessResult> {
    let repo = resolve_repo(&repo_path);
    let parsed_url: url::Url = url_str.parse().map_err(|e| {
        format_error(
            "AUTHS_WITNESS_ERROR",
            format!("Invalid URL '{}': {}", url_str, e),
        )
    })?;

    let mut config = load_witness_config(&repo)?;

    if config.witness_urls.contains(&parsed_url) {
        return Ok(NapiWitnessResult {
            url: url_str,
            did: None,
            label,
        });
    }

    config.witness_urls.push(parsed_url);
    if config.threshold == 0 {
        config.threshold = 1;
    }

    save_witness_config(&repo, &config)?;
    Ok(NapiWitnessResult {
        url: url_str,
        did: None,
        label,
    })
}

#[napi]
pub fn remove_witness(url_str: String, repo_path: String) -> napi::Result<()> {
    let repo = resolve_repo(&repo_path);
    let parsed_url: url::Url = url_str.parse().map_err(|e| {
        format_error(
            "AUTHS_WITNESS_ERROR",
            format!("Invalid URL '{}': {}", url_str, e),
        )
    })?;

    let mut config = load_witness_config(&repo)?;
    config.witness_urls.retain(|u| u != &parsed_url);

    if config.threshold > config.witness_urls.len() {
        config.threshold = config.witness_urls.len();
    }

    save_witness_config(&repo, &config)?;
    Ok(())
}

#[napi]
pub fn list_witnesses(repo_path: String) -> napi::Result<String> {
    let repo = resolve_repo(&repo_path);
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

    serde_json::to_string(&entries).map_err(|e| format_error("AUTHS_WITNESS_ERROR", e))
}
