use std::path::PathBuf;
use std::sync::Arc;

use auths_id::attestation::group::AttestationGroup;
use auths_id::storage::attestation::AttestationSource;
use auths_storage::git::{GitRegistryBackend, RegistryAttestationStorage, RegistryConfig};
use auths_verifier::core::Attestation;
use auths_verifier::types::DeviceDID;
use napi_derive::napi;

use crate::error::format_error;

#[napi(object)]
#[derive(Clone)]
pub struct NapiAttestation {
    pub rid: String,
    pub issuer: String,
    pub subject: String,
    pub device_did: String,
    pub capabilities: Vec<String>,
    pub signer_type: Option<String>,
    pub expires_at: Option<String>,
    pub revoked_at: Option<String>,
    pub created_at: Option<String>,
    pub delegated_by: Option<String>,
    pub json: String,
}

fn attestation_to_napi(att: &Attestation) -> NapiAttestation {
    let json = serde_json::to_string(att).unwrap_or_default();
    NapiAttestation {
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

fn open_attestation_storage(repo_path: &str) -> napi::Result<Arc<RegistryAttestationStorage>> {
    let repo = PathBuf::from(shellexpand::tilde(repo_path).as_ref());
    let config = RegistryConfig::single_tenant(&repo);
    let _backend = GitRegistryBackend::open_existing(config).map_err(|e| {
        format_error(
            "AUTHS_REGISTRY_ERROR",
            format!("Failed to open registry: {e}"),
        )
    })?;
    Ok(Arc::new(RegistryAttestationStorage::new(&repo)))
}

#[napi]
pub fn list_attestations(repo_path: String) -> napi::Result<Vec<NapiAttestation>> {
    let storage = open_attestation_storage(&repo_path)?;
    let all = storage.load_all_attestations().map_err(|e| {
        format_error(
            "AUTHS_REGISTRY_ERROR",
            format!("Failed to load attestations: {e}"),
        )
    })?;
    Ok(all.iter().map(attestation_to_napi).collect())
}

#[napi]
pub fn list_attestations_by_device(
    repo_path: String,
    device_did: String,
) -> napi::Result<Vec<NapiAttestation>> {
    let storage = open_attestation_storage(&repo_path)?;
    let all = storage.load_all_attestations().map_err(|e| {
        format_error(
            "AUTHS_REGISTRY_ERROR",
            format!("Failed to load attestations: {e}"),
        )
    })?;
    let group = AttestationGroup::from_list(all);
    Ok(group
        .get(&device_did)
        .map(|atts| atts.iter().map(attestation_to_napi).collect())
        .unwrap_or_default())
}

#[napi]
pub fn get_latest_attestation(
    repo_path: String,
    device_did: String,
) -> napi::Result<Option<NapiAttestation>> {
    let storage = open_attestation_storage(&repo_path)?;
    let all = storage.load_all_attestations().map_err(|e| {
        format_error(
            "AUTHS_REGISTRY_ERROR",
            format!("Failed to load attestations: {e}"),
        )
    })?;
    let group = AttestationGroup::from_list(all);
    let did = DeviceDID::parse(&device_did).map_err(|e| format_error("AUTHS_INVALID_INPUT", e))?;
    Ok(group.latest(&did).map(attestation_to_napi))
}
