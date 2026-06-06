use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use std::path::PathBuf;
use std::sync::Arc;

use auths_core::signing::{DidResolver, StorageSigner};
use auths_core::storage::keychain::{IdentityDID, KeyAlias, KeyStorage};
use auths_id::attestation::create::create_signed_attestation;
use auths_id::identity::initialize::initialize_registry_identity;
use auths_id::identity::resolve::RegistryDidResolver;
use auths_id::keri::types::Prefix;
use auths_id::storage::git_refs::AttestationMetadata;
use auths_id::storage::registry::RegistryBackend;
use auths_sdk::context::AuthsContext;
use auths_sdk::workflows::org::{add_member, list_members, revoke_member};
use auths_storage::git::{
    GitRegistryBackend, RegistryAttestationStorage, RegistryConfig, RegistryIdentityStorage,
};
use auths_verifier::clock::SystemClock;
use auths_verifier::core::Role;
use auths_verifier::types::CanonicalDid;
use chrono::Utc;

use crate::identity::{make_keychain_config, resolve_passphrase};

fn get_keychain(
    passphrase: &str,
    repo_path: &str,
) -> PyResult<Box<dyn auths_core::storage::keychain::KeyStorage + Send + Sync>> {
    let env_config = make_keychain_config(passphrase, repo_path);
    auths_core::storage::keychain::get_platform_keychain_with_config(&env_config)
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_KEYCHAIN_ERROR] {e}")))
}

fn resolve_repo(repo_path: &str) -> PathBuf {
    PathBuf::from(shellexpand::tilde(repo_path).as_ref())
}

fn find_signer_alias(
    org_did: &str,
    keychain: &(dyn auths_core::storage::keychain::KeyStorage + Send + Sync),
) -> PyResult<KeyAlias> {
    let identity_did = IdentityDID::parse(org_did)
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))?;
    let aliases = keychain
        .list_aliases_for_identity(&identity_did)
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))?;
    let alias = aliases
        .into_iter()
        .find(|a| !a.contains("--next-"))
        .ok_or_else(|| {
            PyRuntimeError::new_err(format!(
                "[AUTHS_ORG_ERROR] No signing key found for org {org_did}"
            ))
        })?;
    Ok(alias)
}

fn extract_org_prefix(org_did: &str) -> String {
    org_did
        .strip_prefix("did:keri:")
        .unwrap_or(org_did)
        .to_string()
}

fn org_prefix_from_did(org_did: &str) -> Prefix {
    Prefix::new_unchecked(extract_org_prefix(org_did))
}

fn build_org_context(
    repo: &std::path::Path,
    passphrase: &str,
    repo_path: &str,
) -> PyResult<AuthsContext> {
    let backend = Arc::new(
        GitRegistryBackend::open_existing(RegistryConfig::single_tenant(repo)).map_err(|e| {
            PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] Failed to open registry: {e}"))
        })?,
    );
    let keychain: Arc<dyn KeyStorage + Send + Sync> =
        Arc::from(get_keychain(passphrase, repo_path)?);
    let provider = Arc::new(auths_core::signing::PrefilledPassphraseProvider::new(
        passphrase,
    ));
    let identity_storage = Arc::new(RegistryIdentityStorage::new(repo.to_path_buf()));
    let attestation_storage = Arc::new(RegistryAttestationStorage::new(repo));

    Ok(AuthsContext::builder()
        .registry(backend)
        .key_storage(keychain)
        .clock(Arc::new(SystemClock))
        .identity_storage(identity_storage)
        .attestation_sink(attestation_storage.clone())
        .attestation_source(attestation_storage)
        .passphrase_provider(provider)
        .build())
}

#[pyfunction]
#[pyo3(signature = (label, repo_path, passphrase=None))]
pub fn create_org(
    _py: Python<'_>,
    label: &str,
    repo_path: &str,
    passphrase: Option<String>,
) -> PyResult<(String, String, String, String)> {
    let passphrase_str = resolve_passphrase(passphrase);
    let repo = resolve_repo(repo_path);
    let label = label.to_string();
    let repo_path_str = repo_path.to_string();

    {
        let key_alias_str = format!(
            "org-{}",
            label
                .chars()
                .filter(|c| c.is_alphanumeric())
                .take(20)
                .collect::<String>()
                .to_lowercase()
        );

        let config = RegistryConfig::single_tenant(&repo);
        let backend = GitRegistryBackend::from_config_unchecked(config);
        backend
            .init_if_needed()
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))?;
        let backend = Arc::new(backend);

        #[allow(clippy::disallowed_methods)] // INVARIANT: key_alias_str from caller input
        let key_alias = KeyAlias::new_unchecked(key_alias_str);
        let keychain = get_keychain(&passphrase_str, &repo_path_str)?;
        let provider = auths_core::signing::PrefilledPassphraseProvider::new(&passphrase_str);

        let (controller_did, alias) = initialize_registry_identity(
            backend.clone(),
            &key_alias,
            &provider,
            &*keychain,
            None,
            auths_crypto::CurveType::default(),
        )
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))?;

        #[allow(clippy::disallowed_methods)] // Presentation boundary: UUID generation
        let rid = uuid::Uuid::new_v4().to_string();

        let resolver = RegistryDidResolver::new(backend.clone());
        let org_resolved = resolver
            .resolve(controller_did.as_str())
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))?;
        let org_pk_bytes = org_resolved.public_key_bytes().to_vec();

        #[allow(clippy::disallowed_methods)] // Presentation boundary
        let now = Utc::now();

        let meta = AttestationMetadata {
            note: Some(format!("Organization '{}' root admin", label)),
            timestamp: Some(now),
            expires_at: None,
        };

        let signer = StorageSigner::new(keychain);
        let org_curve = org_resolved.curve();
        let org_did_device = CanonicalDid::from_public_key_did_key(&org_pk_bytes, org_curve);

        let attestation = create_signed_attestation(
            now,
            auths_sdk::attestation::AttestationInput {
                rid: &rid,
                identity_did: &controller_did,
                subject: &org_did_device,
                device_public_key: &org_pk_bytes,
                device_curve: org_curve,
                payload: Some(serde_json::json!({
                    "org_role": "admin",
                    "org_name": label
                })),
                meta: &meta,
                identity_alias: Some(&alias),
                device_alias: None,
                delegated_by: None,
                commit_sha: None,
                signer_type: None,
            },
            &signer,
            &provider,
        )
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))?;

        let org_prefix = extract_org_prefix(controller_did.as_str());

        backend
            .store_org_member(&org_prefix, &attestation)
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))?;

        Ok((org_prefix, controller_did.to_string(), label, repo_path_str))
    }
}

#[pyfunction]
#[pyo3(signature = (org_did, member_label, role, repo_path, capabilities_json=None, passphrase=None, expires_at=None))]
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn add_org_member(
    _py: Python<'_>,
    org_did: &str,
    member_label: &str,
    role: &str,
    repo_path: &str,
    capabilities_json: Option<String>,
    passphrase: Option<String>,
    expires_at: Option<i64>,
) -> PyResult<(String, String, String, String, String, bool, Option<String>)> {
    let passphrase_str = resolve_passphrase(passphrase);
    let repo = resolve_repo(repo_path);
    let repo_path_str = repo_path.to_string();
    let org_did = org_did.to_string();
    let role_str = role.to_string();

    {
        let role: Role = role_str
            .parse()
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] Invalid role: {e}")))?;

        let capabilities: Vec<String> = if let Some(json) = capabilities_json {
            serde_json::from_str(&json).map_err(|e| {
                PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] Invalid capabilities JSON: {e}"))
            })?
        } else {
            role.default_capabilities()
                .iter()
                .map(|c| c.as_str().to_string())
                .collect()
        };

        let keychain = get_keychain(&passphrase_str, &repo_path_str)?;
        let org_alias = find_signer_alias(&org_did, &*keychain)?;
        drop(keychain);

        #[allow(clippy::disallowed_methods)] // INVARIANT: member_label is caller-provided
        let member_alias = KeyAlias::new_unchecked(format!("org-member-{member_label}"));

        let ctx = build_org_context(&repo, &passphrase_str, &repo_path_str)?;
        let org_prefix = org_prefix_from_did(&org_did);

        let result = add_member(
            &ctx,
            &org_prefix,
            &org_alias,
            &member_alias,
            auths_crypto::CurveType::default(),
            role,
            &capabilities,
            expires_at,
        )
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))?;

        let caps_json = serde_json::to_string(&capabilities).unwrap_or_default();

        Ok((
            result.member_did,
            role_str,
            caps_json,
            org_did,
            result.member_prefix,
            false,
            expires_at
                .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0).map(|d| d.to_rfc3339())),
        ))
    }
}

#[pyfunction]
#[pyo3(signature = (org_did, member_did, repo_path, passphrase=None))]
#[allow(clippy::type_complexity)]
pub fn revoke_org_member(
    _py: Python<'_>,
    org_did: &str,
    member_did: &str,
    repo_path: &str,
    passphrase: Option<String>,
) -> PyResult<(String, String, String, String, String, bool, Option<String>)> {
    let passphrase_str = resolve_passphrase(passphrase);
    let repo = resolve_repo(repo_path);
    let repo_path_str = repo_path.to_string();
    let org_did = org_did.to_string();
    let member_did = member_did.to_string();

    {
        let keychain = get_keychain(&passphrase_str, &repo_path_str)?;
        let org_alias = find_signer_alias(&org_did, &*keychain)?;
        drop(keychain);

        let ctx = build_org_context(&repo, &passphrase_str, &repo_path_str)?;
        let org_prefix = org_prefix_from_did(&org_did);

        revoke_member(&ctx, &org_prefix, &org_alias, &member_did)
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))?;

        Ok((
            member_did,
            "member".to_string(),
            serde_json::to_string(&Vec::<String>::new()).unwrap_or_default(),
            org_did,
            String::new(),
            true,
            None,
        ))
    }
}

#[pyfunction]
#[pyo3(signature = (org_did, include_revoked, repo_path, passphrase=None))]
pub fn list_org_members(
    _py: Python<'_>,
    org_did: &str,
    include_revoked: bool,
    repo_path: &str,
    passphrase: Option<String>,
) -> PyResult<String> {
    let passphrase_str = resolve_passphrase(passphrase);
    let repo = resolve_repo(repo_path);
    let repo_path_str = repo_path.to_string();
    let org_did = org_did.to_string();

    {
        let ctx = build_org_context(&repo, &passphrase_str, &repo_path_str)?;
        let org_prefix = org_prefix_from_did(&org_did);

        let members = list_members(&ctx, &org_prefix)
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))?;

        let result: Vec<serde_json::Value> = members
            .iter()
            .filter_map(|m| {
                if !include_revoked && m.revoked {
                    return None;
                }

                let role_str = m.role.map(|r| r.as_str().to_string());

                Some(serde_json::json!({
                    "member_did": m.member_did,
                    "member_prefix": m.member_prefix,
                    "role": role_str,
                    "capabilities": m.capabilities,
                    "delegated_by_org": m.delegated_by_org,
                    "revoked": m.revoked,
                    "expires_at": m.expires_at,
                }))
            })
            .collect();

        serde_json::to_string(&result)
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))
    }
}
