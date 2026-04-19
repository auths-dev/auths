use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use std::path::PathBuf;
use std::sync::Arc;

use auths_core::ports::clock::SystemClock;
use auths_core::ports::id::SystemUuidProvider;
use auths_core::signing::{DidResolver, StorageSigner};
use auths_core::storage::keychain::{IdentityDID, KeyAlias};
use auths_id::attestation::create::create_signed_attestation;
use auths_id::identity::initialize::initialize_registry_identity;
use auths_id::identity::resolve::RegistryDidResolver;
use auths_id::storage::git_refs::AttestationMetadata;
use auths_id::storage::registry::{MemberFilter, RegistryBackend};
use auths_sdk::workflows::org::{
    AddMemberCommand, OrgContext, RevokeMemberCommand, add_organization_member,
    revoke_organization_member,
};
use auths_storage::git::{GitRegistryBackend, RegistryConfig};
use auths_verifier::core::Role;
use auths_verifier::types::DeviceDID;
use auths_verifier::{Capability, PublicKeyHex};
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
        let admin_capabilities = vec![
            Capability::sign_commit(),
            Capability::sign_release(),
            Capability::manage_members(),
            Capability::rotate_keys(),
        ];

        let meta = AttestationMetadata {
            note: Some(format!("Organization '{}' root admin", label)),
            timestamp: Some(now),
            expires_at: None,
        };

        let signer = StorageSigner::new(keychain);
        let org_curve = org_resolved.curve();
        let org_did_device = DeviceDID::from_public_key(&org_pk_bytes, org_curve);

        let attestation = create_signed_attestation(
            now,
            &rid,
            &controller_did,
            &org_did_device,
            &org_pk_bytes,
            org_curve,
            Some(serde_json::json!({
                "org_role": "admin",
                "org_name": label
            })),
            &meta,
            &signer,
            &provider,
            Some(&alias),
            None,
            admin_capabilities,
            Some(Role::Admin),
            None,
            None, // commit_sha
            None,
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
#[pyo3(signature = (org_did, member_did, role, repo_path, capabilities_json=None, passphrase=None, note=None, member_public_key_hex=None))]
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
pub fn add_org_member(
    _py: Python<'_>,
    org_did: &str,
    member_did: &str,
    role: &str,
    repo_path: &str,
    capabilities_json: Option<String>,
    passphrase: Option<String>,
    note: Option<String>,
    member_public_key_hex: Option<String>,
) -> PyResult<(String, String, String, String, String, bool, Option<String>)> {
    let passphrase_str = resolve_passphrase(passphrase);
    let repo = resolve_repo(repo_path);
    let repo_path_str = repo_path.to_string();
    let org_did = org_did.to_string();
    let member_did = member_did.to_string();
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
        let signer_alias = find_signer_alias(&org_did, &*keychain)?;

        let backend = Arc::new(GitRegistryBackend::from_config_unchecked(
            RegistryConfig::single_tenant(&repo),
        ));

        let resolver = RegistryDidResolver::new(backend.clone());
        #[allow(clippy::disallowed_methods)] // INVARIANT: hex::encode always produces valid hex
        let admin_pk_hex = PublicKeyHex::new_unchecked(hex::encode(
            resolver
                .resolve(&org_did)
                .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))?
                .public_key_bytes(),
        ));

        let (member_pk, member_curve) = if let Some(pk_hex) = member_public_key_hex {
            let pk = hex::decode(&pk_hex).map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "[AUTHS_ORG_ERROR] Invalid member public key hex: {e}"
                ))
            })?;
            let curve = auths_crypto::did_key_decode(&member_did)
                .map(|d| d.curve())
                .unwrap_or_default();
            (pk, curve)
        } else {
            let member_resolved = resolver
                .resolve(&member_did)
                .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))?;
            let curve = member_resolved.curve();
            (member_resolved.public_key_bytes().to_vec(), curve)
        };

        let org_prefix = extract_org_prefix(&org_did);

        let signer = StorageSigner::new(keychain);
        let uuid_provider = SystemUuidProvider;
        let provider = auths_core::signing::PrefilledPassphraseProvider::new(&passphrase_str);

        let org_ctx = OrgContext {
            registry: &*backend,
            clock: &SystemClock,
            uuid_provider: &uuid_provider,
            signer: &signer,
            passphrase_provider: &provider,
            witness_params: auths_id::witness_config::WitnessParams::Disabled,
        };

        let attestation = add_organization_member(
            &org_ctx,
            AddMemberCommand {
                org_prefix,
                member_did: member_did.clone(),
                member_public_key: member_pk,
                member_curve,
                role,
                capabilities: capabilities.clone(),
                admin_public_key_hex: admin_pk_hex,
                signer_alias,
                note,
            },
        )
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))?;

        let caps_json = serde_json::to_string(&capabilities).unwrap_or_default();
        let expires = attestation.expires_at.map(|e| e.to_rfc3339());

        Ok((
            member_did,
            role_str,
            caps_json,
            attestation.issuer.to_string(),
            attestation.rid.to_string(),
            false,
            expires,
        ))
    }
}

#[pyfunction]
#[pyo3(signature = (org_did, member_did, repo_path, passphrase=None, note=None, member_public_key_hex=None))]
#[allow(clippy::type_complexity)]
pub fn revoke_org_member(
    _py: Python<'_>,
    org_did: &str,
    member_did: &str,
    repo_path: &str,
    passphrase: Option<String>,
    note: Option<String>,
    member_public_key_hex: Option<String>,
) -> PyResult<(String, String, String, String, String, bool, Option<String>)> {
    let passphrase_str = resolve_passphrase(passphrase);
    let repo = resolve_repo(repo_path);
    let repo_path_str = repo_path.to_string();
    let org_did = org_did.to_string();
    let member_did = member_did.to_string();

    {
        let keychain = get_keychain(&passphrase_str, &repo_path_str)?;
        let signer_alias = find_signer_alias(&org_did, &*keychain)?;

        let backend = Arc::new(GitRegistryBackend::from_config_unchecked(
            RegistryConfig::single_tenant(&repo),
        ));

        let resolver = RegistryDidResolver::new(backend.clone());
        #[allow(clippy::disallowed_methods)] // INVARIANT: hex::encode always produces valid hex
        let admin_pk_hex = PublicKeyHex::new_unchecked(hex::encode(
            resolver
                .resolve(&org_did)
                .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))?
                .public_key_bytes(),
        ));

        let (member_pk, member_curve) = if let Some(pk_hex) = member_public_key_hex {
            let pk = hex::decode(&pk_hex).map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "[AUTHS_ORG_ERROR] Invalid member public key hex: {e}"
                ))
            })?;
            let curve = auths_crypto::did_key_decode(&member_did)
                .map(|d| d.curve())
                .unwrap_or_default();
            (pk, curve)
        } else {
            let member_resolved = resolver
                .resolve(&member_did)
                .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))?;
            let curve = member_resolved.curve();
            (member_resolved.public_key_bytes().to_vec(), curve)
        };

        let org_prefix = extract_org_prefix(&org_did);

        let signer = StorageSigner::new(keychain);
        let uuid_provider = SystemUuidProvider;
        let provider = auths_core::signing::PrefilledPassphraseProvider::new(&passphrase_str);

        let org_ctx = OrgContext {
            registry: &*backend,
            clock: &SystemClock,
            uuid_provider: &uuid_provider,
            signer: &signer,
            passphrase_provider: &provider,
            witness_params: auths_id::witness_config::WitnessParams::Disabled,
        };

        let revocation = revoke_organization_member(
            &org_ctx,
            RevokeMemberCommand {
                org_prefix,
                member_did: member_did.clone(),
                member_public_key: member_pk,
                member_curve,
                admin_public_key_hex: admin_pk_hex,
                signer_alias,
                note,
            },
        )
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))?;

        let caps: Vec<String> = revocation
            .capabilities
            .iter()
            .map(|c| c.as_str().to_string())
            .collect();
        let caps_json = serde_json::to_string(&caps).unwrap_or_default();
        let role_str = revocation
            .role
            .map(|r| r.as_str().to_string())
            .unwrap_or_else(|| "member".to_string());

        Ok((
            member_did,
            role_str,
            caps_json,
            revocation.issuer.to_string(),
            revocation.rid.to_string(),
            true,
            revocation.expires_at.map(|e| e.to_rfc3339()),
        ))
    }
}

#[pyfunction]
#[pyo3(signature = (org_did, include_revoked, repo_path))]
pub fn list_org_members(
    _py: Python<'_>,
    org_did: &str,
    include_revoked: bool,
    repo_path: &str,
) -> PyResult<String> {
    let repo = resolve_repo(repo_path);
    let org_prefix = extract_org_prefix(org_did);

    {
        let backend =
            GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(&repo));

        let filter = MemberFilter::default();

        let members = backend
            .list_org_members(&org_prefix, &filter)
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))?;

        let result: Vec<serde_json::Value> = members
            .iter()
            .filter_map(|m| {
                // Backend does not compute revoked/expired status;
                // use revoked_at field directly.
                let is_revoked = m.revoked_at.is_some();
                if !include_revoked && is_revoked {
                    return None;
                }

                let caps: Vec<String> = m
                    .capabilities
                    .iter()
                    .map(|c| c.as_str().to_string())
                    .collect();
                let role_str = m.role.as_ref().map(|r| r.as_str()).unwrap_or("member");

                Some(serde_json::json!({
                    "member_did": m.did.to_string(),
                    "role": role_str,
                    "capabilities": caps,
                    "issuer_did": m.issuer.to_string(),
                    "attestation_rid": m.rid.to_string(),
                    "revoked": is_revoked,
                    "expires_at": m.expires_at.map(|e| e.to_rfc3339()),
                }))
            })
            .collect();

        serde_json::to_string(&result)
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))
    }
}
