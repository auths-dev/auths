use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use std::path::PathBuf;
use std::sync::Arc;

use auths_core::ports::clock::SystemClock;
use auths_core::ports::id::SystemUuidProvider;
use auths_core::signing::StorageSigner;
use auths_id::identity::initialize::initialize_registry_identity;
use auths_id::identity::resolve::{DefaultDidResolver, DidResolver};
use auths_id::storage::attestation::AttestationSource;
use auths_id::storage::git_refs::AttestationMetadata;
use auths_id::storage::identity::IdentityStorage;
use auths_sdk::workflows::org::{
    AddMemberCommand, OrgContext, RevokeMemberCommand, add_organization_member,
    revoke_organization_member,
};
use auths_storage::git::adapter::GitRegistryBackend;
use auths_storage::git::attestation_adapter::RegistryAttestationStorage;
use auths_storage::git::identity_adapter::RegistryIdentityStorage;
use auths_storage::git::registry_config::RegistryConfig;
use auths_verifier::core::{
    Attestation, Capability, DeviceDID, Ed25519PublicKey, KeyAlias, Role, VerifiedAttestation,
};
use chrono::Utc;

use crate::identity::{make_keychain_config, resolve_passphrase};

fn get_keychain(
    passphrase: &str,
) -> PyResult<Box<dyn auths_core::ports::keychain::KeyStorage + Send + Sync>> {
    let env_config = make_keychain_config(passphrase);
    auths_core::keychain::get_platform_keychain_with_config(&env_config)
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_KEYCHAIN_ERROR] {e}")))
}

fn resolve_repo(repo_path: &str) -> PathBuf {
    PathBuf::from(shellexpand::tilde(repo_path).as_ref())
}

fn derive_signer_alias(org_did: &str) -> String {
    format!(
        "org-{}",
        org_did
            .chars()
            .filter(|c| c.is_alphanumeric())
            .take(20)
            .collect::<String>()
            .to_lowercase()
    )
}

#[pyfunction]
#[pyo3(signature = (label, repo_path, passphrase=None))]
pub fn create_org(
    py: Python<'_>,
    label: &str,
    repo_path: &str,
    passphrase: Option<String>,
) -> PyResult<(String, String, String, String)> {
    let passphrase_str = resolve_passphrase(passphrase);
    let repo = resolve_repo(repo_path);
    let label = label.to_string();
    let repo_path_str = repo_path.to_string();

    py.allow_threads(move || {
        let key_alias_str = format!(
            "org-{}",
            label
                .chars()
                .filter(|c| c.is_alphanumeric())
                .take(20)
                .collect::<String>()
                .to_lowercase()
        );

        let backend = Arc::new(GitRegistryBackend::from_config_unchecked(
            RegistryConfig::single_tenant(&repo),
        ));

        let key_alias = KeyAlias::new_unchecked(key_alias_str);
        let keychain = get_keychain(&passphrase_str)?;
        let provider =
            auths_core::ports::passphrase::PrefilledPassphraseProvider::new(&passphrase_str);

        let (controller_did, alias) =
            initialize_registry_identity(backend.clone(), &key_alias, &provider, &*keychain, None)
                .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))?;

        // Create admin self-attestation
        let identity_storage = RegistryIdentityStorage::new(&repo);
        let managed_identity = identity_storage
            .load_identity()
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))?;
        let rid = managed_identity.storage_id;

        let resolver = DefaultDidResolver::with_repo(&repo);
        let org_resolved = resolver
            .resolve(controller_did.as_str())
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))?;
        let org_pk_bytes = *org_resolved.public_key();

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
        let org_did = DeviceDID::new(controller_did.to_string());

        let attestation = auths_id::attestation::create::create_signed_attestation(
            now,
            &rid,
            &controller_did,
            &org_did,
            org_pk_bytes.as_bytes(),
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
        )
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))?;

        let attestation_storage = RegistryAttestationStorage::new(&repo);
        attestation_storage
            .export(&VerifiedAttestation::dangerous_from_unchecked(attestation))
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))?;

        let prefix = controller_did
            .as_str()
            .strip_prefix("did:keri:")
            .unwrap_or(controller_did.as_str())
            .to_string();

        Ok((
            prefix,
            controller_did.to_string(),
            label,
            repo_path_str,
        ))
    })
}

#[pyfunction]
#[pyo3(signature = (org_did, member_did, role, capabilities_json=None, repo_path, passphrase=None, note=None))]
pub fn add_org_member(
    py: Python<'_>,
    org_did: &str,
    member_did: &str,
    role: &str,
    capabilities_json: Option<String>,
    repo_path: &str,
    passphrase: Option<String>,
    note: Option<String>,
) -> PyResult<(String, String, String, String, String, bool, Option<String>)> {
    let passphrase_str = resolve_passphrase(passphrase);
    let repo = resolve_repo(repo_path);
    let org_did = org_did.to_string();
    let member_did = member_did.to_string();
    let role_str = role.to_string();
    let note = note;

    py.allow_threads(move || {
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

        let signer_alias_str = derive_signer_alias(&org_did);
        let signer_alias = KeyAlias::new_unchecked(signer_alias_str);

        let keychain = get_keychain(&passphrase_str)?;

        let (stored_did, _role, _encrypted_key) = keychain
            .load_key(&signer_alias)
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))?;
        let resolver = DefaultDidResolver::with_repo(&repo);
        let admin_pk_hex = hex::encode(
            resolver
                .resolve(stored_did.as_str())
                .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))?
                .public_key()
                .as_bytes(),
        );

        let member_resolved = resolver
            .resolve(&member_did)
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))?;
        let member_pk = *member_resolved.public_key();

        let org_prefix = org_did
            .strip_prefix("did:keri:")
            .unwrap_or(&org_did)
            .to_string();

        let signer = StorageSigner::new(keychain);
        let uuid_provider = SystemUuidProvider;
        let provider =
            auths_core::ports::passphrase::PrefilledPassphraseProvider::new(&passphrase_str);

        let backend = Arc::new(GitRegistryBackend::from_config_unchecked(
            RegistryConfig::single_tenant(&repo),
        ));

        let org_ctx = OrgContext {
            registry: &*backend,
            clock: &SystemClock,
            uuid_provider: &uuid_provider,
            signer: &signer,
            passphrase_provider: &provider,
        };

        let attestation = add_organization_member(
            &org_ctx,
            AddMemberCommand {
                org_prefix,
                member_did: member_did.clone(),
                member_public_key: Ed25519PublicKey::try_from_slice(member_pk.as_bytes())
                    .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))?,
                role,
                capabilities: capabilities.clone(),
                admin_public_key_hex: admin_pk_hex,
                signer_alias,
                note,
            },
        )
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))?;

        let attestation_storage = RegistryAttestationStorage::new(&repo);
        attestation_storage
            .export(&VerifiedAttestation::dangerous_from_unchecked(
                attestation.clone(),
            ))
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
    })
}

#[pyfunction]
#[pyo3(signature = (org_did, member_did, repo_path, passphrase=None, note=None))]
pub fn revoke_org_member(
    py: Python<'_>,
    org_did: &str,
    member_did: &str,
    repo_path: &str,
    passphrase: Option<String>,
    note: Option<String>,
) -> PyResult<(String, String, String, String, String, bool, Option<String>)> {
    let passphrase_str = resolve_passphrase(passphrase);
    let repo = resolve_repo(repo_path);
    let org_did = org_did.to_string();
    let member_did = member_did.to_string();

    py.allow_threads(move || {
        let signer_alias_str = derive_signer_alias(&org_did);
        let signer_alias = KeyAlias::new_unchecked(signer_alias_str);

        let keychain = get_keychain(&passphrase_str)?;

        let (stored_did, _role, _encrypted_key) = keychain
            .load_key(&signer_alias)
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))?;
        let resolver = DefaultDidResolver::with_repo(&repo);
        let admin_pk_hex = hex::encode(
            resolver
                .resolve(stored_did.as_str())
                .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))?
                .public_key()
                .as_bytes(),
        );

        let member_resolved = resolver
            .resolve(&member_did)
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))?;
        let member_pk = *member_resolved.public_key();

        let org_prefix = org_did
            .strip_prefix("did:keri:")
            .unwrap_or(&org_did)
            .to_string();

        let signer = StorageSigner::new(keychain);
        let uuid_provider = SystemUuidProvider;
        let provider =
            auths_core::ports::passphrase::PrefilledPassphraseProvider::new(&passphrase_str);

        let backend = Arc::new(GitRegistryBackend::from_config_unchecked(
            RegistryConfig::single_tenant(&repo),
        ));

        let org_ctx = OrgContext {
            registry: &*backend,
            clock: &SystemClock,
            uuid_provider: &uuid_provider,
            signer: &signer,
            passphrase_provider: &provider,
        };

        let revocation = revoke_organization_member(
            &org_ctx,
            RevokeMemberCommand {
                org_prefix,
                member_did: member_did.clone(),
                member_public_key: Ed25519PublicKey::try_from_slice(member_pk.as_bytes())
                    .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))?,
                admin_public_key_hex: admin_pk_hex,
                signer_alias,
                note,
            },
        )
        .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))?;

        let attestation_storage = RegistryAttestationStorage::new(&repo);
        attestation_storage
            .export(&VerifiedAttestation::dangerous_from_unchecked(
                revocation.clone(),
            ))
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
    })
}

#[pyfunction]
#[pyo3(signature = (org_did, include_revoked, repo_path))]
pub fn list_org_members(
    py: Python<'_>,
    org_did: &str,
    include_revoked: bool,
    repo_path: &str,
) -> PyResult<String> {
    let repo = resolve_repo(repo_path);
    let _org_did = org_did.to_string();

    py.allow_threads(move || {
        let attestation_storage = RegistryAttestationStorage::new(&repo);
        let all_attestations: Vec<Attestation> = attestation_storage
            .load_all_attestations()
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))?;

        let now = Utc::now();
        let mut members = Vec::new();

        for att in &all_attestations {
            if att.is_revoked() && !include_revoked {
                continue;
            }
            if att.expires_at.is_some_and(|e| now > e) && !include_revoked {
                continue;
            }

            let caps: Vec<String> = att
                .capabilities
                .iter()
                .map(|c| c.as_str().to_string())
                .collect();
            let role_str = att
                .role
                .as_ref()
                .map(|r| r.as_str())
                .unwrap_or("member");

            members.push(serde_json::json!({
                "member_did": att.subject.to_string(),
                "role": role_str,
                "capabilities": caps,
                "issuer_did": att.issuer.to_string(),
                "attestation_rid": att.rid.to_string(),
                "revoked": att.is_revoked(),
                "expires_at": att.expires_at.map(|e| e.to_rfc3339()),
            }));
        }

        serde_json::to_string(&members)
            .map_err(|e| PyRuntimeError::new_err(format!("[AUTHS_ORG_ERROR] {e}")))
    })
}
