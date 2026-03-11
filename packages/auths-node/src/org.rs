use std::path::PathBuf;
use std::sync::Arc;

use auths_core::ports::clock::SystemClock;
use auths_core::ports::id::SystemUuidProvider;
use auths_core::signing::{DidResolver, PrefilledPassphraseProvider, StorageSigner};
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
use auths_verifier::Capability;
use auths_verifier::PublicKeyHex;
use auths_verifier::core::{Ed25519PublicKey, Role};
use auths_verifier::types::DeviceDID;
use napi_derive::napi;

use crate::error::format_error;
use crate::helpers::{make_env_config, resolve_passphrase};

fn get_keychain(
    passphrase: &str,
    repo_path: &str,
) -> napi::Result<Box<dyn auths_core::storage::keychain::KeyStorage + Send + Sync>> {
    let env_config = make_env_config(passphrase, repo_path);
    auths_core::storage::keychain::get_platform_keychain_with_config(&env_config)
        .map_err(|e| format_error("AUTHS_KEYCHAIN_ERROR", e))
}

fn resolve_repo(repo_path: &str) -> PathBuf {
    PathBuf::from(shellexpand::tilde(repo_path).as_ref())
}

fn find_signer_alias(
    org_did: &str,
    keychain: &(dyn auths_core::storage::keychain::KeyStorage + Send + Sync),
) -> napi::Result<KeyAlias> {
    let identity_did = IdentityDID::new_unchecked(org_did.to_string());
    let aliases = keychain
        .list_aliases_for_identity(&identity_did)
        .map_err(|e| format_error("AUTHS_ORG_ERROR", e))?;
    aliases
        .into_iter()
        .find(|a| !a.contains("--next-"))
        .ok_or_else(|| {
            format_error(
                "AUTHS_ORG_ERROR",
                format!("No signing key found for org {org_did}"),
            )
        })
}

fn extract_org_prefix(org_did: &str) -> String {
    org_did
        .strip_prefix("did:keri:")
        .unwrap_or(org_did)
        .to_string()
}

#[napi(object)]
#[derive(Clone)]
pub struct NapiOrgResult {
    pub org_prefix: String,
    pub org_did: String,
    pub label: String,
    pub repo_path: String,
}

#[napi(object)]
#[derive(Clone)]
pub struct NapiOrgMember {
    pub member_did: String,
    pub role: String,
    pub capabilities_json: String,
    pub issuer_did: String,
    pub attestation_rid: String,
    pub revoked: bool,
    pub expires_at: Option<String>,
}

#[napi]
pub fn create_org(
    label: String,
    repo_path: String,
    passphrase: Option<String>,
) -> napi::Result<NapiOrgResult> {
    let passphrase_str = resolve_passphrase(passphrase);
    let repo = resolve_repo(&repo_path);

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
        .map_err(|e| format_error("AUTHS_ORG_ERROR", e))?;
    let backend = Arc::new(backend);

    let key_alias = KeyAlias::new_unchecked(key_alias_str);
    let keychain = get_keychain(&passphrase_str, &repo_path)?;
    let provider = PrefilledPassphraseProvider::new(&passphrase_str);

    let (controller_did, alias) =
        initialize_registry_identity(backend.clone(), &key_alias, &provider, &*keychain, None)
            .map_err(|e| format_error("AUTHS_ORG_ERROR", e))?;

    let uuid_provider = SystemUuidProvider;
    let rid = auths_core::ports::id::UuidProvider::new_id(&uuid_provider).to_string();

    let resolver = RegistryDidResolver::new(backend.clone());
    let org_resolved = resolver
        .resolve(controller_did.as_str())
        .map_err(|e| format_error("AUTHS_ORG_ERROR", e))?;
    let org_pk_bytes = *org_resolved.public_key();

    #[allow(clippy::disallowed_methods)]
    let now = chrono::Utc::now();
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
    let org_did_device = DeviceDID::new_unchecked(controller_did.to_string());

    let attestation = create_signed_attestation(
        now,
        &rid,
        &controller_did,
        &org_did_device,
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
    .map_err(|e| format_error("AUTHS_ORG_ERROR", e))?;

    let org_prefix = extract_org_prefix(controller_did.as_str());

    backend
        .store_org_member(&org_prefix, &attestation)
        .map_err(|e| format_error("AUTHS_ORG_ERROR", e))?;

    Ok(NapiOrgResult {
        org_prefix,
        org_did: controller_did.to_string(),
        label,
        repo_path,
    })
}

#[napi]
#[allow(clippy::too_many_arguments)]
pub fn add_org_member(
    org_did: String,
    member_did: String,
    role: String,
    repo_path: String,
    capabilities_json: Option<String>,
    passphrase: Option<String>,
    note: Option<String>,
    member_public_key_hex: Option<String>,
) -> napi::Result<NapiOrgMember> {
    let passphrase_str = resolve_passphrase(passphrase);
    let repo = resolve_repo(&repo_path);

    let role_parsed: Role = role
        .parse()
        .map_err(|e| format_error("AUTHS_ORG_ERROR", format!("Invalid role: {e}")))?;

    let capabilities: Vec<String> = if let Some(json) = capabilities_json {
        serde_json::from_str(&json).map_err(|e| {
            format_error("AUTHS_ORG_ERROR", format!("Invalid capabilities JSON: {e}"))
        })?
    } else {
        role_parsed
            .default_capabilities()
            .iter()
            .map(|c| c.as_str().to_string())
            .collect()
    };

    let keychain = get_keychain(&passphrase_str, &repo_path)?;
    let signer_alias = find_signer_alias(&org_did, &*keychain)?;

    let backend = Arc::new(GitRegistryBackend::from_config_unchecked(
        RegistryConfig::single_tenant(&repo),
    ));

    let resolver = RegistryDidResolver::new(backend.clone());
    let admin_pk_hex = PublicKeyHex::new_unchecked(hex::encode(
        resolver
            .resolve(&org_did)
            .map_err(|e| format_error("AUTHS_ORG_ERROR", e))?
            .public_key()
            .as_bytes(),
    ));

    let member_pk = if let Some(pk_hex) = member_public_key_hex {
        let pk_bytes = hex::decode(&pk_hex).map_err(|e| {
            format_error(
                "AUTHS_ORG_ERROR",
                format!("Invalid member public key hex: {e}"),
            )
        })?;
        Ed25519PublicKey::try_from_slice(&pk_bytes)
            .map_err(|e| format_error("AUTHS_ORG_ERROR", e))?
    } else {
        let member_resolved = resolver
            .resolve(&member_did)
            .map_err(|e| format_error("AUTHS_ORG_ERROR", e))?;
        *member_resolved.public_key()
    };

    let org_prefix = extract_org_prefix(&org_did);

    let signer = StorageSigner::new(keychain);
    let uuid_provider = SystemUuidProvider;
    let provider = PrefilledPassphraseProvider::new(&passphrase_str);

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
            member_public_key: member_pk,
            role: role_parsed,
            capabilities: capabilities.clone(),
            admin_public_key_hex: admin_pk_hex,
            signer_alias,
            note,
        },
    )
    .map_err(|e| format_error("AUTHS_ORG_ERROR", e))?;

    let caps_json = serde_json::to_string(&capabilities).unwrap_or_default();

    Ok(NapiOrgMember {
        member_did,
        role,
        capabilities_json: caps_json,
        issuer_did: attestation.issuer.to_string(),
        attestation_rid: attestation.rid.to_string(),
        revoked: false,
        expires_at: attestation.expires_at.map(|e| e.to_rfc3339()),
    })
}

#[napi]
pub fn revoke_org_member(
    org_did: String,
    member_did: String,
    repo_path: String,
    passphrase: Option<String>,
    note: Option<String>,
    member_public_key_hex: Option<String>,
) -> napi::Result<NapiOrgMember> {
    let passphrase_str = resolve_passphrase(passphrase);
    let repo = resolve_repo(&repo_path);

    let keychain = get_keychain(&passphrase_str, &repo_path)?;
    let signer_alias = find_signer_alias(&org_did, &*keychain)?;

    let backend = Arc::new(GitRegistryBackend::from_config_unchecked(
        RegistryConfig::single_tenant(&repo),
    ));

    let resolver = RegistryDidResolver::new(backend.clone());
    let admin_pk_hex = PublicKeyHex::new_unchecked(hex::encode(
        resolver
            .resolve(&org_did)
            .map_err(|e| format_error("AUTHS_ORG_ERROR", e))?
            .public_key()
            .as_bytes(),
    ));

    let member_pk = if let Some(pk_hex) = member_public_key_hex {
        let pk_bytes = hex::decode(&pk_hex).map_err(|e| {
            format_error(
                "AUTHS_ORG_ERROR",
                format!("Invalid member public key hex: {e}"),
            )
        })?;
        Ed25519PublicKey::try_from_slice(&pk_bytes)
            .map_err(|e| format_error("AUTHS_ORG_ERROR", e))?
    } else {
        let member_resolved = resolver
            .resolve(&member_did)
            .map_err(|e| format_error("AUTHS_ORG_ERROR", e))?;
        *member_resolved.public_key()
    };

    let org_prefix = extract_org_prefix(&org_did);

    let signer = StorageSigner::new(keychain);
    let uuid_provider = SystemUuidProvider;
    let provider = PrefilledPassphraseProvider::new(&passphrase_str);

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
            member_public_key: member_pk,
            admin_public_key_hex: admin_pk_hex,
            signer_alias,
            note,
        },
    )
    .map_err(|e| format_error("AUTHS_ORG_ERROR", e))?;

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

    Ok(NapiOrgMember {
        member_did,
        role: role_str,
        capabilities_json: caps_json,
        issuer_did: revocation.issuer.to_string(),
        attestation_rid: revocation.rid.to_string(),
        revoked: true,
        expires_at: revocation.expires_at.map(|e| e.to_rfc3339()),
    })
}

#[napi]
pub fn list_org_members(
    org_did: String,
    include_revoked: bool,
    repo_path: String,
) -> napi::Result<String> {
    let repo = resolve_repo(&repo_path);
    let org_prefix = extract_org_prefix(&org_did);

    let backend = GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(&repo));

    let filter = MemberFilter::default();

    let members = backend
        .list_org_members(&org_prefix, &filter)
        .map_err(|e| format_error("AUTHS_ORG_ERROR", e))?;

    let result: Vec<serde_json::Value> = members
        .iter()
        .filter_map(|m| {
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

    serde_json::to_string(&result).map_err(|e| format_error("AUTHS_ORG_ERROR", e))
}
