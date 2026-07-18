use std::path::PathBuf;
use std::sync::Arc;

// binding-boundary-allow: pre-lint reach; migrate to an auths_sdk workflow
use auths_core::ports::id::SystemUuidProvider;
// binding-boundary-allow: pre-lint reach; migrate to an auths_sdk workflow
use auths_core::signing::{DidResolver, PrefilledPassphraseProvider, StorageSigner};
// binding-boundary-allow: pre-lint reach; migrate to an auths_sdk workflow
use auths_core::storage::keychain::{IdentityDID, KeyAlias, KeyStorage};
// binding-boundary-allow: pre-lint reach; migrate to an auths_sdk workflow
use auths_id::attestation::create::create_signed_attestation;
// binding-boundary-allow: pre-lint reach; migrate to an auths_sdk workflow
use auths_id::identity::initialize::initialize_registry_identity;
// binding-boundary-allow: pre-lint reach; migrate to an auths_sdk workflow
use auths_id::identity::resolve::RegistryDidResolver;
// binding-boundary-allow: pre-lint reach; migrate to an auths_sdk workflow
use auths_id::keri::types::Prefix;
// binding-boundary-allow: pre-lint reach; migrate to an auths_sdk workflow
use auths_id::storage::git_refs::AttestationMetadata;
// binding-boundary-allow: pre-lint reach; migrate to an auths_sdk workflow
use auths_id::storage::registry::RegistryBackend;
use auths_sdk::context::AuthsContext;
use auths_sdk::workflows::org::{add_member, list_members, revoke_member};
// binding-boundary-allow: pre-lint reach; migrate to an auths_sdk workflow
use auths_storage::git::{
    GitRegistryBackend, RegistryAttestationStorage, RegistryConfig, RegistryIdentityStorage,
};
use auths_verifier::clock::SystemClock;
use auths_verifier::core::Role;
use auths_verifier::types::CanonicalDid;
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
    let identity_did =
        IdentityDID::parse(org_did).map_err(|e| format_error("AUTHS_ORG_ERROR", e))?;
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

fn org_prefix_from_did(org_did: &str) -> Prefix {
    Prefix::new_unchecked(extract_org_prefix(org_did))
}

fn build_org_context(
    repo: &std::path::Path,
    passphrase: &str,
    repo_path: &str,
) -> napi::Result<AuthsContext> {
    let backend = Arc::new(
        GitRegistryBackend::open_existing(RegistryConfig::single_tenant(repo)).map_err(|e| {
            format_error("AUTHS_ORG_ERROR", format!("Failed to open registry: {e}"))
        })?,
    );
    let keychain: Arc<dyn KeyStorage + Send + Sync> =
        Arc::from(get_keychain(passphrase, repo_path)?);
    let provider = Arc::new(PrefilledPassphraseProvider::new(passphrase));
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

    #[allow(clippy::disallowed_methods)] // INVARIANT: key_alias_str from caller input
    let key_alias = KeyAlias::new_unchecked(key_alias_str);
    let keychain = get_keychain(&passphrase_str, &repo_path)?;
    let provider = PrefilledPassphraseProvider::new(&passphrase_str);

    let (controller_did, alias) = initialize_registry_identity(
        backend.clone(),
        &key_alias,
        &provider,
        &*keychain,
        None,
        auths_crypto::CurveType::default(),
    )
    .map_err(|e| format_error("AUTHS_ORG_ERROR", e))?;

    let uuid_provider = SystemUuidProvider;
    let rid = auths_core::ports::id::UuidProvider::new_id(&uuid_provider).to_string();

    let resolver = RegistryDidResolver::new(backend.clone());
    let org_resolved = resolver
        .resolve(controller_did.as_str())
        .map_err(|e| format_error("AUTHS_ORG_ERROR", e))?;
    let org_pk_bytes = org_resolved.public_key_bytes().to_vec();
    let org_curve = org_resolved.curve();

    #[allow(clippy::disallowed_methods)]
    let now = chrono::Utc::now();

    let meta = AttestationMetadata {
        note: Some(format!("Organization '{}' root admin", label)),
        timestamp: Some(now),
        expires_at: None,
    };

    let signer = StorageSigner::new(keychain);
    let org_did_device = CanonicalDid::from_public_key_did_key(&org_pk_bytes, org_curve);

    let issuer_canonical = CanonicalDid::from(controller_did.clone());
    let attestation = create_signed_attestation(
        now,
        auths_sdk::attestation::AttestationInput {
            rid: &rid,
            issuer: &issuer_canonical,
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
            oidc_binding: None,
        },
        &signer,
        &provider,
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
    member_label: String,
    role: String,
    repo_path: String,
    capabilities_json: Option<String>,
    passphrase: Option<String>,
    expires_at: Option<i64>,
) -> napi::Result<NapiOrgMember> {
    let passphrase_str = resolve_passphrase(passphrase);
    let repo = resolve_repo(&repo_path);

    let role_parsed: Role = role
        .parse()
        .map_err(|e| format_error("AUTHS_ORG_ERROR", format!("Invalid role: {e}")))?;

    let capabilities: Vec<auths_verifier::Capability> = if let Some(json) = capabilities_json {
        let raw: Vec<String> = serde_json::from_str(&json).map_err(|e| {
            format_error("AUTHS_ORG_ERROR", format!("Invalid capabilities JSON: {e}"))
        })?;
        raw.iter()
            .map(|s| auths_verifier::Capability::parse(s))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| format_error("AUTHS_ORG_ERROR", format!("Invalid capability: {e}")))?
    } else {
        role_parsed.default_capabilities()
    };

    let keychain = get_keychain(&passphrase_str, &repo_path)?;
    let org_alias = find_signer_alias(&org_did, &*keychain)?;
    drop(keychain);

    #[allow(clippy::disallowed_methods)] // INVARIANT: member_label is caller-provided
    let member_alias = KeyAlias::new_unchecked(format!("org-member-{member_label}"));

    let ctx = build_org_context(&repo, &passphrase_str, &repo_path)?;
    let org_prefix = org_prefix_from_did(&org_did);

    let result = add_member(
        &ctx,
        &org_prefix,
        &org_alias,
        &member_alias,
        auths_crypto::CurveType::default(),
        role_parsed,
        &capabilities,
        expires_at,
    )
    .map_err(|e| format_error("AUTHS_ORG_ERROR", e))?;

    let caps_json = serde_json::to_string(&capabilities).unwrap_or_default();

    Ok(NapiOrgMember {
        member_did: result.member_did,
        role,
        capabilities_json: caps_json,
        issuer_did: org_did,
        attestation_rid: result.member_prefix,
        revoked: false,
        expires_at: expires_at
            .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0).map(|d| d.to_rfc3339())),
    })
}

#[napi]
pub fn revoke_org_member(
    org_did: String,
    member_did: String,
    repo_path: String,
    passphrase: Option<String>,
) -> napi::Result<NapiOrgMember> {
    let passphrase_str = resolve_passphrase(passphrase);
    let repo = resolve_repo(&repo_path);

    let keychain = get_keychain(&passphrase_str, &repo_path)?;
    let org_alias = find_signer_alias(&org_did, &*keychain)?;
    drop(keychain);

    let ctx = build_org_context(&repo, &passphrase_str, &repo_path)?;
    let org_prefix = org_prefix_from_did(&org_did);

    revoke_member(&ctx, &org_prefix, &org_alias, &member_did, None)
        .map_err(|e| format_error("AUTHS_ORG_ERROR", e))?;

    Ok(NapiOrgMember {
        member_did,
        role: "member".to_string(),
        capabilities_json: serde_json::to_string(&Vec::<String>::new()).unwrap_or_default(),
        issuer_did: org_did,
        attestation_rid: String::new(),
        revoked: true,
        expires_at: None,
    })
}

#[napi]
pub fn list_org_members(
    org_did: String,
    include_revoked: bool,
    repo_path: String,
    passphrase: Option<String>,
) -> napi::Result<String> {
    let passphrase_str = resolve_passphrase(passphrase);
    let repo = resolve_repo(&repo_path);

    let ctx = build_org_context(&repo, &passphrase_str, &repo_path)?;
    let org_prefix = org_prefix_from_did(&org_did);

    let members =
        list_members(&ctx, &org_prefix).map_err(|e| format_error("AUTHS_ORG_ERROR", e))?;

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

    serde_json::to_string(&result).map_err(|e| format_error("AUTHS_ORG_ERROR", e))
}
