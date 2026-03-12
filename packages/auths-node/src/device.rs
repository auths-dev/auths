use std::path::PathBuf;
use std::sync::Arc;

use auths_core::signing::PrefilledPassphraseProvider;
use auths_core::storage::keychain::get_platform_keychain_with_config;
use auths_sdk::context::AuthsContext;
use auths_sdk::device::extend_device;
use auths_sdk::device::{link_device, revoke_device};
use auths_sdk::types::{DeviceExtensionConfig, DeviceLinkConfig};
use auths_storage::git::{
    GitRegistryBackend, RegistryAttestationStorage, RegistryConfig, RegistryIdentityStorage,
};
use auths_verifier::clock::SystemClock;
use auths_verifier::core::Capability;
use auths_verifier::types::DeviceDID;
use napi_derive::napi;

use crate::error::format_error;
use crate::helpers::{make_env_config, resolve_key_alias, resolve_passphrase};
use crate::types::{NapiExtensionResult, NapiLinkResult};

fn open_backend(repo: &PathBuf) -> napi::Result<Arc<GitRegistryBackend>> {
    let config = RegistryConfig::single_tenant(repo);
    let backend = GitRegistryBackend::open_existing(config).map_err(|e| {
        format_error(
            "AUTHS_REGISTRY_ERROR",
            format!("Failed to open registry: {e}"),
        )
    })?;
    Ok(Arc::new(backend))
}

#[napi]
pub fn link_device_to_identity(
    identity_key_alias: String,
    capabilities: Vec<String>,
    repo_path: String,
    passphrase: Option<String>,
    expires_in: Option<i64>,
) -> napi::Result<NapiLinkResult> {
    let passphrase_str = resolve_passphrase(passphrase);
    let env_config = make_env_config(&passphrase_str, &repo_path);
    let provider = Arc::new(PrefilledPassphraseProvider::new(&passphrase_str));
    let clock = Arc::new(SystemClock);

    let repo = PathBuf::from(shellexpand::tilde(&repo_path).as_ref());
    let backend = open_backend(&repo)?;

    let keychain = get_platform_keychain_with_config(&env_config)
        .map_err(|e| format_error("AUTHS_KEYCHAIN_ERROR", format!("Keychain error: {e}")))?;

    let alias = resolve_key_alias(&identity_key_alias, keychain.as_ref())?;

    let parsed_caps: Vec<Capability> = capabilities
        .iter()
        .map(|c| {
            Capability::parse(c).map_err(|e| {
                format_error(
                    "AUTHS_INVALID_INPUT",
                    format!("Invalid capability '{c}': {e}"),
                )
            })
        })
        .collect::<napi::Result<Vec<_>>>()?;

    let link_config = DeviceLinkConfig {
        identity_key_alias: alias,
        device_key_alias: None,
        device_did: None,
        capabilities: parsed_caps,
        expires_in: expires_in.map(|s| s as u64),
        note: None,
        payload: None,
    };

    let keychain: Arc<dyn auths_core::storage::keychain::KeyStorage + Send + Sync> =
        Arc::from(keychain);
    let identity_storage = Arc::new(RegistryIdentityStorage::new(&repo));
    let attestation_storage = Arc::new(RegistryAttestationStorage::new(&repo));

    let ctx = AuthsContext::builder()
        .registry(backend)
        .key_storage(keychain)
        .clock(clock.clone())
        .identity_storage(identity_storage)
        .attestation_sink(attestation_storage.clone())
        .attestation_source(attestation_storage)
        .passphrase_provider(provider)
        .build();

    let result = link_device(link_config, &ctx, clock.as_ref())
        .map_err(|e| format_error("AUTHS_DEVICE_ERROR", format!("Device linking failed: {e}")))?;

    Ok(NapiLinkResult {
        device_did: result.device_did.to_string(),
        attestation_id: result.attestation_id.to_string(),
    })
}

#[napi]
pub fn revoke_device_from_identity(
    device_did: String,
    identity_key_alias: String,
    repo_path: String,
    passphrase: Option<String>,
    note: Option<String>,
) -> napi::Result<()> {
    let passphrase_str = resolve_passphrase(passphrase);
    let env_config = make_env_config(&passphrase_str, &repo_path);
    let provider = Arc::new(PrefilledPassphraseProvider::new(&passphrase_str));
    let clock = Arc::new(SystemClock);

    let repo = PathBuf::from(shellexpand::tilde(&repo_path).as_ref());
    let backend = open_backend(&repo)?;

    let keychain = get_platform_keychain_with_config(&env_config)
        .map_err(|e| format_error("AUTHS_KEYCHAIN_ERROR", format!("Keychain error: {e}")))?;

    let alias = resolve_key_alias(&identity_key_alias, keychain.as_ref())?;

    let keychain: Arc<dyn auths_core::storage::keychain::KeyStorage + Send + Sync> =
        Arc::from(keychain);
    let identity_storage = Arc::new(RegistryIdentityStorage::new(&repo));
    let attestation_storage = Arc::new(RegistryAttestationStorage::new(&repo));

    let ctx = AuthsContext::builder()
        .registry(backend)
        .key_storage(keychain)
        .clock(clock.clone())
        .identity_storage(identity_storage)
        .attestation_sink(attestation_storage.clone())
        .attestation_source(attestation_storage)
        .passphrase_provider(provider)
        .build();

    revoke_device(&device_did, &alias, &ctx, note, clock.as_ref()).map_err(|e| {
        format_error(
            "AUTHS_DEVICE_ERROR",
            format!("Device revocation failed: {e}"),
        )
    })?;

    Ok(())
}

#[napi]
pub fn extend_device_authorization(
    device_did: String,
    identity_key_alias: String,
    expires_in: i64,
    repo_path: String,
    passphrase: Option<String>,
) -> napi::Result<NapiExtensionResult> {
    if expires_in <= 0 {
        return Err(format_error(
            "AUTHS_INVALID_INPUT",
            "expires_in must be positive (> 0)",
        ));
    }

    let passphrase_str = resolve_passphrase(passphrase);
    let env_config = make_env_config(&passphrase_str, &repo_path);
    let provider = Arc::new(PrefilledPassphraseProvider::new(&passphrase_str));
    let clock = Arc::new(SystemClock);

    let repo = PathBuf::from(shellexpand::tilde(&repo_path).as_ref());
    let backend = open_backend(&repo)?;

    let keychain = get_platform_keychain_with_config(&env_config)
        .map_err(|e| format_error("AUTHS_KEYCHAIN_ERROR", format!("Keychain error: {e}")))?;
    let keychain: Arc<dyn auths_core::storage::keychain::KeyStorage + Send + Sync> =
        Arc::from(keychain);

    let identity_storage = Arc::new(RegistryIdentityStorage::new(&repo));
    let attestation_storage = Arc::new(RegistryAttestationStorage::new(&repo));

    let alias = resolve_key_alias(&identity_key_alias, keychain.as_ref())?;

    let ext_config = DeviceExtensionConfig {
        repo_path: repo,
        device_did: DeviceDID::parse(&device_did)
            .map_err(|e| format_error("AUTHS_INVALID_INPUT", e))?,
        expires_in: expires_in as u64,
        identity_key_alias: alias,
        device_key_alias: None,
    };

    let ctx = AuthsContext::builder()
        .registry(backend)
        .key_storage(keychain)
        .clock(clock.clone())
        .identity_storage(identity_storage)
        .attestation_sink(attestation_storage.clone())
        .attestation_source(attestation_storage)
        .passphrase_provider(provider)
        .build();

    let result = extend_device(ext_config, &ctx, clock.as_ref()).map_err(|e| {
        format_error(
            "AUTHS_DEVICE_ERROR",
            format!("Device extension failed: {e}"),
        )
    })?;

    Ok(NapiExtensionResult {
        device_did: result.device_did.to_string(),
        new_expires_at: result.new_expires_at.to_rfc3339(),
        previous_expires_at: result
            .previous_expires_at
            .map(|t: chrono::DateTime<chrono::Utc>| t.to_rfc3339()),
    })
}
