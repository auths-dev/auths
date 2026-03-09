use std::path::PathBuf;

use auths_core::config::{EnvironmentConfig, KeychainConfig};
use auths_core::storage::keychain::{
    IdentityDID, KeyAlias, KeyRole, KeyStorage, get_platform_keychain_with_config,
};

use crate::error::format_error;

#[allow(clippy::disallowed_methods)] // Presentation boundary: env var read is intentional
pub fn resolve_passphrase(passphrase: Option<String>) -> String {
    passphrase.unwrap_or_else(|| std::env::var("AUTHS_PASSPHRASE").unwrap_or_default())
}

#[allow(clippy::disallowed_methods)] // Presentation boundary: env var read is intentional
pub fn resolve_repo_path(path: Option<String>) -> PathBuf {
    let raw = path
        .unwrap_or_else(|| std::env::var("AUTHS_HOME").unwrap_or_else(|_| "~/.auths".to_string()));
    let expanded = shellexpand::tilde(&raw);
    PathBuf::from(expanded.as_ref())
}

pub fn make_env_config(passphrase: &str, repo_path: &str) -> EnvironmentConfig {
    let mut keychain = KeychainConfig::from_env();
    if keychain.backend.is_none() {
        keychain.backend = Some("file".to_string());
    }
    keychain.passphrase = Some(passphrase.to_string());
    EnvironmentConfig {
        auths_home: Some(repo_path.into()),
        keychain,
        ssh_agent_socket: None,
    }
}

pub fn get_keychain(config: &EnvironmentConfig) -> napi::Result<Box<dyn KeyStorage + Send + Sync>> {
    get_platform_keychain_with_config(config).map_err(|e| format_error("AUTHS_KEYCHAIN_ERROR", e))
}

pub fn resolve_key_alias(
    identity_ref: &str,
    keychain: &(dyn KeyStorage + Send + Sync),
) -> napi::Result<KeyAlias> {
    if identity_ref.starts_with("did:") {
        let did = IdentityDID::new_unchecked(identity_ref.to_string());
        let aliases = keychain
            .list_aliases_for_identity_with_role(&did, KeyRole::Primary)
            .map_err(|e| format_error("AUTHS_KEY_NOT_FOUND", format!("Key lookup failed: {e}")))?;
        aliases.into_iter().next().ok_or_else(|| {
            format_error(
                "AUTHS_KEY_NOT_FOUND",
                format!("No primary key found for identity '{identity_ref}'"),
            )
        })
    } else {
        KeyAlias::new(identity_ref)
            .map_err(|e| format_error("AUTHS_KEY_NOT_FOUND", format!("Invalid key alias: {e}")))
    }
}
