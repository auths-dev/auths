//! Shared device key alias auto-detection.

use std::path::Path;

use anyhow::{Context, Result, anyhow};
use auths_sdk::core_config::EnvironmentConfig;
use auths_sdk::keychain::{IdentityDID, KeyAlias, KeyStorage};
use auths_sdk::ports::IdentityStorage;
use auths_sdk::storage::RegistryIdentityStorage;
use dialoguer::Select;
use std::io::IsTerminal;

use crate::ux::format::is_json_mode;

fn filter_signing_aliases(aliases: Vec<KeyAlias>) -> Vec<KeyAlias> {
    aliases
        .into_iter()
        .filter(|a| !a.as_str().contains("--next-"))
        .collect()
}

/// This root's live delegated device #0 as an `IdentityDID`, or `None` if the root has no
/// delegated device.
///
/// Device #0's signing key is stored in the keychain under the device's OWN AID (not the
/// root's), so day-to-day signing is the device's — distinct from the root identity. This
/// selection mirrors `resolve_local_signer` (first non-revoked delegation) so the key that
/// signs matches the `Auths-Device` trailer the signer reports.
///
/// Args:
/// * `repo_path`: Path to the identity repository (the KEL/registry root).
/// * `root_did`: The root controller's `did:keri`.
///
/// Usage:
/// ```ignore
/// let signer = delegated_primary_device_did(&repo_path, &identity.controller_did)
///     .unwrap_or_else(|| identity.controller_did.clone());
/// ```
fn delegated_primary_device_did(repo_path: &Path, root_did: &IdentityDID) -> Option<IdentityDID> {
    let root_prefix = auths_sdk::keri::parse_did_keri(root_did.as_str()).ok()?;
    let backend = auths_sdk::storage::GitRegistryBackend::from_config_unchecked(
        auths_sdk::storage::RegistryConfig::single_tenant(repo_path),
    );
    let devices =
        auths_sdk::keri::delegation::list_delegated_devices(&backend, &root_prefix).ok()?;
    let device = devices.iter().find(|d| !d.revoked)?;
    IdentityDID::from_prefix(device.device_prefix.as_str()).ok()
}

fn select_device_key_interactive(aliases: &[KeyAlias]) -> Result<String> {
    let display_items: Vec<&str> = aliases.iter().map(|a| a.as_str()).collect();

    let selection = Select::new()
        .with_prompt("Select signing key")
        .items(&display_items)
        .default(0)
        .interact()
        .context("Key selection cancelled")?;

    Ok(aliases[selection].as_str().to_string())
}

/// Auto-detect the device key alias when not explicitly provided.
///
/// Loads the identity from the repository, then lists all key aliases
/// associated with that identity. Filters out `--next-` rotation keys,
/// then either auto-selects (single key) or prompts interactively (multiple keys).
///
/// Args:
/// * `repo_opt`: Optional path to the identity repository.
/// * `env_config`: Environment configuration for keychain access.
///
/// Usage:
/// ```ignore
/// let alias = auto_detect_device_key(repo_opt.as_deref(), env_config)?;
/// ```
pub fn auto_detect_device_key(
    repo_opt: Option<&Path>,
    env_config: &EnvironmentConfig,
) -> Result<String> {
    let repo_path =
        auths_sdk::storage_layout::resolve_repo_path(repo_opt.map(|p| p.to_path_buf()))?;
    let identity_storage = RegistryIdentityStorage::new(repo_path.clone());
    let identity = identity_storage
        .load_identity()
        .map_err(|_| anyhow!("No identity found. Run `auths init` to get started."))?;

    let keychain = auths_sdk::keychain::get_platform_keychain_with_config(env_config)
        .context("Failed to access keychain")?;
    // Prefer this root's delegated device #0's OWN key (stored under the device's AID), so
    // the device SIGNATURE is device #0's, not the root's. Fall back to the root's keys
    // (a root with no delegated device — e.g. CI signing directly).
    let signing_identity = delegated_primary_device_did(&repo_path, &identity.controller_did)
        .unwrap_or_else(|| identity.controller_did.clone());
    let aliases = keychain
        .list_aliases_for_identity(&signing_identity)
        .map_err(|e| anyhow!("Failed to list key aliases: {e}"))?;

    let signing_aliases = filter_signing_aliases(aliases);

    match signing_aliases.len() {
        0 => Err(anyhow!(
            "No signing keys found for identity {}.\n\n\
             All keys are rotation keys (--next- prefixed) or no keys exist.\n\
             Run `auths status` to see your identity details, or `auths pair` to link another device.",
            identity.controller_did
        )),
        1 => Ok(signing_aliases[0].as_str().to_string()),
        _ => {
            if std::io::stdin().is_terminal() && !is_json_mode() {
                select_device_key_interactive(&signing_aliases)
            } else {
                let alias_list: Vec<&str> = signing_aliases.iter().map(|a| a.as_str()).collect();
                Err(anyhow!(
                    "Multiple device keys found. Specify with --device-key.\n\n\
                     Available aliases: {}",
                    alias_list.join(", ")
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_sdk::keychain::KeyAlias;

    #[test]
    fn filter_removes_next_aliases() {
        let aliases = vec![
            KeyAlias::new("main").unwrap(),
            KeyAlias::new("main--next-0").unwrap(),
            KeyAlias::new("secondary").unwrap(),
            KeyAlias::new("main--next-1").unwrap(),
        ];
        let result = filter_signing_aliases(aliases);
        let names: Vec<&str> = result.iter().map(|a| a.as_str()).collect();
        assert_eq!(names, vec!["main", "secondary"]);
    }

    #[test]
    fn filter_all_next_returns_empty() {
        let aliases = vec![
            KeyAlias::new("main--next-0").unwrap(),
            KeyAlias::new("main--next-1").unwrap(),
        ];
        let result = filter_signing_aliases(aliases);
        assert!(result.is_empty());
    }
}
