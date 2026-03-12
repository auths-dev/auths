use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use auths_core::config::EnvironmentConfig;
use auths_core::signing::PassphraseProvider;
use auths_core::storage::keychain::KeyAlias;
use auths_sdk::signing::{ArtifactSigningParams, SigningKeyMaterial, sign_artifact};

use super::file::FileArtifact;
use crate::factories::storage::build_auths_context;

/// Execute the `artifact sign` command.
#[allow(clippy::too_many_arguments)]
pub fn handle_sign(
    file: &Path,
    output: Option<PathBuf>,
    identity_key_alias: Option<&str>,
    device_key_alias: &str,
    expires_in: Option<u64>,
    note: Option<String>,
    repo_opt: Option<PathBuf>,
    passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
    env_config: &EnvironmentConfig,
) -> Result<()> {
    let repo_path = auths_id::storage::layout::resolve_repo_path(repo_opt)?;

    let ctx = build_auths_context(&repo_path, env_config, Some(passphrase_provider))?;

    let params = ArtifactSigningParams {
        artifact: Arc::new(FileArtifact::new(file)),
        identity_key: identity_key_alias
            .map(|a| SigningKeyMaterial::Alias(KeyAlias::new_unchecked(a))),
        device_key: SigningKeyMaterial::Alias(KeyAlias::new_unchecked(device_key_alias)),
        expires_in,
        note,
    };

    let result = sign_artifact(params, &ctx)
        .with_context(|| format!("Failed to sign artifact {:?}", file))?;

    let output_path = output.unwrap_or_else(|| {
        let mut p = file.to_path_buf();
        let new_name = format!(
            "{}.auths.json",
            p.file_name().unwrap_or_default().to_string_lossy()
        );
        p.set_file_name(new_name);
        p
    });

    std::fs::write(&output_path, &result.attestation_json)
        .with_context(|| format!("Failed to write signature to {:?}", output_path))?;

    println!(
        "Signed {:?} -> {:?}",
        file.file_name().unwrap_or_default(),
        output_path
    );
    println!("  RID:    {}", result.rid);
    println!("  Digest: sha256:{}", result.digest);

    Ok(())
}
