use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use auths_sdk::core_config::EnvironmentConfig;
use auths_sdk::domains::signing::service::{
    ArtifactSigningParams, SigningKeyMaterial, sign_artifact,
};
use auths_sdk::keychain::KeyAlias;
use auths_sdk::signing::PassphraseProvider;

use super::file::FileArtifact;
use super::{dsse_pae, merge_transparency, submit_to_log};
use crate::factories::storage::build_auths_context;

/// Execute the `artifact sign` command.
#[allow(clippy::too_many_arguments)]
pub fn handle_sign(
    file: &Path,
    output: Option<PathBuf>,
    key: Option<&str>,
    device_key: &str,
    expires_in: Option<u64>,
    note: Option<String>,
    commit_sha: Option<String>,
    repo_opt: Option<PathBuf>,
    passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
    env_config: &EnvironmentConfig,
    log: &Option<String>,
    allow_unlogged: bool,
) -> Result<()> {
    let repo_path = auths_sdk::storage_layout::resolve_repo_path(repo_opt)?;

    let ctx = build_auths_context(&repo_path, env_config, Some(passphrase_provider.clone()))?;

    let params = ArtifactSigningParams {
        artifact: Arc::new(FileArtifact::new(file)),
        identity_key: key.map(|a| SigningKeyMaterial::Alias(KeyAlias::new_unchecked(a))),
        device_key: SigningKeyMaterial::Alias(KeyAlias::new_unchecked(device_key)),
        expires_in,
        note,
        commit_sha,
    };

    let result = sign_artifact(params, &ctx)
        .with_context(|| format!("Failed to sign artifact {:?}", file))?;

    // Compute DSSE signature if log submission is requested
    let dsse_sig = if log.is_some() && !allow_unlogged {
        let pae = dsse_pae(
            "application/vnd.auths+json",
            result.attestation_json.as_bytes(),
        );
        let alias = KeyAlias::new_unchecked(device_key);
        let (sig, _pubkey, _curve) = auths_sdk::keychain::sign_with_key(
            ctx.key_storage.as_ref(),
            &alias,
            passphrase_provider.as_ref(),
            &pae,
        )
        .context("Failed to sign DSSE PAE for log submission")?;
        Some(sig)
    } else {
        None
    };

    let transparency_json = submit_to_log(
        &result.attestation_json,
        log,
        allow_unlogged,
        dsse_sig.as_deref(),
    )?;

    let final_json = if let Some(transparency) = transparency_json {
        merge_transparency(&result.attestation_json, transparency)?
    } else {
        result.attestation_json.clone()
    };

    let output_path = output.unwrap_or_else(|| {
        let mut p = file.to_path_buf();
        let new_name = format!(
            "{}.auths.json",
            p.file_name().unwrap_or_default().to_string_lossy()
        );
        p.set_file_name(new_name);
        p
    });

    std::fs::write(&output_path, &final_json)
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
