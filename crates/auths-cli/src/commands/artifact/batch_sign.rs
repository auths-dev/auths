//! Handler for `auths artifact batch-sign`.

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::sync::Arc;

use auths_sdk::core_config::EnvironmentConfig;
use auths_sdk::signing::PassphraseProvider;
use auths_sdk::workflows::ci::batch_attest::{
    BatchEntry, BatchEntryResult, BatchSignConfig, batch_sign_artifacts, default_attestation_path,
};

use super::file::FileArtifact;
use crate::factories::storage::build_auths_context;

/// Execute the `artifact batch-sign` command.
///
/// Args:
/// * `pattern`: Glob pattern matching artifact files.
/// * `device_key`: Device key alias for signing.
/// * `key`: Optional identity key alias.
/// * `attestation_dir`: Optional directory to collect attestation files.
/// * `expires_in`: Optional TTL in seconds.
/// * `note`: Optional note for attestations.
/// * `repo_opt`: Optional identity repo path.
/// * `passphrase_provider`: Passphrase provider for key decryption.
/// * `env_config`: Environment configuration.
///
/// Usage:
/// ```ignore
/// handle_batch_sign("dist/*.tar.gz", "ci-device", None, Some(".auths/releases"), ...)?;
/// ```
#[allow(clippy::too_many_arguments)]
pub fn handle_batch_sign(
    pattern: &str,
    device_key: &str,
    key: Option<&str>,
    attestation_dir: Option<PathBuf>,
    expires_in: Option<u64>,
    note: Option<String>,
    commit_sha: Option<String>,
    repo_opt: Option<PathBuf>,
    passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
    env_config: &EnvironmentConfig,
) -> Result<()> {
    let repo_path = auths_sdk::storage_layout::resolve_repo_path(repo_opt)?;
    let ctx = build_auths_context(&repo_path, env_config, Some(passphrase_provider))?;

    let paths = expand_glob(pattern)?;
    if paths.is_empty() {
        println!("No files match pattern: {}", pattern);
        return Ok(());
    }

    let entries: Vec<BatchEntry> = paths
        .iter()
        .map(|p| BatchEntry {
            source: Arc::new(FileArtifact::new(p)),
            output_path: default_attestation_path(p),
        })
        .collect();

    println!("Signing {} artifact(s)...", entries.len());

    let config = BatchSignConfig {
        entries,
        device_key: device_key.to_string(),
        identity_key: key.map(|s| s.to_string()),
        expires_in,
        note,
        commit_sha,
    };

    let result = batch_sign_artifacts(config, &ctx)
        .with_context(|| format!("Batch signing failed for pattern: {}", pattern))?;

    // Write attestation files and collect to directory (file I/O is CLI's job)
    for entry in &result.results {
        if let BatchEntryResult::Signed(s) = entry {
            std::fs::write(&s.output_path, &s.attestation_json)
                .with_context(|| format!("Failed to write {}", s.output_path.display()))?;
            println!(
                "  Signed: {} (sha256:{})",
                s.output_path.display(),
                s.digest
            );
        }
        if let BatchEntryResult::Failed(f) = entry {
            eprintln!("  FAILED: {}: {}", f.output_path.display(), f.error);
        }
    }

    if let Some(ref dir) = attestation_dir {
        collect_to_dir(&result.results, dir)?;
        println!("Collected attestations to: {}", dir.display());
    }

    println!(
        "{} signed, {} failed",
        result.signed_count(),
        result.failed_count()
    );

    if result.failed_count() > 0 {
        anyhow::bail!(
            "{} of {} artifact(s) failed to sign",
            result.failed_count(),
            result.signed_count() + result.failed_count()
        );
    }

    Ok(())
}

fn expand_glob(pattern: &str) -> Result<Vec<PathBuf>> {
    let paths: Vec<PathBuf> = glob::glob(pattern)
        .with_context(|| format!("Invalid glob pattern: {}", pattern))?
        .filter_map(|entry| entry.ok())
        .filter(|p| p.is_file())
        .collect();
    Ok(paths)
}

fn collect_to_dir(results: &[BatchEntryResult], dir: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("Failed to create attestation directory: {}", dir.display()))?;

    for entry in results {
        if let BatchEntryResult::Signed(s) = entry {
            let filename = s
                .output_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let dst = dir.join(&filename);
            std::fs::write(&dst, &s.attestation_json)
                .with_context(|| format!("Failed to write {}", dst.display()))?;
        }
    }

    Ok(())
}
