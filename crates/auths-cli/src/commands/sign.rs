//! Unified sign command: signs a file artifact or a git commit range.

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use auths_core::config::EnvironmentConfig;
use auths_core::signing::PassphraseProvider;

use super::artifact::sign::handle_sign as handle_artifact_sign;

/// Represents the resolved target for a sign operation.
pub enum SignTarget {
    Artifact(PathBuf),
    CommitRange(String),
}

/// Resolves raw CLI input into a concrete target type.
///
/// Checks the filesystem first. If no file exists at the path, assumes a Git reference.
///
/// Args:
/// * `raw_target` - The raw string input from the CLI.
///
/// Usage:
/// ```ignore
/// let target = parse_sign_target("HEAD");
/// assert!(matches!(target, SignTarget::CommitRange(_)));
/// ```
pub fn parse_sign_target(raw_target: &str) -> SignTarget {
    let path = Path::new(raw_target);
    if path.exists() {
        SignTarget::Artifact(path.to_path_buf())
    } else {
        SignTarget::CommitRange(raw_target.to_string())
    }
}

/// Execute `git rebase --exec "git commit --amend --no-edit" <base>` to re-sign a range.
///
/// Args:
/// * `base` - The exclusive base ref (commits after this ref will be re-signed).
fn execute_git_rebase(base: &str) -> Result<()> {
    use std::process::Command;
    let output = Command::new("git")
        .args(["rebase", "--exec", "git commit --amend --no-edit", base])
        .output()
        .context("Failed to spawn git rebase")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("git rebase failed: {}", stderr.trim()));
    }
    Ok(())
}

/// Sign a Git commit range by invoking git-rebase with auths-sign as the signing program.
///
/// Args:
/// * `range` - A git ref or range (e.g., "HEAD", "main..HEAD").
fn sign_commit_range(range: &str) -> Result<()> {
    use std::process::Command;
    let is_range = range.contains("..");
    if is_range {
        let parts: Vec<&str> = range.splitn(2, "..").collect();
        let base = parts[0];
        execute_git_rebase(base)?;
    } else {
        let output = Command::new("git")
            .args(["commit", "--amend", "--no-edit", "--no-verify"])
            .output()
            .context("Failed to spawn git commit --amend")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("git commit --amend failed: {}", stderr.trim()));
        }
    }
    println!("✔ Signed: {}", range);
    Ok(())
}

/// Sign a Git commit or artifact file.
#[derive(Parser, Debug, Clone)]
#[command(about = "Sign a Git commit or artifact file.")]
pub struct SignCommand {
    /// Git ref, commit range (e.g. HEAD, main..HEAD), or path to an artifact file.
    #[arg(help = "Commit ref, range, or artifact file path")]
    pub target: String,

    /// Output path for the signature file. Defaults to <FILE>.auths.json.
    #[arg(long = "sig-output", value_name = "PATH")]
    pub sig_output: Option<PathBuf>,

    /// Local alias of the identity key (for artifact signing).
    #[arg(long)]
    pub identity_key_alias: Option<String>,

    /// Local alias of the device key (for artifact signing, required for files).
    #[arg(long)]
    pub device_key_alias: Option<String>,

    /// Number of days until the signature expires (for artifact signing).
    #[arg(long, value_name = "N")]
    pub expires_in_days: Option<i64>,

    /// Optional note to embed in the attestation (for artifact signing).
    #[arg(long)]
    pub note: Option<String>,
}

/// Handle the unified sign command.
///
/// Args:
/// * `cmd` - Parsed SignCommand arguments.
/// * `repo_opt` - Optional path to the Auths identity repository.
/// * `passphrase_provider` - Provider for key passphrases.
pub fn handle_sign_unified(
    cmd: SignCommand,
    repo_opt: Option<PathBuf>,
    passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
    env_config: &EnvironmentConfig,
) -> Result<()> {
    match parse_sign_target(&cmd.target) {
        SignTarget::Artifact(path) => {
            let device_key_alias = cmd.device_key_alias.as_deref().ok_or_else(|| {
                anyhow!(
                    "artifact signing requires --device-key-alias\n\nRun: auths sign <file> --device-key-alias <alias>"
                )
            })?;
            handle_artifact_sign(
                &path,
                cmd.sig_output,
                cmd.identity_key_alias.as_deref(),
                device_key_alias,
                cmd.expires_in_days,
                cmd.note,
                repo_opt,
                passphrase_provider,
                env_config,
            )
        }
        SignTarget::CommitRange(range) => sign_commit_range(&range),
    }
}

impl crate::commands::executable::ExecutableCommand for SignCommand {
    fn execute(&self, ctx: &crate::config::CliConfig) -> anyhow::Result<()> {
        handle_sign_unified(
            self.clone(),
            ctx.repo_path.clone(),
            ctx.passphrase_provider.clone(),
            &ctx.env_config,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sign_target_commit_ref() {
        let target = parse_sign_target("HEAD");
        assert!(matches!(target, SignTarget::CommitRange(_)));
    }

    #[test]
    fn test_parse_sign_target_range() {
        let target = parse_sign_target("main..HEAD");
        assert!(matches!(target, SignTarget::CommitRange(_)));
    }

    #[test]
    fn test_parse_sign_target_nonexistent_path_is_commit_range() {
        let target = parse_sign_target("/nonexistent/artifact.tar.gz");
        assert!(matches!(target, SignTarget::CommitRange(_)));
    }

    #[test]
    fn test_parse_sign_target_file() {
        use std::fs::File;
        use tempfile::tempdir;
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("artifact.tar.gz");
        File::create(&file_path).unwrap();
        let target = parse_sign_target(file_path.to_str().unwrap());
        assert!(matches!(target, SignTarget::Artifact(_)));
    }
}
