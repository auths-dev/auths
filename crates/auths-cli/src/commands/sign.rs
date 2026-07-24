//! Unified sign command: signs a file artifact or a git commit range.

use anyhow::{Context, Result, anyhow};
use clap::Parser;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use auths_sdk::core_config::EnvironmentConfig;
use auths_sdk::domains::identity::local::{LocalSigner, resolve_local_signer};
use auths_sdk::signing::PassphraseProvider;

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
        if looks_like_artifact_path(raw_target) {
            eprintln!(
                "Warning: '{}' looks like an artifact file path, but the file does not exist.\n\
                 Treating as a git commit range. If you meant to sign a file, check the path.",
                raw_target
            );
        }
        SignTarget::CommitRange(raw_target.to_string())
    }
}

/// Heuristic: does the target look like an artifact file path rather than a git ref?
fn looks_like_artifact_path(target: &str) -> bool {
    // Path-shaped strings
    if target.starts_with("./") || target.starts_with("../") || target.contains('/') {
        let lower = target.to_lowercase();
        return ARTIFACT_EXTENSIONS.iter().any(|ext| lower.ends_with(ext));
    }
    // Bare filename with artifact extension
    let lower = target.to_lowercase();
    ARTIFACT_EXTENSIONS.iter().any(|ext| lower.ends_with(ext))
}

const ARTIFACT_EXTENSIONS: &[&str] = &[
    ".tar.gz", ".tgz", ".zip", ".whl", ".gem", ".jar", ".deb", ".rpm", ".dmg", ".exe", ".msi",
    ".pkg", ".nupkg",
];

/// Ensure the signer's root is pinned in the repo's committed `.auths/roots` and
/// staged, so the pin (the trust declaration teammates and CI inherit) lands with
/// the next commit. Idempotent and best-effort — a pin failure never fails the
/// sign; self-trust already covers the signer's own verification.
fn ensure_repo_root_pin(signer: &LocalSigner) {
    let Ok(output) = crate::subprocess::git_command(&["rev-parse", "--show-toplevel"]).output()
    else {
        return;
    };
    if !output.status.success() {
        return;
    }
    let toplevel = PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    let auths_dir = toplevel.join(".auths");
    let store = crate::adapters::config_store::FileConfigStore;
    let root_did = signer.root_did.to_string();
    if auths_sdk::workflows::roots::is_pinned_root(&store, &auths_dir, &root_did).unwrap_or(false) {
        return;
    }
    if auths_sdk::workflows::roots::add_pinned_root(&store, &auths_dir, &root_did).is_ok() {
        let roots_file = auths_dir.join("roots");
        let _ =
            crate::subprocess::git_command(&["add", "--", &roots_file.to_string_lossy()]).output();
        eprintln!("auths: pinned your identity root in .auths/roots (staged for the next commit)");
    }
}

/// Resolve the local signing identity → the trailer values to embed in-band.
///
/// Resolution reads identity + registry only (no key decryption), so it needs no
/// passphrase. Fails clearly when this machine has no resolvable signing identity.
fn resolve_signer_trailer(
    repo_opt: Option<&Path>,
    env_config: &EnvironmentConfig,
) -> Result<LocalSigner> {
    let repo_path =
        auths_sdk::storage_layout::resolve_repo_path(repo_opt.map(|p| p.to_path_buf()))?;
    let ctx = crate::factories::storage::build_auths_context(&repo_path, env_config, None)
        .context("Failed to build auths context for commit signing")?;
    resolve_local_signer(&ctx).map_err(anyhow::Error::from).context(
        "Could not resolve the local signing identity. Run `auths init`, or pair this device with `auths pair --join`.",
    )
}

/// Sign a Git commit or artifact file.
#[derive(Parser, Debug, Clone)]
#[command(
    about = "Sign a Git commit or artifact file.",
    after_help = "Examples:
  auths sign README.md                    # Sign a file → README.md.auths.json
  auths sign HEAD                         # Sign the current commit
  auths sign main..HEAD                   # Re-sign commits after main

Artifacts:
  Signing files creates a .auths.json attestation with your identity and device.
  Use `auths verify` to check the signature.

Commits:
  Commit signing requires a linked device and Git configuration.
  Verify with `auths verify HEAD` or `git log --show-signature`.

Related:
  auths verify      — Verify signatures
  auths device list — Check linked devices"
)]
pub struct SignCommand {
    /// Git ref, commit range (e.g. HEAD, main..HEAD), or path to an artifact file.
    #[arg(help = "Commit ref, range, or artifact file path")]
    pub target: String,

    /// Output path for the signature file. Defaults to <FILE>.auths.json.
    #[arg(long = "sig-output", value_name = "PATH")]
    pub sig_output: Option<PathBuf>,

    /// Overwrite the signature output file if it already exists.
    #[arg(long)]
    pub force: bool,

    /// Local alias of the identity key (for artifact signing).
    #[arg(long)]
    pub key: Option<String>,

    /// Local alias of the device key (for artifact signing, required for files).
    #[arg(long)]
    pub device_key: Option<String>,

    /// Duration in seconds until expiration (per RFC 6749).
    #[arg(long = "expires-in", value_name = "N")]
    pub expires_in: Option<u64>,

    /// Optional note to embed in the attestation (for artifact signing).
    #[arg(long)]
    pub note: Option<String>,

    /// Capabilities this commit claims it exercises (comma-separated), e.g.
    /// `--scope sign_commit`. Emitted as an `Auths-Scope` trailer so a verifier can
    /// reject a claim outside the signer's delegator-anchored grant. Commit-only.
    #[arg(long, value_delimiter = ',')]
    pub scope: Vec<String>,

    /// Override the signing key alias (defaults to AUTHS_SIGNING_KEY or git config).
    #[arg(long)]
    pub signer: Option<String>,

    /// Automatically stash and restore uncommitted working tree changes during re-signing.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    pub autostash: bool,
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
            let device_key_alias = match cmd.device_key.as_deref() {
                Some(alias) => alias.to_string(),
                None => super::key_detect::auto_detect_device_key(repo_opt.as_deref(), env_config)?,
            };
            // A file attestation does not bind a commit: the ambient git HEAD is unrelated to the
            // file being signed, and inferring it would let whatever commit happens to be checked
            // out be claimed as the attestation's provenance. Bind one explicitly with
            // `auths artifact sign --commit <sha>`.
            let commit_sha: Option<String> = None;
            handle_artifact_sign(
                &path,
                cmd.sig_output,
                cmd.key.as_deref(),
                &device_key_alias,
                cmd.expires_in,
                cmd.note,
                commit_sha,
                repo_opt,
                passphrase_provider,
                env_config,
                &None,
                false,
                cmd.force,
            )
        }
        SignTarget::CommitRange(range) => {
            let signer = resolve_signer_trailer(repo_opt.as_deref(), env_config)?;
            ensure_repo_root_pin(&signer);
            auths_sdk::workflows::commit_signing::sign_commit_range(
                &range,
                &signer,
                &cmd.scope,
                cmd.autostash,
            )?;

            if crate::ux::format::is_json_mode() {
                crate::ux::format::JsonResponse::success(
                    "sign",
                    &serde_json::json!({ "target": range, "type": "commit" }),
                )
                .print()?;
            } else {
                println!("✔ Signed: {}", range);
            }
            Ok(())
        }
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
