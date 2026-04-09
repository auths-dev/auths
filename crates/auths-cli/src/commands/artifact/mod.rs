pub mod core;
pub mod file;
pub mod publish;
pub mod sign;
pub mod verify;

use clap::{Args, Subcommand};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use auths_sdk::core_config::EnvironmentConfig;
use auths_sdk::signing::PassphraseProvider;
use auths_sdk::signing::validate_commit_sha;

#[derive(Args, Debug, Clone)]
#[command(
    about = "Sign and verify arbitrary artifacts (tarballs, binaries, etc.).",
    after_help = "Examples:
  auths artifact sign package.tar.gz     # Sign an artifact
  auths artifact sign package.tar.gz --expires-in 2592000
                                         # Sign with 30-day expiry
  auths artifact verify package.tar.gz.auths.json
                                         # Verify artifact signature
  auths artifact publish package.tar.gz --package npm:react@18.3.0
                                         # Sign and publish to registry

Signature Files:
  Signatures are stored as <file>.auths.json next to the artifact.
  Contains identity, device, and signature information.

Related:
  auths sign    — Sign commits and other files
  auths verify  — Verify signatures
  auths trust   — Manage trusted identities"
)]
pub struct ArtifactCommand {
    #[command(subcommand)]
    pub command: ArtifactSubcommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ArtifactSubcommand {
    /// Sign an artifact file with your Auths identity.
    Sign {
        /// Path to the artifact file to sign.
        #[arg(help = "Path to the artifact file to sign.")]
        file: PathBuf,

        /// Output path for the signature file. Defaults to <FILE>.auths.json.
        #[arg(long = "sig-output", value_name = "PATH")]
        sig_output: Option<PathBuf>,

        /// Local alias of the identity key (used for signing). Omit for CI device-only signing.
        #[arg(
            long,
            help = "Local alias of the identity key. Omit for device-only CI signing."
        )]
        key: Option<String>,

        /// Local alias of the device key (used for dual-signing).
        /// Auto-detected when only one key exists for the identity.
        #[arg(
            long,
            help = "Local alias of the device key. Auto-detected when only one key exists."
        )]
        device_key: Option<String>,

        /// Duration in seconds until expiration (per RFC 6749).
        #[arg(long = "expires-in", value_name = "N")]
        expires_in: Option<u64>,

        /// Optional note to embed in the attestation.
        #[arg(long)]
        note: Option<String>,

        /// Git commit SHA to embed in the attestation (auto-detected from HEAD if omitted).
        #[arg(long, conflicts_with = "no_commit")]
        commit: Option<String>,

        /// Do not embed any commit SHA in the attestation.
        #[arg(long, conflicts_with = "commit")]
        no_commit: bool,

        /// Use ephemeral CI signing (no keychain needed). Requires --commit.
        #[arg(long)]
        ci: bool,

        /// CI platform override when --ci is used outside a detected CI environment.
        #[arg(long, requires = "ci")]
        ci_platform: Option<String>,

        /// Transparency log to submit to (overrides default from trust config).
        #[arg(long, value_name = "LOG_ID")]
        log: Option<String>,

        /// Skip transparency log submission (local testing only).
        /// Produces an unlogged attestation that verifiers reject by default.
        #[arg(long)]
        allow_unlogged: bool,
    },

    /// Sign and publish an artifact attestation to a registry.
    ///
    /// Auto-signs the artifact when no --signature is provided.
    Publish {
        /// Artifact file to sign and publish (auto-signs if no --signature).
        #[arg(help = "Artifact file to sign and publish (auto-signs if no --signature).")]
        file: Option<PathBuf>,

        /// Path to an existing .auths.json signature file. Defaults to <FILE>.auths.json.
        #[arg(long, value_name = "PATH")]
        signature: Option<PathBuf>,

        /// Package identifier for registry indexing (e.g., npm:react@18.3.0).
        #[arg(long)]
        package: Option<String>,

        /// Registry URL to publish to.
        #[arg(long, default_value = "https://auths-registry.fly.dev")]
        registry: String,

        /// Local alias of the identity key. Omit for device-only CI signing.
        #[arg(long)]
        key: Option<String>,

        /// Local alias of the device key. Auto-detected when only one key exists.
        #[arg(long)]
        device_key: Option<String>,

        /// Duration in seconds until expiration.
        #[arg(long = "expires-in", value_name = "N")]
        expires_in: Option<u64>,

        /// Optional note to embed in the attestation.
        #[arg(long)]
        note: Option<String>,

        /// Git commit SHA to embed in the attestation (auto-detected from HEAD if omitted).
        #[arg(long, conflicts_with = "no_commit")]
        commit: Option<String>,

        /// Do not embed any commit SHA in the attestation.
        #[arg(long, conflicts_with = "commit")]
        no_commit: bool,
    },

    /// Verify an artifact's signature against an Auths identity.
    Verify {
        /// Path to the artifact file to verify.
        #[arg(help = "Path to the artifact file to verify.")]
        file: PathBuf,

        /// Path to the signature file. Defaults to <FILE>.auths.json.
        #[arg(long, value_name = "PATH")]
        signature: Option<PathBuf>,

        /// Path to identity bundle JSON (for CI/CD stateless verification).
        #[arg(long, value_parser)]
        identity_bundle: Option<PathBuf>,

        /// Path to witness signatures JSON file.
        #[arg(long = "witness-signatures")]
        witness_receipts: Option<PathBuf>,

        /// Witness public keys as DID:hex pairs (e.g., "did:key:z6Mk...:abcd1234...").
        #[arg(long, num_args = 1..)]
        witness_keys: Vec<String>,

        /// Number of witnesses required (default: 1).
        #[arg(long = "witnesses-required", default_value = "1")]
        witness_threshold: usize,

        /// Also verify the source commit's signing attestation.
        #[arg(long)]
        verify_commit: bool,
    },
}

fn is_rate_limited(err: &auths_sdk::workflows::log_submit::LogSubmitError) -> bool {
    matches!(
        err,
        auths_sdk::workflows::log_submit::LogSubmitError::LogError(
            auths_sdk::ports::LogError::RateLimited { .. }
        )
    )
}

fn rate_limit_secs(err: &auths_sdk::workflows::log_submit::LogSubmitError) -> u64 {
    match err {
        auths_sdk::workflows::log_submit::LogSubmitError::LogError(
            auths_sdk::ports::LogError::RateLimited { retry_after_secs },
        ) => *retry_after_secs,
        _ => 10,
    }
}

/// Resolve the commit SHA from CLI flags.
fn resolve_commit_sha_from_flags(
    commit: Option<String>,
    no_commit: bool,
) -> Result<Option<String>> {
    if no_commit {
        return Ok(None);
    }
    if let Some(sha) = commit {
        let validated = validate_commit_sha(&sha).map_err(anyhow::Error::from)?;
        return Ok(Some(validated));
    }
    Ok(crate::commands::git_helpers::resolve_head_silent())
}

/// Handle the `artifact` command dispatch.
pub fn handle_artifact(
    cmd: ArtifactCommand,
    repo_opt: Option<PathBuf>,
    passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
    env_config: &EnvironmentConfig,
) -> Result<()> {
    match cmd.command {
        ArtifactSubcommand::Sign {
            file,
            sig_output,
            key,
            device_key,
            expires_in,
            note,
            commit,
            no_commit,
            ci,
            ci_platform,
            log,
            allow_unlogged,
        } => {
            if ci {
                // Ephemeral CI signing — no keychain, no passphrase
                use auths_sdk::domains::signing::ci_env::{
                    CiEnvironment, CiPlatform, detect_ci_environment,
                };

                let commit_sha = match commit {
                    Some(sha) => sha,
                    None => bail!("--ci requires --commit <sha>. Pass the commit SHA explicitly."),
                };

                let ci_env = match detect_ci_environment() {
                    Some(env) => env,
                    None => match ci_platform.as_deref() {
                        Some("local") => CiEnvironment {
                            platform: CiPlatform::Local,
                            workflow_ref: None,
                            run_id: None,
                            actor: None,
                            runner_os: None,
                        },
                        Some(name) => CiEnvironment {
                            platform: CiPlatform::Generic,
                            workflow_ref: None,
                            run_id: None,
                            actor: None,
                            runner_os: Some(name.to_string()),
                        },
                        None => bail!(
                            "No CI environment detected. If this is intentional (e.g., testing), \
                             pass --ci-platform local. Otherwise run inside GitHub Actions, \
                             GitLab CI, or a recognized CI runner."
                        ),
                    },
                };

                let ci_env_json = serde_json::to_value(&ci_env)
                    .map_err(|e| anyhow::anyhow!("Failed to serialize CI env: {}", e))?;

                let data = std::fs::read(&file)
                    .with_context(|| format!("Failed to read artifact {:?}", file))?;
                let artifact_name = file.file_name().map(|n| n.to_string_lossy().to_string());

                #[allow(clippy::disallowed_methods)]
                let now = chrono::Utc::now();

                let result = auths_sdk::domains::signing::service::sign_artifact_ephemeral(
                    now,
                    &data,
                    artifact_name,
                    commit_sha,
                    expires_in,
                    note,
                    Some(ci_env_json),
                )
                .map_err(|e| anyhow::anyhow!("Ephemeral signing failed: {}", e))?;

                // Submit to transparency log (unless --allow-unlogged)
                let transparency_json = if allow_unlogged {
                    eprintln!(
                        "WARNING: Signing without transparency log. \
                         This artifact will not be verifiable against any log."
                    );
                    None
                } else {
                    // Parse the attestation to extract public key and signature
                    let attestation_value: serde_json::Value =
                        serde_json::from_str(&result.attestation_json)
                            .map_err(|e| anyhow::anyhow!("Failed to parse attestation: {e}"))?;

                    let identity_sig_hex = attestation_value["identity_signature"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("missing identity_signature"))?;
                    let sig_bytes = hex::decode(identity_sig_hex)
                        .map_err(|e| anyhow::anyhow!("invalid signature hex: {e}"))?;

                    let device_pk_hex = attestation_value["device_public_key"]
                        .as_str()
                        .ok_or_else(|| anyhow::anyhow!("missing device_public_key"))?;
                    let pk_bytes = hex::decode(device_pk_hex)
                        .map_err(|e| anyhow::anyhow!("invalid public key hex: {e}"))?;

                    let rt = tokio::runtime::Runtime::new()
                        .map_err(|e| anyhow::anyhow!("Failed to create async runtime: {e}"))?;

                    // Build the transparency log client
                    let log_client: std::sync::Arc<dyn auths_sdk::ports::TransparencyLog> =
                        match log.as_deref() {
                            Some("sigstore-rekor") | None => std::sync::Arc::new(
                                auths_infra_rekor::RekorClient::public().map_err(|e| {
                                    anyhow::anyhow!("Failed to create Rekor client: {e}")
                                })?,
                            ),
                            Some(other) => {
                                bail!("Unknown log '{}'. Available: sigstore-rekor", other)
                            }
                        };

                    let submit = || {
                        rt.block_on(auths_sdk::workflows::log_submit::submit_attestation_to_log(
                            result.attestation_json.as_bytes(),
                            &pk_bytes,
                            &sig_bytes,
                            log_client.as_ref(),
                        ))
                    };

                    let submission_result = match submit() {
                        Ok(bundle) => Ok(bundle),
                        Err(ref e) if is_rate_limited(e) => {
                            let secs = rate_limit_secs(e);
                            eprintln!("Rate limited by transparency log. Retrying in {secs}s...");
                            std::thread::sleep(std::time::Duration::from_secs(secs));
                            submit()
                        }
                        Err(e) => Err(e),
                    };

                    match submission_result {
                        Ok(bundle) => {
                            eprintln!(
                                "  Logged to {} at index {}",
                                bundle.log_id, bundle.leaf_index
                            );
                            Some(
                                serde_json::to_value(&bundle)
                                    .map_err(|e| anyhow::anyhow!("Failed to serialize: {e}"))?,
                            )
                        }
                        Err(e) => {
                            return Err(anyhow::anyhow!("Transparency log submission failed: {e}"));
                        }
                    }
                };

                // Build final .auths.json with optional transparency section
                let final_json = if let Some(transparency) = transparency_json {
                    let mut attestation: serde_json::Value =
                        serde_json::from_str(&result.attestation_json)
                            .map_err(|e| anyhow::anyhow!("Failed to re-parse attestation: {e}"))?;
                    if let serde_json::Value::Object(ref mut map) = attestation {
                        map.insert("transparency".to_string(), transparency);
                    }
                    serde_json::to_string_pretty(&attestation)
                        .map_err(|e| anyhow::anyhow!("Failed to serialize final JSON: {e}"))?
                } else {
                    result.attestation_json.clone()
                };

                let output_path = sig_output.unwrap_or_else(|| {
                    let mut p = file.clone();
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
                    "Signed {:?} -> {:?} (ephemeral CI key)",
                    file.file_name().unwrap_or_default(),
                    output_path
                );
                println!("  RID:    {}", result.rid);
                println!("  Digest: sha256:{}", result.digest);

                Ok(())
            } else {
                // Standard device-key signing
                let commit_sha = resolve_commit_sha_from_flags(commit, no_commit)?;
                let resolved_alias = match device_key {
                    Some(alias) => alias,
                    None => crate::commands::key_detect::auto_detect_device_key(
                        repo_opt.as_deref(),
                        env_config,
                    )?,
                };
                sign::handle_sign(
                    &file,
                    sig_output,
                    key.as_deref(),
                    &resolved_alias,
                    expires_in,
                    note,
                    commit_sha,
                    repo_opt,
                    passphrase_provider,
                    env_config,
                )
            }
        }
        ArtifactSubcommand::Publish {
            file,
            signature,
            package,
            registry,
            key,
            device_key,
            expires_in,
            note,
            commit,
            no_commit,
        } => {
            let commit_sha = resolve_commit_sha_from_flags(commit, no_commit)?;
            let sig_path = match (signature, file.as_ref()) {
                (Some(sig), _) => sig,
                (None, Some(artifact)) => {
                    let default_sig = derive_signature_path(artifact);
                    if default_sig.exists() {
                        default_sig
                    } else {
                        let resolved_alias = match device_key {
                            Some(alias) => alias,
                            None => crate::commands::key_detect::auto_detect_device_key(
                                repo_opt.as_deref(),
                                env_config,
                            )?,
                        };
                        sign::handle_sign(
                            artifact,
                            None,
                            key.as_deref(),
                            &resolved_alias,
                            expires_in,
                            note,
                            commit_sha,
                            repo_opt.clone(),
                            passphrase_provider,
                            env_config,
                        )?;
                        default_sig
                    }
                }
                (None, None) => bail!(
                    "Provide an artifact file to sign-and-publish, or --signature for an existing signature"
                ),
            };
            publish::handle_publish(&sig_path, package.as_deref(), &registry)
        }
        ArtifactSubcommand::Verify {
            file,
            signature,
            identity_bundle,
            witness_receipts,
            witness_keys,
            witness_threshold,
            verify_commit,
        } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(verify::handle_verify(
                &file,
                signature,
                identity_bundle,
                witness_receipts,
                &witness_keys,
                witness_threshold,
                verify_commit,
            ))
        }
    }
}

fn derive_signature_path(file: &Path) -> PathBuf {
    let mut p = file.to_path_buf();
    let new_name = format!(
        "{}.auths.json",
        p.file_name().unwrap_or_default().to_string_lossy()
    );
    p.set_file_name(new_name);
    p
}

impl crate::commands::executable::ExecutableCommand for ArtifactCommand {
    fn execute(&self, ctx: &crate::config::CliConfig) -> anyhow::Result<()> {
        handle_artifact(
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
    use clap::Parser;

    #[derive(Parser)]
    struct Cli {
        #[command(subcommand)]
        command: ArtifactSubcommand,
    }

    #[test]
    fn derive_signature_path_appends_auths_json() {
        let path = derive_signature_path(Path::new("/tmp/my-pkg-1.0.0.tar.gz"));
        assert_eq!(path, PathBuf::from("/tmp/my-pkg-1.0.0.tar.gz.auths.json"));
    }

    #[test]
    fn derive_signature_path_handles_bare_filename() {
        let path = derive_signature_path(Path::new("artifact.bin"));
        assert_eq!(path, PathBuf::from("artifact.bin.auths.json"));
    }

    #[test]
    fn publish_accepts_file_positional_arg() {
        let cli = Cli::try_parse_from(["test", "publish", "my-file.tar.gz"]).unwrap();
        match cli.command {
            ArtifactSubcommand::Publish {
                file, signature, ..
            } => {
                assert_eq!(file, Some(PathBuf::from("my-file.tar.gz")));
                assert!(signature.is_none());
            }
            _ => panic!("expected Publish"),
        }
    }

    #[test]
    fn publish_accepts_signature_flag_without_file() {
        let cli =
            Cli::try_parse_from(["test", "publish", "--signature", "my-file.auths.json"]).unwrap();
        match cli.command {
            ArtifactSubcommand::Publish {
                file, signature, ..
            } => {
                assert!(file.is_none());
                assert_eq!(signature, Some(PathBuf::from("my-file.auths.json")));
            }
            _ => panic!("expected Publish"),
        }
    }

    #[test]
    fn publish_accepts_both_file_and_signature() {
        let cli = Cli::try_parse_from([
            "test",
            "publish",
            "my-file.tar.gz",
            "--signature",
            "custom.auths.json",
        ])
        .unwrap();
        match cli.command {
            ArtifactSubcommand::Publish {
                file, signature, ..
            } => {
                assert_eq!(file, Some(PathBuf::from("my-file.tar.gz")));
                assert_eq!(signature, Some(PathBuf::from("custom.auths.json")));
            }
            _ => panic!("expected Publish"),
        }
    }

    #[test]
    fn publish_accepts_no_args() {
        let cli = Cli::try_parse_from(["test", "publish"]).unwrap();
        match cli.command {
            ArtifactSubcommand::Publish {
                file, signature, ..
            } => {
                assert!(file.is_none());
                assert!(signature.is_none());
            }
            _ => panic!("expected Publish"),
        }
    }

    #[test]
    fn publish_forwards_signing_flags() {
        let cli = Cli::try_parse_from([
            "test",
            "publish",
            "my-file.tar.gz",
            "--key",
            "main",
            "--device-key",
            "device-1",
            "--expires-in",
            "3600",
            "--note",
            "release build",
        ])
        .unwrap();
        match cli.command {
            ArtifactSubcommand::Publish {
                key,
                device_key,
                expires_in,
                note,
                ..
            } => {
                assert_eq!(key.as_deref(), Some("main"));
                assert_eq!(device_key.as_deref(), Some("device-1"));
                assert_eq!(expires_in, Some(3600));
                assert_eq!(note.as_deref(), Some("release build"));
            }
            _ => panic!("expected Publish"),
        }
    }
}
