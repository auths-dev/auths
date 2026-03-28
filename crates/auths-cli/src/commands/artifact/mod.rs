pub mod core;
pub mod file;
pub mod publish;
pub mod sign;
pub mod verify;

use clap::{Args, Subcommand};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Result, bail};
use auths_core::config::EnvironmentConfig;
use auths_core::signing::PassphraseProvider;

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

        /// Path to witness receipts JSON file.
        #[arg(long)]
        witness_receipts: Option<PathBuf>,

        /// Witness public keys as DID:hex pairs (e.g., "did:key:z6Mk...:abcd1234...").
        #[arg(long, num_args = 1..)]
        witness_keys: Vec<String>,

        /// Witness quorum threshold (default: 1).
        #[arg(long, default_value = "1")]
        witness_threshold: usize,
    },
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
        } => {
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
                repo_opt,
                passphrase_provider,
                env_config,
            )
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
        } => {
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
        } => {
            let rt = tokio::runtime::Runtime::new()?;
            rt.block_on(verify::handle_verify(
                &file,
                signature,
                identity_bundle,
                witness_receipts,
                &witness_keys,
                witness_threshold,
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
