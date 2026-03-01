pub mod core;
pub mod file;
pub mod publish;
pub mod sign;
pub mod verify;

use clap::{Args, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Result;
use auths_core::config::EnvironmentConfig;
use auths_core::signing::PassphraseProvider;

#[derive(Args, Debug, Clone)]
#[command(about = "Sign and verify arbitrary artifacts (tarballs, binaries, etc.).")]
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
        identity_key_alias: Option<String>,

        /// Local alias of the device key (used for dual-signing).
        #[arg(long, help = "Local alias of the device key (used for dual-signing).")]
        device_key_alias: String,

        /// Number of days until the signature expires.
        #[arg(long, value_name = "N")]
        expires_in_days: Option<i64>,

        /// Optional note to embed in the attestation.
        #[arg(long)]
        note: Option<String>,
    },

    /// Publish a signed artifact attestation to a registry.
    Publish {
        /// Path to the .auths.json signature file created by `auths artifact sign`.
        #[arg(long)]
        signature: PathBuf,

        /// Package identifier for registry indexing (e.g., npm:react@18.3.0).
        #[arg(long)]
        package: Option<String>,

        /// Registry URL to publish to.
        #[arg(long, default_value = "https://auths-registry.fly.dev")]
        registry: String,
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
            identity_key_alias,
            device_key_alias,
            expires_in_days,
            note,
        } => sign::handle_sign(
            &file,
            sig_output,
            identity_key_alias.as_deref(),
            &device_key_alias,
            expires_in_days,
            note,
            repo_opt,
            passphrase_provider,
            env_config,
        ),
        ArtifactSubcommand::Publish {
            signature,
            package,
            registry,
        } => publish::handle_publish(&signature, package.as_deref(), &registry),
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
