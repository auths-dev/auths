use anyhow::Result;
use std::path::PathBuf;

use crate::commands::artifact::publish::handle_publish;
use crate::commands::executable::ExecutableCommand;
use crate::config::CliConfig;

/// Top-level `auths publish` command: sign and publish a signed artifact attestation.
#[derive(Debug, clap::Args)]
#[command(
    about = "Publish a signed artifact attestation to the Auths registry.",
    after_help = "Examples:
  auths publish package.tar.gz                            # Sign and publish
  auths publish --signature package.tar.gz.auths.json    # Publish existing signature
  auths publish package.tar.gz --package npm:react@18.3.0

Related:
  auths sign    — Sign an artifact without publishing
  auths verify  — Verify a signed artifact"
)]
pub struct PublishCommand {
    /// Artifact file to sign and publish. Omit if providing --signature directly.
    #[arg(help = "Artifact file to sign and publish.")]
    pub file: Option<PathBuf>,

    /// Path to an existing .auths.json signature file. Defaults to <FILE>.auths.json.
    #[arg(long, value_name = "PATH")]
    pub signature: Option<PathBuf>,

    /// Package identifier for registry indexing (e.g., npm:react@18.3.0).
    #[arg(long)]
    pub package: Option<String>,

    /// Registry URL to publish to.
    #[arg(long, default_value = "https://auths-registry.fly.dev")]
    pub registry: String,
}

impl ExecutableCommand for PublishCommand {
    fn execute(&self, ctx: &CliConfig) -> Result<()> {
        let sig_path = match (&self.signature, &self.file) {
            (Some(sig), _) => sig.clone(),
            (None, Some(file)) => {
                let mut p = file.clone();
                p.set_file_name(format!(
                    "{}.auths.json",
                    p.file_name().unwrap_or_default().to_string_lossy()
                ));
                if !p.exists() {
                    crate::commands::artifact::sign::handle_sign(
                        file,
                        None,
                        None,
                        &crate::commands::key_detect::auto_detect_device_key(
                            ctx.repo_path.as_deref(),
                            &ctx.env_config,
                        )?,
                        None,
                        None,
                        crate::commands::git_helpers::resolve_head_silent(),
                        ctx.repo_path.clone(),
                        ctx.passphrase_provider.clone(),
                        &ctx.env_config,
                        &None,
                        false,
                    )?;
                }
                p
            }
            (None, None) => anyhow::bail!("Provide an artifact file or --signature path"),
        };

        handle_publish(&sig_path, self.package.as_deref(), &self.registry)
    }
}
