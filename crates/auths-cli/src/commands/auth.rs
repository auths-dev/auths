use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};

use auths_sdk::storage_layout::layout;

use crate::factories::storage::build_auths_context;

use crate::commands::executable::ExecutableCommand;
use crate::config::CliConfig;
use crate::ux::format::{JsonResponse, is_json_mode};

/// Authenticate with external services using your auths identity.
#[derive(Parser, Debug, Clone)]
#[command(
    about = "Authenticate with external services using your auths identity",
    after_help = "Examples:
  auths auth challenge --nonce abc123def456 --domain example.com
                        # Sign an authentication challenge
  auths auth challenge --nonce abc123def456
                        # Sign challenge for default domain (auths.dev)

Flow:
  1. Service sends you a nonce
  2. Run: auths auth challenge --nonce <nonce> --domain <domain>
  3. Service verifies your signature against your DID

Related:
  auths id     — Manage your identity
  auths sign   — Sign files and commits
  auths verify — Verify signatures"
)]
pub struct AuthCommand {
    #[clap(subcommand)]
    pub subcommand: AuthSubcommand,
}

/// Subcommands for authentication operations.
#[derive(Subcommand, Debug, Clone)]
pub enum AuthSubcommand {
    /// Sign an authentication challenge for DID-based login
    Challenge {
        /// The challenge nonce from the authentication server
        #[arg(long)]
        nonce: String,

        /// The domain requesting authentication
        #[arg(long, default_value = "auths.dev")]
        domain: String,
    },
}

fn handle_auth_challenge(nonce: &str, domain: &str, ctx: &CliConfig) -> Result<()> {
    let repo_path = layout::resolve_repo_path(ctx.repo_path.clone())?;
    let passphrase_provider = ctx.passphrase_provider.clone();

    let auths_ctx = build_auths_context(
        &repo_path,
        &ctx.env_config,
        Some(ctx.passphrase_provider.clone()),
    )?;
    let managed = auths_ctx
        .identity_storage
        .load_identity()
        .context("No identity found. Run `auths init` first.")?;

    let controller_did = &managed.controller_did;

    let key_alias_str =
        super::key_detect::auto_detect_device_key(ctx.repo_path.as_deref(), &ctx.env_config)?;
    let key_alias = auths_sdk::keychain::KeyAlias::new(&key_alias_str)
        .map_err(|e| anyhow!("Invalid key alias: {e}"))?;

    let message = auths_sdk::workflows::auth::build_auth_challenge_message(nonce, domain)
        .context("Failed to build auth challenge payload")?;

    let (signature_bytes, public_key_bytes, _curve) = auths_sdk::keychain::sign_with_key(
        auths_ctx.key_storage.as_ref(),
        &key_alias,
        passphrase_provider.as_ref(),
        message.as_bytes(),
    )
    .with_context(|| format!("Failed to sign auth challenge with key '{}'", key_alias))?;

    let result = auths_sdk::workflows::auth::SignedAuthChallenge {
        signature_hex: hex::encode(&signature_bytes),
        public_key_hex: hex::encode(&public_key_bytes),
        did: controller_did.to_string(),
    };

    if is_json_mode() {
        JsonResponse::success(
            "auth challenge",
            &serde_json::json!({
                "signature": result.signature_hex,
                "public_key": result.public_key_hex,
                "did": result.did,
            }),
        )
        .print()
        .map_err(anyhow::Error::from)
    } else {
        println!("Signature:  {}", result.signature_hex);
        println!("Public Key: {}", result.public_key_hex);
        println!("DID:        {}", result.did);
        Ok(())
    }
}

impl ExecutableCommand for AuthCommand {
    fn execute(&self, ctx: &CliConfig) -> Result<()> {
        match &self.subcommand {
            AuthSubcommand::Challenge { nonce, domain } => {
                handle_auth_challenge(nonce, domain, ctx)
            }
        }
    }
}
