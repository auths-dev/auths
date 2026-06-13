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
  auths auth verify --nonce abc123def456 --did did:keri:E... --signature <hex>
                        # Verify a challenge response offline, against the
                        # registry's current key for that DID

Flow:
  1. Verifier sends a nonce
  2. Responder runs: auths auth challenge --nonce <nonce> --domain <domain>
  3. Verifier runs:  auths auth verify --nonce <nonce> --domain <domain> \\
                       --did <did> --signature <hex>
     (offline — the signature is checked against the registry's in-force
      key, never a key the responder supplied)

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
        #[arg(long, allow_hyphen_values = true)]
        nonce: String,

        /// The domain requesting authentication
        #[arg(long, default_value = "auths.dev")]
        domain: String,
    },

    /// Verify a challenge response offline against the registry's current key
    Verify {
        /// The challenge nonce this verifier issued
        #[arg(long, allow_hyphen_values = true)]
        nonce: String,

        /// The domain the challenge was bound to
        #[arg(long, default_value = "auths.dev")]
        domain: String,

        /// The responder's did:keri: controller DID (delegated device DIDs
        /// fail closed — their liveness needs the delegator's revocation
        /// verdict)
        #[arg(long)]
        did: String,

        /// Hex-encoded signature from the challenge response
        #[arg(long)]
        signature: String,
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

/// Verify a challenge response offline against the registry's in-force key.
///
/// The verifier-side counterpart of `auth challenge`: no auth server, no
/// network. The DID's KEL is replayed from the local registry and the
/// signature is checked against its *current* key — a response signed by a
/// stale pre-rotation key or a stolen device key fails, a response signed by
/// the identity's in-force key proves it alive.
fn handle_auth_verify(nonce: &str, domain: &str, did: &str, signature_hex: &str) -> Result<()> {
    let signature = hex::decode(signature_hex)
        .context("--signature must be the hex string printed by `auths auth challenge`")?;

    let auths_home = auths_sdk::paths::auths_home().map_err(|e| anyhow!(e))?;
    let registry = auths_sdk::storage::GitRegistryBackend::from_config_unchecked(
        auths_sdk::storage::RegistryConfig::single_tenant(&auths_home),
    );

    let verified = auths_sdk::workflows::auth::verify_auth_challenge(
        &registry, did, nonce, domain, &signature,
    )
    .context("Auth challenge verification failed")?;

    if is_json_mode() {
        JsonResponse::success(
            "auth verify",
            &serde_json::json!({
                "verified": true,
                "did": verified.did,
                "public_key": verified.public_key_hex,
                "curve": verified.curve.to_string(),
                "nonce": nonce,
                "domain": domain,
            }),
        )
        .print()
        .map_err(anyhow::Error::from)
    } else {
        println!("✓ Verified — the signature checks out under the registry's current key");
        println!("DID:        {}", verified.did);
        println!("Public Key: {}", verified.public_key_hex);
        println!("Curve:      {}", verified.curve);
        println!("Domain:     {domain}");
        Ok(())
    }
}

impl ExecutableCommand for AuthCommand {
    fn execute(&self, ctx: &CliConfig) -> Result<()> {
        match &self.subcommand {
            AuthSubcommand::Challenge { nonce, domain } => {
                handle_auth_challenge(nonce, domain, ctx)
            }
            AuthSubcommand::Verify {
                nonce,
                domain,
                did,
                signature,
            } => handle_auth_verify(nonce, domain, did, signature),
        }
    }
}
