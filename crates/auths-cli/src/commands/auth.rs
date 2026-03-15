use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};

use auths_core::crypto::provider_bridge;
use auths_core::crypto::signer::decrypt_keypair;
use auths_core::crypto::ssh::extract_seed_from_pkcs8;
use auths_core::storage::keychain::{KeyStorage, get_platform_keychain_with_config};
use auths_crypto::Pkcs8Der;
use auths_id::storage::identity::IdentityStorage;
use auths_id::storage::layout;
use auths_sdk::workflows::auth::sign_auth_challenge;
use auths_storage::git::RegistryIdentityStorage;

use crate::commands::executable::ExecutableCommand;
use crate::config::CliConfig;
use crate::ux::format::{JsonResponse, is_json_mode};

/// Authenticate with external services using your auths identity.
#[derive(Parser, Debug, Clone)]
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

    let identity_storage = RegistryIdentityStorage::new(repo_path.clone());
    let managed = identity_storage
        .load_identity()
        .context("No identity found. Run `auths init` first.")?;

    let controller_did = &managed.controller_did;

    let key_alias_str =
        super::key_detect::auto_detect_device_key(ctx.repo_path.as_deref(), &ctx.env_config)?;
    let key_alias = auths_core::storage::keychain::KeyAlias::new(&key_alias_str)
        .map_err(|e| anyhow!("Invalid key alias: {e}"))?;

    let keychain = get_platform_keychain_with_config(&ctx.env_config)?;
    let (_stored_did, _role, encrypted_key) = keychain
        .load_key(&key_alias)
        .with_context(|| format!("Failed to load key '{}'", key_alias_str))?;

    let passphrase =
        passphrase_provider.get_passphrase(&format!("Enter passphrase for '{}':", key_alias))?;
    let pkcs8_bytes = decrypt_keypair(&encrypted_key, &passphrase)
        .context("Failed to decrypt key (invalid passphrase?)")?;

    let pkcs8 = Pkcs8Der::new(&pkcs8_bytes[..]);
    let seed =
        extract_seed_from_pkcs8(&pkcs8).context("Failed to extract seed from key material")?;

    // Derive public key from the seed instead of resolving via KEL
    let public_key_bytes = provider_bridge::ed25519_public_key_from_seed_sync(&seed)
        .context("Failed to derive public key from seed")?;
    let public_key_hex = hex::encode(public_key_bytes);

    let result = sign_auth_challenge(
        nonce,
        domain,
        &seed,
        &public_key_hex,
        controller_did.as_str(),
    )
    .context("Failed to sign auth challenge")?;

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
        .map_err(|e| anyhow::anyhow!("{e}"))
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
