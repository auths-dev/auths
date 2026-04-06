//! `auths ci rotate` — refresh CI token without regenerating the device key.

use anyhow::{Context, Result, anyhow};
use std::path::Path;
use std::sync::Arc;

use auths_crypto::did_key::ed25519_pubkey_to_did_key;
use auths_sdk::core_config::EnvironmentConfig;
use auths_sdk::domains::ci::bundle::build_identity_bundle;
use auths_sdk::domains::ci::forge::Forge;
use auths_sdk::domains::ci::token::CiToken;
use auths_sdk::keychain::{KeyAlias, get_platform_keychain};
use auths_sdk::signing::PassphraseProvider;
use ring::signature::KeyPair;
use zeroize::Zeroizing;

use crate::commands::ci::forge_backend::backend_for_forge;
use crate::commands::ci::setup::warn_short_ttl;
use crate::subprocess::git_stdout;

use super::CI_DEVICE_ALIAS;

/// Run the `auths ci rotate` flow.
///
/// Regenerates the file keychain, identity bundle, and verify bundle,
/// but reuses the existing CI device key (no new key generation or device linking).
///
/// Args:
/// * `repo_override`: Optional forge repo. Auto-detected from git remote if `None`.
/// * `max_age_secs`: TTL for the verify bundle in seconds.
/// * `auto_passphrase`: If `true`, generate a random hex passphrase.
/// * `_passphrase_provider`: CLI passphrase provider (unused for rotate, kept for consistency).
/// * `_env_config`: Environment configuration.
/// * `repo_path`: Path to the auths registry.
///
/// Usage:
/// ```ignore
/// run_rotate(None, 31536000, true, &pp, &env, &repo)?;
/// ```
pub fn run_rotate(
    repo_override: Option<String>,
    max_age_secs: u64,
    _auto_passphrase: bool,
    _passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
    _env_config: &EnvironmentConfig,
    repo_path: &Path,
) -> Result<()> {
    println!();
    println!("\x1b[0;36m╔════════════════════════════════════════════════════════════╗\x1b[0m");
    println!(
        "\x1b[0;36m║\x1b[0m\x1b[1m           CI Token Rotation                                \x1b[0m\x1b[0;36m║\x1b[0m"
    );
    println!("\x1b[0;36m╚════════════════════════════════════════════════════════════╝\x1b[0m");
    println!();

    // Verify CI device key exists
    let keychain = get_platform_keychain()?;
    let aliases = keychain
        .list_aliases()
        .context("Failed to list key aliases")?;

    let has_ci_key = aliases.iter().any(|a| *a == CI_DEVICE_ALIAS);
    if !has_ci_key {
        return Err(anyhow!(
            "No CI device key found. Run `auths ci setup` first."
        ));
    }

    // Find identity key alias
    let identity_key_alias = aliases
        .first()
        .ok_or_else(|| anyhow!("No keys found in keychain"))?
        .to_string();

    // Handle passphrase — rotate always reuses the existing key,
    // so we need the ORIGINAL passphrase to decrypt it.
    let ci_pass = {
        #[allow(clippy::disallowed_methods)]
        let env_pass = std::env::var("AUTHS_PASSPHRASE").ok();
        if let Some(pass) = env_pass {
            println!("\x1b[2mUsing passphrase from AUTHS_PASSPHRASE env var.\x1b[0m");
            Zeroizing::new(pass)
        } else {
            let pass =
                rpassword::prompt_password("Passphrase for existing ci-release-device key: ")
                    .context("Failed to read passphrase")?;
            Zeroizing::new(pass)
        }
    };

    // Regenerate file keychain
    println!("\x1b[2mRegenerating file keychain...\x1b[0m");
    let keychain_b64 = super::setup::create_file_keychain(keychain.as_ref(), &ci_pass)?;
    println!("\x1b[0;32m\u{2713}\x1b[0m File keychain regenerated");

    // Derive device DID (for display)
    let key_alias = KeyAlias::new_unchecked(CI_DEVICE_ALIAS);
    let (_, _, encrypted_key) = keychain
        .load_key(&key_alias)
        .context("Failed to load CI device key")?;
    let pkcs8 = auths_sdk::crypto::decrypt_keypair(&encrypted_key, &ci_pass)
        .context("Failed to decrypt CI device key")?;
    let kp = auths_sdk::identity::load_keypair_from_der_or_seed(&pkcs8)?;
    let pub_bytes: [u8; 32] = kp
        .public_key()
        .as_ref()
        .try_into()
        .map_err(|_| anyhow!("Public key is not 32 bytes"))?;
    let device_did = ed25519_pubkey_to_did_key(&pub_bytes);

    // Repackage identity repo
    println!("\x1b[2mRepackaging identity repo...\x1b[0m");
    let identity_repo_b64 =
        build_identity_bundle(repo_path).map_err(|e| anyhow!("Bundle failed: {e}"))?;
    println!("\x1b[0;32m\u{2713}\x1b[0m Identity repo packaged");

    // Re-export verify bundle
    let identity_storage =
        auths_sdk::storage::RegistryIdentityStorage::new(repo_path.to_path_buf());
    let identity = auths_sdk::ports::IdentityStorage::load_identity(&identity_storage)
        .context("Failed to load identity")?;
    let identity_did_str = identity.controller_did.to_string();

    let verify_bundle_json =
        super::setup::build_verify_bundle(&identity_did_str, &pub_bytes, repo_path, max_age_secs)?;

    // Assemble new CiToken
    #[allow(clippy::disallowed_methods)]
    let now = chrono::Utc::now();
    let token = CiToken::new(
        ci_pass.to_string(),
        keychain_b64,
        identity_repo_b64,
        verify_bundle_json,
        now.to_rfc3339(),
        max_age_secs,
    );
    let token_json = token
        .to_json()
        .map_err(|e| anyhow!("Token serialization: {e}"))?;

    warn_short_ttl(max_age_secs);
    if token.is_large() {
        eprintln!(
            "\x1b[1;33mWarning:\x1b[0m CI token is ~{} KB, approaching GitHub's 48 KB secret limit.",
            token.estimated_size() / 1024
        );
        eprintln!("  Consider reducing the identity repo size or splitting secrets.");
    }

    // Detect forge + update secret
    let forge = match repo_override {
        Some(url) => Forge::from_url(&url),
        None => {
            let url = git_stdout(&["remote", "get-url", "origin"])
                .context("No git remote origin found. Use --repo to specify.")?;
            Forge::from_url(&url)
        }
    };

    let backend = backend_for_forge(&forge);
    println!();
    println!(
        "Detected forge: {} ({})",
        backend.name(),
        forge.repo_identifier()
    );

    match backend.set_secret("AUTHS_CI_TOKEN", &token_json) {
        Ok(()) => println!(
            "\x1b[0;32m\u{2713}\x1b[0m AUTHS_CI_TOKEN updated on {}",
            forge.repo_identifier()
        ),
        Err(e) => {
            eprintln!("\x1b[1;33mCould not update secret automatically: {e}\x1b[0m");
            println!();
            println!("Update AUTHS_CI_TOKEN manually:");
            println!();
            println!("{token_json}");
        }
    }

    println!();
    #[allow(clippy::disallowed_methods)]
    let expiry = chrono::Utc::now() + chrono::Duration::seconds(max_age_secs as i64);
    println!(
        "New token expires: {} ({} from now)",
        expiry.format("%Y-%m-%d"),
        super::setup::humanize_duration(max_age_secs)
    );
    println!(
        "To revoke: auths device revoke --device-did {} --key {}",
        device_did, identity_key_alias
    );

    Ok(())
}
