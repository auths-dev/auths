//! `auths ci setup` — one-command CI signing setup.

use anyhow::{Context, Result, anyhow};
use std::path::Path;
use std::sync::Arc;

use auths_crypto::did_key::ed25519_pubkey_to_did_key;
use auths_sdk::core_config::EnvironmentConfig;
use auths_sdk::domains::ci::bundle::{build_identity_bundle, generate_ci_passphrase};
use auths_sdk::domains::ci::forge::Forge;
use auths_sdk::domains::ci::token::CiToken;
use auths_sdk::keychain::EncryptedFileStorage;
use auths_sdk::keychain::{IdentityDID, KeyAlias, KeyRole, KeyStorage, get_platform_keychain};
use auths_sdk::ports::AttestationSource;
use auths_sdk::ports::IdentityStorage;
use auths_sdk::signing::PassphraseProvider;
use auths_sdk::storage::{RegistryAttestationStorage, RegistryIdentityStorage};
use auths_verifier::IdentityBundle;
use ring::signature::KeyPair;
use zeroize::Zeroizing;

use crate::commands::ci::forge_backend::backend_for_forge;
use crate::factories::storage::build_auths_context;
use crate::subprocess::git_stdout;

use super::CI_DEVICE_ALIAS;

/// Run the `auths ci setup` flow.
///
/// Args:
/// * `repo_override`: Optional forge repo (e.g., `owner/repo`). Auto-detected from git remote if `None`.
/// * `max_age_secs`: TTL for the verify bundle in seconds.
/// * `auto_passphrase`: If `true`, generate a random hex passphrase. Otherwise prompt interactively.
/// * `passphrase_provider`: CLI passphrase provider for key operations.
/// * `env_config`: Environment configuration for keychain backend selection.
/// * `repo_path`: Path to the auths registry (typically `~/.auths`).
///
/// Usage:
/// ```ignore
/// run_setup(None, 31536000, true, &pp, &env, &repo)?;
/// ```
pub fn run_setup(
    repo_override: Option<String>,
    max_age_secs: u64,
    auto_passphrase: bool,
    passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
    env_config: &EnvironmentConfig,
    repo_path: &Path,
) -> Result<()> {
    println!();
    println!("\x1b[0;36m╔════════════════════════════════════════════════════════════╗\x1b[0m");
    println!(
        "\x1b[0;36m║\x1b[0m\x1b[1m           CI Release Signing Setup (One-Time)              \x1b[0m\x1b[0;36m║\x1b[0m"
    );
    println!("\x1b[0;36m╚════════════════════════════════════════════════════════════╝\x1b[0m");
    println!();

    // Step 1: Verify identity exists
    let identity_storage = RegistryIdentityStorage::new(repo_path.to_path_buf());
    let identity = identity_storage
        .load_identity()
        .context("No auths identity found. Run `auths init` first.")?;

    let identity_did_str = identity.controller_did.to_string();

    // Step 2: Find primary key alias
    let keychain = get_platform_keychain()?;
    let aliases = keychain
        .list_aliases()
        .context("Failed to list key aliases")?;
    let identity_key_alias = aliases
        .first()
        .ok_or_else(|| anyhow!("No keys found in keychain. Run `auths init` first."))?
        .to_string();

    println!("\x1b[1mIdentity:\x1b[0m  \x1b[0;36m{identity_did_str}\x1b[0m");
    println!("\x1b[1mKey alias:\x1b[0m \x1b[0;36m{identity_key_alias}\x1b[0m");
    println!();

    // Step 3: Check for existing CI device key
    let reuse = aliases.iter().any(|a| *a == CI_DEVICE_ALIAS);
    if reuse {
        println!("\x1b[2mFound existing {CI_DEVICE_ALIAS} key \u{2014} will reuse it.\x1b[0m");
    }

    // Step 4: Handle passphrase
    // When reusing an existing key, we need the ORIGINAL passphrase to decrypt it.
    // Auto-generate is only valid for new keys.
    let ci_pass = if reuse {
        // Existing key — need the original passphrase
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
    } else if auto_passphrase {
        let pass = generate_ci_passphrase();
        println!("\x1b[2mAuto-generated CI passphrase (64-char hex).\x1b[0m");
        Zeroizing::new(pass)
    } else {
        let pass = rpassword::prompt_password("CI device passphrase: ")
            .context("Failed to read passphrase")?;
        let confirm = rpassword::prompt_password("Confirm passphrase: ")
            .context("Failed to read confirmation")?;
        if pass != confirm {
            return Err(anyhow!("Passphrases do not match"));
        }
        Zeroizing::new(pass)
    };

    // Step 5: Generate or reuse CI device key + file keychain
    let keychain_b64 = if !reuse {
        println!();
        println!("\x1b[2mGenerating CI device key...\x1b[0m");

        let seed: [u8; 32] = rand::random();
        let seed_z = Zeroizing::new(seed);

        #[allow(clippy::disallowed_methods)]
        let identity_did = IdentityDID::new_unchecked(identity_did_str.clone());
        auths_sdk::keys::import_seed(
            &seed_z,
            &ci_pass,
            CI_DEVICE_ALIAS,
            &identity_did,
            keychain.as_ref(),
        )
        .map_err(|e| anyhow!("Failed to import CI device key: {e}"))?;

        println!("\x1b[0;32m\u{2713}\x1b[0m CI device key imported");
        create_file_keychain(keychain.as_ref(), &ci_pass)?
    } else {
        println!(
            "\x1b[2mReusing existing {CI_DEVICE_ALIAS} key \u{2014} regenerating file keychain...\x1b[0m"
        );
        create_file_keychain(keychain.as_ref(), &ci_pass)?
    };

    // Step 6: Derive device DID
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
    println!("\x1b[0;32m\u{2713}\x1b[0m Device DID: \x1b[0;36m{device_did}\x1b[0m");

    // Step 7: Link device (if not already linked)
    if !reuse {
        link_ci_device(
            &identity_key_alias,
            &device_did,
            repo_path,
            env_config,
            Arc::clone(&passphrase_provider),
        )?;
    }

    // Step 8: Package identity repo
    println!("\x1b[2mPackaging identity repo...\x1b[0m");
    let identity_repo_b64 =
        build_identity_bundle(repo_path).map_err(|e| anyhow!("Bundle failed: {e}"))?;
    println!("\x1b[0;32m\u{2713}\x1b[0m Identity repo packaged");

    // Step 9: Export verify bundle
    let verify_bundle_json =
        build_verify_bundle(&identity_did_str, &pub_bytes, repo_path, max_age_secs)?;

    // Step 10: Assemble CiToken
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

    // TTL warning
    warn_short_ttl(max_age_secs);

    // Size warning
    if token.is_large() {
        eprintln!(
            "\x1b[1;33mWarning:\x1b[0m CI token is ~{} KB, approaching GitHub's 48 KB secret limit.",
            token.estimated_size() / 1024
        );
        eprintln!("  Consider reducing the identity repo size or splitting secrets.");
    }

    // Step 11: Detect forge + set secret
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
            "\x1b[0;32m\u{2713}\x1b[0m AUTHS_CI_TOKEN set on {}",
            forge.repo_identifier()
        ),
        Err(e) => {
            eprintln!("\x1b[1;33mCould not set secret automatically: {e}\x1b[0m");
            println!();
            println!("Set this manually as a repository secret named AUTHS_CI_TOKEN:");
            println!();
            println!("{token_json}");
        }
    }

    // Step 12: Print template + revocation instructions
    println!();
    backend.print_ci_template();
    println!();

    #[allow(clippy::disallowed_methods)]
    let expiry = chrono::Utc::now() + chrono::Duration::seconds(max_age_secs as i64);
    println!(
        "Token expires: {} ({} from now)",
        expiry.format("%Y-%m-%d"),
        humanize_duration(max_age_secs)
    );
    println!("To rotate: auths ci rotate");
    println!(
        "To revoke: auths device revoke --device-did {} --key {}",
        device_did, identity_key_alias
    );

    Ok(())
}

/// Create a portable file-backend keychain from the platform keychain.
pub(super) fn create_file_keychain(keychain: &dyn KeyStorage, passphrase: &str) -> Result<String> {
    let key_alias = KeyAlias::new_unchecked(CI_DEVICE_ALIAS);
    let (identity_did, _role, encrypted_key_data) = keychain
        .load_key(&key_alias)
        .context("CI device key not found in keychain")?;

    let tmp = tempfile::TempDir::new().context("Failed to create temp directory")?;
    let keychain_path = tmp.path().join("ci-keychain.enc");
    let dst = EncryptedFileStorage::with_path(keychain_path.clone())
        .context("Failed to create file storage")?;
    dst.set_password(Zeroizing::new(passphrase.to_string()));
    dst.store_key(
        &key_alias,
        &identity_did,
        KeyRole::Primary,
        &encrypted_key_data,
    )
    .context("Failed to store key in file keychain")?;

    let keychain_bytes = std::fs::read(&keychain_path).context("Failed to read file keychain")?;
    Ok(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        &keychain_bytes,
    ))
}

/// Link the CI device to the identity.
fn link_ci_device(
    identity_key_alias: &str,
    device_did: &str,
    repo_path: &Path,
    env_config: &EnvironmentConfig,
    passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync>,
) -> Result<()> {
    println!("\x1b[2mLinking CI device to identity...\x1b[0m");

    let link_config = auths_sdk::types::DeviceLinkConfig {
        identity_key_alias: KeyAlias::new_unchecked(identity_key_alias),
        device_key_alias: Some(KeyAlias::new_unchecked(CI_DEVICE_ALIAS)),
        device_did: Some(device_did.to_string()),
        capabilities: vec![auths_verifier::Capability::sign_release()],
        expires_in: None,
        note: Some("CI release signer (auths ci setup)".to_string()),
        payload: None,
    };

    let ctx = build_auths_context(repo_path, env_config, Some(passphrase_provider))?;
    auths_sdk::domains::device::service::link_device(
        link_config,
        &ctx,
        &auths_sdk::ports::SystemClock,
    )
    .map_err(|e| anyhow!("Failed to link CI device: {e}"))?;

    println!("\x1b[0;32m\u{2713}\x1b[0m CI device linked");
    Ok(())
}

/// Build the verify bundle JSON for inclusion in the CiToken.
pub(super) fn build_verify_bundle(
    identity_did_str: &str,
    public_key_bytes: &[u8; 32],
    repo_path: &Path,
    max_age_secs: u64,
) -> Result<serde_json::Value> {
    let attestation_storage = RegistryAttestationStorage::new(repo_path.to_path_buf());
    let attestations = attestation_storage
        .load_all_attestations()
        .unwrap_or_default();

    #[allow(clippy::disallowed_methods)]
    let now = chrono::Utc::now();

    #[allow(clippy::disallowed_methods)]
    let identity_did = auths_sdk::keychain::IdentityDID::new_unchecked(identity_did_str);
    #[allow(clippy::disallowed_methods)]
    let public_key_hex = auths_verifier::PublicKeyHex::new_unchecked(hex::encode(public_key_bytes));

    let bundle = IdentityBundle {
        identity_did,
        public_key_hex,
        attestation_chain: attestations,
        bundle_timestamp: now,
        max_valid_for_secs: max_age_secs,
    };

    serde_json::to_value(&bundle).context("Failed to serialize verify bundle")
}

/// Print a warning for very short TTL values.
pub fn warn_short_ttl(max_age_secs: u64) {
    if max_age_secs < 3600 {
        eprintln!(
            "\x1b[1;33mWarning:\x1b[0m Token TTL is {}s (< 1 hour). CI will fail after expiry.",
            max_age_secs
        );
        eprintln!("  Recommended:");
        eprintln!("          30 days: --max-age-secs 2592000");
        eprintln!("          90 days: --max-age-secs 7776000");
        eprintln!("          1 year:  --max-age-secs 31536000");
    }
}

/// Format a duration in seconds to a human-readable string.
pub(super) fn humanize_duration(secs: u64) -> String {
    if secs >= 86400 * 365 {
        let years = secs / (86400 * 365);
        if years == 1 {
            "1 year".to_string()
        } else {
            format!("{years} years")
        }
    } else if secs >= 86400 {
        let days = secs / 86400;
        if days == 1 {
            "1 day".to_string()
        } else {
            format!("{days} days")
        }
    } else if secs >= 3600 {
        let hours = secs / 3600;
        if hours == 1 {
            "1 hour".to_string()
        } else {
            format!("{hours} hours")
        }
    } else {
        format!("{secs}s")
    }
}
