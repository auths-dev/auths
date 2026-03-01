#![allow(clippy::print_stdout, clippy::print_stderr)]
//! auths-sign: Git SSH signing program compatible with `gpg.ssh.program`
//!
//! Git calls this binary with ssh-keygen compatible arguments:
//! ```
//! auths-sign -Y sign -n git -f <key_file> <buffer_file>
//! ```
//!
//! For Auths keys, the key_file is in the format `auths:<alias>`.
//!
//! ## Passphrase-Free Signing
//!
//! This program implements a three-tier signing strategy:
//!
//! 1. **Tier 1: Agent signing** - If the agent is running with keys loaded,
//!    sign via the agent without any passphrase prompt.
//!
//! 2. **Tier 2: Auto-start + load key** - If the agent is not running or has
//!    no keys, auto-start it, prompt for passphrase once, load the key, and sign.
//!
//! 3. **Tier 3: Direct signing** - If agent approach fails, fall back to
//!    direct passphrase-based signing via SDK pipeline.

use anyhow::{Context, Result, anyhow, bail};
#[cfg(unix)]
use auths_cli::commands::agent::{ensure_agent_running, get_default_socket_path};
use auths_cli::core::pubkey_cache::{cache_pubkey, get_cached_pubkey};
#[cfg(unix)]
use auths_core::agent::{AgentStatus, add_identity, agent_sign, check_agent_status};
use auths_core::crypto::ssh::{
    construct_sshsig_pem, construct_sshsig_signed_data, extract_pubkey_from_key_bytes,
};
use auths_sdk::signing::{self, SigningConfig};
use clap::Parser;
use std::fs;
use std::path::PathBuf;
use zeroize::Zeroizing;

/// Auths SSH signing program for Git integration.
///
/// Compatible with `gpg.ssh.program` interface - mimics ssh-keygen signing behavior.
/// Supports both signing and verification operations.
///
/// Git calls this binary with ssh-keygen compatible arguments:
/// - Signing:           `auths-sign -Y sign -n git -f auths:<alias> <buffer_file>`
/// - Verification:      `auths-sign -Y verify -f <allowed_signers> -I <email> -n git -O verify-time=<ts> -s <sig_file>`
/// - Find principals:   `auths-sign -Y find-principals -f <allowed_signers> -s <sig_file> -Overify-time=<ts>`
/// - Check (no-validate):`auths-sign -Y check-novalidate -n git -s <sig_file> -Overify-time=<ts>`
///
/// Note: `-n` and `-f` are not required by every operation; for example,
/// `find-principals` omits `-n` and `check-novalidate` omits `-f`.
#[derive(Parser, Debug)]
#[command(name = "auths-sign")]
#[command(version)]
struct Args {
    /// Operation type: "sign", "verify", "find-principals", or "check-novalidate"
    #[arg(short = 'Y')]
    operation: String,

    /// Namespace for the signature (e.g., "git"). Not required for all operations.
    #[arg(short = 'n')]
    namespace: Option<String>,

    /// For sign: Key identifier (auths:<alias>)
    /// For verify/find-principals: Allowed signers file
    /// Not required for all operations.
    #[arg(short = 'f')]
    file_arg: Option<String>,

    /// For verify: Identity/principal to check
    #[arg(short = 'I')]
    identity: Option<String>,

    /// For verify/find-principals/check-novalidate: Signature file path
    #[arg(short = 's')]
    signature_file: Option<PathBuf>,

    /// Options forwarded by git (e.g. -O verify-time=<timestamp> or -Overify-time=<ts>).
    #[arg(short = 'O', action = clap::ArgAction::Append, required = false)]
    verify_options: Vec<String>,

    /// For sign: Buffer file containing data to sign
    buffer_file: Option<PathBuf>,
}

fn parse_key_identifier(key_file: &str) -> Result<String> {
    if let Some(alias) = key_file.strip_prefix("auths:") {
        if alias.is_empty() {
            bail!("Invalid Auths key format: alias cannot be empty. Use 'auths:<alias>'");
        }
        Ok(alias.to_string())
    } else {
        bail!(
            "Unsupported key format: '{}'. \
             Auths keys should be specified as 'auths:<alias>' \
             (e.g., 'auths:default' or 'auths:my-signing-key')",
            key_file
        );
    }
}

fn get_passphrase(alias: &str) -> Result<Zeroizing<String>> {
    if let Ok(p) = std::env::var("AUTHS_PASSPHRASE") {
        return Ok(Zeroizing::new(p));
    }
    rpassword::prompt_password(format!("Passphrase for '{}': ", alias))
        .map(Zeroizing::new)
        .context("Failed to read passphrase from terminal")
}

#[cfg(unix)]
fn try_sign_via_agent(alias: &str, data: &[u8], namespace: &str) -> Result<Option<String>> {
    let socket_path = match get_default_socket_path() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Could not determine agent socket path: {}", e);
            return Ok(None);
        }
    };

    match check_agent_status(&socket_path) {
        AgentStatus::Running { key_count } => {
            if key_count == 0 {
                eprintln!("Agent running but no keys loaded");
                return Ok(None);
            }
        }
        AgentStatus::ConnectionFailed => {
            eprintln!("Agent connection failed");
            return Ok(None);
        }
        AgentStatus::NotRunning => {
            return Ok(None);
        }
    }

    let pubkey = match get_cached_pubkey(alias) {
        Ok(Some(pk)) => pk,
        Ok(None) => {
            eprintln!("No cached pubkey for alias '{}', need passphrase", alias);
            return Ok(None);
        }
        Err(e) => {
            eprintln!("Error reading pubkey cache: {}", e);
            return Ok(None);
        }
    };

    let sig_data = construct_sshsig_signed_data(data, namespace)
        .context("Failed to construct SSHSIG signed data")?;

    match agent_sign(&socket_path, &pubkey, &sig_data) {
        Ok(signature) => {
            let pem = construct_sshsig_pem(&pubkey, &signature, namespace)
                .context("Failed to construct SSHSIG PEM")?;
            Ok(Some(pem))
        }
        Err(e) => {
            eprintln!("Agent signing failed: {}", e);
            Ok(None)
        }
    }
}

#[cfg(not(unix))]
fn try_sign_via_agent(_alias: &str, _data: &[u8], _namespace: &str) -> Result<Option<String>> {
    Ok(None)
}

fn main() {
    if let Err(e) = run() {
        auths_cli::errors::renderer::render_error(&e, false);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args = Args::parse();

    match args.operation.as_str() {
        "sign" => run_sign(&args),
        "verify" => run_verify(&args),
        "find-principals" | "check-novalidate" => run_delegate_to_ssh_keygen(&args),
        other => bail!(
            "Unsupported operation: '{}'. Use 'sign', 'verify', 'find-principals', or 'check-novalidate'.",
            other
        ),
    }
}

fn run_verify(args: &Args) -> Result<()> {
    let allowed_signers = args
        .file_arg
        .as_deref()
        .ok_or_else(|| anyhow!("-f <allowed_signers> required for verify"))?;
    let namespace = args
        .namespace
        .as_deref()
        .ok_or_else(|| anyhow!("-n <namespace> required for verify"))?;
    let identity = args.identity.as_deref().unwrap_or("*");
    let sig_file = args
        .signature_file
        .as_ref()
        .ok_or_else(|| anyhow!("-s <signature_file> required for verify"))?;

    let mut cmd = std::process::Command::new("ssh-keygen");
    cmd.args([
        "-Y",
        "verify",
        "-f",
        allowed_signers,
        "-I",
        identity,
        "-n",
        namespace,
        "-s",
        sig_file.to_str().unwrap(),
    ]);
    for opt in &args.verify_options {
        cmd.arg("-O").arg(opt);
    }
    let status = cmd
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .context("Failed to run ssh-keygen")?;

    if status.success() {
        Ok(())
    } else {
        std::process::exit(status.code().unwrap_or(1));
    }
}

fn run_delegate_to_ssh_keygen(args: &Args) -> Result<()> {
    let mut cmd = std::process::Command::new("ssh-keygen");
    cmd.arg("-Y").arg(&args.operation);
    if let Some(ns) = &args.namespace {
        cmd.arg("-n").arg(ns);
    }
    if let Some(f) = &args.file_arg {
        cmd.arg("-f").arg(f);
    }
    if let Some(id) = &args.identity {
        cmd.arg("-I").arg(id);
    }
    if let Some(sig) = &args.signature_file {
        cmd.arg("-s").arg(sig);
    }
    for opt in &args.verify_options {
        cmd.arg("-O").arg(opt);
    }
    let status = cmd
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .context("Failed to run ssh-keygen")?;

    if status.success() {
        Ok(())
    } else {
        std::process::exit(status.code().unwrap_or(1));
    }
}

fn run_sign(args: &Args) -> Result<()> {
    let file_arg = args
        .file_arg
        .as_deref()
        .ok_or_else(|| anyhow!("-f <key_identifier> required for sign (e.g. auths:main)"))?;
    let alias = parse_key_identifier(file_arg)?;
    let namespace = args.namespace.as_deref().unwrap_or("git");

    let buffer_file = args
        .buffer_file
        .as_ref()
        .ok_or_else(|| anyhow!("Buffer file required for signing"))?;

    let data = fs::read(buffer_file)
        .with_context(|| format!("Failed to read input file: {}", buffer_file.display()))?;

    // TIER 1: Try passphrase-free agent signing
    if let Some(pem) = try_sign_via_agent(&alias, &data, namespace)? {
        let sig_path = format!("{}.sig", buffer_file.display());
        fs::write(&sig_path, &pem)
            .with_context(|| format!("Failed to write signature to: {}", sig_path))?;
        return Ok(());
    }

    // TIER 2: Auto-start agent (best effort)
    #[cfg(unix)]
    let _ = ensure_agent_running(true);

    // Load key from keychain with passphrase retry
    let key_bytes = load_key_with_retry(&alias)?;

    // Cache pubkey and load into agent (best effort)
    if let Ok(pubkey) = extract_pubkey_from_key_bytes(&key_bytes) {
        if let Err(e) = cache_pubkey(&alias, &pubkey) {
            eprintln!("Warning: Failed to cache pubkey: {}", e);
        }

        #[cfg(unix)]
        if let Ok(socket_path) = get_default_socket_path()
            && let Err(e) = add_identity(&socket_path, &key_bytes)
        {
            eprintln!("Warning: Failed to add key to agent: {}", e);
        }
    }

    // TIER 3: Direct signing via SDK pipeline
    let config = SigningConfig {
        namespace: namespace.to_string(),
    };
    let repo_path = auths_id::storage::layout::resolve_repo_path(None).ok();
    let seed = auths_core::crypto::ssh::extract_seed_from_pkcs8(&key_bytes)
        .context("Failed to extract seed from PKCS#8")?;

    if let Some(ref path) = repo_path {
        signing::validate_freeze_state(path, chrono::Utc::now()).map_err(|e| anyhow!("{}", e))?;
    }

    let signature_pem =
        signing::sign_with_seed(&seed, &data, &config.namespace).map_err(|e| anyhow!("{}", e))?;

    let sig_path = format!("{}.sig", buffer_file.display());
    fs::write(&sig_path, &signature_pem)
        .with_context(|| format!("Failed to write signature to: {}", sig_path))?;

    Ok(())
}

fn load_key_with_retry(alias: &str) -> Result<Zeroizing<Vec<u8>>> {
    use auths_core::crypto::signer::decrypt_keypair;
    use auths_core::error::AgentError;
    use auths_core::storage::keychain::{KeyAlias, get_platform_keychain};

    let keychain =
        get_platform_keychain().map_err(|e| anyhow!("Failed to get platform keychain: {e}"))?;
    let (_identity_did, encrypted_data) = keychain
        .load_key(&KeyAlias::new_unchecked(alias))
        .map_err(|e| anyhow!("{e}"))?;

    const MAX_ATTEMPTS: u32 = 3;

    for attempt in 1..=MAX_ATTEMPTS {
        let passphrase = get_passphrase(alias)?;

        match decrypt_keypair(&encrypted_data, &passphrase) {
            Ok(decrypted) => return Ok(decrypted),
            Err(AgentError::IncorrectPassphrase) => {
                if attempt < MAX_ATTEMPTS {
                    eprintln!("Incorrect passphrase for '{}'. Try again.", alias);
                } else {
                    eprintln!(
                        "{} incorrect attempts for key '{}'.\n  \
                         Forgot your passphrase? Run: auths key reset {}",
                        MAX_ATTEMPTS, alias, alias
                    );
                    std::process::exit(1);
                }
            }
            Err(e) => return Err(anyhow::Error::new(e)),
        }
    }

    bail!("Failed to decrypt key after maximum attempts")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_args_accepts_o_flag() {
        let args = Args::try_parse_from([
            "auths-sign",
            "-Y",
            "verify",
            "-n",
            "git",
            "-f",
            "/tmp/allowed_signers",
            "-I",
            "user@example.com",
            "-s",
            "/tmp/file.sig",
            "-O",
            "verify-time=1700000000",
        ])
        .expect("Args must accept -O verify-time=<ts>");
        assert_eq!(args.verify_options, vec!["verify-time=1700000000"]);
    }

    #[test]
    fn test_args_accepts_multiple_o_flags() {
        let args = Args::try_parse_from([
            "auths-sign",
            "-Y",
            "verify",
            "-n",
            "git",
            "-f",
            "/tmp/allowed_signers",
            "-I",
            "user@example.com",
            "-s",
            "/tmp/file.sig",
            "-O",
            "verify-time=1700000000",
            "-O",
            "print-pubkey",
        ])
        .expect("Args must accept multiple -O flags");
        assert_eq!(
            args.verify_options,
            vec!["verify-time=1700000000", "print-pubkey"]
        );
    }

    #[test]
    fn test_args_o_flag_absent_defaults_to_empty() {
        let args = Args::try_parse_from(["auths-sign", "-Y", "sign", "-f", "auths:main"])
            .expect("Args without -O should parse fine");
        assert!(args.verify_options.is_empty());
    }

    #[test]
    fn test_args_find_principals_no_namespace() {
        let args = Args::try_parse_from([
            "auths-sign",
            "-Y",
            "find-principals",
            "-f",
            "/tmp/allowed_signers",
            "-s",
            "/tmp/file.sig",
            "-Overify-time=20260218012319",
        ])
        .expect("find-principals without -n must parse");
        assert_eq!(args.operation, "find-principals");
        assert!(args.namespace.is_none());
        assert_eq!(args.verify_options, vec!["verify-time=20260218012319"]);
    }

    #[test]
    fn test_args_check_novalidate_no_file() {
        let args = Args::try_parse_from([
            "auths-sign",
            "-Y",
            "check-novalidate",
            "-n",
            "git",
            "-s",
            "/tmp/file.sig",
            "-Overify-time=20260218012319",
        ])
        .expect("check-novalidate without -f must parse");
        assert_eq!(args.operation, "check-novalidate");
        assert!(args.file_arg.is_none());
        assert_eq!(args.verify_options, vec!["verify-time=20260218012319"]);
    }

    #[test]
    fn test_parse_key_identifier_valid() {
        assert_eq!(parse_key_identifier("auths:default").unwrap(), "default");
        assert_eq!(
            parse_key_identifier("auths:my-key-alias").unwrap(),
            "my-key-alias"
        );
    }

    #[test]
    fn test_parse_key_identifier_invalid() {
        assert!(parse_key_identifier("/path/to/key").is_err());
        assert!(parse_key_identifier("ssh-ed25519 AAAA...").is_err());
        assert!(parse_key_identifier("auths:").is_err());
    }

    #[test]
    fn test_sshsig_format() {
        use auths_core::crypto::ssh::SecureSeed;

        let seed = SecureSeed::new([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ]);

        let data = b"test data to sign";
        let result = auths_core::crypto::ssh::create_sshsig(&seed, data, "git");

        assert!(result.is_ok(), "SSHSIG creation failed: {:?}", result.err());

        let pem = result.unwrap();
        assert!(pem.starts_with("-----BEGIN SSH SIGNATURE-----"));
        assert!(pem.contains("-----END SSH SIGNATURE-----"));
    }

    #[test]
    fn test_encode_ssh_pubkey() {
        use auths_core::crypto::ssh::encode_ssh_pubkey;

        let pubkey = [0x42u8; 32];
        let blob = encode_ssh_pubkey(&pubkey);

        assert_eq!(&blob[0..4], &11u32.to_be_bytes());
        assert_eq!(&blob[4..15], b"ssh-ed25519");
        assert_eq!(&blob[15..19], &32u32.to_be_bytes());
        assert_eq!(&blob[19..51], &[0x42; 32]);
    }

    #[test]
    fn test_construct_sshsig_signed_data() {
        let data = b"test";
        let result = construct_sshsig_signed_data(data, "git");
        assert!(result.is_ok());

        let blob = result.unwrap();

        assert_ne!(
            &blob[0..4],
            &6u32.to_be_bytes(),
            "SSHSIG magic must not have a uint32 length prefix"
        );
        assert_eq!(
            &blob[0..6],
            b"SSHSIG",
            "First 6 bytes must be literal SSHSIG"
        );
        assert_eq!(&blob[6..10], &3u32.to_be_bytes());
        assert_eq!(&blob[10..13], b"git");
        assert_eq!(&blob[13..17], &0u32.to_be_bytes());
        assert_eq!(&blob[17..21], &6u32.to_be_bytes());
        assert_eq!(&blob[21..27], b"sha512");
        assert_eq!(&blob[27..31], &64u32.to_be_bytes());
        assert_eq!(blob.len(), 31 + 64);
    }

    #[test]
    fn test_extract_seed_from_pkcs8_ring_generated_key() {
        use auths_core::crypto::ssh::extract_seed_from_pkcs8;
        use ring::rand::SystemRandom;
        use ring::signature::{Ed25519KeyPair, KeyPair};

        let rng = SystemRandom::new();
        let pkcs8_doc = Ed25519KeyPair::generate_pkcs8(&rng)
            .expect("ring must generate a valid PKCS#8 document");
        let pkcs8_bytes = Zeroizing::new(pkcs8_doc.as_ref().to_vec());

        let result = extract_seed_from_pkcs8(&pkcs8_bytes);
        assert!(
            result.is_ok(),
            "extract_seed_from_pkcs8 must succeed on a ring-generated key, got: {:?}",
            result.err()
        );

        let seed = result.unwrap();
        assert_eq!(seed.as_bytes().len(), 32, "seed must be exactly 32 bytes");

        let derived = Ed25519KeyPair::from_seed_unchecked(seed.as_bytes())
            .expect("extracted seed must be valid");
        let original =
            Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).expect("original key must parse");
        assert_eq!(
            derived.public_key().as_ref(),
            original.public_key().as_ref(),
            "seed must reproduce the original public key"
        );
    }

    #[test]
    fn test_extract_seed_from_pkcs8_rejects_invalid_input() {
        use auths_core::crypto::ssh::extract_seed_from_pkcs8;

        let bad_input = Zeroizing::new(vec![0u8; 50]);
        let result = extract_seed_from_pkcs8(&bad_input);
        assert!(result.is_err(), "must reject non-PKCS#8 input");
    }
}
