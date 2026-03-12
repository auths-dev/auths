#![allow(clippy::print_stdout, clippy::print_stderr, clippy::exit)]
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
//! This program implements a three-tier signing strategy via
//! [`CommitSigningWorkflow`]:
//!
//! 1. **Tier 1: Agent signing** - If the agent is running with keys loaded,
//!    sign via the agent without any passphrase prompt.
//!
//! 2. **Tier 2: Auto-start + load key** - If the agent is not running or has
//!    no keys, auto-start it, prompt for passphrase once, load the key, and sign.
//!
//! 3. **Tier 3: Direct signing** - If agent approach fails, fall back to
//!    direct passphrase-based signing via SDK pipeline.

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;

use auths_cli::adapters::config_store::FileConfigStore;
use auths_cli::core::pubkey_cache::get_cached_pubkey;
use auths_cli::factories::build_agent_provider;
use auths_core::config::{EnvironmentConfig, load_config};
use auths_core::signing::{KeychainPassphraseProvider, PassphraseProvider};
use auths_core::storage::keychain::get_platform_keychain;
use auths_core::storage::passphrase_cache::{get_passphrase_cache, parse_duration_str};
use auths_sdk::workflows::signing::{
    CommitSigningContext, CommitSigningParams, CommitSigningWorkflow,
};

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

fn validate_verify_option(opt: &str) -> Result<()> {
    match opt {
        "print-pubkey" => return Ok(()),
        "hashalg=sha256" | "hashalg=sha512" => return Ok(()),
        _ => {}
    }

    if let Some(value) = opt.strip_prefix("verify-time=")
        && !value.is_empty()
        && value.len() <= 14
        && value.bytes().all(|b| b.is_ascii_digit())
    {
        return Ok(());
    }

    bail!(
        "disallowed verify option '-O {opt}'\n  \
         Only these -O options are permitted: verify-time=<timestamp>, print-pubkey, hashalg=sha256, hashalg=sha512\n  \
         [AUTHS-E0031]"
    );
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

fn build_signing_context(alias: &str) -> Result<CommitSigningContext> {
    let env_config = EnvironmentConfig::from_env();

    let keychain =
        get_platform_keychain().map_err(|e| anyhow!("Failed to access keychain: {e}"))?;

    let passphrase_provider: Arc<dyn PassphraseProvider + Send + Sync> =
        if let Some(passphrase) = env_config.keychain.passphrase.clone() {
            Arc::new(auths_core::PrefilledPassphraseProvider::new(&passphrase))
        } else {
            let config = load_config(&FileConfigStore);
            let cache = get_passphrase_cache(config.passphrase.biometric);
            let ttl_secs = config
                .passphrase
                .duration
                .as_deref()
                .and_then(parse_duration_str);
            let inner = Arc::new(auths_cli::core::provider::CliPassphraseProvider::new());
            Arc::new(KeychainPassphraseProvider::new(
                inner,
                cache,
                alias.to_string(),
                config.passphrase.cache,
                ttl_secs,
            ))
        };

    Ok(CommitSigningContext {
        key_storage: Arc::from(keychain),
        passphrase_provider,
        agent_signing: build_agent_provider(),
    })
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
    ]);
    cmd.arg(sig_file);
    for opt in &args.verify_options {
        validate_verify_option(opt)?;
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
        validate_verify_option(opt)?;
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

    let pubkey = get_cached_pubkey(&alias).ok().flatten().unwrap_or_default();

    let repo_path = auths_id::storage::layout::resolve_repo_path(None).ok();

    let ctx = build_signing_context(&alias)?;
    let mut params = CommitSigningParams::new(&alias, namespace, data).with_pubkey(pubkey);
    if let Some(path) = repo_path {
        params = params.with_repo_path(path);
    }

    #[allow(clippy::disallowed_methods)]
    let now = chrono::Utc::now();
    let signature_pem =
        CommitSigningWorkflow::execute(&ctx, params, now).map_err(anyhow::Error::new)?;

    let sig_path = format!("{}.sig", buffer_file.display());
    fs::write(&sig_path, &signature_pem)
        .with_context(|| format!("Failed to write signature to: {}", sig_path))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_core::crypto::ssh::construct_sshsig_signed_data;
    use auths_crypto::Pkcs8Der;

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
        let pkcs8 = Pkcs8Der::new(pkcs8_doc.as_ref());

        let result = extract_seed_from_pkcs8(&pkcs8);
        assert!(
            result.is_ok(),
            "extract_seed_from_pkcs8 must succeed on a ring-generated key, got: {:?}",
            result.err()
        );

        let seed = result.unwrap();
        assert_eq!(seed.as_bytes().len(), 32, "seed must be exactly 32 bytes");

        let derived = Ed25519KeyPair::from_seed_unchecked(seed.as_bytes())
            .expect("extracted seed must be valid");
        let original = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("original key must parse");
        assert_eq!(
            derived.public_key().as_ref(),
            original.public_key().as_ref(),
            "seed must reproduce the original public key"
        );
    }

    #[test]
    fn test_extract_seed_from_pkcs8_rejects_invalid_input() {
        use auths_core::crypto::ssh::extract_seed_from_pkcs8;

        let bad_input = Pkcs8Der::new(vec![0u8; 50]);
        let result = extract_seed_from_pkcs8(&bad_input);
        assert!(result.is_err(), "must reject non-PKCS#8 input");
    }

    #[test]
    fn test_validate_verify_option_valid() {
        assert!(validate_verify_option("verify-time=1700000000").is_ok());
        assert!(validate_verify_option("verify-time=20260218012319").is_ok());
        assert!(validate_verify_option("verify-time=1").is_ok());
        assert!(validate_verify_option("print-pubkey").is_ok());
        assert!(validate_verify_option("hashalg=sha256").is_ok());
        assert!(validate_verify_option("hashalg=sha512").is_ok());
    }

    #[test]
    fn test_validate_verify_option_invalid() {
        assert!(validate_verify_option("no-touch-required").is_err());
        assert!(validate_verify_option("foo=bar").is_err());
        assert!(validate_verify_option("random-option").is_err());
        assert!(validate_verify_option("").is_err());
    }

    #[test]
    fn test_validate_verify_option_edge_cases() {
        assert!(validate_verify_option("verify-time=").is_err());
        assert!(validate_verify_option("verify-time=abc").is_err());
        assert!(validate_verify_option("VERIFY-TIME=123").is_err());
        assert!(validate_verify_option("hashalg=sha384").is_err());
        assert!(validate_verify_option("verify-time=123=456").is_err());
        assert!(validate_verify_option(" verify-time=123").is_err());
        assert!(validate_verify_option("verify-time=999999999999999").is_err());
    }

    #[test]
    fn test_validate_verify_option_injection_attempts() {
        assert!(validate_verify_option("-D /tmp/evil.so").is_err());
        assert!(validate_verify_option("--help").is_err());
        assert!(validate_verify_option("-t rsa").is_err());
        assert!(validate_verify_option("-w /tmp/fido.so").is_err());
    }
}
