//! Signer management commands for Auths.

use anyhow::{Context, Result};
use auths_sdk::workflows::allowed_signers::{
    AllowedSigners, AllowedSignersError, EmailAddress, SignerPrincipal, SignerSource,
};
use auths_storage::git::RegistryAttestationStorage;
use auths_verifier::core::Ed25519PublicKey;
use clap::{Parser, Subcommand};
use ssh_key::PublicKey as SshPublicKey;
use std::path::PathBuf;

use super::git::expand_tilde;

#[derive(Parser, Debug, Clone)]
#[command(about = "Manage allowed signers for Git commit verification.")]
pub struct SignersCommand {
    #[command(subcommand)]
    pub command: SignersSubcommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum SignersSubcommand {
    /// List all entries in the allowed_signers file.
    List(SignersListArgs),

    /// Add a manual signer entry.
    Add(SignersAddArgs),

    /// Remove a manual signer entry.
    Remove(SignersRemoveArgs),

    /// Sync attestation entries from the auths registry.
    Sync(SignersSyncArgs),

    /// Add a signer from a GitHub user's SSH keys.
    #[command(name = "add-from-github")]
    AddFromGithub(SignersAddFromGithubArgs),
}

#[derive(Parser, Debug, Clone)]
pub struct SignersListArgs {
    /// Output as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct SignersAddArgs {
    /// Email address of the signer.
    pub email: String,

    /// SSH public key (ssh-ed25519 AAAA...).
    pub pubkey: String,
}

#[derive(Parser, Debug, Clone)]
pub struct SignersRemoveArgs {
    /// Email address of the signer to remove.
    pub email: String,
}

#[derive(Parser, Debug, Clone)]
pub struct SignersSyncArgs {
    /// Path to the Auths identity repository.
    #[arg(long, default_value = "~/.auths")]
    pub repo: PathBuf,

    /// Output file path. Overrides the default location.
    #[arg(long = "output", short = 'o')]
    pub output_file: Option<PathBuf>,
}

#[derive(Parser, Debug, Clone)]
pub struct SignersAddFromGithubArgs {
    /// GitHub username whose SSH keys to add.
    pub username: String,
}

fn resolve_signers_path() -> Result<PathBuf> {
    let output = std::process::Command::new("git")
        .args(["config", "--get", "gpg.ssh.allowedSignersFile"])
        .output();

    if let Ok(out) = output {
        if out.status.success() {
            let path_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !path_str.is_empty() {
                let path = PathBuf::from(&path_str);
                return expand_tilde(&path);
            }
        }
    }

    let home = dirs::home_dir().context("Could not determine home directory")?;
    Ok(home.join(".ssh").join("allowed_signers"))
}

fn handle_list(args: &SignersListArgs) -> Result<()> {
    let path = resolve_signers_path()?;
    let signers = AllowedSigners::load(&path)
        .with_context(|| format!("Failed to load {}", path.display()))?;

    if args.json {
        let json = serde_json::to_string_pretty(signers.list())
            .context("Failed to serialize entries")?;
        println!("{}", json);
        return Ok(());
    }

    let entries = signers.list();
    if entries.is_empty() {
        println!("No entries in {}", path.display());
        return Ok(());
    }

    println!(
        "{:<40} {:<12} {}",
        "PRINCIPAL", "SOURCE", "KEY FINGERPRINT"
    );
    for entry in entries {
        let source = match entry.source {
            SignerSource::Attestation => "attestation",
            SignerSource::Manual => "manual",
        };
        let fingerprint = hex::encode(&entry.public_key.as_bytes()[..8]);
        println!(
            "{:<40} {:<12} {}...",
            entry.principal.to_string(),
            source,
            fingerprint
        );
    }

    Ok(())
}

fn handle_add(args: &SignersAddArgs) -> Result<()> {
    let path = resolve_signers_path()?;
    let mut signers = AllowedSigners::load(&path)
        .with_context(|| format!("Failed to load {}", path.display()))?;

    let principal = SignerPrincipal::Email(
        EmailAddress::new(&args.email).map_err(|e| anyhow::anyhow!("{}", e))?,
    );

    let pubkey = parse_ssh_pubkey(&args.pubkey)?;

    signers
        .add(principal, pubkey, SignerSource::Manual)
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    signers
        .save()
        .with_context(|| format!("Failed to write {}", path.display()))?;

    println!("Added {} to {}", args.email, path.display());
    Ok(())
}

fn handle_remove(args: &SignersRemoveArgs) -> Result<()> {
    let path = resolve_signers_path()?;
    let mut signers = AllowedSigners::load(&path)
        .with_context(|| format!("Failed to load {}", path.display()))?;

    let principal = SignerPrincipal::Email(
        EmailAddress::new(&args.email).map_err(|e| anyhow::anyhow!("{}", e))?,
    );

    match signers.remove(&principal) {
        Ok(true) => {
            signers
                .save()
                .with_context(|| format!("Failed to write {}", path.display()))?;
            println!("Removed {} from {}", args.email, path.display());
        }
        Ok(false) => {
            println!("Entry not found: {}", args.email);
        }
        Err(AllowedSignersError::AttestationEntryProtected(p)) => {
            eprintln!(
                "Cannot remove '{}': attestation entries are managed by `auths signers sync`.",
                p
            );
            std::process::exit(1);
        }
        Err(e) => return Err(anyhow::anyhow!("{}", e)),
    }

    Ok(())
}

fn handle_sync(args: &SignersSyncArgs) -> Result<()> {
    let repo_path = expand_tilde(&args.repo)?;
    let storage = RegistryAttestationStorage::new(&repo_path);

    let path = if let Some(ref output) = args.output_file {
        expand_tilde(output)?
    } else {
        resolve_signers_path()?
    };

    let mut signers = AllowedSigners::load(&path)
        .with_context(|| format!("Failed to load {}", path.display()))?;

    let report = signers
        .sync(&storage)
        .context("Failed to sync attestations")?;

    signers
        .save()
        .with_context(|| format!("Failed to write {}", path.display()))?;

    println!(
        "Synced: {} added, {} removed, {} manual preserved",
        report.added, report.removed, report.preserved
    );
    println!("Wrote to {}", path.display());

    Ok(())
}

fn handle_add_from_github(args: &SignersAddFromGithubArgs) -> Result<()> {
    let url = format!("https://github.com/{}.keys", args.username);
    let response = reqwest::blocking::get(&url)
        .with_context(|| format!("Failed to fetch keys from {}", url))?;

    if !response.status().is_success() {
        anyhow::bail!(
            "GitHub returned {} for user '{}'. Check the username.",
            response.status(),
            args.username
        );
    }

    let body = response.text().context("Failed to read response body")?;
    let ed25519_keys: Vec<&str> = body
        .lines()
        .filter(|line| line.starts_with("ssh-ed25519 "))
        .collect();

    if ed25519_keys.is_empty() {
        println!(
            "No ssh-ed25519 keys found for GitHub user '{}'. Only Ed25519 keys are supported.",
            args.username
        );
        return Ok(());
    }

    let path = resolve_signers_path()?;
    let mut signers = AllowedSigners::load(&path)
        .with_context(|| format!("Failed to load {}", path.display()))?;

    let email = format!("{}@github.com", args.username);
    let principal = SignerPrincipal::Email(
        EmailAddress::new(&email).map_err(|e| anyhow::anyhow!("{}", e))?,
    );

    let mut added = 0;
    for key_str in &ed25519_keys {
        let pubkey = match parse_ssh_pubkey(key_str) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("Skipping invalid key: {}", e);
                continue;
            }
        };

        // For multiple keys, append index to email to avoid duplicates
        let p = if ed25519_keys.len() > 1 && added > 0 {
            let indexed_email = format!("{}+{}@github.com", args.username, added);
            SignerPrincipal::Email(
                EmailAddress::new(&indexed_email).map_err(|e| anyhow::anyhow!("{}", e))?,
            )
        } else {
            principal.clone()
        };

        match signers.add(p, pubkey, SignerSource::Manual) {
            Ok(()) => added += 1,
            Err(AllowedSignersError::DuplicatePrincipal(p)) => {
                eprintln!("Skipping duplicate: {}", p);
            }
            Err(e) => return Err(anyhow::anyhow!("{}", e)),
        }
    }

    if added > 0 {
        signers
            .save()
            .with_context(|| format!("Failed to write {}", path.display()))?;
        println!(
            "Added {} key(s) for {} to {}",
            added,
            args.username,
            path.display()
        );
    } else {
        println!("No new keys added.");
    }

    Ok(())
}

fn parse_ssh_pubkey(key_str: &str) -> Result<Ed25519PublicKey> {
    let openssh_str = if key_str.starts_with("ssh-ed25519 ") {
        key_str.to_string()
    } else {
        format!("ssh-ed25519 {}", key_str)
    };

    let ssh_pk = SshPublicKey::from_openssh(&openssh_str)
        .map_err(|e| anyhow::anyhow!("Invalid SSH key: {}", e))?;

    match ssh_pk.key_data() {
        ssh_key::public::KeyData::Ed25519(ed) => Ok(Ed25519PublicKey::from_bytes(ed.0)),
        _ => anyhow::bail!("Only ssh-ed25519 keys are supported"),
    }
}

use crate::commands::executable::ExecutableCommand;
use crate::config::CliConfig;

impl ExecutableCommand for SignersCommand {
    fn execute(&self, _ctx: &CliConfig) -> Result<()> {
        match &self.command {
            SignersSubcommand::List(args) => handle_list(args),
            SignersSubcommand::Add(args) => handle_add(args),
            SignersSubcommand::Remove(args) => handle_remove(args),
            SignersSubcommand::Sync(args) => handle_sync(args),
            SignersSubcommand::AddFromGithub(args) => handle_add_from_github(args),
        }
    }
}
