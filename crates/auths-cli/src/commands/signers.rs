//! Signer management commands for Auths.

use anyhow::{Context, Result};
use auths_sdk::storage::RegistryAttestationStorage;
use auths_sdk::workflows::allowed_signers::{
    AllowedSigners, AllowedSignersError, EmailAddress, SignerPrincipal, SignerSource, SyncReport,
};
use clap::{Parser, Subcommand};
use ssh_key::PublicKey as SshPublicKey;
use std::path::PathBuf;

use crate::adapters::allowed_signers_store::FileAllowedSignersStore;
use auths_utils::path::expand_tilde;

#[derive(Parser, Debug, Clone)]
#[command(
    about = "Manage allowed signers for Git commit verification.",
    after_help = "Examples:
  auths signers list        # Show all entries in allowed_signers file
  auths signers add user@example.com 'ssh-ed25519 AAAA...'
                            # Manually add a signer
  auths signers remove user@example.com
                            # Remove a signer entry
  auths signers sync --repo ~/.auths
                            # Sync attestations from Auths registry
  auths signers add-from-github username
                            # Import SSH keys from a GitHub user

Configuration:
  Git reads allowed_signers from: git config gpg.ssh.allowedSignersFile
  Configure with: git config gpg.ssh.allowedSignersFile ~/.ssh/allowed_signers

Related:
  auths sign    — Sign commits with Auths
  auths verify  — Verify signed commits
  auths git     — Git integration hooks"
)]
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
    if let Some(path_str) =
        crate::subprocess::git_silent(&["config", "--get", "gpg.ssh.allowedSignersFile"])
    {
        let path = PathBuf::from(&path_str);
        return Ok(expand_tilde(&path)?);
    }

    let home = dirs::home_dir().context("Could not determine home directory")?;
    Ok(home.join(".ssh").join("allowed_signers"))
}

fn handle_list(args: &SignersListArgs) -> Result<()> {
    let path = resolve_signers_path()?;
    let signers = AllowedSigners::load(&path, &FileAllowedSignersStore)
        .with_context(|| format!("Failed to load {}", path.display()))?;

    if args.json {
        let json =
            serde_json::to_string_pretty(signers.list()).context("Failed to serialize entries")?;
        println!("{}", json);
        return Ok(());
    }

    let entries = signers.list();
    if entries.is_empty() {
        println!("No entries in {}", path.display());
        return Ok(());
    }

    println!("{:<40} {:<12} KEY FINGERPRINT", "PRINCIPAL", "SOURCE");
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
    let mut signers = AllowedSigners::load(&path, &FileAllowedSignersStore)
        .with_context(|| format!("Failed to load {}", path.display()))?;

    let principal =
        SignerPrincipal::Email(EmailAddress::new(&args.email).map_err(anyhow::Error::from)?);

    let pubkey = parse_ssh_pubkey(&args.pubkey)?;

    signers
        .add(principal, pubkey, SignerSource::Manual)
        .map_err(anyhow::Error::from)?;
    signers
        .save(&FileAllowedSignersStore)
        .with_context(|| format!("Failed to write {}", path.display()))?;

    println!("Added {} to {}", args.email, path.display());
    Ok(())
}

fn handle_remove(args: &SignersRemoveArgs) -> Result<()> {
    let path = resolve_signers_path()?;
    let mut signers = AllowedSigners::load(&path, &FileAllowedSignersStore)
        .with_context(|| format!("Failed to load {}", path.display()))?;

    let principal =
        SignerPrincipal::Email(EmailAddress::new(&args.email).map_err(anyhow::Error::from)?);

    match signers.remove(&principal) {
        Ok(true) => {
            signers
                .save(&FileAllowedSignersStore)
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
        Err(e) => return Err(anyhow::Error::from(e)),
    }

    Ok(())
}

/// Core sync logic — no printing. Reused by init and `auths signers sync`.
pub(crate) fn sync_signers(
    repo: &std::path::Path,
    output_file: &std::path::Path,
) -> Result<(PathBuf, SyncReport)> {
    let storage = RegistryAttestationStorage::new(repo);
    let mut signers = AllowedSigners::load(output_file, &FileAllowedSignersStore)
        .with_context(|| format!("Failed to load {}", output_file.display()))?;
    let report = signers
        .sync(&storage)
        .context("Failed to sync attestations")?;
    signers
        .save(&FileAllowedSignersStore)
        .with_context(|| format!("Failed to write {}", output_file.display()))?;
    Ok((output_file.to_path_buf(), report))
}

pub(crate) fn handle_sync(args: &SignersSyncArgs) -> Result<()> {
    let repo_path = expand_tilde(&args.repo)?;
    let path = if let Some(ref output) = args.output_file {
        expand_tilde(output).map_err(anyhow::Error::from)?
    } else {
        resolve_signers_path()?
    };

    let (path, report) = sync_signers(&repo_path, &path)?;

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
    let mut signers = AllowedSigners::load(&path, &FileAllowedSignersStore)
        .with_context(|| format!("Failed to load {}", path.display()))?;

    let email = format!("{}@github.com", args.username);
    let principal = SignerPrincipal::Email(EmailAddress::new(&email).map_err(anyhow::Error::from)?);

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
            SignerPrincipal::Email(EmailAddress::new(&indexed_email).map_err(anyhow::Error::from)?)
        } else {
            principal.clone()
        };

        match signers.add(p, pubkey, SignerSource::Manual) {
            Ok(()) => added += 1,
            Err(AllowedSignersError::DuplicatePrincipal(p)) => {
                eprintln!("Skipping duplicate: {}", p);
            }
            Err(e) => return Err(anyhow::Error::from(e)),
        }
    }

    if added > 0 {
        signers
            .save(&FileAllowedSignersStore)
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

fn parse_ssh_pubkey(key_str: &str) -> Result<auths_verifier::DevicePublicKey> {
    let openssh_str = if key_str.starts_with("ssh-ed25519 ") {
        key_str.to_string()
    } else {
        format!("ssh-ed25519 {}", key_str)
    };

    let ssh_pk = SshPublicKey::from_openssh(&openssh_str)
        .map_err(|e| anyhow::anyhow!("Invalid SSH key: {}", e))?;

    match ssh_pk.key_data() {
        ssh_key::public::KeyData::Ed25519(ed) => {
            Ok(auths_verifier::DevicePublicKey::from_bytes(&ed.0))
        }
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
