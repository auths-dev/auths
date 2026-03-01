//! Git integration commands for Auths.
//!
//! Provides commands for managing Git allowed_signers files based on
//! Auths device authorizations.

use anyhow::{Context, Result, bail};
use auths_id::storage::attestation::AttestationSource;
use auths_storage::git::RegistryAttestationStorage;
use clap::{Parser, Subcommand};
use ssh_key::PublicKey as SshPublicKey;
use ssh_key::public::Ed25519PublicKey;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(about = "Git integration commands.")]
pub struct GitCommand {
    #[command(subcommand)]
    pub command: GitSubcommand,

    #[command(flatten)]
    pub overrides: crate::commands::registry_overrides::RegistryOverrides,
}

#[derive(Subcommand, Debug, Clone)]
pub enum GitSubcommand {
    /// Generate allowed_signers file from Auths device authorizations.
    ///
    /// Scans the identity repository for authorized devices and outputs
    /// an allowed_signers file compatible with Git's ssh.allowedSignersFile.
    #[command(name = "allowed-signers")]
    AllowedSigners(AllowedSignersCommand),

    /// Install Git hooks for automatic allowed_signers regeneration.
    ///
    /// Installs a post-merge hook that regenerates the allowed_signers file
    /// when identity refs change after a git pull/merge.
    #[command(name = "install-hooks")]
    InstallHooks(InstallHooksCommand),
}

#[derive(Parser, Debug, Clone)]
pub struct AllowedSignersCommand {
    /// Path to the Auths identity repository.
    #[arg(long, default_value = "~/.auths")]
    pub repo: PathBuf,

    /// Output file path. If not specified, outputs to stdout.
    // Named `output_file` rather than `output` because the top-level `Cli` struct
    // has a global `--output` (OutputFormat) argument; clap panics with "Mismatch
    // between definition and access of `output`" when both use the same field name.
    #[arg(long = "output", short = 'o')]
    pub output_file: Option<PathBuf>,
}

#[derive(Parser, Debug, Clone)]
pub struct InstallHooksCommand {
    /// Path to the Git repository where hooks should be installed.
    /// Defaults to the current directory.
    #[arg(long, default_value = ".")]
    pub repo: PathBuf,

    /// Path to the Auths identity repository.
    #[arg(long, default_value = "~/.auths")]
    pub auths_repo: PathBuf,

    /// Path where allowed_signers file should be written.
    #[arg(long, default_value = ".auths/allowed_signers")]
    pub allowed_signers_path: PathBuf,

    /// Overwrite existing hook without prompting.
    #[arg(long)]
    pub force: bool,
}

/// Handle git subcommand.
pub fn handle_git(
    cmd: GitCommand,
    repo_override: Option<PathBuf>,
    attestation_prefix_override: Option<String>,
    attestation_blob_name_override: Option<String>,
) -> Result<()> {
    match cmd.command {
        GitSubcommand::AllowedSigners(subcmd) => handle_allowed_signers(
            subcmd,
            repo_override,
            attestation_prefix_override,
            attestation_blob_name_override,
        ),
        GitSubcommand::InstallHooks(subcmd) => handle_install_hooks(subcmd, repo_override),
    }
}

fn handle_install_hooks(
    cmd: InstallHooksCommand,
    auths_repo_override: Option<PathBuf>,
) -> Result<()> {
    // Find the .git directory
    let git_dir = find_git_dir(&cmd.repo)?;
    let hooks_dir = git_dir.join("hooks");

    // Create hooks directory if it doesn't exist
    if !hooks_dir.exists() {
        fs::create_dir_all(&hooks_dir)
            .with_context(|| format!("Failed to create hooks directory: {:?}", hooks_dir))?;
    }

    let post_merge_path = hooks_dir.join("post-merge");

    // Check if hook already exists
    if post_merge_path.exists() && !cmd.force {
        // Read existing content to check if it's an Auths hook
        let existing = fs::read_to_string(&post_merge_path)
            .with_context(|| format!("Failed to read existing hook: {:?}", post_merge_path))?;

        if existing.contains("auths git allowed-signers") {
            println!(
                "Auths post-merge hook already installed at {:?}",
                post_merge_path
            );
            println!("Use --force to overwrite.");
            return Ok(());
        } else {
            bail!(
                "A post-merge hook already exists at {:?}\n\
                 It was not created by Auths. Use --force to overwrite, or manually \n\
                 add the following to your existing hook:\n\n\
                 auths git allowed-signers --output {}",
                post_merge_path,
                cmd.allowed_signers_path.display()
            );
        }
    }

    // Resolve auths repo path
    let auths_repo = if let Some(override_path) = auths_repo_override {
        override_path
    } else {
        expand_tilde(&cmd.auths_repo)?
    };

    // Generate hook script
    let hook_script = generate_post_merge_hook(&auths_repo, &cmd.allowed_signers_path);

    // Write hook
    fs::write(&post_merge_path, &hook_script)
        .with_context(|| format!("Failed to write hook: {:?}", post_merge_path))?;

    // Make executable (chmod 755) - Unix only
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(&post_merge_path)?.permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&post_merge_path, perms)
            .with_context(|| format!("Failed to set hook permissions: {:?}", post_merge_path))?;
    }

    println!("Installed post-merge hook at {:?}", post_merge_path);
    println!(
        "The hook will regenerate {:?} after each merge/pull.",
        cmd.allowed_signers_path
    );

    // Create the .auths directory if needed
    if let Some(parent) = cmd.allowed_signers_path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {:?}", parent))?;
        println!("Created directory {:?}", parent);
    }

    // Generate initial allowed_signers file
    println!("\nGenerating initial allowed_signers file...");
    let storage = RegistryAttestationStorage::new(&auths_repo);

    match storage.load_all_attestations() {
        Ok(attestations) => {
            let mut entries: Vec<String> = Vec::new();
            for att in attestations {
                if att.is_revoked() {
                    continue;
                }
                let principal = get_principal(&att);
                if let Ok(ssh_key) = public_key_to_ssh(&att.device_public_key) {
                    entries.push(format!("{} namespaces=\"git\" {}", principal, ssh_key));
                }
            }
            entries.sort();
            entries.dedup();

            let output = if entries.is_empty() {
                String::new()
            } else {
                format!("{}\n", entries.join("\n"))
            };

            fs::write(&cmd.allowed_signers_path, &output)
                .with_context(|| format!("Failed to write {:?}", cmd.allowed_signers_path))?;

            println!(
                "Wrote {} entries to {:?}",
                entries.len(),
                cmd.allowed_signers_path
            );
        }
        Err(e) => {
            eprintln!("Warning: Could not generate initial allowed_signers: {}", e);
            eprintln!("You may need to run 'auths git allowed-signers' manually.");
        }
    }

    Ok(())
}

/// Find the .git directory for a repository path.
fn find_git_dir(repo_path: &std::path::Path) -> Result<PathBuf> {
    let repo_path = if repo_path.to_string_lossy() == "." {
        std::env::current_dir().context("Failed to get current directory")?
    } else {
        repo_path.to_path_buf()
    };

    // Check for .git directory
    let git_dir = repo_path.join(".git");
    if git_dir.is_dir() {
        return Ok(git_dir);
    }

    // Check if .git is a file (worktree or submodule)
    if git_dir.is_file() {
        let content = fs::read_to_string(&git_dir)
            .with_context(|| format!("Failed to read {:?}", git_dir))?;

        // Format: "gitdir: <path>"
        if let Some(path) = content.strip_prefix("gitdir: ") {
            let linked_path = PathBuf::from(path.trim());
            if linked_path.is_absolute() {
                return Ok(linked_path);
            } else {
                return Ok(repo_path.join(linked_path));
            }
        }
    }

    // Check if we're inside a git directory
    if repo_path.join("HEAD").exists() && repo_path.join("config").exists() {
        return Ok(repo_path);
    }

    bail!(
        "Not a git repository: {:?}\n\
         Could not find .git directory.",
        repo_path
    );
}

/// Generate the post-merge hook script.
fn generate_post_merge_hook(
    auths_repo: &std::path::Path,
    allowed_signers_path: &std::path::Path,
) -> String {
    format!(
        r#"#!/bin/bash
# Auto-generated by auths git install-hooks
# Regenerates allowed_signers file after merge/pull

# Run auths to regenerate allowed_signers
auths git allowed-signers --repo "{}" --output "{}"
"#,
        auths_repo.display(),
        allowed_signers_path.display()
    )
}

fn handle_allowed_signers(
    cmd: AllowedSignersCommand,
    repo_override: Option<PathBuf>,
    _attestation_prefix_override: Option<String>,
    _attestation_blob_name_override: Option<String>,
) -> Result<()> {
    // Resolve repository path
    let repo_path = if let Some(override_path) = repo_override {
        override_path
    } else {
        expand_tilde(&cmd.repo)?
    };

    // Note: Layout config overrides are deprecated with registry backend.
    // The registry uses a fixed path structure under refs/auths/registry.

    // Create attestation storage
    let storage = RegistryAttestationStorage::new(&repo_path);

    // Load all attestations
    let attestations = storage
        .load_all_attestations()
        .context("Failed to load attestations from repository")?;

    // Generate allowed_signers entries
    let mut entries: Vec<String> = Vec::new();

    for att in attestations {
        // Skip revoked attestations
        if att.is_revoked() {
            continue;
        }

        // Get principal (email) from payload or generate from DID
        let principal = get_principal(&att);

        // Convert device public key to SSH format
        let ssh_key = match public_key_to_ssh(&att.device_public_key) {
            Ok(key) => key,
            Err(e) => {
                eprintln!("Warning: skipping device {} - {}", att.subject, e);
                continue;
            }
        };

        // Format: principal namespaces="git" keytype key
        let entry = format!("{} namespaces=\"git\" {}", principal, ssh_key);
        entries.push(entry);
    }

    // Sort for deterministic output
    entries.sort();
    entries.dedup();

    // Output
    let output = entries.join("\n");
    let output = if output.is_empty() {
        output
    } else {
        format!("{}\n", output)
    };

    if let Some(output_path) = cmd.output_file {
        fs::write(&output_path, &output)
            .with_context(|| format!("Failed to write to {:?}", output_path))?;
        eprintln!("Wrote {} entries to {:?}", entries.len(), output_path);
    } else {
        print!("{}", output);
    }

    Ok(())
}

/// Extract principal (email) from attestation payload, or generate from DID.
pub(crate) fn get_principal(att: &auths_verifier::core::Attestation) -> String {
    // Check for email in payload
    if let Some(ref payload) = att.payload
        && let Some(email) = payload.get("email").and_then(|v| v.as_str())
        && !email.is_empty()
    {
        return email.to_string();
    }

    // Fallback: generate from device DID
    // did:key:z6Mk... -> z6Mk...@auths.local
    let did_str = att.subject.to_string();
    let local_part = did_str.strip_prefix("did:key:").unwrap_or(&did_str);

    format!("{}@auths.local", local_part)
}

/// Convert raw Ed25519 public key bytes to SSH public key string.
pub(crate) fn public_key_to_ssh(public_key_bytes: &[u8]) -> Result<String> {
    if public_key_bytes.len() != 32 {
        anyhow::bail!(
            "Invalid Ed25519 public key length: expected 32, got {}",
            public_key_bytes.len()
        );
    }

    // Create Ed25519PublicKey from raw bytes
    let ed25519_pk = Ed25519PublicKey::try_from(public_key_bytes)
        .context("Failed to parse Ed25519 public key")?;

    // Wrap in SshPublicKey
    let ssh_pk = SshPublicKey::from(ed25519_pk);

    // Format as OpenSSH string (e.g., "ssh-ed25519 AAAA...")
    ssh_pk
        .to_openssh()
        .context("Failed to format SSH public key")
}

/// Expand ~ to home directory.
fn expand_tilde(path: &std::path::Path) -> Result<PathBuf> {
    let path_str = path.to_string_lossy();
    if path_str.starts_with("~/") || path_str == "~" {
        let home = dirs::home_dir().context("Failed to determine home directory")?;
        if path_str == "~" {
            Ok(home)
        } else {
            Ok(home.join(&path_str[2..]))
        }
    } else {
        Ok(path.to_path_buf())
    }
}

use crate::commands::executable::ExecutableCommand;
use crate::config::CliConfig;

impl ExecutableCommand for GitCommand {
    fn execute(&self, ctx: &CliConfig) -> Result<()> {
        handle_git(
            self.clone(),
            ctx.repo_path.clone(),
            self.overrides.attestation_prefix.clone(),
            self.overrides.attestation_blob.clone(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_allowed_signers_output_flag_parses() {
        // Regression: `AllowedSignersCommand.output` used to collide with the global
        // `Cli.output: OutputFormat` argument, causing clap to panic with
        // "Mismatch between definition and access of `output`".
        // The field is now named `output_file` with `long = "output"`.
        let cmd = AllowedSignersCommand::try_parse_from([
            "allowed-signers",
            "--output",
            "/tmp/allowed_signers",
        ])
        .expect("--output flag must parse without panic");
        assert_eq!(cmd.output_file, Some(PathBuf::from("/tmp/allowed_signers")));
    }

    #[test]
    fn test_allowed_signers_no_output_defaults_to_none() {
        let cmd = AllowedSignersCommand::try_parse_from(["allowed-signers"])
            .expect("allowed-signers with no args must parse");
        assert!(cmd.output_file.is_none());
    }

    #[test]
    fn test_public_key_to_ssh() {
        // Test with a known Ed25519 public key
        let pk_bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        let result = public_key_to_ssh(&pk_bytes);
        assert!(result.is_ok(), "Failed: {:?}", result.err());

        let ssh_key = result.unwrap();
        assert!(ssh_key.starts_with("ssh-ed25519 "), "Got: {}", ssh_key);
    }

    #[test]
    fn test_public_key_to_ssh_invalid_length() {
        let pk_bytes = vec![0u8; 16]; // Too short
        let result = public_key_to_ssh(&pk_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_expand_tilde() {
        let path = PathBuf::from("~/.auths");
        let result = expand_tilde(&path);
        assert!(result.is_ok());
        let expanded = result.unwrap();
        assert!(!expanded.to_string_lossy().contains("~"));
    }

    #[test]
    fn test_find_git_dir() {
        let temp = TempDir::new().unwrap();
        let git_dir = temp.path().join(".git");
        fs::create_dir(&git_dir).unwrap();

        let result = find_git_dir(temp.path());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), git_dir);
    }

    #[test]
    fn test_find_git_dir_not_repo() {
        let temp = TempDir::new().unwrap();
        let result = find_git_dir(temp.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_post_merge_hook() {
        let auths_repo = PathBuf::from("/home/user/.auths");
        let allowed_signers = PathBuf::from(".auths/allowed_signers");

        let hook = generate_post_merge_hook(&auths_repo, &allowed_signers);

        assert!(hook.starts_with("#!/bin/bash"));
        assert!(hook.contains("auths git allowed-signers"));
        assert!(hook.contains("/home/user/.auths"));
        assert!(hook.contains(".auths/allowed_signers"));
    }
}
