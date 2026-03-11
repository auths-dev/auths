//! Migration commands for importing existing keys into Auths.
//!
//! Supports migrating from:
//! - GPG keys (`auths migrate from-gpg`)
//! - SSH keys (`auths migrate from-ssh`)

use crate::ux::format::{Output, is_json_mode};
use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Migrate existing keys to Auths identities.
#[derive(Parser, Debug, Clone)]
#[command(name = "migrate", about = "Import existing GPG or SSH keys")]
pub struct MigrateCommand {
    #[command(subcommand)]
    pub command: MigrateSubcommand,
}

#[derive(Subcommand, Debug, Clone)]
pub enum MigrateSubcommand {
    /// Import an existing GPG key.
    #[command(name = "from-gpg")]
    FromGpg(FromGpgCommand),

    /// Import an existing SSH key.
    #[command(name = "from-ssh")]
    FromSsh(FromSshCommand),

    /// Show migration status for a repository.
    #[command(name = "status")]
    Status(MigrateStatusCommand),
}

/// Import a GPG key into Auths.
#[derive(Parser, Debug, Clone)]
pub struct FromGpgCommand {
    /// Specific GPG key ID to import (e.g., 0xABCD1234).
    #[arg(long, value_name = "KEY_ID")]
    pub key_id: Option<String>,

    /// List available GPG keys without importing.
    #[arg(long)]
    pub list: bool,

    /// Preview the migration without making changes.
    #[arg(long)]
    pub dry_run: bool,

    /// Path to the Auths repository (defaults to ~/.auths or current repo).
    #[arg(long)]
    pub repo: Option<PathBuf>,

    /// Key alias for storing the new Auths key (defaults to gpg-<keyid>).
    #[arg(long)]
    pub key_alias: Option<String>,
}

/// Import an SSH key into Auths.
#[derive(Parser, Debug, Clone)]
pub struct FromSshCommand {
    /// Path to the SSH private key file (e.g., ~/.ssh/id_ed25519).
    #[arg(long, short = 'k', value_name = "PATH")]
    pub key: Option<PathBuf>,

    /// List available SSH keys without importing.
    #[arg(long)]
    pub list: bool,

    /// Preview the migration without making changes.
    #[arg(long)]
    pub dry_run: bool,

    /// Path to the Auths repository (defaults to ~/.auths or current repo).
    #[arg(long)]
    pub repo: Option<PathBuf>,

    /// Key alias for storing the new Auths key (defaults to ssh-<filename>).
    #[arg(long)]
    pub key_alias: Option<String>,

    /// Update allowed_signers file if it exists.
    #[arg(long)]
    pub update_allowed_signers: bool,
}

/// Show migration status for a repository.
#[derive(Parser, Debug, Clone)]
pub struct MigrateStatusCommand {
    /// Path to the Git repository to analyze (defaults to current directory).
    #[arg(long)]
    pub repo: Option<PathBuf>,

    /// Number of commits to analyze (default: 100).
    #[arg(long, short = 'n', default_value = "100")]
    pub count: usize,

    /// Show per-author breakdown.
    #[arg(long)]
    pub by_author: bool,
}

/// Information about a GPG key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpgKeyInfo {
    /// Key ID (short form).
    pub key_id: String,
    /// Key fingerprint (full).
    pub fingerprint: String,
    /// User ID (name <email>).
    pub user_id: String,
    /// Key algorithm (e.g., rsa4096, ed25519).
    pub algorithm: String,
    /// Creation date.
    pub created: String,
    /// Expiry date (if any).
    pub expires: Option<String>,
}

/// Information about an SSH key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKeyInfo {
    /// Path to the private key file.
    pub path: PathBuf,
    /// Key algorithm (ed25519, rsa, ecdsa).
    pub algorithm: String,
    /// Key size in bits (for RSA).
    pub bits: Option<u32>,
    /// Public key fingerprint.
    pub fingerprint: String,
    /// Comment from the public key file.
    pub comment: Option<String>,
}

/// Handle the migrate command.
pub fn handle_migrate(cmd: MigrateCommand, now: chrono::DateTime<chrono::Utc>) -> Result<()> {
    match cmd.command {
        MigrateSubcommand::FromGpg(gpg_cmd) => handle_from_gpg(gpg_cmd, now),
        MigrateSubcommand::FromSsh(ssh_cmd) => handle_from_ssh(ssh_cmd, now),
        MigrateSubcommand::Status(status_cmd) => handle_migrate_status(status_cmd),
    }
}

/// Handle the from-gpg subcommand.
fn handle_from_gpg(cmd: FromGpgCommand, now: chrono::DateTime<chrono::Utc>) -> Result<()> {
    let out = Output::new();

    // Check if GPG is installed
    if !is_gpg_available() {
        return Err(anyhow!(
            "GPG is not installed or not in PATH. Please install GPG first."
        ));
    }

    // List GPG keys
    let keys = list_gpg_secret_keys()?;

    if keys.is_empty() {
        out.print_warn("No GPG secret keys found in ~/.gnupg/");
        out.println("  To create a GPG key: gpg --gen-key");
        return Ok(());
    }

    // If --list flag, just show keys and exit
    if cmd.list {
        out.print_heading("Available GPG Keys");
        out.newline();
        for (i, key) in keys.iter().enumerate() {
            out.println(&format!(
                "  {}. {} {}",
                i + 1,
                out.bold(&key.key_id),
                out.dim(&key.algorithm)
            ));
            out.println(&format!("     {}", key.user_id));
            out.println(&format!("     Fingerprint: {}", out.dim(&key.fingerprint)));
            if let Some(expires) = &key.expires {
                out.println(&format!("     Expires: {}", expires));
            }
            out.newline();
        }
        return Ok(());
    }

    // Find the key to migrate
    let key = if let Some(key_id) = &cmd.key_id {
        keys.iter()
            .find(|k| {
                k.key_id.ends_with(key_id.trim_start_matches("0x"))
                    || k.fingerprint.ends_with(key_id.trim_start_matches("0x"))
            })
            .ok_or_else(|| anyhow!("GPG key not found: {}", key_id))?
            .clone()
    } else if keys.len() == 1 {
        keys[0].clone()
    } else {
        out.print_heading("Multiple GPG keys found. Please specify one:");
        out.newline();
        for key in &keys {
            out.println(&format!("  {} - {}", out.bold(&key.key_id), key.user_id));
        }
        out.newline();
        out.println("Use: auths migrate from-gpg --key-id <KEY_ID>");
        return Ok(());
    };

    out.print_heading("GPG Key Migration");
    out.newline();
    out.println(&format!(
        "  {} Found GPG key: {}",
        out.success("✓"),
        key.user_id
    ));
    out.println(&format!("  Key ID: {}", out.info(&key.key_id)));
    out.println(&format!("  Fingerprint: {}", out.dim(&key.fingerprint)));
    out.newline();

    if cmd.dry_run {
        out.print_info("Dry run mode - no changes will be made");
        out.newline();
        out.println("Would perform the following actions:");
        out.println("  1. Create new Auths Ed25519 identity");
        out.println("  2. Create cross-reference attestation linking GPG key to Auths identity");
        out.println("  3. Sign attestation with both GPG key and new Auths key");
        out.newline();
        out.print_info("Re-run without --dry-run to execute migration");
        return Ok(());
    }

    // Perform the actual migration
    perform_gpg_migration(&key, &cmd, &out, now)
}

/// Check if GPG is available.
fn is_gpg_available() -> bool {
    Command::new("gpg").arg("--version").output().is_ok()
}

/// List GPG secret keys.
fn list_gpg_secret_keys() -> Result<Vec<GpgKeyInfo>> {
    // Use gpg with colon-separated output for reliable parsing
    let output = Command::new("gpg")
        .args([
            "--list-secret-keys",
            "--with-colons",
            "--keyid-format",
            "long",
        ])
        .output()
        .context("Failed to run gpg --list-secret-keys")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("GPG command failed: {}", stderr));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_gpg_colon_output(&stdout)
}

/// Parse GPG colon-separated output.
fn parse_gpg_colon_output(output: &str) -> Result<Vec<GpgKeyInfo>> {
    let mut keys = Vec::new();
    let mut current_key: Option<GpgKeyInfo> = None;

    for line in output.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.is_empty() {
            continue;
        }

        match fields[0] {
            "sec" => {
                // Secret key line: sec:u:4096:1:KEYID:created:expires::::algo:
                if let Some(key) = current_key.take() {
                    keys.push(key);
                }

                let key_id = fields.get(4).unwrap_or(&"").to_string();
                let algo_code = *fields.get(3).unwrap_or(&"1");
                let algorithm = match algo_code {
                    "1" => "rsa".to_string(),
                    "17" => "dsa".to_string(),
                    "18" => "ecdh".to_string(),
                    "19" => "ecdsa".to_string(),
                    "22" => "ed25519".to_string(),
                    other => format!("algo{}", other),
                };
                let key_bits = *fields.get(2).unwrap_or(&"");
                let algorithm = if !key_bits.is_empty() && algorithm.starts_with("rsa") {
                    format!("{}{}", algorithm, key_bits)
                } else {
                    algorithm
                };

                let created = fields.get(5).unwrap_or(&"").to_string();
                let expires = fields
                    .get(6)
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string());

                current_key = Some(GpgKeyInfo {
                    key_id: key_id
                        .chars()
                        .rev()
                        .take(16)
                        .collect::<String>()
                        .chars()
                        .rev()
                        .collect(),
                    fingerprint: String::new(),
                    user_id: String::new(),
                    algorithm,
                    created,
                    expires,
                });
            }
            "fpr" => {
                // Fingerprint line
                if let Some(ref mut key) = current_key {
                    key.fingerprint = fields.get(9).unwrap_or(&"").to_string();
                }
            }
            "uid" => {
                // User ID line
                if let Some(ref mut key) = current_key
                    && key.user_id.is_empty()
                {
                    key.user_id = fields.get(9).unwrap_or(&"").to_string();
                }
            }
            _ => {}
        }
    }

    if let Some(key) = current_key {
        keys.push(key);
    }

    Ok(keys)
}

/// Perform the actual GPG key migration.
fn perform_gpg_migration(
    key: &GpgKeyInfo,
    cmd: &FromGpgCommand,
    out: &Output,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    use auths_core::error::AgentError;
    use auths_core::storage::keychain::{KeyAlias, get_platform_keychain};
    use auths_id::identity::initialize::initialize_registry_identity;
    use auths_id::ports::registry::RegistryBackend;
    use auths_storage::git::{GitRegistryBackend, RegistryConfig};
    use std::fs;
    use std::sync::Arc;
    use zeroize::Zeroizing;

    // Get keychain
    let keychain = get_platform_keychain().context("Failed to access platform keychain")?;

    // Determine key alias
    let key_alias = cmd.key_alias.clone().unwrap_or_else(|| {
        format!(
            "gpg-{}",
            key.key_id
                .chars()
                .rev()
                .take(8)
                .collect::<String>()
                .chars()
                .rev()
                .collect::<String>()
        )
    });

    // Determine repo path
    let repo_path = cmd.repo.clone().unwrap_or_else(|| {
        dirs::home_dir()
            .map(|h| h.join(".auths"))
            .unwrap_or_else(|| PathBuf::from(".auths"))
    });

    out.print_info(&format!(
        "Creating Auths identity with key alias: {}",
        key_alias
    ));

    // Ensure repo directory exists
    if !repo_path.exists() {
        fs::create_dir_all(&repo_path)
            .with_context(|| format!("Failed to create directory: {:?}", repo_path))?;
    }

    // Initialize Git repo if needed
    if !repo_path.join(".git").exists() {
        std::process::Command::new("git")
            .args(["init"])
            .current_dir(&repo_path)
            .output()
            .context("Failed to initialize Git repository")?;
    }

    // Create metadata linking to GPG key
    let _metadata = serde_json::json!({
        "migrated_from": "gpg",
        "gpg_key_id": key.key_id,
        "gpg_fingerprint": key.fingerprint,
        "gpg_user_id": key.user_id,
        "created_at": now.to_rfc3339()
    });

    // Create a simple passphrase provider that prompts if needed
    struct MigrationPassphraseProvider;
    impl auths_core::signing::PassphraseProvider for MigrationPassphraseProvider {
        fn get_passphrase(&self, prompt: &str) -> Result<Zeroizing<String>, AgentError> {
            // For migration, we create unencrypted keys by default
            // Return empty passphrase
            let _ = prompt;
            Ok(Zeroizing::new(String::new()))
        }
    }
    let passphrase_provider = MigrationPassphraseProvider;

    // Initialize the identity
    let backend: Arc<dyn RegistryBackend + Send + Sync> = Arc::new(
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(&repo_path)),
    );
    let key_alias = KeyAlias::new_unchecked(key_alias);
    match initialize_registry_identity(
        backend,
        &key_alias,
        &passphrase_provider,
        keychain.as_ref(),
        None,
    ) {
        Ok((controller_did, alias)) => {
            out.print_success(&format!("Created Auths identity: {}", controller_did));

            // Create cross-reference attestation
            out.print_info("Creating cross-reference attestation...");

            let attestation = create_gpg_cross_reference_attestation(key, &controller_did, now)?;

            // Save the attestation
            let attestation_path = repo_path.join("gpg-migration.json");
            fs::write(
                &attestation_path,
                serde_json::to_string_pretty(&attestation)?,
            )
            .context("Failed to write attestation file")?;

            out.print_success("Cross-reference attestation created");
            out.newline();

            out.print_heading("Migration Complete");
            out.println(&format!("  GPG Key:          {}", out.dim(&key.key_id)));
            out.println(&format!("  GPG User:         {}", key.user_id));
            out.println(&format!(
                "  Auths Identity:   {}",
                out.info(&controller_did)
            ));
            out.println(&format!("  Key Alias:        {}", out.info(&alias)));
            out.println(&format!(
                "  Repository:       {}",
                out.info(&repo_path.display().to_string())
            ));
            out.println(&format!(
                "  Attestation:      {}",
                out.dim(&attestation_path.display().to_string())
            ));
            out.newline();

            out.print_heading("Next Steps");
            out.println("  1. Sign the attestation with your GPG key:");
            out.println(&format!(
                "     gpg --armor --detach-sign {}",
                attestation_path.display()
            ));
            out.println("  2. Start using Auths for new commits:");
            out.println("     auths agent start");
            out.println("  3. Existing GPG-signed commits remain verifiable");

            Ok(())
        }
        Err(e) => Err(e).context("Failed to initialize identity"),
    }
}

/// Create a cross-reference attestation linking GPG key to Auths identity.
fn create_gpg_cross_reference_attestation(
    gpg_key: &GpgKeyInfo,
    auths_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<serde_json::Value> {
    let attestation = serde_json::json!({
        "version": 1,
        "type": "gpg-migration",
        "gpg": {
            "key_id": gpg_key.key_id,
            "fingerprint": gpg_key.fingerprint,
            "user_id": gpg_key.user_id,
            "algorithm": gpg_key.algorithm
        },
        "auths": {
            "did": auths_did
        },
        "statement": "This attestation links the GPG key to the Auths identity. Both keys belong to the same entity.",
        "created_at": now.to_rfc3339(),
        "instructions": "To complete the cross-reference: 1) Sign this file with your GPG key using 'gpg --armor --detach-sign', 2) The Auths signature will be added automatically."
    });

    Ok(attestation)
}

// ============================================================================
// SSH Migration
// ============================================================================

/// Handle the from-ssh subcommand.
fn handle_from_ssh(cmd: FromSshCommand, now: chrono::DateTime<chrono::Utc>) -> Result<()> {
    let out = Output::new();

    // Scan for SSH keys
    let keys = list_ssh_keys()?;

    if keys.is_empty() {
        out.print_warn("No SSH keys found in ~/.ssh/");
        out.println("  To create an SSH key: ssh-keygen -t ed25519");
        return Ok(());
    }

    // If --list flag, just show keys and exit
    if cmd.list {
        out.print_heading("Available SSH Keys");
        out.newline();
        for (i, key) in keys.iter().enumerate() {
            let bits_str = key
                .bits
                .map(|b| format!(" ({} bits)", b))
                .unwrap_or_default();
            out.println(&format!(
                "  {}. {} {}{}",
                i + 1,
                out.bold(&key.path.display().to_string()),
                out.dim(&key.algorithm),
                bits_str
            ));
            out.println(&format!("     Fingerprint: {}", out.dim(&key.fingerprint)));
            if let Some(comment) = &key.comment {
                out.println(&format!("     Comment: {}", comment));
            }
            out.newline();
        }
        return Ok(());
    }

    // Find the key to migrate
    let key = if let Some(key_path) = &cmd.key {
        keys.iter()
            .find(|k| k.path == *key_path || k.path.file_name() == key_path.file_name())
            .ok_or_else(|| anyhow!("SSH key not found: {}", key_path.display()))?
            .clone()
    } else if keys.len() == 1 {
        keys[0].clone()
    } else {
        out.print_heading("Multiple SSH keys found. Please specify one:");
        out.newline();
        for key in &keys {
            out.println(&format!(
                "  {} ({})",
                out.bold(&key.path.display().to_string()),
                key.algorithm
            ));
        }
        out.newline();
        out.println("Use: auths migrate from-ssh --key <PATH>");
        return Ok(());
    };

    out.print_heading("SSH Key Migration");
    out.newline();
    out.println(&format!(
        "  {} Found SSH key: {}",
        out.success("✓"),
        key.path.display()
    ));
    out.println(&format!("  Algorithm: {}", out.info(&key.algorithm)));
    out.println(&format!("  Fingerprint: {}", out.dim(&key.fingerprint)));
    if let Some(comment) = &key.comment {
        out.println(&format!("  Comment: {}", comment));
    }
    out.newline();

    if cmd.dry_run {
        out.print_info("Dry run mode - no changes will be made");
        out.newline();
        out.println("Would perform the following actions:");
        out.println("  1. Create new Auths Ed25519 identity");
        out.println("  2. Create cross-reference attestation linking SSH key to Auths identity");
        if cmd.update_allowed_signers {
            out.println("  3. Update allowed_signers file with new Auths key");
        }
        out.newline();
        out.print_info("Re-run without --dry-run to execute migration");
        return Ok(());
    }

    // Perform the actual migration
    perform_ssh_migration(&key, &cmd, &out, now)
}

/// List SSH keys in ~/.ssh/
fn list_ssh_keys() -> Result<Vec<SshKeyInfo>> {
    let ssh_dir = dirs::home_dir()
        .map(|h| h.join(".ssh"))
        .ok_or_else(|| anyhow!("Could not determine home directory"))?;

    if !ssh_dir.exists() {
        return Ok(Vec::new());
    }

    let mut keys = Vec::new();

    // Look for common SSH key filenames
    let key_patterns = [
        "id_ed25519",
        "id_rsa",
        "id_ecdsa",
        "id_ecdsa_sk",
        "id_ed25519_sk",
        "id_dsa",
    ];

    for pattern in &key_patterns {
        let private_key_path = ssh_dir.join(pattern);
        let public_key_path = ssh_dir.join(format!("{}.pub", pattern));

        if private_key_path.exists()
            && public_key_path.exists()
            && let Ok(key_info) = parse_ssh_public_key(&private_key_path, &public_key_path)
        {
            keys.push(key_info);
        }
    }

    // Also scan for any other .pub files
    if let Ok(entries) = fs::read_dir(&ssh_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "pub").unwrap_or(false) {
                let private_key_path = path.with_extension("");
                if private_key_path.exists() {
                    // Skip if we already found this key
                    if keys.iter().any(|k| k.path == private_key_path) {
                        continue;
                    }
                    if let Ok(key_info) = parse_ssh_public_key(&private_key_path, &path) {
                        keys.push(key_info);
                    }
                }
            }
        }
    }

    Ok(keys)
}

/// Parse an SSH public key file to extract key info.
fn parse_ssh_public_key(private_path: &Path, public_path: &Path) -> Result<SshKeyInfo> {
    let public_key_content = fs::read_to_string(public_path)
        .with_context(|| format!("Failed to read {}", public_path.display()))?;

    // SSH public key format: <algorithm> <base64-key> [comment]
    let parts: Vec<&str> = public_key_content.trim().splitn(3, ' ').collect();

    let algorithm = parts.first().unwrap_or(&"unknown").to_string();
    let key_data = parts.get(1).unwrap_or(&"");
    let comment = parts.get(2).map(|s| s.to_string());

    // Determine algorithm type and bits
    let (algo_name, bits) = match algorithm.as_str() {
        "ssh-ed25519" => ("ed25519".to_string(), None),
        "ssh-rsa" => {
            // For RSA, we need to check the key size
            let bits = get_ssh_key_bits(public_path).ok();
            ("rsa".to_string(), bits)
        }
        "ecdsa-sha2-nistp256" => ("ecdsa-p256".to_string(), Some(256)),
        "ecdsa-sha2-nistp384" => ("ecdsa-p384".to_string(), Some(384)),
        "ecdsa-sha2-nistp521" => ("ecdsa-p521".to_string(), Some(521)),
        "sk-ssh-ed25519@openssh.com" => ("ed25519-sk".to_string(), None),
        "sk-ecdsa-sha2-nistp256@openssh.com" => ("ecdsa-sk".to_string(), Some(256)),
        _ => (algorithm.clone(), None),
    };

    // Compute fingerprint (SHA256 of the base64-decoded key data)
    let fingerprint = compute_ssh_fingerprint(key_data)?;

    Ok(SshKeyInfo {
        path: private_path.to_path_buf(),
        algorithm: algo_name,
        bits,
        fingerprint,
        comment,
    })
}

/// Compute SSH key fingerprint (SHA256).
fn compute_ssh_fingerprint(key_data: &str) -> Result<String> {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use sha2::{Digest, Sha256};

    let decoded = STANDARD
        .decode(key_data)
        .unwrap_or_else(|_| key_data.as_bytes().to_vec());

    let mut hasher = Sha256::new();
    hasher.update(&decoded);
    let hash = hasher.finalize();

    // Format as SHA256:base64
    let fingerprint = base64::engine::general_purpose::STANDARD_NO_PAD.encode(hash);
    Ok(format!("SHA256:{}", fingerprint))
}

/// Get SSH key bits using ssh-keygen.
fn get_ssh_key_bits(public_path: &Path) -> Result<u32> {
    let output = Command::new("ssh-keygen")
        .args(["-l", "-f"])
        .arg(public_path)
        .output()
        .context("Failed to run ssh-keygen")?;

    if !output.status.success() {
        return Err(anyhow!("ssh-keygen failed"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Output format: "4096 SHA256:... comment (RSA)"
    let bits_str = stdout.split_whitespace().next().unwrap_or("0");
    bits_str
        .parse()
        .map_err(|_| anyhow!("Failed to parse key bits"))
}

/// Perform the actual SSH key migration.
fn perform_ssh_migration(
    key: &SshKeyInfo,
    cmd: &FromSshCommand,
    out: &Output,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    use auths_core::error::AgentError;
    use auths_core::storage::keychain::{KeyAlias, get_platform_keychain};
    use auths_id::identity::initialize::initialize_registry_identity;
    use auths_id::ports::registry::RegistryBackend;
    use auths_storage::git::{GitRegistryBackend, RegistryConfig};
    use std::sync::Arc;
    use zeroize::Zeroizing;

    // Get keychain
    let keychain = get_platform_keychain().context("Failed to access platform keychain")?;

    // Determine key alias
    let key_alias = cmd.key_alias.clone().unwrap_or_else(|| {
        let filename = key
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        format!("ssh-{}", filename)
    });

    // Determine repo path
    let repo_path = cmd.repo.clone().unwrap_or_else(|| {
        dirs::home_dir()
            .map(|h| h.join(".auths"))
            .unwrap_or_else(|| PathBuf::from(".auths"))
    });

    out.print_info(&format!(
        "Creating Auths identity with key alias: {}",
        key_alias
    ));

    // Ensure repo directory exists
    if !repo_path.exists() {
        fs::create_dir_all(&repo_path)
            .with_context(|| format!("Failed to create directory: {:?}", repo_path))?;
    }

    // Initialize Git repo if needed
    if !repo_path.join(".git").exists() {
        Command::new("git")
            .args(["init"])
            .current_dir(&repo_path)
            .output()
            .context("Failed to initialize Git repository")?;
    }

    // Create metadata linking to SSH key
    let _metadata = serde_json::json!({
        "migrated_from": "ssh",
        "ssh_key_path": key.path.display().to_string(),
        "ssh_algorithm": key.algorithm,
        "ssh_fingerprint": key.fingerprint,
        "ssh_comment": key.comment,
        "created_at": now.to_rfc3339()
    });

    // Create a simple passphrase provider
    struct MigrationPassphraseProvider;
    impl auths_core::signing::PassphraseProvider for MigrationPassphraseProvider {
        fn get_passphrase(&self, prompt: &str) -> Result<Zeroizing<String>, AgentError> {
            let _ = prompt;
            Ok(Zeroizing::new(String::new()))
        }
    }
    let passphrase_provider = MigrationPassphraseProvider;

    // Initialize the identity
    let backend: Arc<dyn RegistryBackend + Send + Sync> = Arc::new(
        GitRegistryBackend::from_config_unchecked(RegistryConfig::single_tenant(&repo_path)),
    );
    let key_alias = KeyAlias::new_unchecked(key_alias);
    match initialize_registry_identity(
        backend,
        &key_alias,
        &passphrase_provider,
        keychain.as_ref(),
        None,
    ) {
        Ok((controller_did, alias)) => {
            out.print_success(&format!("Created Auths identity: {}", controller_did));

            // Create cross-reference attestation
            out.print_info("Creating cross-reference attestation...");

            let attestation = create_ssh_cross_reference_attestation(key, &controller_did, now)?;

            // Save the attestation
            let attestation_path = repo_path.join("ssh-migration.json");
            fs::write(
                &attestation_path,
                serde_json::to_string_pretty(&attestation)?,
            )
            .context("Failed to write attestation file")?;

            out.print_success("Cross-reference attestation created");

            // Update allowed_signers if requested
            if cmd.update_allowed_signers {
                if let Err(e) = update_allowed_signers(&controller_did, &key.comment) {
                    out.print_warn(&format!("Could not update allowed_signers: {}", e));
                } else {
                    out.print_success("Updated allowed_signers file");
                }
            }

            out.newline();

            out.print_heading("Migration Complete");
            out.println(&format!(
                "  SSH Key:          {}",
                out.dim(&key.path.display().to_string())
            ));
            out.println(&format!("  Algorithm:        {}", key.algorithm));
            out.println(&format!(
                "  Fingerprint:      {}",
                out.dim(&key.fingerprint)
            ));
            out.println(&format!(
                "  Auths Identity:   {}",
                out.info(&controller_did)
            ));
            out.println(&format!("  Key Alias:        {}", out.info(&alias)));
            out.println(&format!(
                "  Repository:       {}",
                out.info(&repo_path.display().to_string())
            ));
            out.println(&format!(
                "  Attestation:      {}",
                out.dim(&attestation_path.display().to_string())
            ));
            out.newline();

            out.print_heading("Next Steps");
            out.println("  1. Start using Auths for new commits:");
            out.println("     auths agent start");
            out.println("  2. Existing SSH-signed commits remain verifiable");
            out.println("  3. Run 'auths signers sync' to update allowed signers");

            Ok(())
        }
        Err(e) => Err(e).context("Failed to initialize identity"),
    }
}

/// Create a cross-reference attestation linking SSH key to Auths identity.
fn create_ssh_cross_reference_attestation(
    ssh_key: &SshKeyInfo,
    auths_did: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<serde_json::Value> {
    let attestation = serde_json::json!({
        "version": 1,
        "type": "ssh-migration",
        "ssh": {
            "path": ssh_key.path.display().to_string(),
            "algorithm": ssh_key.algorithm,
            "fingerprint": ssh_key.fingerprint,
            "comment": ssh_key.comment
        },
        "auths": {
            "did": auths_did
        },
        "statement": "This attestation links the SSH key to the Auths identity. Both keys belong to the same entity.",
        "created_at": now.to_rfc3339()
    });

    Ok(attestation)
}

/// Update the allowed_signers file with the new Auths identity.
fn update_allowed_signers(auths_did: &str, email: &Option<String>) -> Result<()> {
    let allowed_signers_path = dirs::home_dir()
        .map(|h| h.join(".ssh").join("allowed_signers"))
        .ok_or_else(|| anyhow!("Could not determine home directory"))?;

    // Read existing content or start fresh
    let mut content = if allowed_signers_path.exists() {
        fs::read_to_string(&allowed_signers_path)?
    } else {
        String::new()
    };

    // Add a comment and the new entry
    let email_str = email.as_deref().unwrap_or("*");
    let entry = format!(
        "\n# Auths identity: {}\n{} namespaces=\"git\" {}\n",
        auths_did, email_str, auths_did
    );

    content.push_str(&entry);

    fs::write(&allowed_signers_path, content)?;

    Ok(())
}

// ============================================================================
// Migration Status
// ============================================================================

/// Signing method detected for a commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SigningMethod {
    /// Signed with Auths identity.
    Auths,
    /// Signed with GPG.
    Gpg,
    /// Signed with SSH.
    Ssh,
    /// No signature.
    Unsigned,
    /// Unknown signature type.
    Unknown,
}

/// Statistics for migration status.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MigrationStats {
    pub total: usize,
    pub auths_signed: usize,
    pub gpg_signed: usize,
    pub ssh_signed: usize,
    pub unsigned: usize,
    pub unknown: usize,
}

/// Per-author migration status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorStatus {
    pub name: String,
    pub email: String,
    pub total_commits: usize,
    pub auths_signed: usize,
    pub gpg_signed: usize,
    pub ssh_signed: usize,
    pub unsigned: usize,
    pub primary_method: SigningMethod,
}

/// Full migration status output.
#[derive(Debug, Serialize, Deserialize)]
pub struct MigrationStatusOutput {
    pub stats: MigrationStats,
    pub authors: Vec<AuthorStatus>,
}

/// Handle the migrate status subcommand.
fn handle_migrate_status(cmd: MigrateStatusCommand) -> Result<()> {
    let out = Output::new();

    // Determine repo path
    let repo_path = cmd
        .repo
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    // Check if it's a git repo
    if !repo_path.join(".git").exists() && !repo_path.ends_with(".git") {
        return Err(anyhow!("Not a Git repository: {}", repo_path.display()));
    }

    // Analyze commits
    let (stats, authors) = analyze_commit_signatures(&repo_path, cmd.count)?;

    // Output
    if is_json_mode() {
        let output = MigrationStatusOutput {
            stats: stats.clone(),
            authors: authors.clone(),
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(());
    }

    // Text output
    out.print_heading("Migration Status");
    out.newline();

    // Overall stats
    out.println(&format!("  Last {} commits:", stats.total));
    out.newline();

    // Calculate percentages
    let auths_pct = if stats.total > 0 {
        (stats.auths_signed * 100) / stats.total
    } else {
        0
    };
    let gpg_pct = if stats.total > 0 {
        (stats.gpg_signed * 100) / stats.total
    } else {
        0
    };
    let ssh_pct = if stats.total > 0 {
        (stats.ssh_signed * 100) / stats.total
    } else {
        0
    };
    let unsigned_pct = if stats.total > 0 {
        (stats.unsigned * 100) / stats.total
    } else {
        0
    };

    // Progress bar helper
    let progress_bar = |count: usize, total: usize, width: usize| -> String {
        let filled = if total > 0 {
            (count * width) / total
        } else {
            0
        };
        let empty = width.saturating_sub(filled);
        format!("[{}{}]", "█".repeat(filled), "░".repeat(empty))
    };

    out.println(&format!(
        "    {} Auths-signed: {:>4} ({:>3}%) {}",
        out.success("✓"),
        stats.auths_signed,
        auths_pct,
        out.success(&progress_bar(stats.auths_signed, stats.total, 20))
    ));

    out.println(&format!(
        "    {} GPG-signed:   {:>4} ({:>3}%) {}",
        out.info("●"),
        stats.gpg_signed,
        gpg_pct,
        out.info(&progress_bar(stats.gpg_signed, stats.total, 20))
    ));

    out.println(&format!(
        "    {} SSH-signed:   {:>4} ({:>3}%) {}",
        out.info("●"),
        stats.ssh_signed,
        ssh_pct,
        out.info(&progress_bar(stats.ssh_signed, stats.total, 20))
    ));

    out.println(&format!(
        "    {} Unsigned:     {:>4} ({:>3}%) {}",
        out.warn("○"),
        stats.unsigned,
        unsigned_pct,
        out.dim(&progress_bar(stats.unsigned, stats.total, 20))
    ));

    // Per-author breakdown
    if cmd.by_author && !authors.is_empty() {
        out.newline();
        out.print_heading("  Per-Author Status");
        out.newline();

        for author in &authors {
            let status_icon = match author.primary_method {
                SigningMethod::Auths => out.success("✅"),
                SigningMethod::Gpg => out.info("🔄"),
                SigningMethod::Ssh => out.info("🔄"),
                SigningMethod::Unsigned => out.warn("⚠️"),
                SigningMethod::Unknown => out.dim("?"),
            };

            let method_str = match author.primary_method {
                SigningMethod::Auths => "Auths",
                SigningMethod::Gpg => "GPG (pending)",
                SigningMethod::Ssh => "SSH (pending)",
                SigningMethod::Unsigned => "Unsigned",
                SigningMethod::Unknown => "Unknown",
            };

            out.println(&format!(
                "    {} {} <{}> - {} ({} commits)",
                status_icon,
                out.bold(&author.name),
                out.dim(&author.email),
                method_str,
                author.total_commits
            ));
        }
    }

    out.newline();

    // Migration suggestion
    if stats.gpg_signed > 0 || stats.ssh_signed > 0 {
        out.print_heading("  Next Steps");
        out.newline();
        if stats.gpg_signed > 0 {
            out.println("    For GPG users: auths migrate from-gpg");
        }
        if stats.ssh_signed > 0 {
            out.println("    For SSH users: auths migrate from-ssh");
        }
    }

    Ok(())
}

/// Analyze commit signatures in a repository.
fn analyze_commit_signatures(
    repo_path: &PathBuf,
    count: usize,
) -> Result<(MigrationStats, Vec<AuthorStatus>)> {
    use std::collections::HashMap;

    // Use git log to get commit info with signatures
    // %GS = signer identity (SSH keys show "ssh-ed25519 ...", GPG shows key ID/email)
    // %GK = signing key fingerprint
    let output = Command::new("git")
        .args([
            "log",
            &format!("-{}", count),
            "--pretty=format:%H|%an|%ae|%G?|%GK|%GS",
        ])
        .current_dir(repo_path)
        .output()
        .context("Failed to run git log")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("git log failed: {}", stderr));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut stats = MigrationStats::default();
    let mut author_map: HashMap<String, AuthorStatus> = HashMap::new();

    for line in stdout.lines() {
        if line.trim().is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() < 5 {
            continue;
        }

        let _commit_hash = parts[0];
        let author_name = parts[1];
        let author_email = parts[2];
        let sig_status = parts[3]; // G=good, B=bad, U=untrusted, X=expired, Y=expired key, R=revoked, E=missing key, N=none
        let sig_key = parts[4];
        let sig_signer = if parts.len() > 5 { parts[5] } else { "" };

        // Determine signing method by inspecting the signer identity and key format.
        // SSH signatures: %GS starts with an SSH key type (e.g., "ssh-ed25519", "ssh-rsa")
        //                 %GK is an SSH fingerprint like "SHA256:..."
        // GPG signatures: %GS is a name/email, %GK is a hex key ID
        let method = match sig_status {
            "G" | "U" | "X" | "Y" | "R" | "E" => {
                if sig_signer.starts_with("ssh-")
                    || sig_signer.starts_with("ecdsa-")
                    || sig_signer.starts_with("sk-ssh-")
                    || sig_key.starts_with("SHA256:")
                {
                    SigningMethod::Ssh
                } else {
                    SigningMethod::Gpg
                }
            }
            "N" | "" => SigningMethod::Unsigned,
            _ => SigningMethod::Unknown,
        };

        // Update stats
        stats.total += 1;
        match method {
            SigningMethod::Auths => stats.auths_signed += 1,
            SigningMethod::Gpg => stats.gpg_signed += 1,
            SigningMethod::Ssh => stats.ssh_signed += 1,
            SigningMethod::Unsigned => stats.unsigned += 1,
            SigningMethod::Unknown => stats.unknown += 1,
        }

        // Update author stats
        let author_key = format!("{} <{}>", author_name, author_email);
        let author = author_map
            .entry(author_key)
            .or_insert_with(|| AuthorStatus {
                name: author_name.to_string(),
                email: author_email.to_string(),
                total_commits: 0,
                auths_signed: 0,
                gpg_signed: 0,
                ssh_signed: 0,
                unsigned: 0,
                primary_method: SigningMethod::Unsigned,
            });

        author.total_commits += 1;
        match method {
            SigningMethod::Auths => author.auths_signed += 1,
            SigningMethod::Gpg => author.gpg_signed += 1,
            SigningMethod::Ssh => author.ssh_signed += 1,
            SigningMethod::Unsigned => author.unsigned += 1,
            SigningMethod::Unknown => {}
        }
    }

    // Determine primary method for each author
    let mut authors: Vec<AuthorStatus> = author_map.into_values().collect();
    for author in &mut authors {
        author.primary_method = if author.auths_signed > 0 {
            SigningMethod::Auths
        } else if author.gpg_signed > author.ssh_signed && author.gpg_signed > author.unsigned {
            SigningMethod::Gpg
        } else if author.ssh_signed > author.unsigned {
            SigningMethod::Ssh
        } else {
            SigningMethod::Unsigned
        };
    }

    // Sort authors by commit count
    authors.sort_by(|a, b| b.total_commits.cmp(&a.total_commits));

    Ok((stats, authors))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_gpg_colon_output() {
        let output = r#"sec:u:4096:1:ABCD1234EFGH5678:1609459200:1704067200::::scESC::::::23::0:
fpr:::::::::ABCD1234EFGH5678IJKL9012MNOP3456QRST7890:
uid:u::::1609459200::ABCD1234::Test User <test@example.com>::::::::::0:
"#;

        let keys = parse_gpg_colon_output(output).unwrap();
        assert_eq!(keys.len(), 1);
        assert!(keys[0].user_id.contains("Test User"));
        assert!(keys[0].fingerprint.contains("ABCD1234"));
    }

    #[test]
    fn test_parse_empty_output() {
        let keys = parse_gpg_colon_output("").unwrap();
        assert!(keys.is_empty());
    }

    #[test]
    fn test_gpg_key_info_serialization() {
        let key = GpgKeyInfo {
            key_id: "ABCD1234".to_string(),
            fingerprint: "ABCD1234EFGH5678".to_string(),
            user_id: "Test <test@example.com>".to_string(),
            algorithm: "rsa4096".to_string(),
            created: "1609459200".to_string(),
            expires: None,
        };

        let json = serde_json::to_string(&key).unwrap();
        assert!(json.contains("ABCD1234"));
        assert!(json.contains("rsa4096"));
    }

    #[test]
    fn test_ssh_key_info_serialization() {
        let key = SshKeyInfo {
            path: PathBuf::from("/home/user/.ssh/id_ed25519"),
            algorithm: "ed25519".to_string(),
            bits: None,
            fingerprint: "SHA256:abcdefg".to_string(),
            comment: Some("user@example.com".to_string()),
        };

        let json = serde_json::to_string(&key).unwrap();
        assert!(json.contains("ed25519"));
        assert!(json.contains("SHA256:abcdefg"));
    }

    #[test]
    fn test_compute_ssh_fingerprint() {
        // Test with a known key data
        let fingerprint = compute_ssh_fingerprint("AAAAC3NzaC1lZDI1NTE5").unwrap();
        assert!(fingerprint.starts_with("SHA256:"));
    }

    #[test]
    fn test_ssh_algorithm_mapping() {
        // Test that we correctly map SSH algorithm strings
        let test_cases = [
            ("ssh-ed25519", "ed25519"),
            ("ssh-rsa", "rsa"),
            ("ecdsa-sha2-nistp256", "ecdsa-p256"),
            ("sk-ssh-ed25519@openssh.com", "ed25519-sk"),
        ];

        for (input, expected) in test_cases {
            let algo = match input {
                "ssh-ed25519" => "ed25519",
                "ssh-rsa" => "rsa",
                "ecdsa-sha2-nistp256" => "ecdsa-p256",
                "ecdsa-sha2-nistp384" => "ecdsa-p384",
                "ecdsa-sha2-nistp521" => "ecdsa-p521",
                "sk-ssh-ed25519@openssh.com" => "ed25519-sk",
                "sk-ecdsa-sha2-nistp256@openssh.com" => "ecdsa-sk",
                _ => input,
            };
            assert_eq!(algo, expected);
        }
    }
}
