#![allow(clippy::disallowed_types)]
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::context::AuthsContext;
use anyhow::{Context, Result, anyhow};
use auths_core::storage::keychain::KeyAlias;
use auths_crypto::CurveType;
use auths_keri::Capability;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Agent provisioning profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentProfile {
    /// CI runner profile.
    Ci,
    /// Interactive AI assistant profile.
    Assistant,
}

impl std::str::FromStr for AgentProfile {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "ci" => Ok(AgentProfile::Ci),
            "assistant" => Ok(AgentProfile::Assistant),
            _ => Err(anyhow!(
                "Invalid agent profile '{}': expected 'ci' or 'assistant'",
                s
            )),
        }
    }
}

/// Parameters for atomic agent provisioning.
#[derive(Debug, Clone)]
pub struct AgentProvisionParams {
    /// Human-readable label / key alias for the agent.
    pub label: String,
    /// Capabilities granted to the agent.
    pub scopes: Vec<Capability>,
    /// Optional expiration duration in seconds.
    pub expires_in_secs: Option<i64>,
    /// Destination directory for agent environment.
    pub destination_dir: PathBuf,
    /// Agent profile preset.
    pub profile: AgentProfile,
}

/// Output metadata from atomic agent provisioning.
#[derive(Debug, Serialize, Deserialize)]
pub struct AgentProvisionResult {
    /// Canonical DID of the provisioned agent.
    pub agent_did: String,
    /// Parent root identity key alias.
    pub parent_alias: String,
    /// Human-readable label alias.
    pub label: String,
    /// Destination workspace directory.
    pub destination_dir: PathBuf,
    /// Keychain path.
    pub keychain_path: PathBuf,
    /// Environment script path (`env.sh`).
    pub env_file_path: PathBuf,
    /// Executable wrapper script path (`bin/auths-agent`).
    pub wrapper_path: PathBuf,
    /// Optional expiration timestamp.
    pub expires_at: Option<DateTime<Utc>>,
}

/// Atomically provisions a delegated headless agent.
pub fn provision_agent_machine(
    ctx: &AuthsContext,
    parent_alias: &KeyAlias,
    params: &AgentProvisionParams,
    passphrase: &str,
    now: DateTime<Utc>,
    root_repo_path: &Path,
) -> Result<AgentProvisionResult> {
    let agent_alias = KeyAlias::new_unchecked(&params.label);
    let expires_at = params.expires_in_secs.map(|secs| now.timestamp() + secs);

    // 1. Delegate agent identity under parent root in KEL using domains::agents::add_scoped
    let agent_info_res = crate::domains::agents::add_scoped(
        ctx,
        parent_alias,
        &agent_alias,
        CurveType::P256,
        &params.scopes,
        expires_at,
    );

    if agent_info_res.is_err() {
        let next_alias = KeyAlias::new_unchecked(format!("{}--next-0", agent_alias.as_str()));
        let _ = ctx.key_storage.delete_key(&agent_alias);
        let _ = ctx.key_storage.delete_key(&next_alias);
    }

    let agent_info = agent_info_res
        .map_err(anyhow::Error::from)
        .context("failed to delegate agent identity in KEL")?;

    let agent_did = agent_info.agent_did;

    // Ensure destination directory exists with 0700 permissions
    fs::create_dir_all(&params.destination_dir)?;
    fs::set_permissions(&params.destination_dir, fs::Permissions::from_mode(0o700))?;

    // 2. Materialize agent machine registry in destination_dir/registry
    let registry_dir = params.destination_dir.join("registry");
    materialize_agent_machine_registry(root_repo_path, &registry_dir, &agent_did)?;

    // 3. Export key bundle (keys.enc) and passphrase (passphrase.txt)
    let keychain_path = params.destination_dir.join("keys.enc");
    let passphrase_path = params.destination_dir.join("passphrase.txt");
    fs::write(&passphrase_path, passphrase)?;
    fs::set_permissions(&passphrase_path, fs::Permissions::from_mode(0o600))?;

    // Copy keys from main keychain to agent file-backend keys.enc
    let export_res =
        export_agent_keys_to_file_backend(ctx, &agent_alias, passphrase, &keychain_path);

    // Clean up temporary staging keys from root key storage so root storage stays clean
    let next_alias = KeyAlias::new_unchecked(format!("{}--next-0", agent_alias.as_str()));
    let _ = ctx.key_storage.delete_key(&agent_alias);
    let _ = ctx.key_storage.delete_key(&next_alias);

    export_res?;

    // 4. Refresh commit-trailers
    let _ = crate::workflows::commit_hooks::refresh_commit_trailers(ctx, &params.destination_dir);

    // 5. Generate env.sh
    let env_file_path = generate_environment_script(
        &params.destination_dir,
        &registry_dir,
        &keychain_path,
        &passphrase_path,
        passphrase,
        &params.label,
    )?;

    // 6. Generate executable wrapper helper bin/auths-agent
    let wrapper_path =
        generate_executable_wrapper(&params.destination_dir, &env_file_path, &params.label)?;

    let expires_dt = expires_at.and_then(|ts| DateTime::from_timestamp(ts, 0));

    Ok(AgentProvisionResult {
        agent_did,
        parent_alias: parent_alias.to_string(),
        label: params.label.clone(),
        destination_dir: params.destination_dir.clone(),
        keychain_path,
        env_file_path,
        wrapper_path,
        expires_at: expires_dt,
    })
}

fn generate_environment_script(
    destination_dir: &Path,
    registry_dir: &Path,
    keychain_path: &Path,
    passphrase_path: &Path,
    passphrase: &str,
    label: &str,
) -> Result<PathBuf> {
    let env_file_path = destination_dir.join("env.sh");
    let env_script_content = format!(
        r#"# Auths Agent Environment Variables for '{label}' — Auto-generated
export AUTHS_AGENT_LABEL="{label}"
export AUTHS_HOME="{home}"
export AUTHS_REPO="{repo}"
export AUTHS_KEYCHAIN_BACKEND="file"
export AUTHS_KEYCHAIN_FILE="{keychain}"
export AUTHS_PASSPHRASE_FILE="{passphrase_file}"
export AUTHS_PASSPHRASE='{passphrase}'
export AUTHS_SIGNING_KEY="auths:{label}"

# Direct Git Native Signing Overrides (No file modifications to .git/config)
export GIT_CONFIG_COUNT=3
export GIT_CONFIG_KEY_0="gpg.format"
export GIT_CONFIG_VALUE_0="ssh"
export GIT_CONFIG_KEY_1="gpg.ssh.program"
export GIT_CONFIG_VALUE_1="auths-sign"
export GIT_CONFIG_KEY_2="user.signingkey"
export GIT_CONFIG_VALUE_2="auths:{label}"
"#,
        home = destination_dir.display(),
        repo = registry_dir.display(),
        keychain = keychain_path.display(),
        passphrase_file = passphrase_path.display(),
        passphrase = passphrase,
        label = label
    );
    fs::write(&env_file_path, &env_script_content)?;
    fs::set_permissions(&env_file_path, fs::Permissions::from_mode(0o600))?;
    Ok(env_file_path)
}

fn generate_executable_wrapper(
    destination_dir: &Path,
    env_file_path: &Path,
    label: &str,
) -> Result<PathBuf> {
    let bin_dir = destination_dir.join("bin");
    fs::create_dir_all(&bin_dir)?;
    let wrapper_path = bin_dir.join("auths-agent");
    let wrapper_content = format!(
        r#"#!/bin/sh
# Auths Agent Executable Wrapper Helper for '{label}'
set -e
source "{env_sh}"
exec auths "$@"
"#,
        label = label,
        env_sh = env_file_path.display()
    );
    fs::write(&wrapper_path, &wrapper_content)?;
    fs::set_permissions(&wrapper_path, fs::Permissions::from_mode(0o755))?;
    Ok(wrapper_path)
}

/// Materializes an isolated delegate-machine registry by copying org KEL and stripping root subtrees.
#[allow(clippy::disallowed_types)]
pub fn materialize_agent_machine_registry(
    root_repo: &Path,
    agent_registry: &Path,
    agent_did: &str,
) -> Result<()> {
    let agent_pfx = auths_verifier::IdentityDID::parse(agent_did)
        .map(|d| d.prefix().to_string())
        .unwrap_or_else(|_| agent_did.to_string());

    if agent_registry.exists() {
        fs::remove_dir_all(agent_registry)?;
    }

    copy_dir_clean(root_repo, agent_registry).context("failed to copy registry repository")?;

    let git_dir = agent_registry.join(".git");
    if git_dir.exists() {
        let gd = git_dir.to_string_lossy().to_string();
        let idx = git_dir.join("tmp-index");
        let idx_s = idx.to_string_lossy().to_string();

        let read_tree_status = Command::new("git")
            .args(["--git-dir", &gd, "read-tree", "refs/auths/registry"])
            .env("GIT_INDEX_FILE", &idx_s)
            .status()
            .context("failed to execute git read-tree")?;

        if !read_tree_status.success() {
            anyhow::bail!("git read-tree failed with status: {}", read_tree_status);
        }

        let listed = Command::new("git")
            .args(["--git-dir", &gd, "ls-files"])
            .env("GIT_INDEX_FILE", &idx_s)
            .output()
            .context("failed to execute git ls-files")?;

        if !listed.status.success() {
            anyhow::bail!("git ls-files failed with status: {}", listed.status);
        }

        let subtree = format!(
            "identities/{}/{}/{}/",
            &agent_pfx[0..2.min(agent_pfx.len())],
            &agent_pfx[2..4.min(agent_pfx.len())],
            agent_pfx
        );

        for line in String::from_utf8_lossy(&listed.stdout).lines() {
            if line.contains(&subtree) {
                let rm_status = Command::new("git")
                    .args(["--git-dir", &gd, "rm", "--cached", "-q", "--", line])
                    .env("GIT_INDEX_FILE", &idx_s)
                    .status()
                    .context("failed to execute git rm")?;

                if !rm_status.success() {
                    anyhow::bail!("git rm failed with status: {}", rm_status);
                }
            }
        }
    }

    Ok(())
}

/// Recursively copies a directory tree, skipping Unix domain sockets, FIFOs, and special IPC handles.
fn copy_dir_clean(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)
        .with_context(|| format!("failed to create directory {}", dst.display()))?;
    for entry_res in
        fs::read_dir(src).with_context(|| format!("failed to read directory {}", src.display()))?
    {
        let entry = entry_res?;
        let file_type = entry.file_type()?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::FileTypeExt;
            if file_type.is_socket() || file_type.is_fifo() {
                continue;
            }
        }

        let dst_path = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_clean(&entry.path(), &dst_path)?;
        } else if file_type.is_file() || file_type.is_symlink() {
            fs::copy(entry.path(), &dst_path)
                .with_context(|| format!("failed to copy file {}", entry.path().display()))?;
        }
    }
    Ok(())
}

fn export_agent_keys_to_file_backend(
    ctx: &AuthsContext,
    agent_alias: &KeyAlias,
    passphrase: &str,
    keychain_path: &Path,
) -> Result<()> {
    use auths_core::storage::encrypted_file::EncryptedFileStorage;
    use auths_core::storage::keychain::KeyStorage;
    use zeroize::Zeroizing;

    let file_storage = EncryptedFileStorage::with_path(keychain_path.to_path_buf())
        .map_err(anyhow::Error::from)?;
    file_storage.set_password(Zeroizing::new(passphrase.to_string()));

    if let Ok((did, role, data)) = ctx.key_storage.load_key(agent_alias) {
        file_storage
            .store_key(agent_alias, &did, role, &data)
            .map_err(anyhow::Error::from)?;
    }

    // Export next key alias if present
    let next_alias = KeyAlias::new_unchecked(format!("{}--next-0", agent_alias.as_str()));
    if let Ok((did, role, data)) = ctx.key_storage.load_key(&next_alias) {
        file_storage
            .store_key(&next_alias, &did, role, &data)
            .map_err(anyhow::Error::from)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_generate_environment_script() {
        let temp_dir = tempdir().unwrap();
        let dest_dir = temp_dir.path();
        let registry_dir = dest_dir.join("registry");
        let keychain_path = dest_dir.join("keys.enc");
        let passphrase_path = dest_dir.join("passphrase.txt");
        let passphrase = "test_passphrase123!";
        let label = "test-agent";

        let env_file = generate_environment_script(
            dest_dir,
            &registry_dir,
            &keychain_path,
            &passphrase_path,
            passphrase,
            label,
        )
        .unwrap();

        assert!(env_file.exists());
        let content = fs::read_to_string(&env_file).unwrap();
        assert!(content.contains(&format!("export AUTHS_AGENT_LABEL=\"{}\"", label)));
        assert!(content.contains(&format!("export AUTHS_PASSPHRASE='{}'", passphrase)));
        assert!(content.contains("export GIT_CONFIG_VALUE_1=\"auths-sign\""));
    }

    #[test]
    fn test_generate_executable_wrapper() {
        let temp_dir = tempdir().unwrap();
        let dest_dir = temp_dir.path();
        let env_file = dest_dir.join("env.sh");
        let label = "test-agent";

        let wrapper_file = generate_executable_wrapper(dest_dir, &env_file, label).unwrap();

        assert!(wrapper_file.exists());
        let content = fs::read_to_string(&wrapper_file).unwrap();
        assert!(content.contains(&format!("source \"{}\"", env_file.display())));
        assert!(content.contains("exec auths \"$@\""));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::metadata(&wrapper_file).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o755);
        }
    }
}
