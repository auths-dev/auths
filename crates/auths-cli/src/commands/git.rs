//! Git integration commands for Auths.

use anyhow::{Context, Result, bail};
use auths_sdk::workflows::allowed_signers::AllowedSigners;
use auths_storage::git::RegistryAttestationStorage;
use clap::{Parser, Subcommand};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::{fs, path::Path};

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
    /// Install Git hooks for automatic allowed_signers regeneration.
    #[command(name = "install-hooks")]
    InstallHooks(InstallHooksCommand),
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
pub fn handle_git(cmd: GitCommand, repo_override: Option<PathBuf>) -> Result<()> {
    match cmd.command {
        GitSubcommand::InstallHooks(subcmd) => handle_install_hooks(subcmd, repo_override),
    }
}

fn handle_install_hooks(
    cmd: InstallHooksCommand,
    auths_repo_override: Option<PathBuf>,
) -> Result<()> {
    let git_dir = find_git_dir(&cmd.repo)?;
    let hooks_dir = git_dir.join("hooks");

    if !hooks_dir.exists() {
        fs::create_dir_all(&hooks_dir)
            .with_context(|| format!("Failed to create hooks directory: {:?}", hooks_dir))?;
    }

    let post_merge_path = hooks_dir.join("post-merge");

    if post_merge_path.exists() && !cmd.force {
        let existing = fs::read_to_string(&post_merge_path)
            .with_context(|| format!("Failed to read existing hook: {:?}", post_merge_path))?;

        if existing.contains("auths git allowed-signers") || existing.contains("auths signers sync")
        {
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
                 auths signers sync --repo {} --output {}",
                post_merge_path,
                cmd.auths_repo.display(),
                cmd.allowed_signers_path.display()
            );
        }
    }

    let auths_repo = if let Some(override_path) = auths_repo_override {
        expand_tilde(&override_path)?
    } else {
        expand_tilde(&cmd.auths_repo)?
    };

    let hook_script = generate_post_merge_hook(&auths_repo, &cmd.allowed_signers_path);

    fs::write(&post_merge_path, &hook_script)
        .with_context(|| format!("Failed to write hook: {:?}", post_merge_path))?;

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

    if let Some(parent) = cmd.allowed_signers_path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {:?}", parent))?;
        println!("Created directory {:?}", parent);
    }

    println!("\nGenerating initial allowed_signers file...");
    let storage = RegistryAttestationStorage::new(&auths_repo);

    let mut signers = AllowedSigners::new(&cmd.allowed_signers_path);
    match signers.sync(&storage) {
        Ok(report) => {
            if let Err(e) = signers.save() {
                eprintln!("Warning: Could not write allowed_signers: {}", e);
            } else {
                println!(
                    "Wrote {} entries to {:?}",
                    report.added, cmd.allowed_signers_path
                );
            }
        }
        Err(e) => {
            eprintln!("Warning: Could not generate initial allowed_signers: {}", e);
            eprintln!("You may need to run 'auths signers sync' manually.");
        }
    }

    Ok(())
}

fn find_git_dir(repo_path: &Path) -> Result<PathBuf> {
    let repo_path = if repo_path.to_string_lossy() == "." {
        std::env::current_dir().context("Failed to get current directory")?
    } else {
        repo_path.to_path_buf()
    };

    let git_dir = repo_path.join(".git");
    if git_dir.is_dir() {
        return Ok(git_dir);
    }

    if git_dir.is_file() {
        let content = fs::read_to_string(&git_dir)
            .with_context(|| format!("Failed to read {:?}", git_dir))?;

        if let Some(path) = content.strip_prefix("gitdir: ") {
            let linked_path = PathBuf::from(path.trim());
            if linked_path.is_absolute() {
                return Ok(linked_path);
            } else {
                return Ok(repo_path.join(linked_path));
            }
        }
    }

    if repo_path.join("HEAD").exists() && repo_path.join("config").exists() {
        return Ok(repo_path);
    }

    bail!(
        "Not a git repository: {:?}\n\
         Could not find .git directory.",
        repo_path
    );
}

fn generate_post_merge_hook(auths_repo: &Path, allowed_signers_path: &Path) -> String {
    format!(
        r#"#!/bin/bash
# Auto-generated by auths git install-hooks
# Regenerates allowed_signers file after merge/pull

# Run auths to regenerate allowed_signers
auths signers sync --repo "{}" --output "{}"
"#,
        auths_repo.display(),
        allowed_signers_path.display()
    )
}

pub(crate) fn expand_tilde(path: &Path) -> Result<PathBuf> {
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
        handle_git(self.clone(), ctx.repo_path.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_expand_tilde() {
        let path = PathBuf::from("~/.auths");
        let result = expand_tilde(&path);
        assert!(result.is_ok());
        let expanded = result.unwrap();
        assert!(!expanded.to_string_lossy().contains("~"));
        assert!(expanded.ends_with(".auths"));
    }

    #[test]
    fn test_expand_tilde_bare() {
        let path = PathBuf::from("~");
        let result = expand_tilde(&path).unwrap();
        assert_eq!(result, dirs::home_dir().unwrap());
    }

    #[test]
    fn test_expand_tilde_absolute_path_unchanged() {
        let path = PathBuf::from("/tmp/auths");
        let result = expand_tilde(&path).unwrap();
        assert_eq!(result, PathBuf::from("/tmp/auths"));
    }

    #[test]
    fn test_expand_tilde_relative_path_unchanged() {
        let path = PathBuf::from("relative/path");
        let result = expand_tilde(&path).unwrap();
        assert_eq!(result, PathBuf::from("relative/path"));
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
        assert!(hook.contains("auths signers sync"));
        assert!(hook.contains("/home/user/.auths"));
        assert!(hook.contains(".auths/allowed_signers"));
    }
}
