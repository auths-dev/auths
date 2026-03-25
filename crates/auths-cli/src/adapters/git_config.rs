use capsec::SendCap;
use std::path::PathBuf;

use auths_sdk::ports::git_config::{GitConfigError, GitConfigProvider};

/// System adapter for git signing configuration.
///
/// Runs `git config <scope> <key> <value>` via `std::process::Command`.
/// Holds a `SendCap<Spawn>` to document subprocess execution.
///
/// Usage:
/// ```ignore
/// let cap_root = capsec::test_root();
/// let provider = SystemGitConfigProvider::global(cap_root.spawn().make_send());
/// provider.set("gpg.format", "ssh")?;
/// ```
pub struct SystemGitConfigProvider {
    scope_flag: &'static str,
    working_dir: Option<PathBuf>,
    _spawn_cap: SendCap<capsec::Spawn>,
}

impl SystemGitConfigProvider {
    /// Creates a provider that sets git config in global scope.
    ///
    /// Args:
    /// * `spawn_cap`: Capability token proving the caller has subprocess execution permission.
    pub fn global(spawn_cap: SendCap<capsec::Spawn>) -> Self {
        Self {
            scope_flag: "--global",
            working_dir: None,
            _spawn_cap: spawn_cap,
        }
    }

    /// Creates a provider that sets git config in local scope for the given repo.
    ///
    /// Args:
    /// * `repo_path`: Path to the git repository to configure.
    /// * `spawn_cap`: Capability token proving the caller has subprocess execution permission.
    pub fn local(repo_path: PathBuf, spawn_cap: SendCap<capsec::Spawn>) -> Self {
        Self {
            scope_flag: "--local",
            working_dir: Some(repo_path),
            _spawn_cap: spawn_cap,
        }
    }
}

impl GitConfigProvider for SystemGitConfigProvider {
    fn set(&self, key: &str, value: &str) -> Result<(), GitConfigError> {
        let mut cmd = std::process::Command::new("git");
        cmd.args(["config", self.scope_flag, key, value]);
        if let Some(dir) = &self.working_dir {
            cmd.current_dir(dir);
        }
        let status = cmd
            .status()
            .map_err(|e| GitConfigError::CommandFailed(format!("failed to run git config: {e}")))?;
        if !status.success() {
            return Err(GitConfigError::CommandFailed(format!(
                "git config {} = {} failed",
                key, value
            )));
        }
        Ok(())
    }
}
