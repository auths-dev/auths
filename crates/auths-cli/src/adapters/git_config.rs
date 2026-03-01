use std::path::PathBuf;

use auths_sdk::ports::git_config::{GitConfigError, GitConfigProvider};

/// System adapter for git signing configuration.
///
/// Runs `git config <scope> <key> <value>` via `std::process::Command`.
/// Construct with `SystemGitConfigProvider::global()` or
/// `SystemGitConfigProvider::local(repo_path)`.
///
/// Usage:
/// ```ignore
/// let provider = SystemGitConfigProvider::global();
/// provider.set("gpg.format", "ssh")?;
/// ```
pub struct SystemGitConfigProvider {
    scope_flag: &'static str,
    working_dir: Option<PathBuf>,
}

impl SystemGitConfigProvider {
    /// Creates a provider that sets git config in global scope.
    pub fn global() -> Self {
        Self {
            scope_flag: "--global",
            working_dir: None,
        }
    }

    /// Creates a provider that sets git config in local scope for the given repo.
    ///
    /// Args:
    /// * `repo_path`: Path to the git repository to configure.
    pub fn local(repo_path: PathBuf) -> Self {
        Self {
            scope_flag: "--local",
            working_dir: Some(repo_path),
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
