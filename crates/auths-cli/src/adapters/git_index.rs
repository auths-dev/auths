use std::path::{Path, PathBuf};

use auths_sdk::ports::git::{IndexError, RepoIndex};

/// System adapter for staging paths into a repository index.
///
/// Runs `git add -- <path>` / `git ls-files --error-unmatch -- <path>` via
/// `std::process::Command`, rooted at the repository working directory.
///
/// Usage:
/// ```ignore
/// let index = SystemRepoIndex::at(repo_root.clone());
/// index.stage(&repo_root.join(".auths/roots"))?;
/// ```
pub struct SystemRepoIndex {
    working_dir: PathBuf,
}

impl SystemRepoIndex {
    /// Creates an index adapter rooted at the given repository.
    ///
    /// Args:
    /// * `working_dir`: Path to the git repository to operate in.
    pub fn at(working_dir: PathBuf) -> Self {
        Self { working_dir }
    }
}

impl RepoIndex for SystemRepoIndex {
    fn stage(&self, path: &Path) -> Result<(), IndexError> {
        let path_str = path.to_string_lossy().to_string();
        let output = crate::subprocess::git_command(&["add", "--", &path_str])
            .current_dir(&self.working_dir)
            .output()
            .map_err(|e| IndexError::Stage {
                path: path_str.clone(),
                message: e.to_string(),
            })?;

        if output.status.success() {
            return Ok(());
        }
        Err(IndexError::Stage {
            path: path_str,
            message: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }

    fn is_tracked(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy().to_string();
        crate::subprocess::git_command(&["ls-files", "--error-unmatch", "--", &path_str])
            .current_dir(&self.working_dir)
            .output()
            .map(|out| out.status.success())
            .unwrap_or(false)
    }
}
