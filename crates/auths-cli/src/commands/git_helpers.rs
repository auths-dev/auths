use anyhow::{Context, Result, anyhow};

use crate::subprocess::{git_command, git_silent};

/// Resolve a git ref to a full commit SHA.
///
/// Args:
/// * `commit_ref`: A git ref (branch name, tag, SHA, HEAD, etc.).
///
/// Usage:
/// ```ignore
/// let sha = resolve_commit_sha("HEAD")?;
/// let sha = resolve_commit_sha("v1.0.0")?;
/// ```
pub fn resolve_commit_sha(commit_ref: &str) -> Result<String> {
    let output = git_command(&["rev-parse", commit_ref])
        .output()
        .context("Failed to resolve commit reference")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let lower = stderr.to_lowercase();

        if lower.contains("unknown revision") || lower.contains("bad revision") {
            let hint = if commit_ref.contains('~') || commit_ref.contains('^') {
                "This repository may not have enough commits. \
                 Try `git log --oneline` to see available history."
            } else {
                "Verify the ref exists with `git branch -a` or `git tag -l`."
            };
            return Err(anyhow!(
                "Cannot resolve '{}': {}\n\nHint: {}",
                commit_ref,
                stderr.trim(),
                hint
            ));
        }

        return Err(anyhow!(
            "Invalid commit reference '{}': {}",
            commit_ref,
            stderr.trim()
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Silently attempt to resolve HEAD to a full commit SHA.
///
/// Returns `None` if not in a git repo, no commits exist, or git is unavailable.
///
/// Usage:
/// ```ignore
/// let sha = resolve_head_silent(); // Some("abc123...") or None
/// ```
pub fn resolve_head_silent() -> Option<String> {
    git_silent(&["rev-parse", "--verify", "--quiet", "HEAD"])
}
