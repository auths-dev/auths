use anyhow::{Context, Result, anyhow};
use std::process::Command;

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
    let output = Command::new("git")
        .args(["rev-parse", commit_ref])
        .output()
        .context("Failed to resolve commit reference")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
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
    Command::new("git")
        .args(["rev-parse", "--verify", "--quiet", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}
