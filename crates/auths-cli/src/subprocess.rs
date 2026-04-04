//! Subprocess helpers — standardized command builders for external tools.
//!
//! All git subprocess calls should use [`git_command`] to ensure locale
//! normalization (`LC_ALL=C`), which prevents non-English error messages
//! from breaking stderr pattern matching.

use std::path::Path;
use std::process::{Command, Output};

use anyhow::{Context, Result, anyhow};

/// Build a `git` command with `LC_ALL=C` pre-set.
///
/// Callers can chain additional configuration (`.current_dir()`, `.stdin()`, etc.)
/// before calling `.output()` or `.status()`.
///
/// Args:
/// * `args`: Arguments to pass to git.
///
/// Usage:
/// ```ignore
/// let output = git_command(&["rev-parse", "HEAD"]).output()?;
/// let output = git_command(&["log", "--oneline"]).current_dir(&repo).output()?;
/// ```
pub fn git_command(args: &[&str]) -> Command {
    let mut cmd = Command::new("git");
    cmd.args(args).env("LC_ALL", "C");
    cmd
}

/// Run a git command and return its stdout as a trimmed string.
///
/// Returns an error with stderr context if the command fails.
///
/// Args:
/// * `args`: Arguments to pass to git.
///
/// Usage:
/// ```ignore
/// let sha = git_stdout(&["rev-parse", "HEAD"])?;
/// ```
pub fn git_stdout(args: &[&str]) -> Result<String> {
    let output = git_command(args)
        .output()
        .with_context(|| format!("Failed to run: git {}", args.join(" ")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("git {} failed: {}", args.join(" "), stderr.trim()));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Run a git command in a specific directory and return stdout as a trimmed string.
///
/// Args:
/// * `args`: Arguments to pass to git.
/// * `dir`: Working directory for the git command.
///
/// Usage:
/// ```ignore
/// let log = git_stdout_in(&["log", "--oneline", "-1"], &repo_path)?;
/// ```
pub fn git_stdout_in(args: &[&str], dir: &Path) -> Result<String> {
    let output = git_command(args)
        .current_dir(dir)
        .output()
        .with_context(|| format!("Failed to run: git {}", args.join(" ")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("git {} failed: {}", args.join(" "), stderr.trim()));
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Run a git command, returning stdout on success or `None` on failure.
///
/// Use for optional checks where failure is not an error condition.
///
/// Args:
/// * `args`: Arguments to pass to git.
///
/// Usage:
/// ```ignore
/// if let Some(sha) = git_silent(&["rev-parse", "--verify", "HEAD"]) { ... }
/// ```
pub fn git_silent(args: &[&str]) -> Option<String> {
    git_command(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Run a git command and return the raw [`Output`].
///
/// Always sets `LC_ALL=C`. Use when you need to inspect both stdout and stderr,
/// or when the caller has custom status-checking logic.
///
/// Args:
/// * `args`: Arguments to pass to git.
///
/// Usage:
/// ```ignore
/// let output = git_output(&["rev-list", "HEAD~5..HEAD"])?;
/// if !output.status.success() { /* custom handling */ }
/// ```
pub fn git_output(args: &[&str]) -> Result<Output> {
    git_command(args)
        .output()
        .with_context(|| format!("Failed to run: git {}", args.join(" ")))
}
