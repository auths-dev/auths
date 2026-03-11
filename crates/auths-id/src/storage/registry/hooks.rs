//! Git hooks for cache invalidation.
//!
//! Installs Git hooks (post-merge, post-checkout, post-rewrite) in the auths
//! repository that touch a `.stale` sentinel file. This triggers cache
//! invalidation on the next read operation.

#[cfg(not(windows))]
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use thiserror::Error;

/// Errors that can occur during hook installation.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HookError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Not a Git repository: {0}")]
    NotGitRepo(String),
}

impl auths_core::error::AuthsErrorInfo for HookError {
    fn error_code(&self) -> &'static str {
        match self {
            Self::Io(_) => "AUTHS-E4991",
            Self::NotGitRepo(_) => "AUTHS-E4992",
        }
    }

    fn suggestion(&self) -> Option<&'static str> {
        match self {
            Self::Io(_) => Some("Check file permissions on the Git hooks directory"),
            Self::NotGitRepo(_) => Some("Ensure the path points to a valid Git repository"),
        }
    }
}

/// Hook types that invalidate the cache.
#[cfg(not(windows))]
const CACHE_HOOKS: &[&str] = &["post-merge", "post-checkout", "post-rewrite"];

/// Marker comment to identify the linearity enforcement hook.
#[cfg(not(windows))]
const LINEARITY_MARKER: &str = "# auths-linearity-enforcement";

/// Marker comment to identify our hooks.
#[cfg(not(windows))]
const HOOK_MARKER: &str = "# auths-cache-invalidation";

/// The shell script snippet that touches the sentinel file.
#[cfg(not(windows))]
fn cache_invalidation_snippet(cache_dir: &Path) -> String {
    let sentinel = cache_dir.join(".stale");
    format!(
        r#"
{HOOK_MARKER}
# Touch sentinel file to invalidate cache on next read
touch "{}" 2>/dev/null || true
"#,
        sentinel.display()
    )
}

/// Install cache invalidation hooks in a Git repository.
///
/// Appends to existing hooks (doesn't overwrite user scripts).
/// Skips gracefully on Windows (hooks are optional for cache).
///
/// # Arguments
/// * `repo_path` - Path to the Git repository (e.g., `~/.auths`)
/// * `cache_dir` - Path to the cache directory (e.g., `~/.auths/.cache`)
pub fn install_cache_hooks(_repo_path: &Path, _cache_dir: &Path) -> Result<(), HookError> {
    #[cfg(windows)]
    {
        return Ok(());
    }

    #[cfg(not(windows))]
    {
        let git_dir = find_git_dir(_repo_path)?;
        let hooks_dir = git_dir.join("hooks");

        if !hooks_dir.exists() {
            fs::create_dir_all(&hooks_dir)?;
        }

        let snippet = cache_invalidation_snippet(_cache_dir);

        for hook_name in CACHE_HOOKS {
            install_hook(&hooks_dir, hook_name, &snippet)?;
        }

        Ok(())
    }
}

/// Install a single hook, appending to existing content.
#[cfg(not(windows))]
fn install_hook(hooks_dir: &Path, hook_name: &str, snippet: &str) -> Result<(), HookError> {
    let hook_path = hooks_dir.join(hook_name);

    let existing_content = if hook_path.exists() {
        fs::read_to_string(&hook_path)?
    } else {
        String::new()
    };

    // Skip if already installed
    if existing_content.contains(HOOK_MARKER) {
        return Ok(());
    }

    // Build new content
    let new_content = if existing_content.is_empty() {
        // New hook - add shebang
        format!("#!/bin/sh\n{}", snippet)
    } else if existing_content.starts_with("#!") {
        // Append to existing hook
        format!("{}\n{}", existing_content.trim_end(), snippet)
    } else {
        // Existing content without shebang - add one
        format!("#!/bin/sh\n{}\n{}", existing_content.trim_end(), snippet)
    };

    fs::write(&hook_path, new_content)?;

    // Make executable
    let mut perms = fs::metadata(&hook_path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&hook_path, perms)?;

    Ok(())
}

/// Find the .git directory for a repository.
#[cfg(not(windows))]
fn find_git_dir(repo_path: &Path) -> Result<std::path::PathBuf, HookError> {
    // Check for .git directory
    let git_dir = repo_path.join(".git");
    if git_dir.is_dir() {
        return Ok(git_dir);
    }

    // Check if .git is a file (worktree or submodule)
    if git_dir.is_file()
        && let Ok(content) = fs::read_to_string(&git_dir)
        && let Some(path) = content.strip_prefix("gitdir: ")
    {
        let linked_path = std::path::PathBuf::from(path.trim());
        if linked_path.is_absolute() {
            return Ok(linked_path);
        } else {
            return Ok(repo_path.join(linked_path));
        }
    }

    // Check if we're inside a git directory (bare repo)
    if repo_path.join("HEAD").exists() && repo_path.join("config").exists() {
        return Ok(repo_path.to_path_buf());
    }

    Err(HookError::NotGitRepo(repo_path.display().to_string()))
}

/// Uninstall cache invalidation hooks from a Git repository.
///
/// Removes our snippet from hooks but preserves other user content.
pub fn uninstall_cache_hooks(_repo_path: &Path) -> Result<(), HookError> {
    #[cfg(windows)]
    {
        return Ok(());
    }

    #[cfg(not(windows))]
    {
        let git_dir = find_git_dir(_repo_path)?;
        let hooks_dir = git_dir.join("hooks");

        for hook_name in CACHE_HOOKS {
            let hook_path = hooks_dir.join(hook_name);
            if hook_path.exists() {
                let content = fs::read_to_string(&hook_path)?;

                // Find and remove our snippet by filtering lines
                if content.contains(HOOK_MARKER) {
                    let mut in_our_snippet = false;
                    let mut kept_lines: Vec<&str> = Vec::new();

                    for line in content.lines() {
                        if line.contains(HOOK_MARKER) {
                            in_our_snippet = true;
                            continue;
                        }
                        if in_our_snippet {
                            // Our snippet ends after the touch command
                            if line.trim().starts_with("touch") && line.contains(".stale") {
                                in_our_snippet = false;
                                continue;
                            }
                            // Skip comment lines that are part of our snippet
                            if line.starts_with("# Touch sentinel") {
                                continue;
                            }
                        }
                        kept_lines.push(line);
                    }

                    let new_content = kept_lines.join("\n");

                    // If only shebang left, remove the hook
                    let trimmed = new_content.trim();
                    if trimmed.is_empty() || trimmed == "#!/bin/sh" || trimmed == "#!/bin/bash" {
                        fs::remove_file(&hook_path)?;
                    } else {
                        fs::write(&hook_path, format!("{}\n", new_content))?;
                    }
                }
            }
        }

        Ok(())
    }
}

/// The pre-receive hook script that rejects non-fast-forward pushes and ref
/// deletions for Auths identity ref namespaces.
#[cfg(not(windows))]
const LINEARITY_HOOK_SCRIPT: &str = r#"#!/bin/sh
# auths-linearity-enforcement
# Reject non-fast-forward pushes and ref deletions for Auths identity refs.
# Installed automatically by auths — do not edit the marked section.

ZERO="0000000000000000000000000000000000000000"

auths_reject() {
    echo "*** REJECTED: $1" >&2
    echo "***" >&2
    echo "*** Auths identity refs are append-only. Force pushes and" >&2
    echo "*** ref deletions are prohibited to maintain KEL integrity." >&2
    echo "***" >&2
    exit 1
}

auths_is_protected_ref() {
    case "$1" in
        refs/keri/*|refs/auths/*|refs/did/keri/*|refs/auths/*)
            return 0
            ;;
    esac
    return 1
}

while read oldrev newrev refname; do
    if ! auths_is_protected_ref "$refname"; then
        continue
    fi
    if [ "$oldrev" = "$ZERO" ]; then
        continue
    fi
    if [ "$newrev" = "$ZERO" ]; then
        auths_reject "Deleting protected ref '$refname' is not allowed."
    fi
    if ! git merge-base --is-ancestor "$oldrev" "$newrev" 2>/dev/null; then
        auths_reject "Non-fast-forward push to '$refname' is not allowed."
    fi
done

exit 0
"#;

/// Install the linearity enforcement pre-receive hook in a Git repository.
///
/// This hook rejects non-fast-forward pushes and ref deletions for protected
/// Auths ref namespaces (`refs/keri/`, `refs/auths/`, `refs/did/keri/`,
/// `refs/auths/`). It prevents Git-level KEL rewrites that would bypass the
/// Rust registry's application-level checks.
///
/// For bare repos that already have a pre-receive hook, this appends rather
/// than overwrites. Idempotent — safe to call multiple times.
///
/// # Arguments
/// * `repo_path` - Path to the Git repository (e.g., `~/.auths`)
pub fn install_linearity_hook(_repo_path: &Path) -> Result<(), HookError> {
    #[cfg(windows)]
    {
        return Ok(());
    }

    #[cfg(not(windows))]
    {
        let git_dir = find_git_dir(_repo_path)?;
        let hooks_dir = git_dir.join("hooks");

        if !hooks_dir.exists() {
            fs::create_dir_all(&hooks_dir)?;
        }

        let hook_path = hooks_dir.join("pre-receive");

        let existing_content = if hook_path.exists() {
            fs::read_to_string(&hook_path)?
        } else {
            String::new()
        };

        // Skip if already installed
        if existing_content.contains(LINEARITY_MARKER) {
            return Ok(());
        }

        // The script includes its own shebang, so if the file is empty we
        // write it directly. If there's an existing hook, append our logic.
        let new_content = if existing_content.is_empty() {
            LINEARITY_HOOK_SCRIPT.to_string()
        } else {
            // Strip our shebang line — the existing file already has one.
            let without_shebang = LINEARITY_HOOK_SCRIPT
                .strip_prefix("#!/bin/sh\n")
                .unwrap_or(LINEARITY_HOOK_SCRIPT);
            format!("{}\n{}", existing_content.trim_end(), without_shebang)
        };

        fs::write(&hook_path, new_content)?;

        #[cfg(unix)]
        {
            let mut perms = fs::metadata(&hook_path)?.permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&hook_path, perms)?;
        }

        Ok(())
    }
}

/// Uninstall the linearity enforcement hook from a Git repository.
///
/// Removes the auths linearity section from the pre-receive hook while
/// preserving any other content.
pub fn uninstall_linearity_hook(_repo_path: &Path) -> Result<(), HookError> {
    #[cfg(windows)]
    {
        return Ok(());
    }

    #[cfg(not(windows))]
    {
        let git_dir = find_git_dir(_repo_path)?;
        let hook_path = git_dir.join("hooks").join("pre-receive");

        if !hook_path.exists() {
            return Ok(());
        }

        let content = fs::read_to_string(&hook_path)?;
        if !content.contains(LINEARITY_MARKER) {
            return Ok(());
        }

        // Remove everything from the marker to "exit 0" (inclusive)
        let mut kept_lines: Vec<&str> = Vec::new();
        let mut in_our_section = false;

        for line in content.lines() {
            if line.contains(LINEARITY_MARKER) {
                in_our_section = true;
                continue;
            }
            if in_our_section {
                if line.trim() == "exit 0" {
                    in_our_section = false;
                    continue;
                }
                continue;
            }
            kept_lines.push(line);
        }

        let new_content = kept_lines.join("\n");
        let trimmed = new_content.trim();

        if trimmed.is_empty() || trimmed == "#!/bin/sh" || trimmed == "#!/bin/bash" {
            fs::remove_file(&hook_path)?;
        } else {
            fs::write(&hook_path, format!("{}\n", new_content))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_install_new_hooks() {
        let temp = TempDir::new().unwrap();
        let repo_path = temp.path();
        let git_dir = repo_path.join(".git");
        fs::create_dir(&git_dir).unwrap();

        let cache_dir = repo_path.join(".cache");
        fs::create_dir(&cache_dir).unwrap();

        install_cache_hooks(repo_path, &cache_dir).unwrap();

        // Check hooks were created
        let hooks_dir = git_dir.join("hooks");
        for hook_name in CACHE_HOOKS {
            let hook_path = hooks_dir.join(hook_name);
            assert!(hook_path.exists(), "Hook {} should exist", hook_name);

            let content = fs::read_to_string(&hook_path).unwrap();
            assert!(content.contains("#!/bin/sh"));
            assert!(content.contains(HOOK_MARKER));
            assert!(content.contains(".stale"));
        }
    }

    #[test]
    fn test_install_appends_to_existing() {
        let temp = TempDir::new().unwrap();
        let repo_path = temp.path();
        let git_dir = repo_path.join(".git");
        let hooks_dir = git_dir.join("hooks");
        fs::create_dir_all(&hooks_dir).unwrap();

        // Create existing hook
        let existing_content = "#!/bin/bash\necho 'existing hook'\n";
        fs::write(hooks_dir.join("post-merge"), existing_content).unwrap();

        let cache_dir = repo_path.join(".cache");
        install_cache_hooks(repo_path, &cache_dir).unwrap();

        let content = fs::read_to_string(hooks_dir.join("post-merge")).unwrap();
        assert!(
            content.contains("existing hook"),
            "Should preserve existing content"
        );
        assert!(content.contains(HOOK_MARKER), "Should add our marker");
    }

    #[test]
    fn test_install_idempotent() {
        let temp = TempDir::new().unwrap();
        let repo_path = temp.path();
        let git_dir = repo_path.join(".git");
        fs::create_dir(&git_dir).unwrap();

        let cache_dir = repo_path.join(".cache");

        // Install twice
        install_cache_hooks(repo_path, &cache_dir).unwrap();
        install_cache_hooks(repo_path, &cache_dir).unwrap();

        // Should only have one marker
        let content = fs::read_to_string(git_dir.join("hooks").join("post-merge")).unwrap();
        let marker_count = content.matches(HOOK_MARKER).count();
        assert_eq!(marker_count, 1, "Should have exactly one marker");
    }

    #[test]
    fn test_uninstall_hooks() {
        let temp = TempDir::new().unwrap();
        let repo_path = temp.path();
        let git_dir = repo_path.join(".git");
        fs::create_dir(&git_dir).unwrap();

        let cache_dir = repo_path.join(".cache");

        // Install then uninstall
        install_cache_hooks(repo_path, &cache_dir).unwrap();
        uninstall_cache_hooks(repo_path).unwrap();

        // Hooks should be removed (since they only had our content)
        let hooks_dir = git_dir.join("hooks");
        for hook_name in CACHE_HOOKS {
            let hook_path = hooks_dir.join(hook_name);
            assert!(!hook_path.exists(), "Hook {} should be removed", hook_name);
        }
    }

    // --- Linearity hook tests ---

    #[test]
    fn test_install_linearity_hook_new() {
        let temp = TempDir::new().unwrap();
        let repo_path = temp.path();
        let git_dir = repo_path.join(".git");
        fs::create_dir(&git_dir).unwrap();

        install_linearity_hook(repo_path).unwrap();

        let hook_path = git_dir.join("hooks").join("pre-receive");
        assert!(hook_path.exists(), "pre-receive hook should exist");

        let content = fs::read_to_string(&hook_path).unwrap();
        assert!(content.contains("#!/bin/sh"));
        assert!(content.contains(LINEARITY_MARKER));
        assert!(content.contains("auths_is_protected_ref"));
        assert!(content.contains("merge-base --is-ancestor"));
    }

    #[test]
    fn test_install_linearity_hook_idempotent() {
        let temp = TempDir::new().unwrap();
        let repo_path = temp.path();
        let git_dir = repo_path.join(".git");
        fs::create_dir(&git_dir).unwrap();

        install_linearity_hook(repo_path).unwrap();
        install_linearity_hook(repo_path).unwrap();

        let content = fs::read_to_string(git_dir.join("hooks").join("pre-receive")).unwrap();
        let marker_count = content.matches(LINEARITY_MARKER).count();
        assert_eq!(marker_count, 1, "Should have exactly one marker");
    }

    #[test]
    fn test_install_linearity_hook_appends_to_existing() {
        let temp = TempDir::new().unwrap();
        let repo_path = temp.path();
        let git_dir = repo_path.join(".git");
        let hooks_dir = git_dir.join("hooks");
        fs::create_dir_all(&hooks_dir).unwrap();

        let existing = "#!/bin/bash\necho 'existing pre-receive'\n";
        fs::write(hooks_dir.join("pre-receive"), existing).unwrap();

        install_linearity_hook(repo_path).unwrap();

        let content = fs::read_to_string(hooks_dir.join("pre-receive")).unwrap();
        assert!(content.contains("existing pre-receive"));
        assert!(content.contains(LINEARITY_MARKER));
        // Should not have a duplicate shebang
        assert_eq!(content.matches("#!/bin/").count(), 1);
    }

    #[test]
    fn test_uninstall_linearity_hook() {
        let temp = TempDir::new().unwrap();
        let repo_path = temp.path();
        let git_dir = repo_path.join(".git");
        fs::create_dir(&git_dir).unwrap();

        install_linearity_hook(repo_path).unwrap();
        uninstall_linearity_hook(repo_path).unwrap();

        let hook_path = git_dir.join("hooks").join("pre-receive");
        assert!(!hook_path.exists(), "pre-receive should be removed");
    }

    #[test]
    fn test_uninstall_linearity_hook_preserves_other_content() {
        let temp = TempDir::new().unwrap();
        let repo_path = temp.path();
        let git_dir = repo_path.join(".git");
        let hooks_dir = git_dir.join("hooks");
        fs::create_dir_all(&hooks_dir).unwrap();

        let existing = "#!/bin/bash\necho 'keep me'\n";
        fs::write(hooks_dir.join("pre-receive"), existing).unwrap();

        install_linearity_hook(repo_path).unwrap();
        uninstall_linearity_hook(repo_path).unwrap();

        let hook_path = hooks_dir.join("pre-receive");
        assert!(hook_path.exists(), "pre-receive should still exist");
        let content = fs::read_to_string(&hook_path).unwrap();
        assert!(content.contains("keep me"));
        assert!(!content.contains(LINEARITY_MARKER));
    }
}
