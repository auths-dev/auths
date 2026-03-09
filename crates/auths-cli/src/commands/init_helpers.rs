use anyhow::{Context, Result, anyhow};
use clap_complete::Shell;
use dialoguer::MultiSelect;
use std::path::{Path, PathBuf};
use std::process::Command;

use auths_sdk::workflows::allowed_signers::AllowedSigners;
use auths_storage::git::RegistryAttestationStorage;

use crate::ux::format::Output;

pub(crate) const MIN_GIT_VERSION: (u32, u32, u32) = (2, 34, 0);

pub(crate) fn get_auths_repo_path() -> Result<PathBuf> {
    auths_core::paths::auths_home().map_err(|e| anyhow!(e))
}

pub(crate) fn check_git_version(out: &Output) -> Result<()> {
    let output = Command::new("git")
        .arg("--version")
        .output()
        .context("Failed to run git --version")?;

    if !output.status.success() {
        return Err(anyhow!("Git is not installed or not in PATH"));
    }

    let version_str = String::from_utf8_lossy(&output.stdout);
    let version = parse_git_version(&version_str)?;

    if version < MIN_GIT_VERSION {
        return Err(anyhow!(
            "Git version {}.{}.{} found, but {}.{}.{} or higher is required for SSH signing",
            version.0,
            version.1,
            version.2,
            MIN_GIT_VERSION.0,
            MIN_GIT_VERSION.1,
            MIN_GIT_VERSION.2
        ));
    }

    out.println(&format!(
        "  Git: {}.{}.{} (OK)",
        version.0, version.1, version.2
    ));
    Ok(())
}

pub(crate) fn parse_git_version(version_str: &str) -> Result<(u32, u32, u32)> {
    let parts: Vec<&str> = version_str.split_whitespace().collect();
    let version_part = parts
        .iter()
        .find(|s| s.chars().next().is_some_and(|c| c.is_ascii_digit()))
        .ok_or_else(|| anyhow!("Could not parse Git version from: {}", version_str))?;

    let numbers: Vec<u32> = version_part
        .split('.')
        .take(3)
        .filter_map(|s| {
            s.chars()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>()
                .parse()
                .ok()
        })
        .collect();

    match numbers.as_slice() {
        [major, minor, patch, ..] => Ok((*major, *minor, *patch)),
        [major, minor] => Ok((*major, *minor, 0)),
        [major] => Ok((*major, 0, 0)),
        _ => Err(anyhow!("Could not parse Git version: {}", version_str)),
    }
}

pub(crate) fn detect_ci_environment() -> Option<String> {
    if std::env::var("GITHUB_ACTIONS").is_ok() {
        Some("GitHub Actions".to_string())
    } else if std::env::var("GITLAB_CI").is_ok() {
        Some("GitLab CI".to_string())
    } else if std::env::var("CIRCLECI").is_ok() {
        Some("CircleCI".to_string())
    } else if std::env::var("JENKINS_URL").is_ok() {
        Some("Jenkins".to_string())
    } else if std::env::var("TRAVIS").is_ok() {
        Some("Travis CI".to_string())
    } else if std::env::var("BUILDKITE").is_ok() {
        Some("Buildkite".to_string())
    } else if std::env::var("CI").is_ok() {
        Some("Generic CI".to_string())
    } else {
        None
    }
}

pub(crate) fn write_allowed_signers(key_alias: &str, out: &Output) -> Result<()> {
    let _ = key_alias;

    let repo_path = get_auths_repo_path()?;
    let storage = RegistryAttestationStorage::new(&repo_path);

    let home = dirs::home_dir().ok_or_else(|| anyhow!("Could not determine home directory"))?;
    let ssh_dir = home.join(".ssh");
    std::fs::create_dir_all(&ssh_dir)?;
    let signers_path = ssh_dir.join("allowed_signers");

    let mut signers = AllowedSigners::load(&signers_path)
        .unwrap_or_else(|_| AllowedSigners::new(&signers_path));
    let report = signers
        .sync(&storage)
        .map_err(|e| anyhow!("Failed to sync allowed signers: {}", e))?;
    signers
        .save()
        .map_err(|e| anyhow!("Failed to write allowed signers: {}", e))?;

    let signers_str = signers_path
        .to_str()
        .ok_or_else(|| anyhow!("allowed signers path is not valid UTF-8"))?;
    set_git_config("gpg.ssh.allowedSignersFile", signers_str, "--global")?;

    out.println(&format!(
        "  Wrote {} allowed signer(s) to {}",
        report.added,
        signers_path.display()
    ));
    out.println(&format!(
        "  Set gpg.ssh.allowedSignersFile = {}",
        signers_path.display()
    ));

    Ok(())
}

fn set_git_config(key: &str, value: &str, scope: &str) -> Result<()> {
    let status = Command::new("git")
        .args(["config", scope, key, value])
        .status()
        .with_context(|| format!("Failed to run git config {scope} {key} {value}"))?;

    if !status.success() {
        return Err(anyhow!("Failed to set git config {key} = {value}"));
    }
    Ok(())
}

// --- Agent Capability Helpers ---

#[derive(Debug, Clone)]
pub(crate) struct AgentCapability {
    pub name: String,
    pub description: String,
}

impl AgentCapability {
    pub fn new(name: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
        }
    }
}

pub(crate) fn get_available_capabilities() -> Vec<AgentCapability> {
    vec![
        AgentCapability::new("sign_commit", "Sign Git commits"),
        AgentCapability::new("sign_release", "Sign releases and tags"),
        AgentCapability::new("manage_members", "Manage organization members"),
        AgentCapability::new("rotate_keys", "Rotate identity keys"),
    ]
}

pub(crate) fn select_agent_capabilities(
    interactive: bool,
    out: &Output,
) -> Result<Vec<AgentCapability>> {
    let available = get_available_capabilities();

    if !interactive {
        out.println("  Using default capability: sign_commit");
        return Ok(vec![available[0].clone()]);
    }

    let items: Vec<String> = available
        .iter()
        .map(|c| format!("{} - {}", c.name, c.description))
        .collect();

    let defaults = vec![true, false, false, false];

    let selections = MultiSelect::new()
        .with_prompt("Select capabilities for this agent (space to toggle, enter to confirm)")
        .items(&items)
        .defaults(&defaults)
        .interact()?;

    if selections.is_empty() {
        out.print_warn("No capabilities selected, defaulting to sign_commit");
        return Ok(vec![available[0].clone()]);
    }

    Ok(selections.iter().map(|&i| available[i].clone()).collect())
}

// --- Shell Completion Helpers ---

pub(crate) fn detect_shell() -> Option<Shell> {
    std::env::var("SHELL").ok().and_then(|shell_path| {
        if shell_path.contains("zsh") {
            Some(Shell::Zsh)
        } else if shell_path.contains("bash") {
            Some(Shell::Bash)
        } else if shell_path.contains("fish") {
            Some(Shell::Fish)
        } else {
            None
        }
    })
}

pub(crate) fn get_completion_path(shell: Shell) -> Option<PathBuf> {
    let home = dirs::home_dir()?;

    match shell {
        Shell::Zsh => {
            let omz_path = home.join(".oh-my-zsh/completions");
            if omz_path.exists() {
                return Some(omz_path.join("_auths"));
            }
            Some(home.join(".zfunc/_auths"))
        }
        Shell::Bash => dirs::data_local_dir().map(|d| d.join("bash-completion/completions/auths")),
        Shell::Fish => dirs::config_dir().map(|d| d.join("fish/completions/auths.fish")),
        _ => None,
    }
}

pub(crate) fn offer_shell_completions(interactive: bool, out: &Output) -> Result<()> {
    let shell = match detect_shell() {
        Some(s) => s,
        None => return Ok(()),
    };

    let path = match get_completion_path(shell) {
        Some(p) => p,
        None => return Ok(()),
    };

    if path.exists() {
        return Ok(());
    }

    if !interactive {
        if path.parent().is_some_and(|p| p.exists()) {
            if let Err(e) = install_shell_completions(shell, &path) {
                out.print_warn(&format!("Could not install completions: {}", e));
            } else {
                out.print_success(&format!("Installed {} completions", shell));
            }
        }
        return Ok(());
    }

    out.newline();
    let install = dialoguer::Confirm::new()
        .with_prompt(format!(
            "Install {} completions to {}?",
            shell,
            path.display()
        ))
        .default(true)
        .interact()?;

    if install {
        match install_shell_completions(shell, &path) {
            Ok(()) => {
                out.print_success(&format!("Installed {} completions", shell));
                out.println(&format!(
                    "  Restart your shell or run: source {}",
                    path.display()
                ));
            }
            Err(e) => {
                out.print_warn(&format!("Could not install completions: {}", e));
            }
        }
    }

    Ok(())
}

fn install_shell_completions(shell: Shell, path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {:?}", parent))?;
    }

    let shell_name = match shell {
        Shell::Bash => "bash",
        Shell::Zsh => "zsh",
        Shell::Fish => "fish",
        _ => return Err(anyhow!("Unsupported shell: {:?}", shell)),
    };

    let output = Command::new("auths")
        .args(["completions", shell_name])
        .output()
        .context("Failed to run auths completions")?;

    if !output.status.success() {
        return Err(anyhow!(
            "auths completions failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    std::fs::write(path, &output.stdout)
        .with_context(|| format!("Failed to write completions to {:?}", path))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_git_version() {
        assert_eq!(parse_git_version("git version 2.39.0").unwrap(), (2, 39, 0));
        assert_eq!(parse_git_version("git version 2.34.1").unwrap(), (2, 34, 1));
        assert_eq!(
            parse_git_version("git version 2.39.0.windows.1").unwrap(),
            (2, 39, 0)
        );
        assert_eq!(parse_git_version("git version 2.30").unwrap(), (2, 30, 0));
    }

    #[test]
    fn test_min_git_version() {
        assert!(MIN_GIT_VERSION <= (2, 34, 0));
        assert!(MIN_GIT_VERSION <= (2, 39, 0));
        assert!(MIN_GIT_VERSION > (2, 33, 0));
    }

    #[test]
    fn test_detect_ci_environment_none() {
        let result = detect_ci_environment();
        let _ = result;
    }

    #[test]
    fn test_get_available_capabilities() {
        let caps = get_available_capabilities();
        assert_eq!(caps.len(), 4);
        assert_eq!(caps[0].name, "sign_commit");
        assert_eq!(caps[1].name, "sign_release");
        assert_eq!(caps[2].name, "manage_members");
        assert_eq!(caps[3].name, "rotate_keys");
    }

    #[test]
    fn test_agent_capability() {
        let cap = AgentCapability::new("test_cap", "Test capability");
        assert_eq!(cap.name, "test_cap");
        assert_eq!(cap.description, "Test capability");
    }

    #[test]
    fn test_detect_shell() {
        let _ = detect_shell();
    }

    #[test]
    fn test_get_completion_path_zsh() {
        let path = get_completion_path(Shell::Zsh);
        assert!(path.is_some());
        let p = path.unwrap();
        assert!(p.ends_with("_auths"));
    }

    #[test]
    fn test_get_completion_path_bash() {
        let path = get_completion_path(Shell::Bash);
        assert!(path.is_some());
        let p = path.unwrap();
        assert!(p.ends_with("auths"));
    }

    #[test]
    fn test_get_completion_path_fish() {
        let path = get_completion_path(Shell::Fish);
        assert!(path.is_some());
        let p = path.unwrap();
        assert!(p.ends_with("auths.fish"));
    }
}
