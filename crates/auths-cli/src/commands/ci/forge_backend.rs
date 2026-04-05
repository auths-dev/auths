//! Forge backend implementations for setting CI secrets.

use anyhow::{Context, Result, anyhow};
use auths_sdk::domains::ci::forge::Forge;
use std::io::Write;
use std::process::{Command, Stdio};

/// Abstraction over forge-specific secret-setting operations.
///
/// Usage:
/// ```ignore
/// let backend = backend_for_forge(&forge);
/// backend.set_secret("AUTHS_CI_TOKEN", &token_json)?;
/// backend.print_ci_template();
/// ```
pub trait ForgeBackend {
    /// Set a CI secret/variable on the forge.
    fn set_secret(&self, name: &str, value: &str) -> Result<()>;

    /// Human-readable forge name.
    fn name(&self) -> &str;

    /// Print CI workflow template for this forge.
    fn print_ci_template(&self);
}

/// GitHub backend — sets secrets via `gh secret set`.
pub struct GitHubBackend {
    pub owner_repo: String,
}

impl ForgeBackend for GitHubBackend {
    fn set_secret(&self, name: &str, value: &str) -> Result<()> {
        // Check gh is available and authenticated (strip GH_TOKEN to avoid stale tokens)
        let auth_status = Command::new("gh")
            .args(["auth", "status"])
            .env_remove("GH_TOKEN")
            .env_remove("GITHUB_TOKEN")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("gh CLI not found — install it from https://cli.github.com")?;

        if !auth_status.success() {
            return Err(anyhow!(
                "gh CLI is not authenticated. Run `gh auth login` first."
            ));
        }

        let mut child = Command::new("gh")
            .args(["secret", "set", name, "--repo", &self.owner_repo])
            .env_remove("GH_TOKEN")
            .env_remove("GITHUB_TOKEN")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn gh secret set")?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(value.as_bytes())
                .context("Failed to write secret to gh stdin")?;
        }

        let output = child
            .wait_with_output()
            .context("Failed to wait for gh secret set")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow!("gh secret set failed: {}", stderr.trim()));
        }

        Ok(())
    }

    fn name(&self) -> &str {
        "GitHub"
    }

    fn print_ci_template(&self) {
        println!("Add to your release workflow:");
        println!();
        println!("  - uses: auths-dev/attest-action@v1");
        println!("    with:");
        println!("      token: ${{{{ secrets.AUTHS_CI_TOKEN }}}}");
        println!("      files: 'dist/*.tar.gz'");
    }
}

/// Fallback backend for unsupported forges — prints values for manual setup.
pub struct ManualBackend {
    pub forge_name: String,
}

impl ForgeBackend for ManualBackend {
    fn set_secret(&self, _name: &str, _value: &str) -> Result<()> {
        // No-op — values are printed by the caller on failure
        Ok(())
    }

    fn name(&self) -> &str {
        &self.forge_name
    }

    fn print_ci_template(&self) {
        println!("Set AUTHS_CI_TOKEN as a masked CI variable in your forge's settings.");
        println!("See https://docs.auths.dev/ci for forge-specific instructions.");
    }
}

/// Create the appropriate backend for a detected forge.
///
/// Args:
/// * `forge`: The detected forge variant.
///
/// Usage:
/// ```ignore
/// let backend = backend_for_forge(&forge);
/// ```
pub fn backend_for_forge(forge: &Forge) -> Box<dyn ForgeBackend> {
    match forge {
        Forge::GitHub { owner_repo } => Box::new(GitHubBackend {
            owner_repo: owner_repo.clone(),
        }),
        Forge::GitLab { .. } => Box::new(ManualBackend {
            forge_name: "GitLab".into(),
        }),
        Forge::Bitbucket { .. } => Box::new(ManualBackend {
            forge_name: "Bitbucket".into(),
        }),
        Forge::Radicle { .. } => Box::new(ManualBackend {
            forge_name: "Radicle".into(),
        }),
        Forge::Unknown { .. } => Box::new(ManualBackend {
            forge_name: "Unknown".into(),
        }),
    }
}
