//! Signing domain types for platform verification and Git configuration.

use std::path::PathBuf;

/// How to verify a platform identity.
///
/// The CLI obtains tokens interactively (OAuth device flow, browser open).
/// The SDK accepts the resulting token — it never opens a browser.
///
/// Usage:
/// ```ignore
/// let platform = PlatformVerification::GitHub {
///     access_token: "ghp_abc123".into(),
/// };
/// ```
#[derive(Debug, Clone)]
pub enum PlatformVerification {
    /// Verify via GitHub using a personal access token.
    GitHub {
        /// The GitHub personal access token.
        access_token: String,
    },
    /// Verify via GitLab using a personal access token.
    GitLab {
        /// The GitLab personal access token.
        access_token: String,
    },
    /// Skip platform verification.
    Skip,
}

/// Whether and how to configure Git commit signing.
///
/// Usage:
/// ```ignore
/// let scope = GitSigningScope::Global;
/// ```
#[derive(Debug, Clone, Default)]
pub enum GitSigningScope {
    /// Configure signing for a specific repository only.
    Local {
        /// Path to the repository to configure.
        repo_path: PathBuf,
    },
    /// Configure signing globally for all repositories (default).
    #[default]
    Global,
    /// Do not configure git signing.
    Skip,
}

/// Outcome of a successful platform claim verification.
///
/// Usage:
/// ```ignore
/// let claim: PlatformClaimResult = sdk.platform_claim(platform).await?;
/// println!("Verified as {} on {}", claim.username, claim.platform);
/// ```
#[derive(Debug, Clone)]
pub struct PlatformClaimResult {
    /// The platform name (e.g. `"github"`).
    pub platform: String,
    /// The verified username on the platform.
    pub username: String,
    /// Optional URL to the public proof artifact (e.g. a GitHub gist).
    pub proof_url: Option<String>,
}
