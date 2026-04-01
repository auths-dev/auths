//! CI domain types shared across all CI workflows.

use std::path::PathBuf;

/// CI platform environment.
///
/// Usage:
/// ```ignore
/// let env = CiEnvironment::GitHubActions;
/// ```
#[derive(Debug, Clone)]
pub enum CiEnvironment {
    /// GitHub Actions CI environment.
    GitHubActions,
    /// GitLab CI/CD environment.
    GitLabCi,
    /// A custom CI platform with a user-provided name.
    Custom {
        /// The name of the custom CI platform.
        name: String,
    },
    /// The CI platform could not be detected.
    Unknown,
}

/// Configuration for CI/ephemeral identity.
///
/// The keychain and passphrase are passed separately to [`crate::domains::identity::service::initialize`] —
/// this struct carries only the CI-specific configuration values.
///
/// Args:
/// * `ci_environment`: The detected or specified CI platform.
/// * `registry_path`: Path to the ephemeral auths registry.
///
/// Usage:
/// ```ignore
/// let config = CiIdentityConfig {
///     ci_environment: CiEnvironment::GitHubActions,
///     registry_path: PathBuf::from("/tmp/.auths"),
/// };
/// ```
#[derive(Debug, Clone)]
pub struct CiIdentityConfig {
    /// The detected or specified CI platform.
    pub ci_environment: CiEnvironment,
    /// Path to the ephemeral auths registry directory.
    pub registry_path: PathBuf,
}
