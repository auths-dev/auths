//! CI domain types shared across all CI workflows.

use std::fmt;
use std::path::PathBuf;

/// Default passphrase used to encrypt the file-backed CI key when `AUTHS_PASSPHRASE`
/// is not set in the environment.
///
/// CI identities are ephemeral and low-value, so this default keeps the documented
/// quickstart copy-paste runnable. Production pipelines should export their own
/// `AUTHS_PASSPHRASE` (a managed secret) before running `auths init --profile ci`.
pub const DEFAULT_CI_PASSPHRASE: &str = "Ci-ephemeral-pass1!";

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
/// The signing keychain is passed separately to [`crate::domains::identity::service::initialize`];
/// this struct carries the CI-specific configuration values, including the file-backed
/// key location and the passphrase needed to reconstruct it in a later `auths sign` process.
///
/// Args:
/// * `ci_environment`: The detected or specified CI platform.
/// * `registry_path`: Path to the ephemeral auths registry.
/// * `keychain_file`: Path to the encrypted file holding the CI signing key.
/// * `passphrase`: Passphrase encrypting the file-backed key (echoed into the env block).
///
/// Usage:
/// ```ignore
/// let config = CiIdentityConfig {
///     ci_environment: CiEnvironment::GitHubActions,
///     registry_path: PathBuf::from("/tmp/.auths-ci"),
///     keychain_file: PathBuf::from("/tmp/.auths-ci/keys.enc"),
///     passphrase: "ci-secret".to_string(),
/// };
/// ```
#[derive(Clone)]
pub struct CiIdentityConfig {
    /// The detected or specified CI platform.
    pub ci_environment: CiEnvironment,
    /// Path to the ephemeral auths registry directory.
    pub registry_path: PathBuf,
    /// Path to the encrypted file-backed keychain holding the CI signing key.
    pub keychain_file: PathBuf,
    /// Passphrase that encrypts the file-backed CI key. Echoed into the generated
    /// env block so the follow-up `auths sign` can decrypt the key headlessly.
    pub passphrase: String,
}

impl fmt::Debug for CiIdentityConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CiIdentityConfig")
            .field("ci_environment", &self.ci_environment)
            .field("registry_path", &self.registry_path)
            .field("keychain_file", &self.keychain_file)
            .field("passphrase", &"[REDACTED]")
            .finish()
    }
}
