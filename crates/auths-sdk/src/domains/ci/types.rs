//! CI domain types shared across all CI workflows.

use std::fmt;
use std::path::PathBuf;

use ring::rand::{SecureRandom, SystemRandom};

/// Generate a strong, random, per-identity passphrase for encrypting a CI identity's file-backed key
/// when `AUTHS_PASSPHRASE` is not supplied.
///
/// Each CI identity gets its own secret, so obtaining one CI identity's encrypted key reveals nothing
/// about another's — unlike the former shared constant, which was public in the source tree. The value
/// is echoed once into the generated env block (see [`CiIdentityConfig`]) so the follow-up `auths sign`
/// can decrypt the key headlessly within the same job.
///
/// Usage:
/// ```ignore
/// let passphrase = generate_ci_passphrase();
/// ```
pub fn generate_ci_passphrase() -> String {
    let rng = SystemRandom::new();
    let mut bytes = [0u8; 24];
    #[allow(clippy::expect_used)]
    // INVARIANT: OS CSPRNG (ring SystemRandom) failure is unrecoverable, like a poisoned mutex.
    rng.fill(&mut bytes).expect("system CSPRNG unavailable");
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ci_passphrase_is_unique_per_call() {
        // a per-identity secret: two CI inits must not share a passphrase
        assert_ne!(generate_ci_passphrase(), generate_ci_passphrase());
    }

    #[test]
    fn ci_passphrase_is_strong() {
        let p = generate_ci_passphrase();
        assert!(p.len() >= 32, "passphrase too short ({} chars)", p.len());
    }
}
