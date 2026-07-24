use std::path::{Path, PathBuf};

use crate::config::EnvironmentConfig;

/// Unified paths resolution for the Auths environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthsPaths {
    /// Machine home directory (e.g. ~/.auths or ~/.auths-agents/<label>)
    pub home_dir: PathBuf,
    /// Registry repository directory (e.g. ~/.auths or ~/.auths-agents/<label>/registry)
    pub registry_dir: PathBuf,
    /// Encrypted file keystore path (e.g. ~/.auths/keys.enc)
    pub keychain_file: PathBuf,
    /// Key storage directory for Secure Enclave and software keys (e.g. <home_dir>/se_keys)
    pub keys_dir: PathBuf,
}

impl AuthsPaths {
    /// Resolves environment paths from an injected `EnvironmentConfig` and an optional CLI repo override.
    ///
    /// Priority rules:
    /// 1. Explicit CLI override (`repo_override`) if non-empty
    /// 2. `AUTHS_REPO` environment variable (`config.auths_repo`)
    /// 3. `AUTHS_HOME` environment variable (`config.auths_home`)
    /// 4. Platform default `$HOME/.auths`
    pub fn resolve_with_config(
        config: &EnvironmentConfig,
        repo_override: Option<&Path>,
    ) -> Result<Self, AuthsHomeError> {
        let home_dir = auths_home_with_config(config)?;

        let registry_dir = if let Some(repo) = repo_override {
            let s = repo.to_string_lossy();
            if s.trim().is_empty() {
                if let Some(ref r) = config.auths_repo {
                    r.clone()
                } else {
                    home_dir.clone()
                }
            } else {
                repo.to_path_buf()
            }
        } else if let Some(ref repo) = config.auths_repo {
            repo.clone()
        } else {
            home_dir.clone()
        };

        let keychain_file = home_dir.join("keys.enc");
        let keys_dir = home_dir.join("se_keys");

        Ok(Self {
            home_dir,
            registry_dir,
            keychain_file,
            keys_dir,
        })
    }

    /// Resolves environment paths using `EnvironmentConfig::from_env()`.
    pub fn resolve(repo_override: Option<&Path>) -> Result<Self, AuthsHomeError> {
        Self::resolve_with_config(&EnvironmentConfig::from_env(), repo_override)
    }
}

/// Resolves the Auths home directory from an injected `EnvironmentConfig`.
///
/// Uses `config.auths_home` when set; otherwise falls back to `~/.auths`.
/// Prefer this over `auths_home()` for new code — it keeps env-var reads at the
/// process boundary.
///
/// Args:
/// * `config` - The environment configuration to source the home path from.
///
/// Usage:
/// ```ignore
/// let env = auths_core::config::EnvironmentConfig::from_env();
/// let dir = auths_core::paths::auths_home_with_config(&env)?;
/// ```
#[allow(clippy::disallowed_methods)] // INVARIANT: designated home-dir resolution boundary — dirs::home_dir is the OS-level fallback
pub fn auths_home_with_config(config: &EnvironmentConfig) -> Result<PathBuf, AuthsHomeError> {
    if let Some(ref home) = config.auths_home {
        return Ok(home.clone());
    }
    let home = dirs::home_dir().ok_or(AuthsHomeError::NoHomeDir)?;
    Ok(home.join(".auths"))
}

/// Resolves the Auths home directory.
///
/// Reads `AUTHS_HOME` from the environment (via `EnvironmentConfig::from_env()`),
/// then falls back to `~/.auths`.
///
/// Prefer `auths_home_with_config` for new code.
///
/// Usage:
/// ```ignore
/// let dir = auths_core::paths::auths_home()?;
/// let keys = dir.join("keys.enc");
/// ```
pub fn auths_home() -> Result<PathBuf, AuthsHomeError> {
    auths_home_with_config(&EnvironmentConfig::from_env())
}

/// Error returned when the Auths home directory cannot be resolved.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuthsHomeError {
    /// The user's home directory could not be determined.
    #[error("Could not determine home directory")]
    NoHomeDir,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_home_overrides_default() {
        let env = EnvironmentConfig::builder()
            .auths_home(std::path::PathBuf::from("/tmp/custom-auths"))
            .build();
        assert_eq!(
            auths_home_with_config(&env).unwrap(),
            std::path::PathBuf::from("/tmp/custom-auths")
        );
    }

    #[test]
    fn no_override_falls_back_to_default() {
        let env = EnvironmentConfig::builder().build();
        let path = auths_home_with_config(&env).unwrap();
        assert!(path.ends_with(".auths"));
    }

    #[test]
    fn test_auths_paths_resolution_order() {
        let home_path = PathBuf::from("/tmp/custom-home");
        let repo_path = PathBuf::from("/tmp/custom-repo");
        let cli_override = PathBuf::from("/tmp/cli-override");

        // 1. Home alone
        let env = EnvironmentConfig::builder()
            .auths_home(home_path.clone())
            .build();
        let paths = AuthsPaths::resolve_with_config(&env, None).unwrap();
        assert_eq!(paths.home_dir, home_path);
        assert_eq!(paths.registry_dir, home_path);
        assert_eq!(paths.keychain_file, home_path.join("keys.enc"));
        assert_eq!(paths.keys_dir, home_path.join("se_keys"));

        // 2. Repo alone
        let env = EnvironmentConfig::builder()
            .auths_repo(repo_path.clone())
            .build();
        let paths = AuthsPaths::resolve_with_config(&env, None).unwrap();
        assert_eq!(paths.registry_dir, repo_path);

        // 3. Home + Repo simultaneously
        let env = EnvironmentConfig::builder()
            .auths_home(home_path.clone())
            .auths_repo(repo_path.clone())
            .build();
        let paths = AuthsPaths::resolve_with_config(&env, None).unwrap();
        assert_eq!(paths.home_dir, home_path);
        assert_eq!(paths.registry_dir, repo_path);

        // 4. CLI override takes precedence
        let paths = AuthsPaths::resolve_with_config(&env, Some(&cli_override)).unwrap();
        assert_eq!(paths.home_dir, home_path);
        assert_eq!(paths.registry_dir, cli_override);
    }

    #[test]
    fn test_auths_paths_whitespace_cli_override_ignored() {
        let home_path = PathBuf::from("/tmp/custom-home");
        let env = EnvironmentConfig::builder()
            .auths_home(home_path.clone())
            .build();
        let whitespace_path = PathBuf::from("   ");
        let paths = AuthsPaths::resolve_with_config(&env, Some(&whitespace_path)).unwrap();
        assert_eq!(paths.registry_dir, home_path);
    }
}
