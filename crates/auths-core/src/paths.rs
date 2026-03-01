//! Shared path resolution for the Auths home directory.
//!
//! All code that needs the `~/.auths` directory should call [`auths_home_with_config`]
//! (or the legacy shim [`auths_home`]) instead of hardcoding
//! `dirs::home_dir().join(".auths")`. This enables multi-agent simulation and CI
//! overrides via the `AUTHS_HOME` env var.

use std::path::PathBuf;

use crate::config::EnvironmentConfig;

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
}
