//! Configuration types.

use crate::crypto::EncryptionAlgorithm;
use crate::paths::auths_home;
use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::PathBuf;
use std::sync::RwLock;

/// Globally selected encryption algorithm (defaults to AES-GCM).
static ENCRYPTION_ALGO: Lazy<RwLock<EncryptionAlgorithm>> =
    Lazy::new(|| RwLock::new(EncryptionAlgorithm::AesGcm256));

/// Returns the currently selected encryption algorithm.
#[allow(clippy::unwrap_used)] // RwLock poisoning is fatal by design
pub fn current_algorithm() -> EncryptionAlgorithm {
    *ENCRYPTION_ALGO.read().unwrap()
}

/// Sets the encryption algorithm to use globally.
#[allow(clippy::unwrap_used)] // RwLock poisoning is fatal by design
pub fn set_encryption_algorithm(algo: EncryptionAlgorithm) {
    *ENCRYPTION_ALGO.write().unwrap() = algo;
}

/// Keychain backend configuration, typically sourced from environment variables.
///
/// Use `KeychainConfig::from_env()` at process boundaries (CLI entry point, FFI
/// call sites) and then thread the value through the call graph.
///
/// `Debug` output redacts the `passphrase` field to prevent accidental log leakage.
#[derive(Clone, Default)]
pub struct KeychainConfig {
    /// Override for the keychain backend (`AUTHS_KEYCHAIN_BACKEND`).
    /// Supported values: `"file"`, `"memory"`.
    pub backend: Option<String>,
    /// Override for the encrypted-file storage path (`AUTHS_KEYCHAIN_FILE`).
    pub file_path: Option<PathBuf>,
    /// Passphrase for the encrypted-file backend (`AUTHS_PASSPHRASE`).
    pub passphrase: Option<String>,
}

impl fmt::Debug for KeychainConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeychainConfig")
            .field("backend", &self.backend)
            .field("file_path", &self.file_path)
            .field(
                "passphrase",
                &self.passphrase.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl KeychainConfig {
    /// Build a `KeychainConfig` from the process environment.
    ///
    /// Reads `AUTHS_KEYCHAIN_BACKEND`, `AUTHS_KEYCHAIN_FILE`, and `AUTHS_PASSPHRASE`.
    /// Call once at the process/FFI boundary; pass the result into subsystems.
    ///
    /// Usage:
    /// ```ignore
    /// let config = KeychainConfig::from_env();
    /// let keychain = get_platform_keychain_with_config(&EnvironmentConfig { keychain: config, ..Default::default() })?;
    /// ```
    pub fn from_env() -> Self {
        Self {
            backend: std::env::var("AUTHS_KEYCHAIN_BACKEND").ok(),
            file_path: std::env::var("AUTHS_KEYCHAIN_FILE").ok().map(PathBuf::from),
            passphrase: std::env::var("AUTHS_PASSPHRASE").ok(),
        }
    }
}

/// Full environment configuration for an Auths process.
///
/// Collect all environment-variable inputs at the process boundary (main, FFI entry)
/// and thread this struct through the call graph. Subsystems accept `&EnvironmentConfig`
/// instead of reading env vars directly.
///
/// Usage:
/// ```ignore
/// let env = EnvironmentConfig::from_env();
/// let home = auths_home_with_config(&env)?;
/// let keychain = get_platform_keychain_with_config(&env)?;
/// ```
#[derive(Debug, Clone, Default)]
pub struct EnvironmentConfig {
    /// Override for the Auths home directory (`AUTHS_HOME`).
    /// `None` falls back to `~/.auths`.
    pub auths_home: Option<PathBuf>,
    /// Keychain backend settings.
    pub keychain: KeychainConfig,
    /// Path to the SSH agent socket (`SSH_AUTH_SOCK`).
    pub ssh_agent_socket: Option<PathBuf>,
}

impl EnvironmentConfig {
    /// Build an `EnvironmentConfig` from the process environment.
    ///
    /// Reads `AUTHS_HOME`, `AUTHS_KEYCHAIN_BACKEND`, `AUTHS_KEYCHAIN_FILE`,
    /// `AUTHS_PASSPHRASE`, and `SSH_AUTH_SOCK`.
    ///
    /// Usage:
    /// ```ignore
    /// let env = EnvironmentConfig::from_env();
    /// ```
    pub fn from_env() -> Self {
        Self {
            auths_home: std::env::var("AUTHS_HOME")
                .ok()
                .filter(|s| !s.is_empty())
                .map(PathBuf::from),
            keychain: KeychainConfig::from_env(),
            ssh_agent_socket: std::env::var("SSH_AUTH_SOCK").ok().map(PathBuf::from),
        }
    }

    /// Returns a builder for constructing test configurations without env vars.
    ///
    /// Usage:
    /// ```ignore
    /// let env = EnvironmentConfig::builder()
    ///     .auths_home(temp_dir.path().to_path_buf())
    ///     .build();
    /// ```
    pub fn builder() -> EnvironmentConfigBuilder {
        EnvironmentConfigBuilder::default()
    }
}

/// Builder for `EnvironmentConfig` — use in tests to avoid env var manipulation.
///
/// Usage:
/// ```ignore
/// let env = EnvironmentConfig::builder()
///     .auths_home(PathBuf::from("/tmp/test-auths"))
///     .build();
/// ```
#[derive(Default)]
pub struct EnvironmentConfigBuilder {
    auths_home: Option<PathBuf>,
    keychain: Option<KeychainConfig>,
    ssh_agent_socket: Option<PathBuf>,
}

impl EnvironmentConfigBuilder {
    /// Set the Auths home directory override.
    pub fn auths_home(mut self, home: PathBuf) -> Self {
        self.auths_home = Some(home);
        self
    }

    /// Set the keychain configuration.
    pub fn keychain(mut self, keychain: KeychainConfig) -> Self {
        self.keychain = Some(keychain);
        self
    }

    /// Set the SSH agent socket path.
    pub fn ssh_agent_socket(mut self, path: PathBuf) -> Self {
        self.ssh_agent_socket = Some(path);
        self
    }

    /// Consume the builder and produce an `EnvironmentConfig`.
    pub fn build(self) -> EnvironmentConfig {
        EnvironmentConfig {
            auths_home: self.auths_home,
            keychain: self.keychain.unwrap_or_default(),
            ssh_agent_socket: self.ssh_agent_socket,
        }
    }
}

/// Passphrase caching policy.
///
/// Controls how `auths-sign` caches the passphrase between invocations:
/// - `always`: Store in OS keychain permanently until explicitly cleared.
/// - `session`: Rely on the in-memory agent (Tier 1/2) — prompt once per agent lifetime.
/// - `duration`: Store in OS keychain with a TTL (see [`PassphraseConfig::duration`]).
/// - `never`: Always prompt interactively.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PassphraseCachePolicy {
    /// Store passphrase in OS keychain permanently.
    Always,
    /// Cache passphrase in the running agent's memory (default).
    #[default]
    Session,
    /// Store passphrase in OS keychain with a configurable TTL.
    Duration,
    /// Never cache — always prompt.
    Never,
}

/// Passphrase section of `~/.auths/config.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassphraseConfig {
    /// Caching policy.
    #[serde(default)]
    pub cache: PassphraseCachePolicy,
    /// Duration string (e.g. `"7d"`, `"24h"`, `"30m"`). Only used when `cache = "duration"`.
    pub duration: Option<String>,
    /// Use Touch ID (biometric) to protect cached passphrases on macOS.
    /// Defaults to `true` on macOS, ignored on other platforms.
    #[serde(default = "default_biometric")]
    pub biometric: bool,
}

fn default_biometric() -> bool {
    cfg!(target_os = "macos")
}

impl Default for PassphraseConfig {
    fn default() -> Self {
        Self {
            cache: PassphraseCachePolicy::Duration,
            duration: Some("1h".to_string()),
            biometric: default_biometric(),
        }
    }
}

/// Top-level `~/.auths/config.toml` structure.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuthsConfig {
    /// Passphrase caching settings.
    #[serde(default)]
    pub passphrase: PassphraseConfig,
}

/// Loads `~/.auths/config.toml`, returning defaults on any error.
///
/// Usage:
/// ```ignore
/// let config = auths_core::config::load_config();
/// match config.passphrase.cache {
///     PassphraseCachePolicy::Always => { /* ... */ }
///     _ => {}
/// }
/// ```
pub fn load_config() -> AuthsConfig {
    let home = match auths_home() {
        Ok(h) => h,
        Err(_) => return AuthsConfig::default(),
    };
    let path = home.join("config.toml");
    match std::fs::read_to_string(&path) {
        Ok(contents) => toml::from_str(&contents).unwrap_or_default(),
        Err(_) => AuthsConfig::default(),
    }
}

/// Writes `~/.auths/config.toml`.
///
/// Args:
/// * `config`: The configuration to persist.
///
/// Usage:
/// ```ignore
/// let mut config = load_config();
/// config.passphrase.cache = PassphraseCachePolicy::Always;
/// save_config(&config)?;
/// ```
pub fn save_config(config: &AuthsConfig) -> Result<(), std::io::Error> {
    let home = auths_home().map_err(|e| std::io::Error::other(e.to_string()))?;
    std::fs::create_dir_all(&home)?;
    let path = home.join("config.toml");
    let contents =
        toml::to_string_pretty(config).map_err(|e| std::io::Error::other(e.to_string()))?;
    std::fs::write(&path, contents)
}
