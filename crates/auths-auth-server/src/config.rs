//! Auth server configuration.

use std::net::SocketAddr;
use std::path::PathBuf;

/// How to resolve identity public keys.
#[derive(Debug, Clone)]
pub enum ResolverMode {
    /// Resolve via the registry server HTTP API.
    RegistryHttp { url: String },
    /// Resolve from a local git repository — no network required.
    /// Used for integration testing and self-hosted deployments.
    LocalGit { repo_path: PathBuf },
}

/// Configuration for the auth server.
#[derive(Debug, Clone)]
pub struct AuthServerConfig {
    /// Address to bind the server to.
    pub bind_addr: SocketAddr,
    /// How to resolve identity public keys.
    pub resolver_mode: ResolverMode,
    /// How long challenges remain valid, in seconds.
    pub challenge_ttl_secs: u64,
    /// Log level filter.
    pub log_level: String,
    /// Directory containing static files (index.html, etc.).
    pub static_dir: PathBuf,
    /// Whether dynamic client registration is enabled.
    pub registration_enabled: bool,
    /// Allow HTTP (non-HTTPS) redirect URIs for development.
    pub allow_http_redirects: bool,
    /// Default client TTL in seconds. None means clients don't expire.
    pub client_ttl_secs: Option<u64>,
}

impl Default for AuthServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:3001".parse().unwrap(),
            resolver_mode: ResolverMode::RegistryHttp {
                url: "http://localhost:3000".to_string(),
            },
            challenge_ttl_secs: 300,
            log_level: "info".to_string(),
            static_dir: PathBuf::from("static"),
            registration_enabled: true,
            allow_http_redirects: false,
            client_ttl_secs: Some(86400), // 24 hours
        }
    }
}

impl AuthServerConfig {
    pub fn with_addr(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = addr;
        self
    }

    pub fn with_registry_url(mut self, url: impl Into<String>) -> Self {
        self.resolver_mode = ResolverMode::RegistryHttp { url: url.into() };
        self
    }

    pub fn with_local_git_resolver(mut self, repo_path: impl Into<PathBuf>) -> Self {
        self.resolver_mode = ResolverMode::LocalGit {
            repo_path: repo_path.into(),
        };
        self
    }

    pub fn with_challenge_ttl(mut self, secs: u64) -> Self {
        self.challenge_ttl_secs = secs;
        self
    }

    pub fn with_log_level(mut self, level: impl Into<String>) -> Self {
        self.log_level = level.into();
        self
    }

    pub fn with_static_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.static_dir = dir.into();
        self
    }

    pub fn with_registration_enabled(mut self, enabled: bool) -> Self {
        self.registration_enabled = enabled;
        self
    }

    pub fn with_allow_http_redirects(mut self, allow: bool) -> Self {
        self.allow_http_redirects = allow;
        self
    }

    pub fn with_client_ttl(mut self, secs: u64) -> Self {
        self.client_ttl_secs = Some(secs);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn default_config_uses_registry_http() {
        let cfg = AuthServerConfig::default();
        assert!(matches!(
            cfg.resolver_mode,
            ResolverMode::RegistryHttp { .. }
        ));
    }

    #[test]
    fn local_git_mode_stores_path() {
        let cfg = AuthServerConfig::default().with_local_git_resolver("/tmp/repo");
        match cfg.resolver_mode {
            ResolverMode::LocalGit { repo_path } => {
                assert_eq!(repo_path, PathBuf::from("/tmp/repo"));
            }
            other => panic!("expected LocalGit, got {:?}", other),
        }
    }

    #[test]
    fn registry_http_mode_stores_url() {
        let cfg = AuthServerConfig::default().with_registry_url("http://reg.example.com");
        match cfg.resolver_mode {
            ResolverMode::RegistryHttp { url } => {
                assert_eq!(url, "http://reg.example.com");
            }
            other => panic!("expected RegistryHttp, got {:?}", other),
        }
    }
}
