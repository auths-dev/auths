//! SCIM server configuration.

/// SCIM server configuration.
#[derive(Debug, Clone)]
pub struct ScimServerConfig {
    /// Listen address (e.g., "0.0.0.0:8082").
    pub listen_addr: String,
    /// PostgreSQL connection URL.
    pub database_url: String,
    /// Path to the Auths registry Git repository.
    pub registry_path: String,
    /// Base URL for SCIM resource locations.
    pub base_url: String,
    /// Require TLS for production tokens.
    pub require_tls: bool,
    /// Enable test mode (allows `scim_test_` tokens without TLS).
    pub test_mode: bool,
    /// Request body size limit in bytes.
    pub max_body_size: usize,
    /// Maximum filter results.
    pub max_filter_results: u64,
}

impl Default for ScimServerConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:8082".into(),
            database_url: String::new(),
            registry_path: String::new(),
            base_url: "http://localhost:8082".into(),
            require_tls: false,
            test_mode: false,
            max_body_size: 1024 * 1024, // 1 MiB
            max_filter_results: 100,
        }
    }
}

impl ScimServerConfig {
    /// Create a new config builder.
    pub fn builder() -> ScimServerConfigBuilder {
        ScimServerConfigBuilder::default()
    }
}

/// Builder for `ScimServerConfig`.
#[derive(Debug, Default)]
pub struct ScimServerConfigBuilder {
    config: ScimServerConfig,
}

impl ScimServerConfigBuilder {
    pub fn listen_addr(mut self, addr: impl Into<String>) -> Self {
        self.config.listen_addr = addr.into();
        self
    }

    pub fn database_url(mut self, url: impl Into<String>) -> Self {
        self.config.database_url = url.into();
        self
    }

    pub fn registry_path(mut self, path: impl Into<String>) -> Self {
        self.config.registry_path = path.into();
        self
    }

    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.config.base_url = url.into();
        self
    }

    pub fn require_tls(mut self, require: bool) -> Self {
        self.config.require_tls = require;
        self
    }

    pub fn test_mode(mut self, enabled: bool) -> Self {
        self.config.test_mode = enabled;
        self
    }

    pub fn build(self) -> ScimServerConfig {
        self.config
    }
}

impl ScimServerConfig {
    /// Load configuration from environment variables.
    ///
    /// Usage:
    /// ```ignore
    /// let config = ScimServerConfig::from_env()?;
    /// ```
    #[allow(clippy::disallowed_methods)] // Designated env-var reading boundary
    pub fn from_env() -> Result<Self, anyhow::Error> {
        let database_url = std::env::var("DATABASE_URL")
            .or_else(|_| std::env::var("SCIM_DATABASE_URL"))
            .unwrap_or_default();
        let listen_addr =
            std::env::var("SCIM_LISTEN_ADDR").unwrap_or_else(|_| "0.0.0.0:8082".into());
        let base_url =
            std::env::var("SCIM_BASE_URL").unwrap_or_else(|_| format!("http://{listen_addr}"));
        let registry_path = std::env::var("SCIM_REGISTRY_PATH").unwrap_or_default();
        let test_mode = std::env::var("AUTHS_SCIM_TEST")
            .map(|v| v == "1" || v == "true")
            .unwrap_or(false);

        Ok(Self {
            listen_addr,
            database_url,
            registry_path,
            base_url,
            require_tls: !test_mode,
            test_mode,
            max_body_size: 1024 * 1024,
            max_filter_results: 100,
        })
    }
}
