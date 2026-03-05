//! Shared MCP server state.

use std::sync::Arc;

use crate::auth::AuthsToolAuth;
use crate::config::McpServerConfig;

/// Shared state for the MCP server, wrapped in Arc for Axum handlers.
#[derive(Clone)]
pub struct McpServerState {
    inner: Arc<McpServerStateInner>,
}

struct McpServerStateInner {
    auth: AuthsToolAuth,
    config: McpServerConfig,
}

impl McpServerState {
    /// Create a new MCP server state from configuration.
    pub fn new(config: McpServerConfig) -> Self {
        let auth = AuthsToolAuth::with_options(
            &config.jwks_url,
            &config.expected_issuer,
            &config.expected_audience,
            config.tool_capabilities.clone(),
            std::time::Duration::from_secs(config.jwks_cache_ttl_secs),
            config.leeway_secs,
        );

        Self {
            inner: Arc::new(McpServerStateInner { auth, config }),
        }
    }

    /// Get a reference to the AuthsToolAuth instance.
    pub fn auth(&self) -> &AuthsToolAuth {
        &self.inner.auth
    }

    /// Get a reference to the server config.
    pub fn config(&self) -> &McpServerConfig {
        &self.inner.config
    }
}
