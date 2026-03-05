//! MCP server configuration.

use std::collections::HashMap;
use std::net::SocketAddr;

/// Configuration for the MCP tool server.
#[derive(Debug, Clone)]
pub struct McpServerConfig {
    /// Address to bind the server to.
    pub bind_addr: SocketAddr,

    /// URL to the OIDC bridge's JWKS endpoint.
    pub jwks_url: String,

    /// Expected issuer URL in JWTs (must match the OIDC bridge's issuer).
    pub expected_issuer: String,

    /// Expected audience value in JWTs.
    pub expected_audience: String,

    /// Map of tool names to required capabilities.
    pub tool_capabilities: HashMap<String, String>,

    /// Clock skew tolerance in seconds for JWT validation.
    pub leeway_secs: u64,

    /// JWKS cache TTL in seconds.
    pub jwks_cache_ttl_secs: u64,

    /// Enable CORS for browser access.
    pub enable_cors: bool,

    /// Log level filter.
    pub log_level: String,
}

impl Default for McpServerConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([0, 0, 0, 0], 8080)),
            jwks_url: "http://localhost:3300/.well-known/jwks.json".to_string(),
            expected_issuer: "http://localhost:3300".to_string(),
            expected_audience: "auths-mcp-server".to_string(),
            tool_capabilities: default_tool_capabilities(),
            leeway_secs: 5,
            jwks_cache_ttl_secs: 3600,
            enable_cors: false,
            log_level: "info".to_string(),
        }
    }
}

fn default_tool_capabilities() -> HashMap<String, String> {
    HashMap::from([
        ("read_file".to_string(), "fs:read".to_string()),
        ("write_file".to_string(), "fs:write".to_string()),
        ("deploy".to_string(), "deploy:staging".to_string()),
    ])
}

impl McpServerConfig {
    /// Set the bind address.
    pub fn with_addr(mut self, addr: SocketAddr) -> Self {
        self.bind_addr = addr;
        self
    }

    /// Set the JWKS URL.
    pub fn with_jwks_url(mut self, url: impl Into<String>) -> Self {
        self.jwks_url = url.into();
        self
    }

    /// Set the expected issuer.
    pub fn with_expected_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.expected_issuer = issuer.into();
        self
    }

    /// Set the expected audience.
    pub fn with_expected_audience(mut self, audience: impl Into<String>) -> Self {
        self.expected_audience = audience.into();
        self
    }

    /// Set tool-to-capability mappings.
    pub fn with_tool_capabilities(mut self, caps: HashMap<String, String>) -> Self {
        self.tool_capabilities = caps;
        self
    }

    /// Set JWT validation leeway.
    pub fn with_leeway(mut self, secs: u64) -> Self {
        self.leeway_secs = secs;
        self
    }

    /// Set JWKS cache TTL.
    pub fn with_jwks_cache_ttl(mut self, secs: u64) -> Self {
        self.jwks_cache_ttl_secs = secs;
        self
    }

    /// Enable CORS.
    pub fn with_cors(mut self, enable: bool) -> Self {
        self.enable_cors = enable;
        self
    }

    /// Set log level.
    pub fn with_log_level(mut self, level: impl Into<String>) -> Self {
        self.log_level = level.into();
        self
    }
}
