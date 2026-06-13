//! MCP server configuration.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use auths_rp::{Audience, DEFAULT_CHALLENGE_TTL_SECS};
use auths_sdk::keychain::KeyAlias;

/// Default bound on live single-use challenges (DoS hygiene).
pub const DEFAULT_MAX_LIVE_CHALLENGES: usize = 10_000;

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

    /// Directory the file-touching tools (`read_file`, `write_file`) are
    /// confined to. A relying party roots tool execution at its own workspace
    /// instead of a pinned location.
    pub sandbox_root: PathBuf,
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
            sandbox_root: PathBuf::from("/tmp"),
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

    /// Set the sandbox root the file-touching tools are confined to.
    pub fn with_sandbox_root(mut self, root: impl Into<PathBuf>) -> Self {
        self.sandbox_root = root.into();
        self
    }
}

/// Settings for the KERI presentation (no-issuer) authentication path.
///
/// Carries only parsed types — an empty audience or alias is unrepresentable here,
/// so the router never re-checks them. Building the server state
/// [`with_keri_presentation`](crate::state::McpServerState::with_keri_presentation)
/// from these settings is what mounts the `Auths-Presentation` scheme and the
/// `/v1/auth/challenge` mint route alongside the JWT path.
#[derive(Debug, Clone)]
pub struct KeriPresentationConfig {
    /// Path to the Auths registry the verifier resolves KELs/TELs/credentials from.
    pub registry_path: PathBuf,

    /// Keychain alias of the pinned issuer whose namespace holds presented credentials.
    pub issuer_alias: KeyAlias,

    /// This server's own audience — the trust source, never the wire header.
    pub audience: Audience,

    /// TTL of a minted single-use challenge, in seconds.
    pub challenge_ttl_secs: i64,

    /// Bound on live challenges (the mint route answers 503 at capacity).
    pub max_live_challenges: usize,
}

impl KeriPresentationConfig {
    /// Presentation settings with the default challenge TTL and capacity bound.
    ///
    /// Args:
    /// * `registry_path`: Path to the Auths registry repository.
    /// * `issuer_alias`: Keychain alias of the pinned credential issuer.
    /// * `audience`: This server's canonical audience.
    pub fn new(registry_path: PathBuf, issuer_alias: KeyAlias, audience: Audience) -> Self {
        Self {
            registry_path,
            issuer_alias,
            audience,
            challenge_ttl_secs: DEFAULT_CHALLENGE_TTL_SECS,
            max_live_challenges: DEFAULT_MAX_LIVE_CHALLENGES,
        }
    }

    /// Set the challenge TTL in seconds.
    pub fn with_challenge_ttl_secs(mut self, secs: i64) -> Self {
        self.challenge_ttl_secs = secs;
        self
    }

    /// Set the bound on live challenges.
    pub fn with_max_live_challenges(mut self, max: usize) -> Self {
        self.max_live_challenges = max;
        self
    }
}
