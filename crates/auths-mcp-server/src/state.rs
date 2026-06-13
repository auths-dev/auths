//! Shared MCP server state.

use std::sync::Arc;

use crate::auth::AuthsToolAuth;
use crate::config::McpServerConfig;
use crate::keri_auth::KeriToolAuth;

/// Shared state for the MCP server, wrapped in Arc for Axum handlers.
///
/// The JWT authorizer is always present; the KERI presentation authorizer is the
/// optional second mode — its presence here is the single switch the router and
/// middleware read, so a server built without it has no presentation path at all.
#[derive(Clone)]
pub struct McpServerState {
    inner: Arc<McpServerStateInner>,
}

struct McpServerStateInner {
    auth: AuthsToolAuth,
    keri: Option<Arc<KeriToolAuth>>,
    config: McpServerConfig,
}

impl McpServerState {
    /// Create a JWT-only MCP server state from configuration.
    pub fn new(config: McpServerConfig) -> Self {
        Self::assemble(config, None)
    }

    /// Create a dual-mode state: Bearer JWTs plus the KERI presentation path.
    ///
    /// Agents may then also authenticate with `Authorization: Auths-Presentation
    /// <token>` signed over a nonce minted at `/v1/auth/challenge` — no issuer in
    /// the trust path.
    ///
    /// Args:
    /// * `config`: The server configuration (JWT settings, tool capabilities).
    /// * `keri`: The KERI presentation authorizer (see [`KeriToolAuth::from_config`]).
    pub fn with_keri_presentation(config: McpServerConfig, keri: Arc<KeriToolAuth>) -> Self {
        Self::assemble(config, Some(keri))
    }

    fn assemble(config: McpServerConfig, keri: Option<Arc<KeriToolAuth>>) -> Self {
        let auth = AuthsToolAuth::with_options(
            &config.jwks_url,
            &config.expected_issuer,
            &config.expected_audience,
            config.tool_capabilities.clone(),
            std::time::Duration::from_secs(config.jwks_cache_ttl_secs),
            config.leeway_secs,
        );

        Self {
            inner: Arc::new(McpServerStateInner { auth, keri, config }),
        }
    }

    /// Get a reference to the AuthsToolAuth instance.
    pub fn auth(&self) -> &AuthsToolAuth {
        &self.inner.auth
    }

    /// The KERI presentation authorizer, if this server mounts the presentation path.
    pub fn keri(&self) -> Option<&Arc<KeriToolAuth>> {
        self.inner.keri.as_ref()
    }

    /// Get a reference to the server config.
    pub fn config(&self) -> &McpServerConfig {
        &self.inner.config
    }
}
