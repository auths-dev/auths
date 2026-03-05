//! Core authorization logic for MCP tool calls.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use auths_oidc_bridge::token::OidcClaims;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};

use crate::error::McpServerError;
use crate::jwks::JwksCache;
use crate::types::VerifiedAgent;

/// MCP tool server middleware that validates Auths-backed JWTs.
///
/// Args:
/// * `jwks_url`: The OIDC bridge's `/.well-known/jwks.json` endpoint.
/// * `tool_capabilities`: Map of tool names to required capabilities.
///
/// Usage:
/// ```ignore
/// let auth = AuthsToolAuth::new(
///     "https://oidc.example.com/.well-known/jwks.json",
///     "https://oidc.example.com",
///     "auths-mcp-server",
///     HashMap::from([
///         ("read_file".into(), "fs:read".into()),
///         ("write_file".into(), "fs:write".into()),
///         ("deploy".into(), "deploy:staging".into()),
///     ]),
/// );
/// ```
pub struct AuthsToolAuth {
    jwks_cache: Arc<JwksCache>,
    tool_capabilities: HashMap<String, String>,
    expected_issuer: String,
    expected_audience: String,
    leeway: u64,
}

impl AuthsToolAuth {
    /// Creates a new AuthsToolAuth.
    ///
    /// Args:
    /// * `jwks_url`: The OIDC bridge's JWKS endpoint URL.
    /// * `expected_issuer`: The expected `iss` claim value.
    /// * `expected_audience`: The expected `aud` claim value.
    /// * `tool_capabilities`: Map of tool name to required capability string.
    pub fn new(
        jwks_url: impl Into<String>,
        expected_issuer: impl Into<String>,
        expected_audience: impl Into<String>,
        tool_capabilities: HashMap<String, String>,
    ) -> Self {
        let jwks_cache = Arc::new(JwksCache::new(jwks_url, Duration::from_secs(3600)));

        Self {
            jwks_cache,
            tool_capabilities,
            expected_issuer: expected_issuer.into(),
            expected_audience: expected_audience.into(),
            leeway: 5,
        }
    }

    /// Creates an AuthsToolAuth with custom JWKS cache TTL and leeway.
    pub fn with_options(
        jwks_url: impl Into<String>,
        expected_issuer: impl Into<String>,
        expected_audience: impl Into<String>,
        tool_capabilities: HashMap<String, String>,
        jwks_cache_ttl: Duration,
        leeway: u64,
    ) -> Self {
        let jwks_cache = Arc::new(JwksCache::new(jwks_url, jwks_cache_ttl));

        Self {
            jwks_cache,
            tool_capabilities,
            expected_issuer: expected_issuer.into(),
            expected_audience: expected_audience.into(),
            leeway,
        }
    }

    /// Validate a Bearer token and check capabilities for the given tool.
    ///
    /// Args:
    /// * `bearer_token`: The JWT from the Authorization header.
    /// * `tool_name`: The MCP tool being invoked.
    ///
    /// Usage:
    /// ```ignore
    /// let agent = auth.authorize_tool_call("eyJ...", "read_file").await?;
    /// println!("Authorized agent: {}", agent.did);
    /// ```
    pub async fn authorize_tool_call(
        &self,
        bearer_token: &str,
        tool_name: &str,
    ) -> Result<VerifiedAgent, McpServerError> {
        let claims = self.validate_jwt(bearer_token).await?;

        let required_cap = self
            .tool_capabilities
            .get(tool_name)
            .ok_or_else(|| McpServerError::UnknownTool(tool_name.to_string()))?;

        if !claims.capabilities.contains(&required_cap.to_string()) {
            return Err(McpServerError::InsufficientCapabilities {
                tool: tool_name.to_string(),
                required: required_cap.to_string(),
                granted: claims.capabilities.clone(),
            });
        }

        Ok(VerifiedAgent {
            did: claims.sub,
            keri_prefix: claims.keri_prefix,
            capabilities: claims.capabilities,
        })
    }

    /// Validate a JWT without checking tool capabilities.
    ///
    /// Args:
    /// * `bearer_token`: The raw JWT string.
    pub async fn validate_jwt(&self, bearer_token: &str) -> Result<OidcClaims, McpServerError> {
        let header = decode_header(bearer_token)
            .map_err(|e| McpServerError::TokenInvalid(format!("invalid JWT header: {e}")))?;

        let kid = header
            .kid
            .ok_or_else(|| McpServerError::TokenInvalid("JWT header missing kid".to_string()))?;

        let decoding_key = self.jwks_cache.get_key_for_kid(&kid).await?;

        let claims = decode_jwt(
            bearer_token,
            &decoding_key,
            &self.expected_issuer,
            &self.expected_audience,
            self.leeway,
        )?;

        Ok(claims)
    }

    /// Returns the set of registered tool names.
    pub fn tool_names(&self) -> Vec<String> {
        self.tool_capabilities.keys().cloned().collect()
    }

    /// Returns the tool-to-capability mapping.
    pub fn tool_capabilities(&self) -> &HashMap<String, String> {
        &self.tool_capabilities
    }
}

fn decode_jwt(
    token: &str,
    key: &DecodingKey,
    expected_issuer: &str,
    expected_audience: &str,
    leeway: u64,
) -> Result<OidcClaims, McpServerError> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_issuer(&[expected_issuer]);
    validation.set_audience(&[expected_audience]);
    validation.validate_exp = true;
    validation.validate_nbf = false;
    validation.leeway = leeway;
    validation.set_required_spec_claims(&["exp", "iss", "sub", "aud"]);

    let token_data = decode::<OidcClaims>(token, key, &validation)
        .map_err(|e| McpServerError::TokenInvalid(format!("JWT validation failed: {e}")))?;

    Ok(token_data.claims)
}
