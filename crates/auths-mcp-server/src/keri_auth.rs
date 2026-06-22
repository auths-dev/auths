//! KERI-native MCP tool authorization (dual-mode, alongside the JWT path).
//!
//! The JWT path (`auth.rs`) validates an OIDC-bridge-minted token against a JWKS endpoint —
//! an issuer in the trust path. This module is the no-issuer alternative: an agent presents
//! proof-of-control of a delegated KERI credential (an `Auths-Presentation`), the relying
//! party verifies it offline via `auths_sdk::authenticate_presentation`, and the **same**
//! per-tool capability gate produces a [`VerifiedAgent`]. The router serves both modes
//! together when built with a [`KeriPresentationConfig`], so OAuth/JWT clients keep working
//! while new agents adopt the no-issuer passport.
//!
//! No verification logic is duplicated: the full verify flow lives in `auths-sdk`, and the
//! capability gate ([`gate`]) is a free function so it is unit-testable without a registry.

use std::collections::HashMap;
use std::sync::Arc;

use auths_rp::{
    Audience, ChallengeStore, InMemoryChallengeStore, VerifiedPrincipal, WirePresentation,
};
use auths_sdk::context::AuthsContext;
use auths_sdk::domains::credentials::authenticate_presentation;
use auths_sdk::keychain::KeyAlias;
use auths_verifier::Capability;
use chrono::{DateTime, Duration, Utc};

use crate::config::KeriPresentationConfig;
use crate::error::McpServerError;
use crate::types::VerifiedAgent;

/// KERI-native tool authorization: an `Auths-Presentation` (not a JWT) gates each tool call.
pub struct KeriToolAuth {
    ctx: Arc<AuthsContext>,
    issuer_alias: KeyAlias,
    challenges: Arc<dyn ChallengeStore>,
    audience: Audience,
    tool_capabilities: HashMap<String, String>,
}

impl KeriToolAuth {
    /// Create a KERI-native tool authorizer.
    ///
    /// Args:
    /// * `ctx`: Auths context (registry for KEL/TEL/credential resolution).
    /// * `issuer_alias`: The pinned issuer whose namespace holds presented credentials.
    /// * `challenges`: The single-use challenge store.
    /// * `audience`: This server's own audience (the trust source, not the wire header).
    /// * `tool_capabilities`: Map of tool name to the required capability string.
    ///
    /// Usage:
    /// ```ignore
    /// let auth = KeriToolAuth::new(ctx, issuer, challenges, audience, tool_caps);
    /// let agent = auth.authorize_tool_call_keri(presentation, "open_pr", now).await?;
    /// ```
    pub fn new(
        ctx: Arc<AuthsContext>,
        issuer_alias: KeyAlias,
        challenges: Arc<dyn ChallengeStore>,
        audience: Audience,
        tool_capabilities: HashMap<String, String>,
    ) -> Self {
        Self {
            ctx,
            issuer_alias,
            challenges,
            audience,
            tool_capabilities,
        }
    }

    /// Build a KERI tool authorizer from parsed presentation settings.
    ///
    /// Owns the shipped bounded in-memory challenge store; use [`KeriToolAuth::new`]
    /// to supply a custom [`ChallengeStore`] backend (e.g. shared across nodes).
    ///
    /// Args:
    /// * `ctx`: Auths context over the registry at `config.registry_path`.
    /// * `config`: Parsed presentation settings (issuer, audience, TTL, capacity).
    /// * `tool_capabilities`: Map of tool name to the required capability string.
    pub fn from_config(
        ctx: Arc<AuthsContext>,
        config: &KeriPresentationConfig,
        tool_capabilities: HashMap<String, String>,
    ) -> Self {
        let challenges: Arc<dyn ChallengeStore> = Arc::new(InMemoryChallengeStore::with_ttl(
            config.max_live_challenges,
            Duration::seconds(config.challenge_ttl_secs),
        ));
        Self::new(
            ctx,
            config.issuer_alias.clone(),
            challenges,
            config.audience.clone(),
            tool_capabilities,
        )
    }

    /// Authenticate an `Auths-Presentation` into a [`VerifiedAgent`] — no per-tool gate.
    ///
    /// The route layer gates per tool afterwards, exactly as it does for the JWT
    /// path, so one capability check governs both schemes.
    ///
    /// Args:
    /// * `presentation`: The `WirePresentation` parsed from the `Authorization` header.
    /// * `now`: The current time (read at the server boundary).
    pub async fn authenticate(
        &self,
        presentation: WirePresentation,
        now: DateTime<Utc>,
    ) -> Result<VerifiedAgent, McpServerError> {
        Ok(verified_agent(&self.verify(presentation, now).await?))
    }

    /// Authorize a tool call from an `Auths-Presentation` (no JWT, no issuer in the path).
    ///
    /// Verifies the presentation offline (single-use challenge, audience-binding, revocation)
    /// via `auths_sdk::authenticate_presentation`, then checks the per-tool capability —
    /// yielding the same [`VerifiedAgent`] shape the JWT path produces. The one-call
    /// embedding API; the Axum middleware authenticates here and gates in the route layer.
    ///
    /// Args:
    /// * `presentation`: The `WirePresentation` parsed from the `Authorization` header.
    /// * `tool_name`: The MCP tool being invoked.
    /// * `now`: The current time (read at the server boundary).
    pub async fn authorize_tool_call_keri(
        &self,
        presentation: WirePresentation,
        tool_name: &str,
        now: DateTime<Utc>,
    ) -> Result<VerifiedAgent, McpServerError> {
        let principal = self.verify(presentation, now).await?;
        gate(&self.tool_capabilities, &principal, tool_name)
    }

    /// Verify the presentation offline, consuming its single-use challenge.
    async fn verify(
        &self,
        presentation: WirePresentation,
        now: DateTime<Utc>,
    ) -> Result<VerifiedPrincipal, McpServerError> {
        authenticate_presentation(
            &self.ctx,
            &self.issuer_alias,
            &*self.challenges,
            &self.audience,
            presentation,
            now,
        )
        .await
        .map_err(|e| McpServerError::Unauthorized(e.to_string()))
    }

    /// The single-use challenge store (shared with the `/v1/auth/challenge` mint route).
    pub fn challenges(&self) -> Arc<dyn ChallengeStore> {
        Arc::clone(&self.challenges)
    }

    /// The audience presentations must bind to.
    pub fn audience(&self) -> &Audience {
        &self.audience
    }

    /// The tool-to-capability map.
    pub fn tool_capabilities(&self) -> &HashMap<String, String> {
        &self.tool_capabilities
    }
}

/// Check a verified principal against the per-tool capability and build a [`VerifiedAgent`].
///
/// Separated from [`KeriToolAuth`] so the capability gate is unit-testable without a registry.
/// Distinguishes an unregistered tool ([`McpServerError::UnknownTool`], 404) from an
/// authenticated-but-insufficient principal ([`McpServerError::InsufficientCapabilities`], 403).
fn gate(
    tool_capabilities: &HashMap<String, String>,
    principal: &VerifiedPrincipal,
    tool_name: &str,
) -> Result<VerifiedAgent, McpServerError> {
    let required = tool_capabilities
        .get(tool_name)
        .ok_or_else(|| McpServerError::UnknownTool(tool_name.to_string()))?;
    let needed = Capability::parse(required).map_err(|e| {
        McpServerError::Internal(format!("misconfigured capability '{required}': {e}"))
    })?;
    if principal.authorize(&needed).is_err() {
        return Err(McpServerError::InsufficientCapabilities {
            tool: tool_name.to_string(),
            required: required.clone(),
            granted: granted_caps(principal),
        });
    }
    Ok(verified_agent(principal))
}

/// Map a verified principal to the MCP [`VerifiedAgent`] shape.
fn verified_agent(principal: &VerifiedPrincipal) -> VerifiedAgent {
    let did = principal.subject().as_str().to_string();
    let keri_prefix = did
        .strip_prefix("did:keri:")
        .unwrap_or(did.as_str())
        .to_string();
    VerifiedAgent {
        did,
        keri_prefix,
        capabilities: principal.capabilities().iter().cloned().collect(),
    }
}

/// The principal's capabilities as strings.
fn granted_caps(principal: &VerifiedPrincipal) -> Vec<String> {
    principal
        .capabilities()
        .iter()
        .map(|cap| cap.as_str().to_string())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_verifier::{CanonicalDid, Capability, IdentityDID, PresentationVerdict};

    fn principal_with(caps: &[&str]) -> VerifiedPrincipal {
        let verdict = PresentationVerdict::Valid {
            issuer: IdentityDID::parse("did:keri:Eissuer").expect("valid test issuer"),
            subject: CanonicalDid::parse("did:keri:Eagent").expect("valid test subject"),
            caps: caps
                .iter()
                .map(|c| Capability::parse(c).expect("valid test capability"))
                .collect(),
            role: None,
            expires_at: None,
            freshness: auths_verifier::Freshness::Unknown,
        };
        VerifiedPrincipal::from_verdict(verdict).expect("valid verdict -> principal")
    }

    fn tools() -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("open_pr".to_string(), "acme:pr".to_string());
        map
    }

    #[test]
    fn authorized_tool_yields_verified_agent() {
        let principal = principal_with(&["acme:pr"]);
        let agent = gate(&tools(), &principal, "open_pr").expect("authorized");
        assert_eq!(agent.did, "did:keri:Eagent");
        assert_eq!(agent.keri_prefix, "Eagent");
        assert!(
            agent
                .capabilities
                .contains(&Capability::parse("acme:pr").unwrap())
        );
    }

    #[test]
    fn missing_capability_is_insufficient_403() {
        let principal = principal_with(&["acme:read"]);
        match gate(&tools(), &principal, "open_pr") {
            Err(McpServerError::InsufficientCapabilities { tool, required, .. }) => {
                assert_eq!(tool, "open_pr");
                assert_eq!(required, "acme:pr");
            }
            other => panic!("expected InsufficientCapabilities, got {other:?}"),
        }
    }

    #[test]
    fn unknown_tool_rejected() {
        let principal = principal_with(&["acme:pr"]);
        assert!(matches!(
            gate(&tools(), &principal, "no_such_tool"),
            Err(McpServerError::UnknownTool(_))
        ));
    }
}
