//! Bearer-token tenant authentication.
//!
//! SCIM clients (Okta/Entra) authenticate with a static bearer token — an
//! accepted risk documented in the crate README. The token authenticates the
//! provisioning channel only; the provisioned identity is a real delegated KERI
//! identity. Discovery endpoints are unauthenticated; resource endpoints extract
//! [`AuthenticatedTenant`], which fails closed (401) without a valid token.

use std::future::Future;

use auths_scim::ScimError;
use auths_verifier::Capability;
use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;

use crate::error::ScimServerError;
use crate::state::ScimServerState;

/// A request authenticated as a specific SCIM tenant.
///
/// Extracting this in a handler proves the caller presented a valid per-tenant
/// bearer token; the resolved `org_prefix` is the Auths org the request may
/// provision into, signed by `org_key_alias`.
#[derive(Debug, Clone)]
pub struct AuthenticatedTenant {
    /// The authenticated tenant's id.
    pub tenant_id: String,
    /// The Auths org prefix this tenant provisions into.
    pub org_prefix: String,
    /// Keychain alias of the org signing key that anchors delegations.
    pub org_key_alias: String,
    /// Capabilities this tenant may grant (empty = permit all).
    pub allowed_capabilities: Vec<Capability>,
    /// Base URL used for SCIM `meta.location`.
    pub base_url: String,
}

impl FromRequestParts<ScimServerState> for AuthenticatedTenant {
    type Rejection = ScimServerError;

    fn from_request_parts(
        parts: &mut Parts,
        state: &ScimServerState,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let unauthorized = |detail: &str| {
            ScimServerError::from(ScimError::Unauthorized {
                message: detail.to_string(),
            })
        };

        let result = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| unauthorized("missing bearer token"))
            .and_then(|raw| {
                raw.strip_prefix("Bearer ")
                    .ok_or_else(|| unauthorized("expected Bearer authorization scheme"))
            })
            .and_then(|token| {
                state
                    .authenticate_token(token)
                    .map(|t| AuthenticatedTenant {
                        tenant_id: t.tenant_id,
                        org_prefix: t.org_prefix,
                        org_key_alias: t.org_key_alias,
                        allowed_capabilities: t.allowed_capabilities,
                        base_url: t.base_url,
                    })
                    .ok_or_else(|| unauthorized("invalid bearer token"))
            });

        async move { result }
    }
}
