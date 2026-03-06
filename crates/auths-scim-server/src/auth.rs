//! Bearer token authentication middleware.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use sha2::{Digest, Sha256};

use crate::error::ScimServerError;

/// Authenticated tenant extracted from the bearer token.
#[derive(Debug, Clone)]
pub struct AuthenticatedTenant {
    /// Tenant UUID.
    pub tenant_id: uuid::Uuid,
    /// Tenant name.
    pub name: String,
    /// Capabilities allowed for this tenant.
    pub allowed_capabilities: Vec<String>,
    /// Whether this is a test-mode tenant.
    pub is_test: bool,
}

/// Hash a bearer token for storage/lookup.
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

impl<S> FromRequestParts<S> for AuthenticatedTenant
where
    S: Send + Sync,
{
    type Rejection = ScimServerError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                ScimServerError::Scim(auths_scim::ScimError::Unauthorized {
                    message: "Missing Authorization header. Include 'Bearer <token>'.".into(),
                })
            })?;

        let token = auth_header.strip_prefix("Bearer ").ok_or_else(|| {
            ScimServerError::Scim(auths_scim::ScimError::Unauthorized {
                message: "Invalid Authorization format. Use 'Bearer <token>'.".into(),
            })
        })?;

        let _token_hash = hash_token(token);

        // TODO: Look up tenant from database by token_hash.
        // For now, return a placeholder error until database wiring is complete.
        Err(ScimServerError::Scim(auths_scim::ScimError::Unauthorized {
            message: "Token validation not yet wired to database.".into(),
        }))
    }
}
