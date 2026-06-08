//! Shared SCIM server state.
//!
//! KERI/registry is the source of truth; this state holds only the tenant→org
//! routing and the hashed per-tenant channel tokens. It is cheap to clone (an
//! `Arc` internally) so it can be passed to `axum`'s `with_state`.

use std::collections::HashMap;
use std::sync::Arc;

use sha2::{Digest, Sha256};

/// Per-tenant SCIM configuration.
///
/// A tenant maps an external IdP (Okta/Entra) provisioning channel to an Auths
/// org. The bearer token authenticates the **channel only** — the provisioned
/// identity is a real delegated KERI identity (wired in later tasks). The token
/// is stored only as a SHA-256 hash; the plaintext never lives in state.
#[derive(Debug, Clone)]
pub struct TenantConfig {
    /// Stable tenant identifier (matches the IdP's configured tenant).
    pub tenant_id: String,
    /// The Auths org prefix this tenant provisions into (used by Joiner/Leaver).
    pub org_prefix: String,
    token_hash: [u8; 32],
}

impl TenantConfig {
    /// Build a tenant from its id, target org prefix, and bearer token.
    ///
    /// Args:
    /// * `tenant_id`: Stable tenant identifier.
    /// * `org_prefix`: The Auths org prefix to provision into.
    /// * `bearer_token`: The SCIM channel token (stored only as a SHA-256 hash).
    ///
    /// Usage:
    /// ```ignore
    /// let t = TenantConfig::new("acme", "EAbc...", "scim_secret");
    /// ```
    pub fn new(
        tenant_id: impl Into<String>,
        org_prefix: impl Into<String>,
        bearer_token: &str,
    ) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            org_prefix: org_prefix.into(),
            token_hash: Sha256::digest(bearer_token.as_bytes()).into(),
        }
    }
}

struct Inner {
    tenants: HashMap<String, TenantConfig>,
}

/// Shared, cheap-to-clone SCIM server state.
#[derive(Clone)]
pub struct ScimServerState {
    inner: Arc<Inner>,
}

impl ScimServerState {
    /// Build state from the configured tenants.
    ///
    /// Args:
    /// * `tenants`: The tenants this server accepts provisioning for.
    ///
    /// Usage:
    /// ```ignore
    /// let state = ScimServerState::new(vec![TenantConfig::new("acme", "EAbc", "tok")]);
    /// ```
    pub fn new(tenants: Vec<TenantConfig>) -> Self {
        let tenants = tenants
            .into_iter()
            .map(|t| (t.tenant_id.clone(), t))
            .collect();
        Self {
            inner: Arc::new(Inner { tenants }),
        }
    }

    /// Resolve a presented bearer token to its tenant via a constant-time hash
    /// comparison. Returns the matching tenant, or `None` if no token matches.
    pub(crate) fn authenticate_token(&self, presented: &str) -> Option<TenantConfig> {
        use subtle::ConstantTimeEq;
        let presented_hash: [u8; 32] = Sha256::digest(presented.as_bytes()).into();
        self.inner
            .tenants
            .values()
            .find(|t| {
                t.token_hash
                    .as_slice()
                    .ct_eq(presented_hash.as_slice())
                    .into()
            })
            .cloned()
    }
}
