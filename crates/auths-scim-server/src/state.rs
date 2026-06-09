//! Shared SCIM server state.
//!
//! KERI/registry is the source of truth; this state holds the tenant→org routing,
//! the hashed per-tenant channel tokens, the [`Provisioner`] port, and a derived
//! `(tenant, externalId) → resource` idempotency index. The index is a cache — the
//! KEL is authoritative — so it is rebuildable and never the source of truth. The
//! state is cheap to clone (an `Arc` internally) for `axum`'s `with_state`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

use auths_scim::ScimError;
use auths_scim::resource::ScimUser;
use sha2::{Digest, Sha256};

use crate::provisioner::Provisioner;

/// Per-tenant SCIM configuration.
///
/// A tenant maps an external IdP (Okta/Entra) provisioning channel to an Auths
/// org. The bearer token authenticates the **channel only** — the provisioned
/// identity is a real delegated KERI identity. The token is stored only as a
/// SHA-256 hash; the plaintext never lives in state.
#[derive(Debug, Clone)]
pub struct TenantConfig {
    /// Stable tenant identifier (matches the IdP's configured tenant).
    pub tenant_id: String,
    /// The Auths org prefix this tenant provisions into.
    pub org_prefix: String,
    /// Keychain alias of the org signing key that anchors delegations.
    pub org_key_alias: String,
    /// Capabilities this tenant may grant (empty = permit all).
    pub allowed_capabilities: Vec<String>,
    /// Base URL used for SCIM `meta.location` (e.g. `https://scim.acme.com/scim/v2`).
    pub base_url: String,
    token_hash: [u8; 32],
}

/// Default org signing-key alias derived from the org prefix (`org-<slug>`),
/// matching the `auths org` convention. Override with [`TenantConfig::with_org_key_alias`].
fn default_org_alias(org_prefix: &str) -> String {
    format!(
        "org-{}",
        org_prefix
            .chars()
            .filter(|c| c.is_alphanumeric())
            .take(20)
            .collect::<String>()
            .to_lowercase()
    )
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
    /// let t = TenantConfig::new("acme", "EAbc...", "scim_secret")
    ///     .with_org_key_alias("org-acme");
    /// ```
    pub fn new(
        tenant_id: impl Into<String>,
        org_prefix: impl Into<String>,
        bearer_token: &str,
    ) -> Self {
        let org_prefix = org_prefix.into();
        Self {
            org_key_alias: default_org_alias(&org_prefix),
            tenant_id: tenant_id.into(),
            org_prefix,
            allowed_capabilities: Vec::new(),
            base_url: String::new(),
            token_hash: Sha256::digest(bearer_token.as_bytes()).into(),
        }
    }

    /// Set the org signing-key alias that anchors this tenant's delegations.
    pub fn with_org_key_alias(mut self, alias: impl Into<String>) -> Self {
        self.org_key_alias = alias.into();
        self
    }

    /// Restrict the capabilities this tenant may grant (empty = permit all).
    pub fn with_allowed_capabilities(mut self, capabilities: Vec<String>) -> Self {
        self.allowed_capabilities = capabilities;
        self
    }

    /// Set the base URL used for SCIM `meta.location`.
    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }
}

/// A stored SCIM resource plus the tenant that owns it.
///
/// `deleted` is the soft-Leaver tombstone: a `DELETE` (deprovision) hides the
/// resource (404 / unlisted) without cryptographically revoking the underlying
/// KERI identity, so an accidental delete is recoverable and a stale Joiner replay
/// cannot resurrect authority. Hard-revocation is the separate, explicit step.
struct StoredUser {
    tenant_id: String,
    user: ScimUser,
    deleted: bool,
}

/// The derived idempotency index. KEL is authoritative; this is a rebuildable cache.
#[derive(Default)]
struct UserStore {
    /// `(tenant_id, externalId)` → resource id — the idempotency key.
    by_external: HashMap<(String, String), String>,
    /// resource id → the stored resource.
    by_id: HashMap<String, StoredUser>,
}

struct Inner {
    tenants: HashMap<String, TenantConfig>,
    provisioner: Arc<dyn Provisioner>,
    store: Mutex<UserStore>,
}

impl Inner {
    /// Lock the store, recovering the guard if a prior holder panicked (poison) —
    /// a poisoned cache is still safe to read/overwrite, so we never `unwrap`.
    fn store(&self) -> MutexGuard<'_, UserStore> {
        self.store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Shared, cheap-to-clone SCIM server state.
#[derive(Clone)]
pub struct ScimServerState {
    inner: Arc<Inner>,
}

impl ScimServerState {
    /// Build state from the configured tenants and the identity provisioner.
    ///
    /// Args:
    /// * `tenants`: The tenants this server accepts provisioning for.
    /// * `provisioner`: The identity-lifecycle port (real [`crate::SdkProvisioner`]).
    ///
    /// Usage:
    /// ```ignore
    /// let state = ScimServerState::new(tenants, Arc::new(SdkProvisioner::new(ctx)));
    /// ```
    pub fn new(tenants: Vec<TenantConfig>, provisioner: Arc<dyn Provisioner>) -> Self {
        let tenants = tenants
            .into_iter()
            .map(|t| (t.tenant_id.clone(), t))
            .collect();
        Self {
            inner: Arc::new(Inner {
                tenants,
                provisioner,
                store: Mutex::new(UserStore::default()),
            }),
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

    /// The identity-provisioning port.
    pub(crate) fn provisioner(&self) -> &Arc<dyn Provisioner> {
        &self.inner.provisioner
    }

    /// Look up a live resource by `(tenant, externalId)` — the idempotency key. A
    /// soft-deleted resource reads as absent, so a Joiner replay provisions afresh
    /// rather than resurrecting a deprovisioned member.
    pub(crate) fn find_by_external(&self, tenant_id: &str, external_id: &str) -> Option<ScimUser> {
        let store = self.inner.store();
        store
            .by_external
            .get(&(tenant_id.to_string(), external_id.to_string()))
            .and_then(|id| store.by_id.get(id))
            .filter(|s| !s.deleted)
            .map(|s| s.user.clone())
    }

    /// Look up a live resource by its id, scoped to the owning tenant (soft-deleted
    /// resources read as absent → 404).
    pub(crate) fn find_by_id(&self, tenant_id: &str, id: &str) -> Option<ScimUser> {
        let store = self.inner.store();
        store
            .by_id
            .get(id)
            .filter(|s| s.tenant_id == tenant_id && !s.deleted)
            .map(|s| s.user.clone())
    }

    /// Look up a resource by id ignoring the soft-delete tombstone, scoped to the
    /// owning tenant. Used by hard-revoke so a deprovisioned member can still be
    /// escalated to cryptographic off-boarding.
    pub(crate) fn find_any_by_id(&self, tenant_id: &str, id: &str) -> Option<ScimUser> {
        let store = self.inner.store();
        store
            .by_id
            .get(id)
            .filter(|s| s.tenant_id == tenant_id)
            .map(|s| s.user.clone())
    }

    /// All live resources owned by a tenant (unordered; the handler sorts for
    /// determinism). Soft-deleted resources are excluded.
    pub(crate) fn users_for_tenant(&self, tenant_id: &str) -> Vec<ScimUser> {
        let store = self.inner.store();
        store
            .by_id
            .values()
            .filter(|s| s.tenant_id == tenant_id && !s.deleted)
            .map(|s| s.user.clone())
            .collect()
    }

    /// Insert a freshly provisioned resource and index it on `(tenant, externalId)`.
    pub(crate) fn insert_user(&self, tenant_id: &str, external_id: Option<String>, user: ScimUser) {
        let mut store = self.inner.store();
        let id = user.id.clone();
        if let Some(ext) = external_id {
            store
                .by_external
                .insert((tenant_id.to_string(), ext), id.clone());
        }
        store.by_id.insert(
            id,
            StoredUser {
                tenant_id: tenant_id.to_string(),
                user,
                deleted: false,
            },
        );
    }

    /// Atomically read-modify-write a live resource under a single lock.
    ///
    /// The lock is held across the whole transform, so concurrent PATCHes on the
    /// same resource serialize (last-writer-wins) and can never interleave into a
    /// split state. The write is all-or-nothing: if `f` returns `Err` the stored
    /// resource is left untouched, giving PATCH its RFC 7644 rollback for free.
    ///
    /// Args:
    /// * `tenant_id`: The owning tenant.
    /// * `id`: The resource id.
    /// * `f`: A pure transform from the current resource to the next one.
    ///
    /// Usage:
    /// ```ignore
    /// let updated = state.update_user(&tenant, &id, |u| apply_patch_operations(u, &ops))?;
    /// ```
    pub(crate) fn update_user<F>(
        &self,
        tenant_id: &str,
        id: &str,
        f: F,
    ) -> Result<ScimUser, ScimError>
    where
        F: FnOnce(ScimUser) -> Result<ScimUser, ScimError>,
    {
        let mut store = self.inner.store();
        let current = store
            .by_id
            .get(id)
            .filter(|s| s.tenant_id == tenant_id && !s.deleted)
            .map(|s| s.user.clone())
            .ok_or_else(|| ScimError::NotFound { id: id.to_string() })?;
        let updated = f(current)?;
        if let Some(slot) = store.by_id.get_mut(id) {
            slot.user = updated.clone();
        }
        Ok(updated)
    }

    /// Flip a resource to hard-revoked: `active:false` and the honest
    /// `revoked:true` extension flag. Called only after the cryptographic
    /// off-boarding succeeds on the KEL.
    pub(crate) fn mark_revoked(&self, tenant_id: &str, id: &str) {
        let mut store = self.inner.store();
        if let Some(slot) = store.by_id.get_mut(id)
            && slot.tenant_id == tenant_id
        {
            slot.user.active = false;
            if let Some(ext) = slot.user.auths_extension.as_mut() {
                ext.revoked = true;
            }
        }
    }

    /// Soft-delete (deprovision) a resource: tombstone it and deactivate it without
    /// touching the KEL. Idempotent — an unknown or already-deleted id is a no-op.
    pub(crate) fn soft_delete(&self, tenant_id: &str, id: &str) {
        let mut store = self.inner.store();
        if let Some(slot) = store.by_id.get_mut(id)
            && slot.tenant_id == tenant_id
        {
            slot.deleted = true;
            slot.user.active = false;
        }
    }
}
