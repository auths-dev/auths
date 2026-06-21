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
use auths_scim::resource::{ScimGroup, ScimUser};
use auths_verifier::Capability;
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
    /// Capabilities this tenant may grant. Empty = deny all (RT-006) unless
    /// `allow_all` is set.
    pub allowed_capabilities: Vec<Capability>,
    /// Opt-in permit-all: grant ANY requested capability, bypassing the
    /// allowlist. Off by default; for single-tenant pilots that consciously
    /// accept it.
    pub allow_all: bool,
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
            allow_all: false,
            base_url: String::new(),
            token_hash: Sha256::digest(bearer_token.as_bytes()).into(),
        }
    }

    /// Set the org signing-key alias that anchors this tenant's delegations.
    pub fn with_org_key_alias(mut self, alias: impl Into<String>) -> Self {
        self.org_key_alias = alias.into();
        self
    }

    /// Restrict the capabilities this tenant may grant. Empty denies all (the
    /// secure default) unless [`with_allow_all`](Self::with_allow_all) is set.
    pub fn with_allowed_capabilities(mut self, capabilities: Vec<Capability>) -> Self {
        self.allowed_capabilities = capabilities;
        self
    }

    /// Opt into permit-all: grant any requested capability, bypassing the
    /// allowlist. For single-tenant pilots that consciously accept it.
    pub fn with_allow_all(mut self, allow_all: bool) -> Self {
        self.allow_all = allow_all;
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

/// A stored SCIM Group plus its owning tenant. `deleted` is the soft-delete tombstone,
/// matching the user store's semantics (hidden from reads, recoverable).
struct StoredGroup {
    tenant_id: String,
    group: ScimGroup,
    deleted: bool,
}

/// The per-tenant Group index. Mirrors [`UserStore`]; KEL plays no part — Groups are an
/// org-directory convenience, not cryptographic identities.
#[derive(Default)]
struct GroupStore {
    by_id: HashMap<String, StoredGroup>,
}

impl GroupStore {
    /// Insert a group, stamping a fresh content ETag, and return the stored value.
    fn insert(&mut self, tenant_id: &str, mut group: ScimGroup) -> ScimGroup {
        recompute_group_etag(&mut group);
        let stored = group.clone();
        self.by_id.insert(
            group.id.clone(),
            StoredGroup {
                tenant_id: tenant_id.to_string(),
                group,
                deleted: false,
            },
        );
        stored
    }

    /// A live group by id, scoped to its tenant (a tombstoned or cross-tenant id reads absent).
    fn find_by_id(&self, tenant_id: &str, id: &str) -> Option<ScimGroup> {
        self.by_id
            .get(id)
            .filter(|s| s.tenant_id == tenant_id && !s.deleted)
            .map(|s| s.group.clone())
    }

    /// All live groups owned by a tenant (unordered; the handler sorts for determinism).
    fn list_for_tenant(&self, tenant_id: &str) -> Vec<ScimGroup> {
        self.by_id
            .values()
            .filter(|s| s.tenant_id == tenant_id && !s.deleted)
            .map(|s| s.group.clone())
            .collect()
    }

    /// Apply `f` to a live group, refreshing its ETag on write. Unknown/cross-tenant → NotFound.
    fn update<F>(&mut self, tenant_id: &str, id: &str, f: F) -> Result<ScimGroup, ScimError>
    where
        F: FnOnce(ScimGroup) -> Result<ScimGroup, ScimError>,
    {
        let current = self
            .by_id
            .get(id)
            .filter(|s| s.tenant_id == tenant_id && !s.deleted)
            .map(|s| s.group.clone())
            .ok_or_else(|| ScimError::NotFound { id: id.to_string() })?;
        let mut updated = f(current)?;
        recompute_group_etag(&mut updated);
        if let Some(slot) = self.by_id.get_mut(id) {
            slot.group = updated.clone();
        }
        Ok(updated)
    }

    /// Soft-delete (tombstone) a group, scoped to its tenant. Idempotent.
    fn delete(&mut self, tenant_id: &str, id: &str) {
        if let Some(slot) = self.by_id.get_mut(id)
            && slot.tenant_id == tenant_id
        {
            slot.deleted = true;
        }
    }
}

/// Recompute a group's ETag (`meta.version`) from its content, so a mutation changes it — what
/// `If-Match` needs to detect a stale write. Stable for unchanged content.
fn recompute_group_etag(group: &mut ScimGroup) {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    group.display_name.hash(&mut hasher);
    group.external_id.hash(&mut hasher);
    for member in &group.members {
        member.value.hash(&mut hasher);
    }
    group.meta.version = format!("W/\"{:x}\"", hasher.finish());
}

struct Inner {
    tenants: HashMap<String, TenantConfig>,
    provisioner: Arc<dyn Provisioner>,
    store: Mutex<UserStore>,
    groups: Mutex<GroupStore>,
}

impl Inner {
    /// Lock the store, recovering the guard if a prior holder panicked (poison) —
    /// a poisoned cache is still safe to read/overwrite, so we never `unwrap`.
    fn store(&self) -> MutexGuard<'_, UserStore> {
        self.store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Lock the group store, recovering a poisoned guard the same way.
    fn groups(&self) -> MutexGuard<'_, GroupStore> {
        self.groups
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
                groups: Mutex::new(GroupStore::default()),
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
        let mut updated = f(current)?;
        recompute_etag(&mut updated);
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
            recompute_etag(&mut slot.user);
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

    /// Store a new group (stamps its ETag), returning the stored value.
    pub(crate) fn insert_group(&self, tenant_id: &str, group: ScimGroup) -> ScimGroup {
        self.inner.groups().insert(tenant_id, group)
    }

    /// A live group by id, scoped to its tenant (tombstoned/cross-tenant → absent).
    pub(crate) fn find_group_by_id(&self, tenant_id: &str, id: &str) -> Option<ScimGroup> {
        self.inner.groups().find_by_id(tenant_id, id)
    }

    /// All live groups owned by a tenant (unordered; the handler sorts for determinism).
    pub(crate) fn groups_for_tenant(&self, tenant_id: &str) -> Vec<ScimGroup> {
        self.inner.groups().list_for_tenant(tenant_id)
    }

    /// Apply `f` to a live group, refreshing its ETag on write. Unknown/cross-tenant → NotFound.
    pub(crate) fn update_group<F>(
        &self,
        tenant_id: &str,
        id: &str,
        f: F,
    ) -> Result<ScimGroup, ScimError>
    where
        F: FnOnce(ScimGroup) -> Result<ScimGroup, ScimError>,
    {
        self.inner.groups().update(tenant_id, id, f)
    }

    /// Soft-delete (tombstone) a group, scoped to its tenant. Idempotent.
    pub(crate) fn delete_group(&self, tenant_id: &str, id: &str) {
        self.inner.groups().delete(tenant_id, id)
    }
}

/// Recompute a resource's ETag (`meta.version`) from its mutable content, so any mutation
/// changes it — what an `If-Match` optimistic-concurrency check needs to detect a stale write.
/// A weak ETag; stable for unchanged content so a re-read is not seen as modified.
fn recompute_etag(user: &mut ScimUser) {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    user.user_name.hash(&mut hasher);
    user.external_id.hash(&mut hasher);
    user.display_name.hash(&mut hasher);
    user.active.hash(&mut hasher);
    if let Some(ext) = &user.auths_extension {
        ext.revoked.hash(&mut hasher);
    }
    user.meta.version = format!("W/\"{:x}\"", hasher.finish());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(name: &str) -> ScimUser {
        ScimUser {
            schemas: ScimUser::default_schemas(),
            id: "id-1".to_string(),
            external_id: None,
            user_name: name.to_string(),
            display_name: None,
            active: true,
            meta: Default::default(),
            auths_extension: None,
        }
    }

    #[test]
    fn recompute_etag_changes_with_content_for_if_match() {
        let mut a = user("alice");
        recompute_etag(&mut a);
        let v1 = a.meta.version.clone();
        assert!(v1.starts_with("W/\""), "weak ETag, got {v1}");

        // Same content → same ETag (a no-op re-read is not seen as modified).
        let mut same = user("alice");
        recompute_etag(&mut same);
        assert_eq!(same.meta.version, v1);

        // A content change → a different ETag (a stale If-Match no longer matches).
        a.user_name = "alice-renamed".to_string();
        recompute_etag(&mut a);
        assert_ne!(a.meta.version, v1, "a content change must change the ETag");
    }

    fn group(id: &str, display: &str) -> ScimGroup {
        ScimGroup {
            schemas: ScimGroup::default_schemas(),
            id: id.to_string(),
            external_id: None,
            display_name: display.to_string(),
            members: vec![],
            meta: Default::default(),
        }
    }

    #[test]
    fn group_store_isolates_tenants_and_bumps_etag_on_update() {
        let mut store = GroupStore::default();
        let inserted = store.insert("t1", group("g1", "eng"));
        store.insert("t2", group("g2", "sales"));
        assert!(
            inserted.meta.version.starts_with("W/\""),
            "insert stamps a real ETag"
        );

        // Reads are tenant-scoped.
        assert_eq!(store.find_by_id("t1", "g1").unwrap().display_name, "eng");
        assert!(store.find_by_id("t2", "g1").is_none(), "tenant isolation");
        assert_eq!(store.list_for_tenant("t1").len(), 1);

        // An update applies the change and bumps the ETag; a cross-tenant update is NotFound.
        let before = inserted.meta.version.clone();
        let updated = store
            .update("t1", "g1", |mut g| {
                g.display_name = "engineering".to_string();
                Ok(g)
            })
            .unwrap();
        assert_eq!(updated.display_name, "engineering");
        assert_ne!(
            updated.meta.version, before,
            "a mutation bumps the group ETag"
        );
        assert!(store.update("t2", "g1", Ok).is_err(), "cross-tenant update");

        // Delete tombstones: hidden from find + list.
        store.delete("t1", "g1");
        assert!(store.find_by_id("t1", "g1").is_none());
        assert_eq!(store.list_for_tenant("t1").len(), 0);
    }
}
