//! Configuration and tenant lifecycle types for the Git registry backend.

use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use auths_id::ports::registry::{RegistryError, ValidatedTenantId};

/// Configuration for a Git registry backend instance.
///
/// Encapsulates both the base storage path and optional tenant context.
/// Validation and normalization happen at construction time so that
/// `resolve_repo_path` is infallible.
#[derive(Debug, Clone)]
pub struct RegistryConfig {
    /// Base directory for all registry storage.
    pub base_path: PathBuf,
    /// Validated tenant ID, or `None` in single-tenant mode.
    pub tenant_id: Option<ValidatedTenantId>,
}

impl RegistryConfig {
    /// Single-tenant mode: uses `base_path` directly as the repo root.
    ///
    /// Usage:
    /// ```ignore
    /// let config = RegistryConfig::single_tenant("/var/lib/auths");
    /// ```
    pub fn single_tenant(base_path: impl Into<PathBuf>) -> Self {
        Self {
            base_path: base_path.into(),
            tenant_id: None,
        }
    }

    /// Multi-tenant mode: normalizes `tenant_id` to lowercase, then validates.
    ///
    /// Args:
    /// * `base_path`: Root directory under which tenant repos live.
    /// * `tenant_id`: Raw tenant identifier (will be normalized to lowercase).
    ///
    /// Usage:
    /// ```ignore
    /// let config = RegistryConfig::for_tenant("/var/lib/auths-saas", "Acme").unwrap();
    /// assert_eq!(config.tenant_id.as_ref().map(|t| t.as_str()), Some("acme"));
    /// ```
    pub fn for_tenant(
        base_path: impl Into<PathBuf>,
        tenant_id: impl Into<String>,
    ) -> Result<Self, RegistryError> {
        let validated = ValidatedTenantId::new(tenant_id)?;
        Ok(Self {
            base_path: base_path.into(),
            tenant_id: Some(validated),
        })
    }

    /// Resolve the on-disk repo path for this config.
    ///
    /// Infallible — validation and normalization already done at construction.
    ///
    /// - Single-tenant: returns `base_path` unchanged.
    /// - Multi-tenant: returns `base_path/tenants/<tenant_id>`.
    pub fn resolve_repo_path(&self) -> PathBuf {
        match &self.tenant_id {
            None => self.base_path.clone(),
            Some(tid) => {
                let s: &str = tid.as_ref();
                self.base_path.join("tenants").join(s)
            }
        }
    }
}

/// Lifecycle status of a tenant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantStatus {
    /// Tenant is active and accepting requests.
    Active,
    /// Tenant has been suspended; reads may still be allowed.
    Suspended,
    /// Tenant has been deprovisioned; repo may be retained for audit.
    Deprovisioned,
}

/// Metadata stored alongside a tenant's Git repository in `tenant.json`.
///
/// The server layer reads `tenant_id` and `status` for display; provisioning
/// writes this via `GitRegistryBackend::init_if_needed`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantMetadata {
    /// Schema version for forward-compatibility.
    pub version: u32,
    /// Canonical (lowercase) tenant identifier.
    pub tenant_id: String,
    /// Wall-clock time the tenant was first provisioned.
    pub created_at: DateTime<Utc>,
    /// Current lifecycle status.
    pub status: TenantStatus,
    /// Reserved for future billing integration.
    pub plan: Option<String>,
}

impl TenantMetadata {
    /// Create a new active tenant metadata record.
    ///
    /// Args:
    /// * `tenant_id`: Canonical (already-normalized) tenant identifier.
    pub fn new_active(tenant_id: impl Into<String>) -> Self {
        Self {
            version: 1,
            tenant_id: tenant_id.into(),
            created_at: Utc::now(),
            status: TenantStatus::Active,
            plan: None,
        }
    }
}
