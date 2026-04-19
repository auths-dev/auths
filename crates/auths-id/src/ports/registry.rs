//! Re-exports the registry port surface.
//!
//! This module provides the canonical import path for all types that appear
//! in the `RegistryBackend` trait's method signatures. Downstream crates
//! (e.g., `auths-storage`) import from here rather than from deep internal
//! paths under `storage::registry::*`.

pub use crate::storage::registry::backend::{
    AtomicWriteBatch, AtomicWriteOp, RegistryBackend, RegistryError, TenantIdError,
    ValidatedTenantId,
};
pub use crate::storage::registry::org_member::{
    MemberFilter, MemberInvalidReason, MemberStatus, MemberStatusKind, MemberView, OrgMemberEntry,
};
pub use crate::storage::registry::schemas::{CachedStateJson, RegistryMetadata, TipInfo};
