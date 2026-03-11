//! Registry port definitions and domain types.
//!
//! Concrete Git/Postgres implementations have moved to `auths-storage`.

pub mod backend;
#[allow(clippy::disallowed_methods)]
// INVARIANT: entire module is an I/O adapter — installs Git hooks to disk
pub mod hooks;
pub mod org_member;
pub mod schemas;
pub mod shard;

pub use backend::{RegistryBackend, RegistryError, TenantIdError, ValidatedTenantId};
pub use hooks::{
    HookError, install_cache_hooks, install_linearity_hook, uninstall_cache_hooks,
    uninstall_linearity_hook,
};
pub use org_member::{
    MemberFilter, MemberInvalidReason, MemberStatus, MemberStatusKind, MemberView, OrgMemberEntry,
    attestation_capability_strings, attestation_capability_vec, compute_status,
    expected_org_issuer,
};
pub use schemas::{CachedStateJson, RegistryMetadata, TipInfo};
pub use shard::{path_parts, shard_device_did, shard_prefix};
