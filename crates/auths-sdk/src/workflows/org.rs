//! Re-exports from [`crate::domains::org::service`].
//!
//! All org workflow logic lives in `domains::org::service`. This module
//! exists only to keep existing `use auths_sdk::workflows::org::*` imports
//! working across CLI, Node, and Python crates.

pub use crate::domains::org::delegation::{
    OrgMemberAuthority, OrgMemberResult, add_member, list_members, member_policy_context,
    resolve_member_authority, revoke_member,
};
pub use crate::domains::org::service::*;
