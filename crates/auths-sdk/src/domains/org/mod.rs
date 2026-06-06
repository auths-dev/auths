//! Domain services for org.

/// KERI-native org membership — members as `dip`s delegated by the org AID.
pub mod delegation;
/// Org errors
pub mod error;
/// Org services
pub mod service;
pub mod types;

pub use delegation::{
    OrgMemberAuthority, OrgMemberResult, add_member, list_members, member_policy_context,
    resolve_member_authority, revoke_member,
};
