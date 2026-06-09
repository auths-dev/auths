//! Agent identity domain.
//!
//! The legacy bearer-token session model (UUID `did:keri`, random `bearer_token`,
//! in-memory `AgentRegistry`) was removed in Epic E — it violated the project rule
//! "bearer tokens are a red flag; default to DeviceDID signatures." The real agent
//! surface — agents as KERI `dip`-delegated identifiers — lands in E.3+ (CLI/SDK).
//!
//! For now this module carries only the reusable scope-constraint rules that E.7's
//! delegator-anchored scope seal builds on.

/// Agent delegation workflow — add an agent as a KERI `dip`-delegated identifier.
pub mod delegation;
/// Agent delegation error type.
pub mod error;
/// Reusable capability-subset / TTL / depth scope constraints.
pub mod scope;

pub use delegation::{
    AgentDelegationResult, AgentInfo, BatchRevocation, add, add_scoped, list, revoke, revoke_batch,
    rotate,
};
pub use error::AgentError;
pub use scope::{DelegationError, DelegatorScope, RequestedScope, validate_delegation_constraints};
