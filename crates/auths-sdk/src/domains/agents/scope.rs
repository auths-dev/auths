//! Reusable agent scope constraints — capability subset, TTL, and delegation depth.
//!
//! Salvaged from the deleted bearer-token agents model (Epic E). The bearer-token
//! session machinery is gone, but these *constraint rules* are sound and are reused
//! by E.7's delegator-anchored scope seal. Pure: no session types, no I/O, no clock —
//! the caller resolves the delegator's remaining TTL and passes it in.

use thiserror::Error;

/// A scope-constraint violation between a delegator and a would-be delegate.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DelegationError {
    /// The delegate requested a capability the delegator does not hold.
    #[error("delegator does not grant capability: {0}")]
    CapabilityNotGranted(String),
    /// The delegate's requested TTL exceeds the delegator's remaining TTL.
    #[error("requested TTL {requested}s exceeds delegator's remaining {available}s")]
    TtlExceedsParent {
        /// The delegate's requested time-to-live, in seconds.
        requested: u64,
        /// The delegator's remaining time-to-live, in seconds.
        available: u64,
    },
    /// The delegator is already at its delegation-depth cap.
    #[error("delegation depth limit reached")]
    DepthLimitExceeded,
}

/// The delegator's scope envelope that a delegate must stay within.
pub struct DelegatorScope<'a> {
    /// Capabilities the delegator itself holds.
    pub capabilities: &'a [String],
    /// The delegator's remaining time-to-live, in seconds.
    pub remaining_ttl_secs: u64,
    /// The delegator's current delegation depth.
    pub depth: u32,
    /// The maximum delegation depth the delegator may reach.
    pub max_depth: u32,
}

/// A delegate's requested scope.
pub struct RequestedScope<'a> {
    /// Capabilities the delegate requests (must be a subset of the delegator's).
    pub capabilities: &'a [String],
    /// The delegate's requested time-to-live, in seconds.
    pub ttl_secs: u64,
}

/// Validate that a delegate's requested scope stays within its delegator's:
/// capability subset, TTL ≤ remaining, and depth below the cap.
///
/// Args:
/// * `delegator`: The delegator's scope envelope.
/// * `requested`: The delegate's requested scope.
///
/// Usage:
/// ```
/// use auths_sdk::domains::agents::scope::{
///     DelegatorScope, RequestedScope, validate_delegation_constraints,
/// };
/// let parent = vec!["read".to_string(), "write".to_string()];
/// let child = vec!["read".to_string()];
/// let delegator = DelegatorScope { capabilities: &parent, remaining_ttl_secs: 3600, depth: 0, max_depth: 2 };
/// let requested = RequestedScope { capabilities: &child, ttl_secs: 1800 };
/// assert!(validate_delegation_constraints(&delegator, &requested).is_ok());
/// ```
pub fn validate_delegation_constraints(
    delegator: &DelegatorScope<'_>,
    requested: &RequestedScope<'_>,
) -> Result<(), DelegationError> {
    for cap in requested.capabilities {
        if !delegator.capabilities.iter().any(|held| held == cap) {
            return Err(DelegationError::CapabilityNotGranted(cap.clone()));
        }
    }
    if requested.ttl_secs > delegator.remaining_ttl_secs {
        return Err(DelegationError::TtlExceedsParent {
            requested: requested.ttl_secs,
            available: delegator.remaining_ttl_secs,
        });
    }
    if delegator.depth >= delegator.max_depth {
        return Err(DelegationError::DepthLimitExceeded);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_subset_valid() {
        let parent = vec!["read".to_string(), "write".to_string()];
        let child = vec!["read".to_string()];
        let d = DelegatorScope {
            capabilities: &parent,
            remaining_ttl_secs: 3600,
            depth: 0,
            max_depth: 2,
        };
        let r = RequestedScope {
            capabilities: &child,
            ttl_secs: 3600,
        };
        assert!(validate_delegation_constraints(&d, &r).is_ok());
    }

    #[test]
    fn capability_subset_invalid() {
        let parent = vec!["read".to_string()];
        let child = vec!["admin".to_string()];
        let d = DelegatorScope {
            capabilities: &parent,
            remaining_ttl_secs: 3600,
            depth: 0,
            max_depth: 2,
        };
        let r = RequestedScope {
            capabilities: &child,
            ttl_secs: 3600,
        };
        assert_eq!(
            validate_delegation_constraints(&d, &r),
            Err(DelegationError::CapabilityNotGranted("admin".to_string()))
        );
    }

    #[test]
    fn ttl_exceeding_parent_is_rejected() {
        let parent = vec!["read".to_string()];
        let child = vec!["read".to_string()];
        let d = DelegatorScope {
            capabilities: &parent,
            remaining_ttl_secs: 3600,
            depth: 0,
            max_depth: 2,
        };
        let r = RequestedScope {
            capabilities: &child,
            ttl_secs: 7200,
        };
        assert!(matches!(
            validate_delegation_constraints(&d, &r),
            Err(DelegationError::TtlExceedsParent { .. })
        ));
    }

    #[test]
    fn depth_limit_is_rejected() {
        let parent = vec!["read".to_string()];
        let child = vec!["read".to_string()];
        let d = DelegatorScope {
            capabilities: &parent,
            remaining_ttl_secs: 3600,
            depth: 2,
            max_depth: 2,
        };
        let r = RequestedScope {
            capabilities: &child,
            ttl_secs: 3600,
        };
        assert_eq!(
            validate_delegation_constraints(&d, &r),
            Err(DelegationError::DepthLimitExceeded)
        );
    }
}
