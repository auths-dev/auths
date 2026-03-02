//! No-op witness implementation.
//!
//! This is the default witness that disables all witness checks.
//! Use this when:
//! - You don't need split-view protection
//! - You're in a private/trusted environment
//! - The system has other consistency mechanisms (e.g., external consistency logic)

use auths_verifier::keri::Prefix;

use super::hash::EventHash;
use super::provider::WitnessProvider;

/// A no-op witness that returns `None` for all queries.
///
/// This effectively disables witness checking, which is the default
/// behavior for Auths. Split-view protection is opt-in.
///
/// # Example
///
/// ```rust
/// use auths_core::witness::{WitnessProvider, NoOpWitness};
/// use auths_verifier::keri::Prefix;
///
/// let witness = NoOpWitness;
/// let prefix = Prefix::new_unchecked("E123abc".into());
///
/// // Always returns None (no opinion)
/// assert!(witness.observe_identity_head(&prefix).is_none());
///
/// // Disabled by default
/// assert!(!witness.is_enabled());
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOpWitness;

impl NoOpWitness {
    /// Create a new no-op witness.
    pub fn new() -> Self {
        Self
    }
}

impl WitnessProvider for NoOpWitness {
    fn observe_identity_head(&self, _prefix: &Prefix) -> Option<EventHash> {
        None
    }

    fn quorum(&self) -> usize {
        0 // No quorum needed when disabled
    }

    fn is_enabled(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_noop_returns_none() {
        let witness = NoOpWitness;
        let prefix = Prefix::new_unchecked("ETestPrefix".into());
        assert!(witness.observe_identity_head(&prefix).is_none());
    }

    #[test]
    fn test_noop_is_disabled() {
        let witness = NoOpWitness;
        assert!(!witness.is_enabled());
    }

    #[test]
    fn test_noop_quorum_is_zero() {
        let witness = NoOpWitness;
        assert_eq!(witness.quorum(), 0);
    }

    #[test]
    fn test_noop_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NoOpWitness>();
    }
}
