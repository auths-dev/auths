//! Witness provider trait.

use auths_verifier::keri::Prefix;

use super::hash::EventHash;

/// A provider that observes identity KEL heads for split-view detection.
///
/// Implementations of this trait act as "witnesses" that can report
/// what they believe to be the current head of an identity's KEL.
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync` to allow use across threads.
/// This is required because policy evaluation may happen in async contexts.
///
/// # No Networking in Trait
///
/// Note that this trait definition contains no networking code. Implementations
/// may use networking internally (e.g., to query remote witnesses), but the
/// trait itself is pure and synchronous.
///
/// # Example
///
/// ```rust,ignore
/// use auths_core::witness::{WitnessProvider, NoOpWitness};
/// use auths_verifier::keri::Prefix;
///
/// // Default: no witness checking
/// let witness = NoOpWitness;
/// let prefix = Prefix::new_unchecked("E123".into());
/// assert!(witness.observe_identity_head(&prefix).is_none());
///
/// // Custom witness implementation
/// struct MyWitness { /* ... */ }
/// impl WitnessProvider for MyWitness {
///     fn observe_identity_head(&self, prefix: &Prefix) -> Option<EventHash> {
///         // Query witness infrastructure
///         EventHash::from_hex("0123456789abcdef0123456789abcdef01234567")
///     }
/// }
/// ```
pub trait WitnessProvider: Send + Sync {
    /// Observe the current head of an identity's KEL.
    ///
    /// Returns the hash of the most recent event the witness has seen
    /// for the given identity prefix.
    ///
    /// # Returns
    ///
    /// - `Some(hash)` - The witness has an opinion on this identity's head
    /// - `None` - The witness has no opinion (offline, not tracking, or disabled)
    ///
    /// # Arguments
    ///
    /// * `prefix` - The KERI prefix of the identity (e.g., "E123abc...")
    fn observe_identity_head(&self, prefix: &Prefix) -> Option<EventHash>;

    /// Get the minimum quorum required for consistency.
    ///
    /// When multiple witnesses are used, this specifies how many must agree
    /// for the head to be considered consistent.
    ///
    /// # Default
    ///
    /// Returns `1` (single witness is sufficient).
    ///
    /// # Quorum Semantics
    ///
    /// - `quorum = 1`: Any single witness disagreement triggers alert
    /// - `quorum = 2`: Requires 2+ witnesses to agree
    /// - `quorum = n`: Requires n witnesses to agree (Byzantine quorum)
    fn quorum(&self) -> usize {
        1
    }

    /// Check if this witness is enabled.
    ///
    /// # Default
    ///
    /// Returns `true`. Override to return `false` for no-op implementations.
    fn is_enabled(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockWitness {
        head: Option<EventHash>,
        quorum: usize,
    }

    impl WitnessProvider for MockWitness {
        fn observe_identity_head(&self, _prefix: &Prefix) -> Option<EventHash> {
            self.head
        }

        fn quorum(&self) -> usize {
            self.quorum
        }
    }

    #[test]
    fn test_default_quorum() {
        let witness = MockWitness {
            head: None,
            quorum: 1,
        };
        assert_eq!(witness.quorum(), 1);
    }

    #[test]
    fn test_custom_quorum() {
        let witness = MockWitness {
            head: None,
            quorum: 3,
        };
        assert_eq!(witness.quorum(), 3);
    }

    #[test]
    fn test_is_enabled_default() {
        let witness = MockWitness {
            head: None,
            quorum: 1,
        };
        assert!(witness.is_enabled());
    }
}
