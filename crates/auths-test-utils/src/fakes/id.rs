use auths_core::ports::id::UuidProvider;
use std::sync::atomic::{AtomicU64, Ordering};
use uuid::Uuid;

/// Deterministic UUID provider for tests: each call returns the next value in a
/// monotonically increasing counter, producing reproducible sequences with no
/// wall-clock or OS entropy dependency.
///
/// Usage:
/// ```ignore
/// use auths_test_utils::fakes::id::DeterministicUuidProvider;
/// use auths_core::ports::id::UuidProvider;
///
/// let provider = DeterministicUuidProvider::new();
/// assert_eq!(provider.new_id(), uuid::Uuid::from_u128(0));
/// assert_eq!(provider.new_id(), uuid::Uuid::from_u128(1));
/// ```
pub struct DeterministicUuidProvider {
    counter: AtomicU64,
}

impl DeterministicUuidProvider {
    pub fn new() -> Self {
        Self {
            counter: AtomicU64::new(0),
        }
    }
}

impl Default for DeterministicUuidProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl UuidProvider for DeterministicUuidProvider {
    fn new_id(&self) -> Uuid {
        Uuid::from_u128(u128::from(self.counter.fetch_add(1, Ordering::SeqCst)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn increments_deterministically() {
        let p = DeterministicUuidProvider::new();
        assert_eq!(p.new_id(), Uuid::from_u128(0));
        assert_eq!(p.new_id(), Uuid::from_u128(1));
        assert_eq!(p.new_id(), Uuid::from_u128(2));
    }
}
