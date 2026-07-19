//! The default embedded [`AnchorStore`] adapter.
//!
//! The compare-and-set IS the anti-equivocation mechanism (I-DUP-1, D7): the
//! store, not the request handler, is the serialization point, so concurrency
//! can never co-sign a fork. This in-memory adapter implements that contract
//! exactly and is the reference for the production SQLite adapter (single
//! `links=sqlite3` writer — never a second, eventually-consistent store).

use std::collections::HashMap;

use auths_anchor::{Anchor, AnchorStore, CasOutcome, SeedId, StoreError};
use parking_lot::Mutex;

/// An in-memory, single-process latest-anchor store with atomic CAS.
#[derive(Default)]
pub struct InMemoryAnchorStore {
    latest: Mutex<HashMap<[u8; 32], Anchor>>,
}

impl InMemoryAnchorStore {
    /// A fresh, empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl AnchorStore for InMemoryAnchorStore {
    fn compare_and_set(
        &self,
        seed: &SeedId,
        expected_index: Option<u64>,
        next: &Anchor,
    ) -> Result<CasOutcome, StoreError> {
        let mut latest = self.latest.lock();
        let key = *seed.as_bytes();
        match (latest.get(&key), expected_index) {
            (None, None) => {
                latest.insert(key, next.clone());
                Ok(CasOutcome::Won)
            }
            (Some(current), Some(expected)) if current.index == expected => {
                latest.insert(key, next.clone());
                Ok(CasOutcome::Won)
            }
            (Some(current), _) => Ok(CasOutcome::Lost(Box::new(current.clone()))),
            (None, Some(_)) => Err(StoreError::Backend(
                "caller expected a prior anchor but the store has none".into(),
            )),
        }
    }

    fn latest(&self, seed: &SeedId) -> Result<Option<Anchor>, StoreError> {
        Ok(self.latest.lock().get(seed.as_bytes()).cloned())
    }
}
