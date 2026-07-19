//! The per-seed latest-anchor store port.
//!
//! The compare-and-set *is* the I-DUP-1 mechanism (D7): an adapter that cannot
//! atomically CAS cannot implement this trait, so an eventually-consistent
//! backend is structurally inexpressible. The default embedded adapter (SQLite)
//! lives in the node; Postgres lives in the cloud repo.

use crate::error::StoreError;
use crate::types::{Anchor, SeedId};

/// The outcome of a [`AnchorStore::compare_and_set`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CasOutcome {
    /// The caller's anchor is now the stored latest for the seed.
    Won,
    /// Another writer advanced the seed first; the winning anchor is returned so
    /// the caller can re-run the pure acceptance rule against it (which yields a
    /// duplicity proof if the heads differ at the same index).
    Lost(Box<Anchor>),
}

/// Per-seed latest-anchor state with a compare-and-set contract.
///
/// The accept path is: pure `accept_anchor` → sign → `compare_and_set` → on
/// `Lost`, re-run the rule against the winner. Concurrency cannot co-sign a
/// fork because the store, not the handler, is the serialization point.
pub trait AnchorStore: Send + Sync {
    /// Store `next` iff the current stored index for `seed` equals
    /// `expected_index` (`None` = the seed has no prior anchor).
    ///
    /// Args:
    /// * `seed`: the spend chain being advanced.
    /// * `expected_index`: the index the caller believes is current.
    /// * `next`: the anchor to store when the expectation holds.
    ///
    /// Returns [`CasOutcome::Won`] on success, or [`CasOutcome::Lost`] carrying
    /// the winner when the expectation failed.
    fn compare_and_set(
        &self,
        seed: &SeedId,
        expected_index: Option<u64>,
        next: &Anchor,
    ) -> Result<CasOutcome, StoreError>;

    /// The latest co-signed anchor for `seed`, if any (FR-7 read surface).
    ///
    /// Args:
    /// * `seed`: the spend chain to read.
    fn latest(&self, seed: &SeedId) -> Result<Option<Anchor>, StoreError>;
}
