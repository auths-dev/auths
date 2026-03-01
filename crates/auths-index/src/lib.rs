//! SQLite-backed index for O(1) attestation, identity, and org member lookups.
//!
//! This crate provides an index layer that enables fast queries on attestation metadata
//! without iterating through all Git refs. The index is stored in a SQLite database
//! (typically `.auths-index.db` in the repository root).
//!
//! # Usage
//!
//! ```rust,ignore
//! use auths_index::{AttestationIndex, IndexedAttestation};
//! use std::path::Path;
//!
//! // Open or create an index
//! let index = AttestationIndex::open_or_create(Path::new(".auths-index.db"))?;
//!
//! // Query attestations by device
//! let attestations = index.query_by_device("did:key:z6Mk...")?;
//!
//! // Get index statistics
//! let stats = index.stats()?;
//! println!("Total attestations: {}", stats.total_attestations);
//! ```

pub mod error;
pub mod index;
pub mod rebuild;
mod schema;

// Re-export main types at crate root
pub use error::{IndexError, Result};
pub use index::{
    AttestationIndex, IndexStats, IndexedAttestation, IndexedIdentity, IndexedOrgMember,
};
pub use rebuild::{DEFAULT_ATTESTATION_PREFIX, RebuildStats, rebuild_attestations_from_git};
