//! Re-exports the storage port surface.
//!
//! This module provides the canonical import path for auxiliary storage traits
//! that `GitRegistryBackend` (and future backends) implement alongside
//! `RegistryBackend`.

pub use crate::storage::attestation::AttestationSource;
pub use crate::storage::driver::{StorageDriver, StorageError};
pub use crate::storage::identity::IdentityStorage;
