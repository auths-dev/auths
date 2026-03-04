//! Git storage adapter layer for Auths.
//!
//! Implements the storage port traits defined in `auths-core` using `libgit2`.
//! Each adapter wraps a bare Git repository and provides typed access to
//! identity data stored as Git objects.
//!
//! ## Modules
//!
//! - [`GitBlobStore`] — content-addressable blob storage
//! - [`GitRefStore`] — ref-based key-value storage for identity state
//! - [`GitEventLog`] — append-only event log backed by Git refs
//! - [`audit`] — audit log helpers for registry operations

pub mod audit;
mod blob_store;
mod error;
mod event_log;
mod helpers;
mod ref_store;
mod repo;

pub use blob_store::GitBlobStore;
pub use event_log::GitEventLog;
pub use ref_store::GitRefStore;
pub use repo::GitRepo;
