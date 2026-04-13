// crate-level allow during curve-agnostic refactor.
#![allow(clippy::disallowed_methods)]

//! Storage adapters for auths-id ports.
//!
//! This crate provides concrete implementations of the storage port traits
//! defined in `auths-id::ports`. Each backend is gated behind a feature flag
//! so consumers only pull in the dependencies they need.
//!
//! ## Features
//!
//! - `backend-git` — Git-backed storage via `libgit2` (enables `GitRegistryBackend`)
//! - `backend-postgres` — PostgreSQL-backed storage via `sqlx` (stub, not yet implemented)
//!
//! ## Usage
//!
//! ```toml
//! [dependencies]
//! auths-storage = { path = "...", features = ["backend-git"] }
//! ```
//!
//! Instantiate the backend and inject it at the composition root:
//!
//! ```rust,ignore
//! use std::sync::Arc;
//! use auths_id::ports::RegistryBackend;
//! use auths_storage::git::GitRegistryBackend;
//!
//! let backend: Arc<dyn RegistryBackend + Send + Sync> =
//!     Arc::new(GitRegistryBackend::new(config));
//! ```

#[cfg(feature = "backend-git")]
pub mod git;

#[cfg(feature = "backend-postgres")]
pub mod postgres;
