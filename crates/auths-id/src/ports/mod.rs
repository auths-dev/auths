//! Port traits for hexagonal architecture.
//!
//! This module is the canonical public API surface for all traits that
//! storage backends (e.g., `auths-storage`) must implement. Consumers
//! import from `auths_id::ports::*` rather than from deep internal paths.
//!
//! ## Dependency direction
//!
//! ```text
//! auths-storage  ──depends on──▶  auths-id::ports
//! auths-id       (never imports from auths-storage)
//! ```

pub mod registry;
pub mod storage;

pub use registry::*;
pub use storage::*;
