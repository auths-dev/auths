//! Domain services for Auths functionality.
//!
//! Modules organize domain-specific business logic separate from I/O concerns.
//!
//! ## Domain Architecture
//!
//! Each domain is self-contained with:
//! - `types.rs` — Request/response/config types and domain models
//! - `service.rs` — Business logic and orchestration
//! - `error.rs` — Domain-specific error types

pub mod agents;
pub mod auth;
pub mod ci;
pub mod compliance;
pub mod device;
pub mod diagnostics;
pub mod identity;
pub mod namespace;
pub mod org;
pub mod signing;
