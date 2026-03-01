//! Policy engine for authorization decisions.
//!
//! This module provides the policy evaluation layer that determines whether
//! a device or identity is authorized to perform specific actions.
//!
//! # Architecture
//!
//! The policy engine sits between storage (which provides data) and
//! application code (which needs authorization decisions):
//!
//! ```text
//! ┌─────────────────┐     ┌──────────────┐     ┌─────────────────┐
//! │ Storage/Registry │ ──► │ Policy Engine │ ──► │ Decision (Y/N/?) │
//! └─────────────────┘     └──────────────┘     └─────────────────┘
//!        (data)              (evaluation)           (result)
//! ```
//!
//! # Relationship to Trust Module
//!
//! This module handles **authorization** (can X do Y?), while the
//! [`crate::trust`] module handles **identity verification** (is X who they
//! claim?). Both are needed for secure operation:
//!
//! 1. First, verify identity using [`crate::trust::check_trust`]
//! 2. Then, check authorization using this policy module
//!
//! # Sans-IO Design (INVARIANT)
//!
//! **This module MUST remain pure/sans-IO.** All policy functions take their
//! inputs explicitly and never access storage or system resources directly.
//!
//! ## Prohibited in Production Code
//!
//! - `RegistryBackend` or any storage trait
//! - `git2` or filesystem access
//! - `Utc::now()` or other system clock access
//! - Network I/O
//!
//! ## Required Pattern
//!
//! All external data must be passed as parameters:
//!
//! ```rust,ignore
//! fn evaluate(
//!     attestation: &Attestation,  // Data from storage (caller fetches)
//!     action: &Action,            // What to authorize
//!     now: DateTime<Utc>,         // Time (caller provides)
//! ) -> Decision
//! ```
//!
//! ## Benefits
//!
//! - **Testable**: No mocks needed, just pass test data
//! - **Deterministic**: Same inputs always produce same outputs
//! - **Portable**: Works in WASM, embedded, anywhere
//! - **Auditable**: All decision factors are explicit
//!
//! ## CI Verification
//!
//! Run to verify invariant is maintained:
//! ```bash
//! grep -rn "RegistryBackend\|git2\|std::fs" crates/auths-core/src/policy/
//! # Production code should return nothing (tests/docs excluded)
//! ```

mod decision;
pub mod device;
pub mod org;

pub use decision::Decision;
