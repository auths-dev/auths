//! Diagnostics domain types and errors.

pub mod error;
/// Diagnostics types and configuration
pub mod types;

pub use types::{AgentStatus, AuditSummary, IdentityStatus, NextStep, StatusReport};
