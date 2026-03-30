//! Agent domain types, errors, and service orchestration.
//!
//! Manages agent identity provisioning, authorization, and revocation.

/// Delegation constraints and validation
pub mod delegation;
/// Agent operation errors
pub mod error;
/// Storage abstraction for agent sessions
pub mod persistence;
/// In-memory registry for agent sessions with indexing
pub mod registry;
/// Service orchestration for agent operations
pub mod service;
/// Types for agent sessions and requests
pub mod types;

pub use delegation::DelegationError;
pub use error::AgentError;
pub use persistence::AgentPersistencePort;
pub use registry::AgentRegistry;
pub use service::AgentService;
pub use types::{
    AgentSession, AgentStatus, AuthorizeRequest, AuthorizeResponse, ProvisionRequest,
    ProvisionResponse,
};
