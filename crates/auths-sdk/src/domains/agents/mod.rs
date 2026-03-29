//! Agent provisioning and authorization domain
//!
//! Provides services for agent identity management, including provisioning,
//! authorization, and revocation with delegation support.

/// Delegation constraints and validation
pub mod delegation;
/// Storage abstraction for agent sessions
pub mod persistence;
/// In-memory registry for agent sessions with indexing
pub mod registry;
/// Agent lifecycle and authorization service
pub mod service;
/// Types for agent sessions and requests
pub mod types;

pub use delegation::{DelegationError, validate_delegation_constraints};
pub use persistence::AgentPersistencePort;
pub use registry::AgentRegistry;
pub use service::AgentService;
pub use types::{
    AgentSession, AgentStatus, AuthorizeRequest, AuthorizeResponse, ProvisionRequest,
    ProvisionResponse,
};
