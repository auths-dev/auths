//! Agent domain HTTP handlers and routes
//!
//! HTTP presentation layer for agent provisioning and authorization.
//! Business logic is in auths-sdk::domains::agents.

pub mod handlers;
pub mod routes;

// Re-export SDK domain types for convenience
pub use auths_sdk::domains::agents::{
    AgentRegistry, AgentService, AgentSession, AgentStatus, AuthorizeRequest, AuthorizeResponse,
    ProvisionRequest, ProvisionResponse,
};
pub use routes::routes;
