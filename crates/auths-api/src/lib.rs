//! Auths API Server
//!
//! HTTP server for agent provisioning and authorization using cryptographic identity.
//!
//! # Architecture
//!
//! - **Domains**: Feature-driven modules (agents, developers, etc)
//! - **Shared Infrastructure**: error handling, persistence, middleware
//! - **Services**: Business logic layer (separate from HTTP handlers)
//! - **Handlers**: HTTP request/response handling
//! - **Routes**: Endpoint definitions

pub mod error;

#[path = "middleware.rs"]
pub mod middleware;

#[path = "persistence.rs"]
pub mod persistence;

pub mod app;
pub mod domains;

// Re-export public API
pub use app::{AppState, build_router};
pub use auths_sdk::domains::agents::AgentRegistry;
pub use error::ApiError;
pub use persistence::AgentPersistence;
