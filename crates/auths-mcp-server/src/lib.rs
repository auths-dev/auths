// MCP server is a server boundary — Utc::now() is expected for request handling.
#![allow(clippy::disallowed_methods)]
//! # auths-mcp-server
//!
//! Reference MCP tool server that validates Auths-backed JWTs for tool authorization.
//!
//! ## How it works
//!
//! 1. Agent acquires a JWT from the OIDC bridge (via attestation chain exchange)
//! 2. Agent calls MCP tool endpoints with `Authorization: Bearer <jwt>`
//! 3. MCP server validates the JWT against the bridge's JWKS endpoint
//! 4. MCP server checks that the JWT's capabilities match the requested tool
//! 5. Tool executes if authorized, returns 401/403 otherwise

pub mod auth;
pub mod config;
pub mod error;
pub mod jwks;
pub mod middleware;
pub mod routes;
pub mod state;
pub mod tools;
pub mod types;

pub use auth::AuthsToolAuth;
pub use config::McpServerConfig;
pub use error::{McpServerError, McpServerResult};
pub use routes::router;
pub use state::McpServerState;
pub use types::VerifiedAgent;
