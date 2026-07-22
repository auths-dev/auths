// MCP server is a server boundary — Utc::now() is expected for request handling.
#![allow(clippy::disallowed_methods)]
//! # auths-mcp-server
//!
//! Reference MCP tool server that authorizes tool calls with either Auths-backed
//! JWTs or KERI `Auths-Presentation`s (the no-issuer passport).
//!
//! ## The JWT mode (an issuer in the path)
//!
//! 1. Agent acquires a JWT from the OIDC bridge (via attestation chain exchange)
//! 2. Agent calls MCP tool endpoints with `Authorization: Bearer <jwt>`
//! 3. MCP server validates the JWT against the bridge's JWKS endpoint
//! 4. MCP server checks that the JWT's capabilities match the requested tool
//! 5. Tool executes if authorized, returns 401/403 otherwise
//!
//! ## The KERI presentation mode (no issuer in the path)
//!
//! Enabled by building the state with
//! [`McpServerState::with_keri_presentation`] (the binary switches it on via
//! `AUTHS_MCP_REGISTRY`):
//!
//! 1. Agent mints a single-use nonce at `GET /v1/auth/challenge`
//! 2. Agent signs a presentation of its delegated credential over the nonce
//! 3. Agent calls tools with `Authorization: Auths-Presentation <token>`
//! 4. MCP server verifies the presentation offline against the KERI registry
//!    (challenge consume, audience binding, revocation) — no token service called
//! 5. The same per-tool capability gate authorizes the call
//!
//! Both modes share one capability gate, so a tool grants the same way no matter
//! how the agent authenticated.

pub mod auth;
pub mod capsec_guard;
pub mod config;
pub mod error;
pub mod jwks;
pub mod keri_auth;
pub mod middleware;
pub mod routes;
pub mod state;
pub mod tools;
pub mod types;

pub use auth::AuthsToolAuth;
pub use config::{KeriPresentationConfig, McpServerConfig};
pub use error::{McpServerError, McpServerResult};
pub use keri_auth::KeriToolAuth;
pub use routes::router;
pub use state::McpServerState;
pub use types::VerifiedAgent;
