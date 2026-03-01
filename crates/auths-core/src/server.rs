//! HTTP server for agent signing (not yet implemented).
//!
//! This module will provide an HTTP endpoint for remote signing requests,
//! complementing the Unix socket-based SSH agent protocol.
//!
//! Planned endpoints:
//! - `POST /sign` — sign a message using a loaded key
//!
//! Depends on: a production-ready async HTTP library (e.g., axum).
